"""Policy precedence, decision reasons, versioning and a simulator (roadmap item 1c).

Several things can speak about one agent action: the agent's own tool limit, the task
boundary, grants a person made mid-task, standing rules, the risk policy, the graduated
response, and the kernel. This module writes down the order in which they are consulted
and who wins, explains each decision layer by layer, fingerprints the policy a decision
was made under, and answers "what would happen if..." without running anything.

The simulator does not re-implement the checks. It calls the same evaluator, policy
engine, risk assessment and standing-rule matcher the live broker calls, in the order
the broker calls them; tests/test_policy_sim.py runs the real ToolBroker and the
simulator over the same actions and requires the same outcome and the same reason.

Precedence (deny wins; nothing can grant past a layer above it):

  Tool calls (read_file, write_file, http_get, call_agent, run_command)
    1 identity            the task token is valid and the task is live       deny only
    2 agent_tool_limit    the agent's own tool limit (its profile)           deny only, a ceiling
    3 boundary_tools      the tool is in the task boundary (files only)      deny only
    4 boundary_resource   the resolved boundary, with active grants          allow or deny
    5 graduated_response  repeated violations pause (3rd) or kill (5th)      deny only
    6 workspace           the resolved path is inside the task folder        deny only
    7 kernel              Landlock and seccomp, from the same resolved       deny only, independent
                          boundary: a broker allow can still be denied by
                          the kernel, never the reverse

  Access requests (request_access, when step 4 said no)
    A request_shape       exact target, no wildcards                         deny only
    B risk_tier           structure and sensitive names                      LOW / MEDIUM / HIGH
    C provenance          untrusted reads earlier and not anticipated by     raises one tier
                          the user's own request
    D risk_policy         LOW auto-approved, HIGH denied, MEDIUM continues   allow / deny / continue
    E standing_rules      block > ask > allow; never for HIGH or escalated   allow / deny / ask
    F person              allow once, for the task, or for N minutes         allow / deny
    then revocation and expiry remove a grant again (a new boundary version).
"""
from __future__ import annotations

import copy
import datetime
import hashlib
import json
from typing import Any

from .broker import ToolBroker
from .evaluator import BoundaryEvaluator
from .expansion import ExpansionService
from .models import EventVerdict, ExpansionRequest, ExpansionStatus, RiskTier, TaskAction, TaskBoundary
from .policy import TaskPolicyEngine
from .standing_rules import StandingRule, is_standing_rules_enabled, pick_rule

PRECEDENCE_VERSION = "precedence_v1"

TOOL_LAYERS: tuple[tuple[str, str], ...] = (
    ("identity", "Task token valid and task live"),
    ("agent_tool_limit", "The agent's own tool limit"),
    ("boundary_tools", "Tool in the task boundary"),
    ("boundary_resource", "Resolved boundary, with active grants"),
    ("graduated_response", "Repeated violations pause or stop the task"),
    ("workspace", "Path inside the task folder"),
    ("kernel", "Landlock and seccomp (same resolved boundary)"),
)
REQUEST_LAYERS: tuple[tuple[str, str], ...] = (
    ("request_shape", "Exact target, no wildcards"),
    ("risk_tier", "Baseline risk from structure and sensitive names"),
    ("provenance", "Untrusted reads earlier in the task"),
    ("risk_policy", "LOW auto-approved, MEDIUM to a person, HIGH denied"),
    ("standing_rules", "Standing rules (block > ask > allow)"),
    ("person", "A person decides"),
)

TOOLS = ("read_file", "write_file", "http_get", "call_agent", "run_command")
DENY_ACTIONS = (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK)


def policy_version(boundary: TaskBoundary, rules: list[StandingRule] | None = None,
                   resolver: str | None = None) -> str:
    """A short fingerprint of everything that decides an action for this task.

    Two decisions with the same fingerprint were made under the same policy. It changes
    when the boundary changes (a grant, a revoke, an expiry), when the agent's tool limit
    changes, when a standing rule is added, edited or switched off, or when the
    precedence or the boundary resolver changes.
    """
    from .resolved_boundary import RESOLVER_VERSION

    active_rules = sorted(
        ({"id": r.rule_id, "agent": r.agent_or_profile, "action": r.action, "target": r.target,
          "response": r.response, "team": r.team, "expires_at": r.expires_at}
         for r in (rules or []) if r.is_active),
        key=lambda r: r["id"],
    )
    doc = {
        "precedence": PRECEDENCE_VERSION,
        "resolver": resolver or RESOLVER_VERSION,
        "boundary": {
            "version": boundary.version,
            "files_read": sorted(boundary.files_read),
            "files_write": sorted(boundary.files_write),
            "network": sorted(boundary.network),
            "peer_agents": sorted(boundary.peer_agents),
            "tools": sorted(boundary.tools),
            "enforcement_mode": getattr(boundary.enforcement_mode, "value", str(boundary.enforcement_mode)),
        },
        "agent_tool_limit": sorted(boundary.metadata.get("agent_tool_limit") or []) or None,
        "standing_rules": active_rules,
        "standing_rules_enabled": is_standing_rules_enabled(),
    }
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return f"pv_{digest[:16]}"


def receipt_policy_section(initial: TaskBoundary | None, final: TaskBoundary | None) -> dict[str, Any]:
    """Receipt section: the precedence order and the policy fingerprint at start and end."""
    out: dict[str, Any] = {"precedence": PRECEDENCE_VERSION}
    try:
        out["initial_policy_version"] = policy_version(initial) if initial is not None else None
        out["final_policy_version"] = policy_version(final) if final is not None else None
    except Exception as e:  # never let the fingerprint break a receipt
        out["error"] = f"{type(e).__name__}: {e}"[:200]
    return out


def _step(layer: str, result: str, reason: str) -> dict[str, str]:
    return {"layer": layer, "result": result, "reason": reason}


class PolicySimulator:
    """Answers "what would the broker do with this action" without doing it."""

    def __init__(self, evaluator: BoundaryEvaluator | None = None, rules: list[StandingRule] | None = None,
                 rules_enabled: bool | None = None, interactive: bool = False) -> None:
        self.evaluator = evaluator or BoundaryEvaluator()
        self.rules = list(rules or [])
        self.rules_enabled = is_standing_rules_enabled() if rules_enabled is None else rules_enabled
        self.interactive = interactive

    # --- tool calls ---------------------------------------------------------------------

    def tool_call(self, boundary: TaskBoundary, tool: str, target: str, violations_so_far: int = 0,
                  engine: TaskPolicyEngine | None = None) -> dict[str, Any]:
        """The decision for one tool call. `violations_so_far` (or a shared `engine`, for a
        sequence) is what the graduated response has already counted for this task."""
        if tool not in TOOLS:
            raise ValueError(f"unknown tool {tool!r}; one of {', '.join(TOOLS)}")
        b = copy.deepcopy(boundary)
        if engine is None:
            engine = TaskPolicyEngine()
            engine.task_violation_counts[b.task_id] = max(0, int(violations_so_far))
        trace: list[dict[str, str]] = [_step("identity", "pass", "simulated for a valid, live task token")]

        def done(outcome: str, layer: str, reason: str, action: TaskAction, risk: RiskTier | None,
                 resolved: str | None = None, rule: str | None = None) -> dict[str, Any]:
            if outcome == "allow":
                trace.append(_step("kernel", "applies",
                                   "Landlock and seccomp enforce the same resolved boundary on what the agent "
                                   "process and its commands do" if tool == "run_command" else
                                   "Landlock enforces the same resolved boundary on the agent process"))
            return {
                "kind": "tool_call", "tool": tool, "target": target, "outcome": outcome,
                "decided_by": layer, "reason": reason, "rule_matched": rule or reason, "action": action.value,
                "risk_tier": risk.value if risk else None, "resolved_path": resolved,
                "trace": trace, "boundary_version": b.version,
                "violations_counted": engine.task_violation_counts.get(b.task_id, 0),
            }

        # 2 the agent's own tool limit (every tool, run_command included)
        limit_eval = self.evaluator.evaluate_agent_tool(b, tool)
        if limit_eval is not None:
            action, _ = engine.decide(b, limit_eval, interactive=self.interactive)
            trace.append(_step("agent_tool_limit", "deny", limit_eval.rule_matched))
            return done("deny", "agent_tool_limit", limit_eval.rule_matched, action, limit_eval.risk_tier)
        limit = b.metadata.get("agent_tool_limit")
        trace.append(_step("agent_tool_limit", "pass",
                           "no agent tool limit on this task" if limit is None else f"{tool} is in the agent's tool limit"))

        if tool in ("read_file", "write_file"):
            target = ToolBroker._console_path(b, target, tool)
            # 3 the tool is in the task boundary
            tool_eval = self.evaluator.evaluate_tool(b, tool)
            if tool_eval.verdict != EventVerdict.INSIDE:
                action, _ = engine.decide(b, tool_eval, interactive=self.interactive)
                trace.append(_step("boundary_tools", "deny", tool_eval.rule_matched))
                return done("deny", "boundary_tools", tool_eval.rule_matched, action, tool_eval.risk_tier)
            trace.append(_step("boundary_tools", "pass", tool_eval.rule_matched))
            ev = self.evaluator.evaluate_file_access(b, target, is_write=(tool == "write_file"))
        elif tool == "http_get":
            ev = self.evaluator.evaluate_network(b, target)
        elif tool == "call_agent":
            ev = self.evaluator.evaluate_peer_agent(b, target)
        else:
            ev = self.evaluator.evaluate_command(b, target)

        # 4 the resolved boundary; 5 the graduated response on top of it
        action, prevented = engine.decide(b, ev, interactive=self.interactive)
        inside = ev.verdict == EventVerdict.INSIDE
        trace.append(_step("boundary_resource", "allow" if inside else "deny", ev.rule_matched))
        if not inside:
            count = engine.task_violation_counts.get(b.task_id, 0)
            if action in (TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
                trace.append(_step("graduated_response", "deny",
                                   f"violation {count} of this task: {action.value}"))
            else:
                trace.append(_step("graduated_response", "pass", f"violation {count} of this task: {action.value}"))
        if prevented or action in DENY_ACTIONS:
            layer = "graduated_response" if action in (TaskAction.PAUSE_TASK, TaskAction.KILL_TASK) else "boundary_resource"
            return done("deny", layer, ev.rule_matched, action, ev.risk_tier, ev.resolved_path)

        # 6 the file must resolve inside the task folder
        if tool in ("read_file", "write_file"):
            from pathlib import Path

            resolved = Path(ev.resolved_path) if ev.resolved_path else Path(target)
            if not resolved.is_absolute():
                resolved = Path(b.workspace_root) / resolved
            if not ToolBroker._is_path_inside_workspace(resolved, b.workspace_root):
                # The broker refuses without running it, with this message, in both modes.
                reason = "denied (observe: host path not executed)"
                trace.append(_step("workspace", "deny", reason))
                return done("deny", "workspace", reason, action, ev.risk_tier, ev.resolved_path, ev.rule_matched)
            trace.append(_step("workspace", "pass", "inside the task folder"))
        if not inside:  # OBSERVE mode: outside the boundary but only logged
            return done("allow", "boundary_resource", f"observe mode, logged only: {ev.rule_matched}",
                        action, ev.risk_tier, ev.resolved_path, ev.rule_matched)
        return done("allow", "boundary_resource", ev.rule_matched, action, ev.risk_tier, ev.resolved_path)

    def sequence(self, boundary: TaskBoundary, calls: list[tuple[str, str]]) -> list[dict[str, Any]]:
        """Several calls in order, sharing one violation count, as one task would."""
        engine = TaskPolicyEngine()
        return [self.tool_call(boundary, tool, target, engine=engine) for tool, target in calls]

    # --- access requests ------------------------------------------------------------------

    def access_request(self, boundary: TaskBoundary, request_text: str, resource_type: str, target: str,
                       agent_id: str = "agent", untrusted_reads: list[Any] | None = None,
                       provenance_mode: str = "any", staged_snapshot: bool = False,
                       task_team: str | None = None,
                       now: datetime.datetime | None = None) -> dict[str, Any]:
        """The decision for a request_access call (what happens before any person is asked)."""
        trace: list[dict[str, str]] = []

        def done(outcome: str, layer: str, reason: str, **extra: Any) -> dict[str, Any]:
            return {"kind": "access_request", "resource_type": resource_type, "target": target,
                    "outcome": outcome, "decided_by": layer, "reason": reason, "trace": trace,
                    "boundary_version": boundary.version, **extra}

        if not target or not str(target).strip() or any(c in target for c in "*?[]"):
            trace.append(_step("request_shape", "deny", "targets must be exact: no wildcards, not empty"))
            return done("deny", "request_shape", "targets must be exact: no wildcards, not empty")
        trace.append(_step("request_shape", "pass", "exact target"))

        a = ExpansionService.assess_request(request_text, resource_type, target, list(untrusted_reads or []),
                                            provenance_mode=provenance_mode, staged_snapshot=staged_snapshot)
        base, eff = a["baseline_tier"], a["effective_tier"]
        tiers = {"baseline_risk": base.value, "effective_risk": eff.value, "escalated_by_provenance": a["escalated"],
                 "anticipated_by_user": a["anticipated_by_user"]}
        trace.append(_step("risk_tier", base.value, f"baseline {base.value} for {resource_type} {target}"))
        if a["escalated"]:
            trace.append(_step("provenance", f"raised to {eff.value}", a["escalation_reason"] or "untrusted reads"))
        elif a["provenance_mode"] == "off":
            trace.append(_step("provenance", "pass", "provenance escalation is off"))
        elif a["anticipated_by_user"]:
            trace.append(_step("provenance", "pass", "the user's own request names this target"))
        else:
            trace.append(_step("provenance", "pass", "no untrusted reads before this request"))

        if a["status"] == ExpansionStatus.APPROVED:
            trace.append(_step("risk_policy", "allow", "LOW risk is approved automatically"))
            return done("allow", "risk_policy", "LOW risk is approved automatically", **tiers)
        if a["status"] == ExpansionStatus.DENIED:
            trace.append(_step("risk_policy", "deny", "HIGH risk requests from an agent are denied"))
            return done("deny", "risk_policy", "HIGH risk requests from an agent are denied", **tiers)
        trace.append(_step("risk_policy", "continue", "MEDIUM risk: a person decides unless a standing rule does"))

        req = ExpansionRequest(
            request_id="exp_sim", task_id=boundary.task_id, agent_id=agent_id, resource_type=resource_type,
            resource_target=target, justification="(simulated)", baseline_risk_tier=base, effective_risk_tier=eff,
            escalated_by_provenance=a["escalated"], status=ExpansionStatus.PENDING,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        if not self.rules_enabled:
            trace.append(_step("standing_rules", "skip", "standing rules are off (GOVERNANCE_STANDING_RULES)"))
        else:
            rule = pick_rule(self.rules, req, task_team=task_team, now=now, force_enabled=True)
            if rule is None:
                trace.append(_step("standing_rules", "pass", "no standing rule matches"))
            elif rule.response == "allow":
                why = f"allowed by rule {rule.rule_id} (owner {rule.owner})"
                trace.append(_step("standing_rules", "allow", why))
                return done("allow", "standing_rules", why, rule_id=rule.rule_id, **tiers)
            elif rule.response == "block":
                why = f"blocked by rule {rule.rule_id} (owner {rule.owner})"
                trace.append(_step("standing_rules", "deny", why))
                return done("deny", "standing_rules", why, rule_id=rule.rule_id, **tiers)
            else:
                trace.append(_step("standing_rules", "ask", f"rule {rule.rule_id} says always ask a person"))
        trace.append(_step("person", "ask", "waits for a person: allow once, for the task, or for N minutes"))
        return done("ask", "person", "a person decides", **tiers)


def what_if(events: list[dict[str, Any]], before: TaskBoundary, after: TaskBoundary,
            evaluator: BoundaryEvaluator | None = None) -> dict[str, Any]:
    """Replays the tool calls of a past run under two boundaries and lists what changes.

    `events` are receipt or storage events of the broker (kind file_read, file_write,
    network_http, peer_agent, run_command, tool_invocation). Each call is replayed in order
    with its own violation count per boundary, as a real run would count them.
    """
    kind_to_tool = {"file_read": "read_file", "file_write": "write_file", "network_http": "http_get",
                    "peer_agent": "call_agent", "run_command": "run_command"}
    calls: list[tuple[str, str]] = []
    for e in events:
        tool = kind_to_tool.get(str(e.get("kind")))
        if tool and e.get("target") is not None and not e.get("syscall"):
            calls.append((tool, str(e["target"])))
    sim = PolicySimulator(evaluator)
    a = sim.sequence(before, calls)
    b = sim.sequence(after, calls)
    changes = [{"tool": x["tool"], "target": x["target"], "before": x["outcome"], "after": y["outcome"],
                "before_reason": x["reason"], "after_reason": y["reason"], "after_decided_by": y["decided_by"]}
               for x, y in zip(a, b) if x["outcome"] != y["outcome"]]
    return {"calls": len(calls), "changed": len(changes), "changes": changes,
            "before_policy_version": policy_version(before), "after_policy_version": policy_version(after)}
