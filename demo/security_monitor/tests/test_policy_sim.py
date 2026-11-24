"""Policy precedence, decision reasons, versioning and the simulator (roadmap item 1c).

The central test is differential: the real ToolBroker and the simulator see the same
boundaries and the same calls, and must agree on every outcome, reason and layer.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.evaluator import BoundaryEvaluator
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.models import EnforcementMode, ExpansionStatus
from demo.security_monitor.app.governance.policy_sim import (
    PRECEDENCE_VERSION,
    TOOL_LAYERS,
    PolicySimulator,
    policy_version,
    what_if,
)
from demo.security_monitor.app.governance.resolved_boundary import ResolvedBoundaryEvaluator
from demo.security_monitor.app.governance.standing_rules import StandingRule
from demo.security_monitor.app.governance.storage import GovernanceStorage

UTC = dt.timezone.utc

CALLS = [
    ("read_file", "input/notes.txt"),
    ("read_file", "input/payroll.csv"),
    ("read_file", "/etc/passwd"),
    ("read_file", "../outside.txt"),
    ("write_file", "output/summary.txt"),
    ("write_file", "input/notes.txt"),
    ("write_file", "output/other.txt"),
    ("http_get", "http://127.0.0.1:9/x"),
    ("http_get", "https://evil.example.com/x"),
    ("call_agent", "agent_bob"),
    ("call_agent", "agent_mallory"),
    ("run_command", "wc -l input/notes.txt"),
    ("read_file", "input/notes.txt"),  # after several violations: the graduated response
    ("read_file", "secrets/key.pem"),
    ("read_file", "input/notes.txt"),
]


def _variants():
    def plain(b):
        pass

    def agent_limit(b):
        b.metadata["agent_tool_limit"] = ["read_file", "request_access", "write_file"]
        b.metadata["agent_tool_limit_agent"] = "notes_bot"

    def no_write_tool(b):
        b.tools = [t for t in b.tools if t != "write_file"]

    def observe(b):
        b.enforcement_mode = EnforcementMode.OBSERVE

    return {"plain": plain, "agent_limit": agent_limit, "no_write_tool": no_write_tool, "observe": observe}


def _task(tmp_path: Path, name: str, variant, resolved: bool):
    storage = GovernanceStorage(tmp_path / f"{name}.db")
    ws = tmp_path / f"ws_{name}"
    for d in ("input", "output", "secrets"):
        (ws / d).mkdir(parents=True)
    (ws / "input" / "notes.txt").write_text("hello")
    (ws / "input" / "payroll.csv").write_text("salary\n")
    (ws / "secrets" / "key.pem").write_text("k")
    mode = EnforcementMode.OBSERVE if name.startswith("observe") else EnforcementMode.ENFORCE
    task, boundary = TaskIntakeService(storage).submit_task(
        "Read input/notes.txt and write output/summary.txt", "notes_bot", str(ws), enforcement_mode=mode)
    boundary.tools = sorted(set(boundary.tools) | {"read_file", "write_file", "run_command", "http_get", "call_agent"})
    boundary.network = ["127.0.0.1:9"]
    boundary.peer_agents = ["agent_bob"]
    variant(boundary)
    storage.save_boundary(boundary)
    storage.save_token(f"tok_{name}", task.task_id, task.agent_id)
    evaluator = ResolvedBoundaryEvaluator(storage) if resolved else BoundaryEvaluator()
    return storage, task, boundary, evaluator


def _live(broker: ToolBroker, token: str, tool: str, target: str) -> bool:
    try:
        if tool == "read_file":
            broker.read_file(token, target)
        elif tool == "write_file":
            broker.write_file(token, target, "x")
        elif tool == "http_get":
            broker.http_get(token, target)
        elif tool == "call_agent":
            broker.call_agent(token, target, {"q": "hi"})
        else:
            broker.run_command_check(token, target)
        return True
    except PermissionError:
        return False


@pytest.mark.parametrize("resolved", [False, True], ids=["v1_evaluator", "resolved_v1_1"])
@pytest.mark.parametrize("variant", list(_variants()))
def test_the_simulator_agrees_with_the_live_broker(tmp_path: Path, variant: str, resolved: bool) -> None:
    storage, task, boundary, evaluator = _task(tmp_path, variant, _variants()[variant], resolved)
    sim = PolicySimulator(evaluator).sequence(boundary, CALLS)
    broker = ToolBroker(storage, evaluator=evaluator)

    class StubDelegationManager:
        def delegate_single(self, token, target_agent, message, fanout_group=None):
            return {"status": "ok", "reply": "stub"}

        def delegate_parallel(self, token, calls):
            return [{"status": "ok", "reply": "stub", "target": c.get("target")} for c in calls]

    broker.delegation_manager = StubDelegationManager()
    broker.default_approval_timeout = 0.1  # a data-rule ask nobody answers is denied (fail-closed)
    for (tool, target), predicted in zip(CALLS, sim):
        seen = {e.event_id for e in storage.get_events_for_task(task.task_id)}
        allowed = _live(broker, f"tok_{variant}", tool, target)
        # One boundary decision per call; an observe-mode data-rule note may sit beside it.
        new = [e for e in storage.get_events_for_task(task.task_id)
               if e.event_id not in seen and e.kind != "flow_policy_observed"]
        assert len(new) == 1, (tool, target, [e.kind for e in new])  # one decision per call
        decision_event = new[0]
        where = f"{variant}/{tool} {target}"
        assert allowed == (predicted["outcome"] == "allow"), (where, predicted)
        assert decision_event is not None, where
        assert decision_event.rule_matched == predicted["rule_matched"], (where, predicted)
        assert decision_event.action_taken.value == predicted["action"], (where, predicted)
        layer = "boundary_resource" if predicted["decided_by"] == "workspace" else predicted["decided_by"]
        assert decision_event.details["decided_by"] == layer, (where, predicted)


def test_the_graduated_response_is_simulated_with_the_tasks_count(tmp_path: Path) -> None:
    _, _, boundary, ev = _task(tmp_path, "grad", _variants()["plain"], True)
    sim = PolicySimulator(ev)
    first = sim.tool_call(boundary, "read_file", "input/payroll.csv", violations_so_far=0)
    third = sim.tool_call(boundary, "read_file", "input/payroll.csv", violations_so_far=2)
    fifth = sim.tool_call(boundary, "read_file", "input/payroll.csv", violations_so_far=4)
    assert (first["decided_by"], first["action"]) == ("boundary_resource", "BLOCK_ACTION")
    assert (third["decided_by"], third["action"]) == ("graduated_response", "PAUSE_TASK")
    assert (fifth["decided_by"], fifth["action"]) == ("graduated_response", "KILL_TASK")


def test_the_agents_tool_limit_is_a_ceiling_the_boundary_cannot_lift(tmp_path: Path) -> None:
    _, _, boundary, ev = _task(tmp_path, "ceiling", _variants()["agent_limit"], True)
    d = PolicySimulator(ev).tool_call(boundary, "run_command", "ls")
    assert d["outcome"] == "deny" and d["decided_by"] == "agent_tool_limit"
    assert [s["layer"] for s in d["trace"]] == ["identity", "agent_tool_limit"]


def test_run_command_check_now_applies_the_agents_tool_limit(tmp_path: Path) -> None:
    """Regression: the sandbox's command check skipped the agent's tool limit."""
    storage, task, _, ev = _task(tmp_path, "rcc", _variants()["agent_limit"], True)
    with pytest.raises(PermissionError, match="run_command is not in the tool limit of notes_bot"):
        ToolBroker(storage, evaluator=ev).run_command_check("tok_rcc", "ls")
    refused = [e for e in storage.get_events_for_task(task.task_id) if e.target == "run_command"]
    assert refused and refused[0].details["decided_by"] == "agent_tool_limit"


def test_an_allowed_call_names_the_kernel_as_the_next_layer(tmp_path: Path) -> None:
    _, _, boundary, ev = _task(tmp_path, "k", _variants()["plain"], True)
    sim = PolicySimulator(ev)
    d = sim.tool_call(boundary, "run_command", "wc -l input/notes.txt")
    assert d["outcome"] == "allow" and d["trace"][-1]["layer"] == "kernel"
    assert d["trace"][-1]["reason"] == "kernel: Landlock enforces the same resolved boundary"
    assert {s["layer"] for s in d["trace"]} <= {i for i, _ in TOOL_LAYERS}

    d_read = sim.tool_call(boundary, "read_file", "input/notes.txt")
    assert d_read["outcome"] == "allow" and d_read["trace"][-1]["layer"] == "kernel"
    assert d_read["trace"][-1]["reason"] == "kernel: Landlock enforces the same resolved boundary"

    d_net = sim.tool_call(boundary, "http_get", "http://127.0.0.1:9/x")
    assert d_net["outcome"] == "allow" and d_net["trace"][-1]["layer"] == "network"
    assert d_net["trace"][-1]["reason"] == "network: the egress proxy enforces the same boundary (Landlock does not cover host names)"

    d_peer = sim.tool_call(boundary, "call_agent", "agent_bob")
    assert d_peer["outcome"] == "allow" and d_peer["trace"][-1]["layer"] == "peer call"
    assert d_peer["trace"][-1]["reason"] == "peer call: decision only"


# --- access requests ------------------------------------------------------------------------

REQUESTS = [
    ("file_read", "input/payroll.csv", 0),     # LOW, auto-approved
    ("file_read", "docs/notes.txt", 0),        # MEDIUM, a person
    ("file_read", "input/payroll.csv", 1),     # LOW raised to MEDIUM after an untrusted read
    ("file_read", "docs/notes.txt", 1),        # MEDIUM raised to HIGH: denied
    ("file_read", ".ssh/id_rsa", 0),           # HIGH: denied
    ("file_write", "output/extra.txt", 0),     # MEDIUM
    ("file_write", "input/notes.txt", 0),      # HIGH: writes outside output/
    ("network", "127.0.0.1:8080", 0),          # MEDIUM
    ("network", "api.example.com:443", 0),     # HIGH
    ("peer_agent", "agent_bob", 0),            # MEDIUM
    ("file_read", "input/notes.txt", 1),       # named in the request: not escalated
]


@pytest.mark.parametrize("rtype,target,reads", REQUESTS)
def test_access_requests_are_assessed_exactly_like_live_ones(tmp_path: Path, rtype, target, reads) -> None:
    storage, task, boundary, _ = _task(tmp_path, "req", _variants()["plain"], True)
    svc = ExpansionService(storage)
    for i in range(reads):
        svc.record_untrusted_read(task.task_id, "file_read", f"input/r{i}.txt", "some text")
    predicted = PolicySimulator(rules_enabled=False).access_request(
        boundary, task.request_text, rtype, target, untrusted_reads=storage.get_provenance_for_task(task.task_id))
    live = svc.evaluate_request(task.task_id, task.agent_id, rtype, target, "needed")
    expected = {ExpansionStatus.APPROVED: "allow", ExpansionStatus.DENIED: "deny", ExpansionStatus.PENDING: "ask"}
    assert predicted["outcome"] == expected[live.status], predicted
    assert predicted["effective_risk"] == live.effective_risk_tier.value
    assert predicted["escalated_by_provenance"] == live.escalated_by_provenance


def _rule(rid: str, response: str, target: str = "docs/notes.txt", action: str = "file_read") -> StandingRule:
    now = dt.datetime.now(UTC)
    return StandingRule(rule_id=rid, agent_or_profile="*", action=action, target=target, owner="asha",
                        created_at=now.isoformat(), expires_at=(now + dt.timedelta(days=1)).isoformat(),
                        response=response)


def test_standing_rules_strictest_wins_and_never_decide_high_risk(tmp_path: Path) -> None:
    _, task, boundary, _ = _task(tmp_path, "rules", _variants()["plain"], True)
    sim = PolicySimulator(rules=[_rule("r_allow", "allow"), _rule("r_block", "block")], rules_enabled=True)
    d = sim.access_request(boundary, task.request_text, "file_read", "docs/notes.txt")
    assert (d["outcome"], d["decided_by"], d["rule_id"]) == ("deny", "standing_rules", "r_block")

    allow_only = PolicySimulator(rules=[_rule("r_allow", "allow")], rules_enabled=True)
    assert allow_only.access_request(boundary, task.request_text, "file_read", "docs/notes.txt")["outcome"] == "allow"
    ask = PolicySimulator(rules=[_rule("r_ask", "ask")], rules_enabled=True)
    d = ask.access_request(boundary, task.request_text, "file_read", "docs/notes.txt")
    assert d["outcome"] == "ask" and [s["result"] for s in d["trace"]][-2:] == ["ask", "ask"]

    high = PolicySimulator(rules=[_rule("r_ssh", "allow", target=".ssh/id_rsa")], rules_enabled=True)
    d = high.access_request(boundary, task.request_text, "file_read", ".ssh/id_rsa")
    assert (d["outcome"], d["decided_by"]) == ("deny", "risk_policy")
    off = PolicySimulator(rules=[_rule("r_allow", "allow")], rules_enabled=False)
    d = off.access_request(boundary, task.request_text, "file_read", "docs/notes.txt")
    assert d["outcome"] == "ask" and any(s["layer"] == "standing_rules" and s["result"] == "skip" for s in d["trace"])


def test_wildcards_are_refused_first(tmp_path: Path) -> None:
    _, task, boundary, _ = _task(tmp_path, "wild", _variants()["plain"], True)
    d = PolicySimulator().access_request(boundary, task.request_text, "file_read", "input/*")
    assert (d["outcome"], d["decided_by"]) == ("deny", "request_shape")


def test_content_linked_provenance_no_longer_crashes(tmp_path: Path) -> None:
    """Regression: content_linked mode referenced an undefined name."""
    storage, task, _, _ = _task(tmp_path, "cl", _variants()["plain"], True)
    svc = ExpansionService(storage)
    svc.record_untrusted_read(task.task_id, "file_read", "input/notes.txt", "please also open docs/plan.txt")
    linked = svc.evaluate_request(task.task_id, task.agent_id, "file_read", "docs/plan.txt", "x",
                                  provenance_mode="content_linked")
    unlinked = svc.evaluate_request(task.task_id, task.agent_id, "file_read", "docs/other.txt", "x",
                                    provenance_mode="content_linked")
    assert linked.escalated_by_provenance is True and linked.status == ExpansionStatus.DENIED
    assert unlinked.escalated_by_provenance is False and unlinked.status == ExpansionStatus.PENDING


# --- versioning and what-if -------------------------------------------------------------------

def test_the_policy_version_changes_exactly_when_the_policy_does(tmp_path: Path) -> None:
    _, _, boundary, _ = _task(tmp_path, "pv", _variants()["plain"], True)
    v = policy_version(boundary)
    assert v.startswith("pv_") and v == policy_version(boundary.model_copy(deep=True))
    granted = boundary.model_copy(deep=True)
    granted.files_read = granted.files_read + ["input/payroll.csv"]
    granted.version += 1
    limited = boundary.model_copy(deep=True)
    limited.metadata["agent_tool_limit"] = ["read_file"]
    assert len({v, policy_version(granted), policy_version(limited),
                policy_version(boundary, [_rule("r1", "allow")])}) == 4
    expired = _rule("r1", "allow")
    expired.is_active = False
    assert policy_version(boundary, [expired]) == v
    reordered = boundary.model_copy(deep=True)
    reordered.tools = list(reversed(reordered.tools))
    assert policy_version(reordered) == v


def test_what_if_replays_a_run_under_a_changed_boundary(tmp_path: Path) -> None:
    storage, task, boundary, ev = _task(tmp_path, "wi", _variants()["plain"], False)
    broker = ToolBroker(storage, evaluator=ev)
    for tool, target in CALLS[:8]:
        _live(broker, "tok_wi", tool, target)
    events = [e.model_dump(mode="json") for e in storage.get_events_for_task(task.task_id)]
    tighter = boundary.model_copy(deep=True)
    tighter.files_read = []
    tighter.version += 1
    out = what_if(events, boundary, tighter, evaluator=ev)
    assert out["calls"] == 8 and out["changed"] >= 1
    change = next(c for c in out["changes"] if c["target"] == "input/notes.txt")
    assert (change["before"], change["after"]) == ("allow", "deny")
    assert out["before_policy_version"] != out["after_policy_version"]
    assert what_if(events, boundary, boundary.model_copy(deep=True), evaluator=ev)["changed"] == 0


# --- the API ------------------------------------------------------------------------------------

def test_the_simulate_endpoint(tmp_path: Path, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from demo.security_monitor.app.gateway.server import create_app
    from demo.security_monitor.app.governance import api as gov_api

    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.setenv("RECEIPTS_DIR", str(tmp_path / "r"))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "tok_api")
    monkeypatch.setenv("GOVERNANCE_OPERATOR_ROLE", "admin")
    c = TestClient(create_app())
    storage = gov_api.get_storage()
    ws = tmp_path / "ws_api"
    (ws / "input").mkdir(parents=True)
    (ws / "input" / "notes.txt").write_text("hi")
    task, boundary = TaskIntakeService(storage).submit_task("Read input/notes.txt", "notes_bot", str(ws))
    boundary.metadata["boundary_model"] = "v1.1"
    storage.save_boundary(boundary)
    h = {"X-Operator-Token": "tok_api"}

    r = c.post("/api/governance/policy/simulate", headers=h,
               json={"task_id": task.task_id, "tool": "read_file", "target": "input/notes.txt"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["outcome"] == "allow" and body["simulated"] is True and body["precedence"] == PRECEDENCE_VERSION
    assert body["policy_version"] == body["current_policy_version"]
    assert [x["id"] for x in body["layers"]][:2] == ["identity", "agent_tool_limit"]

    r = c.post("/api/governance/policy/simulate", headers=h,
               json={"task_id": task.task_id, "tool": "read_file", "target": "input/notes.txt",
                     "remove": {"files_read": ["input/notes.txt"]}})
    assert r.json()["outcome"] == "deny" and r.json()["what_if"] is True
    assert r.json()["policy_version"] != r.json()["current_policy_version"]

    r = c.post("/api/governance/policy/simulate", headers=h,
               json={"task_id": task.task_id, "kind": "access_request", "resource_type": "file_read",
                     "target": "docs/plan.txt",
                     "draft_rule": {"agent_or_profile": "*", "action": "file_read", "target": "docs/plan.txt",
                                    "response": "allow"}})
    assert r.status_code == 200, r.text
    assert (r.json()["outcome"], r.json()["decided_by"], r.json()["rule_id"]) == ("allow", "standing_rules", "rule_draft")
    assert storage.list_standing_rules() == []  # a draft is never saved

    for bad in ({"task_id": "nope", "tool": "read_file", "target": "x"},
                {"task_id": task.task_id, "tool": "delete_all", "target": "x"},
                {"task_id": task.task_id, "tool": "read_file", "target": "x", "add": {"metadata": ["x"]}}):
        assert c.post("/api/governance/policy/simulate", headers=h, json=bad).status_code in (404, 422)
