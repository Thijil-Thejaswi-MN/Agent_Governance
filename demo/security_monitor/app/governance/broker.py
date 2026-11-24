"""Tool Broker (F5.1).

Mediates agent tool execution, validates scoped per-task tokens (F6), evaluates
the Task Boundary BEFORE execution (F7), enforces graduated policies (F9),
and emits normalized governance audit events.
"""
from __future__ import annotations

import concurrent.futures
import datetime
import fnmatch
import json
import os
import stat
import time
import uuid
from pathlib import Path
from typing import Any

import urllib.parse
from .models import (
    EventSource,
    GovernanceEvent,
    RiskTier,
    TaskAction,
    EventVerdict,
    ExpansionRequest,
    ExpansionStatus,
    EnforcementMode,
    TaskBoundary,
)
from .storage import GovernanceStorage
from .evaluator import BoundaryEvaluator
from .policy import TaskPolicyEngine
from .expansion import ExpansionService
from .single_use import consume_single_use
from .llm_providers import redact_llm_error



def _recover_tool_use_failed(body: str) -> dict[str, Any] | None:
    """Turn a provider's HTTP 400 "tool_use_failed" reply back into the tool call the model made.

    Returns an OpenAI-style tool call, or None if the body is not a tool_use_failed error or the
    model's generation cannot be parsed into a single named call.
    """
    try:
        err = (json.loads(body) or {}).get("error") or {}
    except (ValueError, TypeError, AttributeError):
        return None
    if err.get("code") != "tool_use_failed":
        return None
    gen = err.get("failed_generation")
    try:
        call = json.loads(gen) if isinstance(gen, str) else gen
    except (ValueError, TypeError):
        return None
    if isinstance(call, list) and len(call) == 1:
        call = call[0]
    if not isinstance(call, dict) or not isinstance(call.get("name"), str) or not call["name"]:
        return None
    args = call.get("arguments", call.get("parameters", {}))
    if not isinstance(args, str):
        args = json.dumps(args if args is not None else {})
    return {
        "id": "recovered_" + uuid.uuid4().hex[:12],
        "type": "function",
        "function": {"name": call["name"], "arguments": args},
    }

# One read_file returns at most 1 MB; a call_agents request carries at most 8 calls.
MAX_READ_BYTES = 1_048_576
MAX_CALLS_PER_FANOUT = 8


class ToolBroker:
    """Tool execution broker that intercepts and enforces task boundaries prior to execution."""

    def __init__(
        self,
        storage: GovernanceStorage,
        evaluator: BoundaryEvaluator | None = None,
        policy_engine: TaskPolicyEngine | None = None,
        expansion_service: ExpansionService | None = None,
    ) -> None:
        self.storage = storage
        self.evaluator = evaluator or BoundaryEvaluator()
        self.policy_engine = policy_engine or TaskPolicyEngine()
        self.expansion_service = expansion_service or ExpansionService(self.storage)
        self._policy_cache: dict[str, dict[tuple[str, str, int, Any], tuple[Any, Any, TaskAction, bool]]] = {}
        if hasattr(self.storage, "register_boundary_change_callback"):
            self.storage.register_boundary_change_callback(self.invalidate_policy_cache)
        self._event_counter = 0
        self.llm_calls = 0
        self.llm_ok_calls = 0
        self.llm_rate_limited = 0
        self.llm_tool_use_recovered = 0
        self.llm_wait_s = 0.0
        self._llm_in_flight = 0
        self.llm_in_flight_at_end = False
        self.last_llm_error: str | None = None

    def _generate_event_id(self) -> str:
        self._event_counter += 1
        return f"evt_broker_{self._event_counter:04d}_{uuid.uuid4().hex[:6]}"

    def invalidate_policy_cache(self, task_id: str | None = None) -> None:
        """Invalidates cached policy decisions for a specific task or all tasks."""
        if task_id:
            self._policy_cache.pop(task_id, None)
        else:
            self._policy_cache.clear()

    @staticmethod
    def _cached_path_still_valid(eval_res: Any) -> bool:
        """A cached file decision holds only while its resolved path still resolves to itself."""
        resolved = getattr(eval_res, "resolved_path", "") or ""
        if not resolved:
            return False
        try:
            return str(Path(os.path.realpath(resolved))).replace("\\", "/") == resolved.replace("\\", "/")
        except (OSError, ValueError):
            return False

    def _get_grant_state(self, task_id: str) -> tuple:
        """Returns a stable tuple representing the current grant state of the task."""
        try:
            reqs = self.storage.list_expansion_requests(task_id=task_id)
            return tuple((r.request_id, r.status.value, r.used_count or 0) for r in reqs)
        except Exception:
            return ()

    @staticmethod
    def decided_by(ev: GovernanceEvent) -> str:
        """Which precedence layer (policy_sim.TOOL_LAYERS) made this decision."""
        if ev.kind == "authentication":
            return "identity"
        if ev.kind == "request_access":
            return "access_request"
        if ev.kind == "tool_invocation":
            return "agent_tool_limit" if "tool limit" in (ev.rule_matched or "") else "boundary_tools"
        if ev.action_taken in (TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            return "graduated_response"
        return "boundary_resource"

    def _record(self, ev: GovernanceEvent) -> None:
        """Records a broker decision with the precedence layer that made it (decision reasons, item 1c)."""
        ev.details = {**(ev.details or {}), "decided_by": self.decided_by(ev)}
        self.storage.record_event(ev)

    def _check_and_consume_single_use(self, boundary: Any, resource_type: str, target: str) -> None:
        """Uses up every single-use grant of this task that the access matches (single_use.py)."""
        consume_single_use(self.storage, boundary, resource_type, target)

    def request_expansion(
        self,
        token: str,
        resource_type: str,
        resource_target: str,
        justification: str,
        timeout_seconds: float | None = None,
    ) -> tuple[bool, str]:
        if timeout_seconds is None:
            timeout_seconds = getattr(self, "default_approval_timeout", 2.0)
        """Allows an agent to synchronously request boundary expansion mid-execution."""
        if not resource_target or not str(resource_target).strip():
            raise ValueError("resource_target cannot be empty in expansion request")
        if not resource_type or not str(resource_type).strip():
            raise ValueError("resource_type cannot be empty in expansion request")
        if str(resource_type).strip().lower() == "flow":
            raise PermissionError("resource_type 'flow' is reserved for data-flow rules and cannot be requested by agents")
        task_id, agent_id = self._authenticate(token)
        needs_person_reason = None
        boundary = self.storage.get_boundary(task_id)
        if self._flow_rules_apply(task_id, boundary):
            integ, _ = self.storage.get_task_context_label(task_id)
            if integ == "untrusted":
                reason = self._flow_reason(task_id, agent_id, "request_access", resource_target, False)
                if boundary is not None and boundary.enforcement_mode == EnforcementMode.OBSERVE:
                    self._record_flow_observed(task_id, agent_id, boundary, resource_target, reason, "Rule 2")
                else:
                    needs_person_reason = reason
        return self.expansion_service.request_and_wait(
            task_id=task_id,
            agent_id=agent_id,
            resource_type=resource_type,
            resource_target=resource_target,
            justification=justification,
            timeout_seconds=timeout_seconds,
            needs_person_reason=needs_person_reason,
        )

    def request_access(
        self,
        token: str,
        resource_type: str,
        resource_target: str,
        justification: str,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        if timeout_seconds is None:
            timeout_seconds = getattr(self, "default_approval_timeout", 2.0)
        """
        Tool: request_access (F13.2 / M5).
        Agent-facing tool for dynamic boundary expansion requests.
        """
        if not resource_target or not str(resource_target).strip():
            raise ValueError("resource_target cannot be empty in expansion request")
        if not resource_type or not str(resource_type).strip():
            raise ValueError("resource_type cannot be empty in expansion request")
        if str(resource_type).strip().lower() == "flow":
            raise PermissionError("resource_type 'flow' is reserved for data-flow rules and cannot be requested by agents")

        granted, status_or_reason = self.request_expansion(
            token=token,
            resource_type=resource_type,
            resource_target=resource_target,
            justification=justification,
            timeout_seconds=timeout_seconds,
        )
        task_id, agent_id = self._authenticate(token)
        reqs = self.storage.list_expansion_requests(task_id=task_id)
        latest_req = max(reqs, key=lambda r: r.created_at) if reqs else None  # the request just made

        base_risk = latest_req.baseline_risk_tier.value if latest_req and hasattr(latest_req.baseline_risk_tier, "value") else "LOW"
        eff_risk = latest_req.effective_risk_tier.value if latest_req and hasattr(latest_req.effective_risk_tier, "value") else "LOW"
        escalated = bool(latest_req.escalated_by_provenance) if latest_req else False

        # Emit audit event for request_access
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            bnd = self.storage.get_boundary(task_id)
            bnd_ver = bnd.version if bnd else None
        except Exception:
            bnd_ver = None

        eff_risk_tier = latest_req.effective_risk_tier if latest_req and hasattr(latest_req, "effective_risk_tier") else RiskTier.LOW
        ev = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=now_utc,
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            kind="request_access",
            target=resource_target,
            details={
                "resource_type": resource_type,
                "status": status_or_reason,
                "granted": granted,
                "justification": justification,
            },
            verdict=EventVerdict.INSIDE if granted else EventVerdict.OUTSIDE,
            risk_tier=eff_risk_tier,
            action_taken=TaskAction.ALLOW if granted else TaskAction.BLOCK_ACTION,
            prevented=not granted,
            rule_matched=status_or_reason,
            boundary_version=bnd_ver,
        )
        self._record(ev)

        return {
            "granted": granted,
            "status": status_or_reason,
            "resource_type": resource_type,
            "resource_target": resource_target,
            "baseline_risk": base_risk,
            "effective_risk": eff_risk,
            "baseline_risk_tier": base_risk,
            "effective_risk_tier": eff_risk,
            "escalated_by_provenance": escalated,
        }

    @staticmethod
    def _console_path(boundary: Any, file_path: str, tool: str) -> str:
        """Console runs only (the evaluation scripts never set GOVERNANCE_FRIENDLY_PATHS).

        A call with no path is a malformed call, not an attempt to reach a file, so it is
        answered with an error and not recorded as a blocked action. A bare file name that
        matches exactly one allowed file (e.g. "sales_1.csv" for "input/sales_1.csv") is read
        or written as that file, the same way request_access answers it.
        """
        if os.environ.get("GOVERNANCE_FRIENDLY_PATHS") != "1":
            return file_path
        name = (file_path or "").strip()
        if not name:
            raise ValueError(f"{tool} needs a file path, for example 'input/<name>' or 'output/<name>'.")
        if "/" in name or "\\" in name or name.startswith("~"):
            return file_path
        allowed = boundary.files_write if tool == "write_file" else boundary.files_read
        hits = [f for f in allowed if "*" not in f and "?" not in f and f.rsplit("/", 1)[-1] == name]
        return hits[0] if len(hits) == 1 else file_path

    def _check_agent_tool(self, task_id: str, agent_id: str, boundary: Any, tool_name: str) -> None:
        """Refuse a tool outside the agent's own tool limit, and record the refusal."""
        check = getattr(self.evaluator, "evaluate_agent_tool", None)
        limit_eval = check(boundary, tool_name) if check else None
        if limit_eval is None:
            return
        action, prevented = self.policy_engine.decide(boundary, limit_eval)
        self._record(GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="tool_invocation",
            target=tool_name,
            verdict=limit_eval.verdict,
            risk_tier=limit_eval.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=limit_eval.rule_matched,
            boundary_version=boundary.version,
        ))
        raise PermissionError(f"Tool {tool_name} denied: {limit_eval.rule_matched}")

    def _authenticate(self, token: str) -> tuple[str, str]:
        """
        Validates token and returns (task_id, agent_id).
        Raises PermissionError if token is invalid or revoked.
        """
        res = self.storage.lookup_task_by_token(token)
        if not res:
            # Emit UNATTRIBUTED security event
            event = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.TOOL_BROKER,
                task_id=None,
                agent_id="UNATTRIBUTED",
                pid=os.getpid(),
                kind="authentication",
                target="tool_broker",
                verdict=EventVerdict.OUTSIDE,
                risk_tier=RiskTier.HIGH,
                action_taken=TaskAction.BLOCK_ACTION,
                prevented=True,
                rule_matched="invalid or revoked task authorization token",
                boundary_version=None,
            )
            self._record(event)
            raise PermissionError("Access denied: Invalid or revoked task token")
        return res

    @staticmethod
    def _is_path_inside_workspace(target_path: Path | str, workspace_root: Path | str) -> bool:
        try:
            ws_real = Path(workspace_root).resolve()
            target_p = Path(target_path)
            if not target_p.is_absolute():
                target_p = ws_real / target_p
            target_real = target_p.resolve()
            target_real.relative_to(ws_real)
            return True
        except (ValueError, RuntimeError, OSError):
            return False

    # --- Broker Tools ---

    def read_file(self, token: str, file_path: str) -> str:
        """
        Tool: read_file
        Checks task boundary BEFORE opening file.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")
        self._check_agent_tool(task_id, agent_id, boundary, "read_file")
        file_path = self._console_path(boundary, file_path, "read_file")

        norm_target = str(file_path).strip().replace("\\", "/")
        grant_state = self._get_grant_state(task_id)
        cache_key = ("read_file", norm_target, boundary.version, grant_state)
        cached = self._policy_cache.get(task_id, {}).get(cache_key)
        if cached is not None and not self._cached_path_still_valid(cached[1]):
            # A path component changed since the decision was cached (e.g. the file was
            # replaced by a symlink): evaluate it again.
            self._policy_cache.get(task_id, {}).pop(cache_key, None)
            cached = None

        if cached is not None:
            tool_eval, eval_res, action, prevented = cached
        else:
            # Check tool granted
            tool_eval = self.evaluator.evaluate_tool(boundary, "read_file")
            if tool_eval.verdict != EventVerdict.INSIDE:
                action, prevented = self.policy_engine.decide(boundary, tool_eval)
                event = GovernanceEvent(
                    event_id=self._generate_event_id(),
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    source=EventSource.TOOL_BROKER,
                    task_id=task_id,
                    agent_id=agent_id,
                    pid=os.getpid(),
                    kind="tool_invocation",
                    target="read_file",
                    verdict=tool_eval.verdict,
                    risk_tier=tool_eval.risk_tier,
                    action_taken=action,
                    prevented=prevented,
                    rule_matched=tool_eval.rule_matched,
                    boundary_version=boundary.version,
                )
                self._record(event)
                raise PermissionError(f"Tool read_file not granted in task boundary: {tool_eval.rule_matched}")

            # Evaluate target file path
            eval_res = self.evaluator.evaluate_file_access(boundary, file_path, is_write=False)
            action, prevented = self.policy_engine.decide(boundary, eval_res)
            if eval_res.verdict == EventVerdict.INSIDE and not prevented and action == TaskAction.ALLOW:
                if task_id not in self._policy_cache:
                    self._policy_cache[task_id] = {}
                self._policy_cache[task_id][cache_key] = (tool_eval, eval_res, action, prevented)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="file_read",
            target=file_path,
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self._record(event)

        target_display = eval_res.resolved_path or file_path
        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            msg = f"Access to file '{target_display}' denied by boundary: {eval_res.rule_matched}"
            if os.environ.get("GOVERNANCE_ACCESS_HINT") == "1":
                # Console runs only (the evaluation scripts never set this): say how to ask.
                msg += (f". If this file is genuinely needed for the user's task, call request_access with "
                        f"resource_type 'file_read', resource_target '{file_path}' and a short justification; "
                        f"a person will decide.")
            raise PermissionError(msg)

        # REALEXECUTION (Inside boundary)
        target = Path(eval_res.resolved_path) if eval_res.resolved_path else Path(file_path)
        if not target.is_absolute():
            target = Path(boundary.workspace_root) / target

        if not self._is_path_inside_workspace(target, boundary.workspace_root):
            if boundary.enforcement_mode.value == 'OBSERVE' or not prevented:
                raise PermissionError("denied (observe: host path not executed)")
            raise PermissionError(f"Access to file '{target_display}' denied: path is outside task workspace")

        # O_NONBLOCK: opening a FIFO the agent made must not block the shared server.
        flags = os.O_RDONLY | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(target), flags)
        f = None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError(f"Access to file '{target_display}' denied: not a regular file")
            if st.st_size > MAX_READ_BYTES:
                raise PermissionError(f"Access to file '{target_display}' denied: file size ({st.st_size} bytes) exceeds 1 MB limit")
            f = open(fd, "r", encoding="utf-8", errors="replace", closefd=True)  # f now owns fd
            content = f.read(MAX_READ_BYTES + 1)[: MAX_READ_BYTES]
        finally:
            if f is not None:
                f.close()
            else:
                os.close(fd)

        # Update confidentiality context label
        meta = boundary.metadata or {}
        is_secret = False
        pfiles = meta.get("private_files", [])
        norm_fp = str(file_path).replace("\\", "/").lstrip("./")
        fname = Path(file_path).name
        for pf in pfiles:
            p = pf.get("path") if isinstance(pf, dict) else str(pf)
            if p and (norm_fp == str(p).lstrip("./") or fnmatch.fnmatch(norm_fp, str(p).lstrip("./")) or fname == Path(str(p)).name):
                is_secret = True
                break
        canary = meta.get("canary")
        if canary and canary in content:
            is_secret = True
        spats = list(meta.get("sensitive_patterns", []))
        if hasattr(boundary, "sensitive_patterns") and boundary.sensitive_patterns:
            spats.extend(boundary.sensitive_patterns)
        for pat in spats:
            if fnmatch.fnmatch(file_path, pat) or fnmatch.fnmatch(fname, pat):
                is_secret = True
                break

        if is_secret:
            self.storage.update_task_context_label(task_id, confidentiality="secret")
        else:
            self.storage.update_task_context_label(task_id, confidentiality="internal")

        # Record untrusted read in provenance tracker
        if self.expansion_service:
            self.expansion_service.record_untrusted_read(
                task_id=task_id,
                source_type="file_read",
                source_target=file_path,
                content=content,
            )

        # Enforce single-use consumption if granted under HIGH human approval
        self._check_and_consume_single_use(boundary, "file_read", file_path)

        return content

    def write_file(self, token: str, file_path: str, content: str) -> dict[str, Any]:
        """
        Tool: write_file
        Checks task boundary BEFORE writing content.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")
        self._check_agent_tool(task_id, agent_id, boundary, "write_file")
        file_path = self._console_path(boundary, file_path, "write_file")

        norm_target = str(file_path).strip().replace("\\", "/")
        grant_state = self._get_grant_state(task_id)
        cache_key = ("write_file", norm_target, boundary.version, grant_state)
        cached = self._policy_cache.get(task_id, {}).get(cache_key)
        if cached is not None and not self._cached_path_still_valid(cached[1]):
            # A path component changed since the decision was cached (e.g. the file was
            # replaced by a symlink): evaluate it again.
            self._policy_cache.get(task_id, {}).pop(cache_key, None)
            cached = None

        if cached is not None:
            tool_eval, eval_res, action, prevented = cached
        else:
            tool_eval = self.evaluator.evaluate_tool(boundary, "write_file")
            if tool_eval.verdict != EventVerdict.INSIDE:
                action, prevented = self.policy_engine.decide(boundary, tool_eval)
                event = GovernanceEvent(
                    event_id=self._generate_event_id(),
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    source=EventSource.TOOL_BROKER,
                    task_id=task_id,
                    agent_id=agent_id,
                    pid=os.getpid(),
                    kind="tool_invocation",
                    target="write_file",
                    verdict=tool_eval.verdict,
                    risk_tier=tool_eval.risk_tier,
                    action_taken=action,
                    prevented=prevented,
                    rule_matched=tool_eval.rule_matched,
                    boundary_version=boundary.version,
                )
                self._record(event)
                raise PermissionError(f"Tool write_file not granted: {tool_eval.rule_matched}")

            eval_res = self.evaluator.evaluate_file_access(boundary, file_path, is_write=True)
            action, prevented = self.policy_engine.decide(boundary, eval_res)
            if eval_res.verdict == EventVerdict.INSIDE and not prevented and action == TaskAction.ALLOW:
                if task_id not in self._policy_cache:
                    self._policy_cache[task_id] = {}
                self._policy_cache[task_id][cache_key] = (tool_eval, eval_res, action, prevented)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="file_write",
            target=file_path,
            details={"bytes_to_write": len(content.encode("utf-8"))},
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self._record(event)

        target_display = eval_res.resolved_path or file_path
        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            msg = f"Write to file '{target_display}' denied by boundary: {eval_res.rule_matched}"
            if os.environ.get("GOVERNANCE_ACCESS_HINT") == "1" and type(self.evaluator).__name__ == "ResolvedBoundaryEvaluator":
                # Console runs only: say how to have a new file saved after a person reviews it.
                msg += (f". If the user's task genuinely needs this file, write the full content to "
                        f"'staged/{file_path}' instead, then call request_access with resource_type 'file_write' "
                        f"and resource_target '{file_path}'; a person will review that content.")
            raise PermissionError(msg)

        target = Path(eval_res.resolved_path) if eval_res.resolved_path else Path(file_path)
        if not target.is_absolute():
            target = Path(boundary.workspace_root) / target

        if not self._is_path_inside_workspace(target, boundary.workspace_root):
            if boundary.enforcement_mode.value == 'OBSERVE' or not prevented:
                raise PermissionError("denied (observe: host path not executed)")
            raise PermissionError(f"Write to file '{target_display}' denied: path is outside task workspace")

        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        return {"bytes_written": len(content.encode("utf-8")), "path": str(target)}

    def http_get(self, token: str, url: str) -> dict[str, Any]:
        """
        Tool: http_get
        Checks network destination BEFORE opening socket.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")
        self._check_agent_tool(task_id, agent_id, boundary, "http_get")

        # Check tool granted
        tool_eval = self.evaluator.evaluate_tool(boundary, "http_get")
        if tool_eval.verdict != EventVerdict.INSIDE:
            action, prevented = self.policy_engine.decide(boundary, tool_eval)
            event = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.TOOL_BROKER,
                task_id=task_id,
                agent_id=agent_id,
                pid=os.getpid(),
                kind="tool_invocation",
                target="http_get",
                verdict=tool_eval.verdict,
                risk_tier=tool_eval.risk_tier,
                action_taken=action,
                prevented=prevented,
                rule_matched=tool_eval.rule_matched,
                boundary_version=boundary.version,
            )
            self._record(event)
            raise PermissionError(f"Tool http_get not granted, denied by boundary: {tool_eval.rule_matched}")

        norm_target = str(url).strip()
        grant_state = self._get_grant_state(task_id)
        cache_key = ("http_get", norm_target, boundary.version, grant_state)
        cached = self._policy_cache.get(task_id, {}).get(cache_key)

        if cached is not None:
            eval_res, action, prevented = cached
        else:
            eval_res = self.evaluator.evaluate_network(boundary, url)
            action, prevented = self.policy_engine.decide(boundary, eval_res)
            if eval_res.verdict == EventVerdict.INSIDE and not prevented and action == TaskAction.ALLOW:
                if task_id not in self._policy_cache:
                    self._policy_cache[task_id] = {}
                self._policy_cache[task_id][cache_key] = (eval_res, action, prevented)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="network_http",
            target=url,
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self._record(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            parsed = urllib.parse.urlsplit(url)
            host = parsed.netloc.split(":")[0] if parsed.netloc else url
            task = self.storage.get_task(task_id)
            root_id = task.root_task_id or task_id if task else task_id
            refused_msg = {
                "message_id": f"msg_{uuid.uuid4().hex[:16]}",
                "root_task_id": root_id,
                "parent_task_id": task_id,
                "child_task_id": None,
                "from_agent": agent_id,
                "to_agent": f"host:{host}",
                "kind": "request",
                "fanout_group": None,
                "reply_to": None,
                "sent_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "text": url,
                "verdict": "refused",
                "reason": eval_res.rule_matched,
                "integrity": "trusted",
                "forwarded_from": [],
                "contains_private": False,
            }
            self.storage.save_a2a_message(refused_msg)
            raise PermissionError(f"Outbound network request to '{url}' denied by boundary: {eval_res.rule_matched}")

        # Check flow rules: while a multi-agent task is secret, an http_get whose URL has a query string needs the OK
        parsed_url = urllib.parse.urlsplit(url)
        if self._flow_rules_apply(task_id, boundary) and parsed_url.query:
            integ, conf = self.storage.get_task_context_label(task_id)
            if conf == "secret":
                self._check_flow_approval(task_id, agent_id, boundary, "http_get", url)

        # M6: when a fetcher is attached (launcher routes it through the per-task
        # egress proxy), perform the real GET; otherwise keep the M5 stub.
        fetcher = getattr(self, "http_fetcher", None)
        if fetcher is not None:
            fetched = fetcher(token=token, task_id=task_id, url=url)
            body_content = fetched.get("body", "")
            if self.expansion_service:
                self.expansion_service.record_untrusted_read(
                    task_id=task_id,
                    source_type="http_get",
                    source_target=url,
                    content=body_content,
                )
            self.storage.update_task_context_label(task_id, integrity="untrusted")
            self._check_and_consume_single_use(boundary, "network", url)
            return {"status": fetched.get("status", 0), "url": url, "body": body_content}

        # In testing / stub mode:
        body_content = "Mock response from authorized endpoint"
        if self.expansion_service:
            self.expansion_service.record_untrusted_read(
                task_id=task_id,
                source_type="http_get",
                source_target=url,
                content=body_content,
            )
        self.storage.update_task_context_label(task_id, integrity="untrusted")
        self._check_and_consume_single_use(boundary, "network", url)
        return {"status": 200, "url": url, "body": body_content}

    def http_post(
        self,
        token: str,
        url: str,
        file_path: str | None = None,
        data: str | None = None,
    ) -> dict[str, Any]:
        """
        Tool: http_post
        Checks network destination BEFORE opening socket.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")
        self._check_agent_tool(task_id, agent_id, boundary, "http_post")

        # Check tool granted
        tool_eval = self.evaluator.evaluate_tool(boundary, "http_post")
        if tool_eval.verdict != EventVerdict.INSIDE:
            action, prevented = self.policy_engine.decide(boundary, tool_eval)
            event = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.TOOL_BROKER,
                task_id=task_id,
                agent_id=agent_id,
                pid=os.getpid(),
                kind="tool_invocation",
                target="http_post",
                verdict=tool_eval.verdict,
                risk_tier=tool_eval.risk_tier,
                action_taken=action,
                prevented=prevented,
                rule_matched=tool_eval.rule_matched,
                boundary_version=boundary.version,
            )
            self._record(event)
            raise PermissionError(f"Tool http_post not granted, denied by boundary: {tool_eval.rule_matched}")

        eval_res = self.evaluator.evaluate_network(boundary, url)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="network_http",
            target=url,
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self._record(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            parsed = urllib.parse.urlsplit(url)
            host = parsed.netloc.split(":")[0] if parsed.netloc else url
            task = self.storage.get_task(task_id)
            root_id = task.root_task_id or task_id if task else task_id

            contains_priv = False
            if file_path:
                fname = Path(file_path).name
                pfiles = (boundary.metadata or {}).get("private_files", [])
                ppaths = {p if isinstance(p, str) else p.get("path") for p in pfiles}
                if file_path in ppaths or fname in ppaths or any(p and (p.endswith(file_path) or p.endswith(fname)) for p in ppaths if isinstance(p, str)):
                    contains_priv = True
                spats = list((boundary.metadata or {}).get("sensitive_patterns", []))
                if hasattr(boundary, "sensitive_patterns") and boundary.sensitive_patterns:
                    spats.extend(boundary.sensitive_patterns)
                if any(fnmatch.fnmatch(file_path, pat) or fnmatch.fnmatch(fname, pat) for pat in spats):
                    contains_priv = True

            payload_text = Path(file_path).name if file_path else (str(data)[:200] if data else "")
            refused_msg = {
                "message_id": f"msg_{uuid.uuid4().hex[:16]}",
                "root_task_id": root_id,
                "parent_task_id": task_id,
                "child_task_id": None,
                "from_agent": agent_id,
                "to_agent": f"host:{host}",
                "kind": "request",
                "fanout_group": None,
                "reply_to": None,
                "sent_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "text": payload_text,
                "verdict": "refused",
                "reason": eval_res.rule_matched,
                "integrity": "trusted",
                "forwarded_from": [],
                "contains_private": contains_priv,
            }
            self.storage.save_a2a_message(refused_msg)
            raise PermissionError(f"Outbound network request to '{url}' denied by boundary: {eval_res.rule_matched}")

        # When file_path is given, the broker reads it through the same checks as read_file (boundary + realpath)
        # Reading raises the confidentiality context label before checking flow approval.
        post_data = data
        if file_path:
            post_data = self.read_file(token, file_path)

        # Check flow rules: Rule 1 (Secret data) and Rule 2 (Untrusted content)
        self._check_flow_approval(task_id, agent_id, boundary, "http_post", url)

        fetcher = getattr(self, "http_fetcher", None)
        if fetcher is not None:
            fetched = fetcher(token=token, task_id=task_id, url=url, method="POST", data=post_data)
            self.storage.update_task_context_label(task_id, integrity="untrusted")
            return {"status": fetched.get("status", 200), "url": url, "body": fetched.get("body", "")}

        self.storage.update_task_context_label(task_id, integrity="untrusted")
        return {"status": 200, "url": url, "body": "Mock POST response from authorized endpoint"}

    def handle_http_redirect(self, token: str, original_url: str, redirect_target: str) -> str:
        """
        Re-evaluates a redirect hop against the task boundary before following.
        Prevents redirect-based boundary escapes (e.g. allowed.host -> 302 -> evil.com).
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

        eval_res = self.evaluator.evaluate_network(boundary, redirect_target)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="network_http_redirect",
            target=redirect_target,
            details={"original_url": original_url},
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self._record(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"HTTP redirect to '{redirect_target}' denied by boundary: {eval_res.rule_matched}")

        return redirect_target

    def run_command(self, token: str, command: str, workspace_root: Path | str | None = None) -> dict[str, Any]:
        """
        Tool: run_command
        Executes commands under M4 OS enforcement when permitted by boundary.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")
        self._check_agent_tool(task_id, agent_id, boundary, "run_command")

        eval_res = self.evaluator.evaluate_command(boundary, command)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="run_command",
            target=command,
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self._record(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"Command execution denied: {eval_res.rule_matched}")

        import subprocess
        import sys

        # On Linux, run via CgroupTaskRunner if available
        if sys.platform == "linux":
            try:
                from .os_layer.runner import CgroupTaskRunner, TaskWorkspace
            except ImportError:
                pass  # Linux isolation deps not installed; fall through to basic subprocess
            else:
                # M6: Landlock rules are compiled from the task boundary (--rules mode),
                # not from the workspace layout.
                from .os_layer.sandbox_spec import compile_landlock_rules, compile_landlock_rules_resolved, write_rules_file
                from .resolved_boundary import ResolvedBoundaryEvaluator

                runner = CgroupTaskRunner(self.storage)
                ws_root = Path(workspace_root or boundary.workspace_root).resolve()
                ws = TaskWorkspace(task_id=ws_root.name, base_dir=ws_root.parent)
                ws.setup()
                control = ws_root.parent / ".control" / task_id
                control.mkdir(parents=True, exist_ok=True)
                if isinstance(self.evaluator, ResolvedBoundaryEvaluator):  # M7 path: same resolved entries as the file tools
                    compiled = compile_landlock_rules_resolved(self.evaluator.resolve(boundary), proxy_port=None)
                else:
                    compiled = compile_landlock_rules(boundary, ws_root, proxy_port=None)
                rules = write_rules_file(compiled, control / f"rules_broker_{uuid.uuid4().hex[:8]}.json")
                res = runner.run_task_command(
                    task_id=task_id,
                    cmd=["/bin/sh", "-c", command],
                    workspace=ws,
                    token=token,
                    rules_file=rules,
                )
                return {
                    "stdout": res.stdout,
                    "stderr": res.stderr,
                    "exit_code": res.returncode,
                    "isolation_level": getattr(res, "isolation_level", "unknown"),
                }

        # Subprocess execution fallback
        cwd_dir = str(workspace_root) if workspace_root and Path(workspace_root).exists() else None
        res = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            cwd=cwd_dir,
            timeout=30.0,
        )
        return {
            "stdout": res.stdout,
            "stderr": res.stderr,
            "exit_code": res.returncode,
        }

    def run_command_check(self, token: str, command: str) -> dict[str, Any]:
        """
        Tool: run_command_check (M6).
        Decides whether run_command is in the task boundary WITHOUT executing it.
        The agent shim executes allowed commands itself, inside the sandbox, so the
        OS layer (not this broker) is what limits their effects.
        """
        from .redaction import redact_command

        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

        # The agent's own tool limit applies to sandboxed commands too (it used to be skipped
        # here, so an agent without run_command could still run commands if the boundary had it).
        self._check_agent_tool(task_id, agent_id, boundary, "run_command")

        norm_target = str(command).strip()
        grant_state = self._get_grant_state(task_id)
        cache_key = ("run_command", norm_target, boundary.version, grant_state)
        cached = self._policy_cache.get(task_id, {}).get(cache_key)

        if cached is not None:
            eval_res, action, prevented = cached
        else:
            eval_res = self.evaluator.evaluate_command(boundary, command)
            action, prevented = self.policy_engine.decide(boundary, eval_res)
            if eval_res.verdict == EventVerdict.INSIDE and not prevented and action == TaskAction.ALLOW:
                if task_id not in self._policy_cache:
                    self._policy_cache[task_id] = {}
                self._policy_cache[task_id][cache_key] = (eval_res, action, prevented)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="run_command",
            target=redact_command(command),
            details={"execution": "agent_local_in_sandbox", "check_only": True},
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self._record(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"Command execution denied: {eval_res.rule_matched}")
        return {"allowed": True, "rule_matched": eval_res.rule_matched}

    def _flow_rules_apply(self, task_id: str, boundary: TaskBoundary | None) -> bool:
        """The two data-flow rules apply to multi-agent jobs only: a task that was delegated
        (it has a parent) or one that may call other agents. Single-agent tasks behave as before."""
        task_rec = self.storage.get_task(task_id)
        if task_rec is not None and getattr(task_rec, "parent_task_id", None):
            return True
        return bool(boundary is not None and (boundary.peer_agents or []))

    @staticmethod
    def _display_name(agent_id: str) -> str:
        try:
            from .agent_profiles import load_agent_profile

            name = str(load_agent_profile(agent_id).get("name") or "").strip()
        except Exception:
            name = ""
        if name.endswith(" Agent"):
            name = name[: -len(" Agent")]
        return name or agent_id.replace("_", " ").title()

    def _flow_reason(self, task_id: str, agent_id: str, action_type: str, target: str, is_secret: bool) -> str:
        who = self._display_name(agent_id)
        if action_type in ("call_agent", "call_agents"):
            names = ", ".join(self._display_name(t.strip()) for t in target.split(",") if t.strip())
            action = f"message {names}"
        elif action_type == "http_post":
            action = f"send data to {target}"
        else:
            action = f"ask for access to {target}"
        if is_secret:
            return f"{who} wants to {action} while holding private data"
        sources = {getattr(p, "source_type", "") for p in self.storage.get_provenance_for_task(task_id)}
        if "peer_message" in sources and "http_get" not in sources:
            seen = "a reply from another agent"
        elif "http_get" in sources and "peer_message" not in sources:
            seen = "content from a website"
        else:
            seen = "content from a website or another agent"
        return f"{who} wants to {action} after reading {seen}"

    def _record_flow_observed(self, task_id: str, agent_id: str, boundary: TaskBoundary, target: str, reason: str, rule: str) -> None:
        """Observe mode: the data-flow rule is recorded, not enforced."""
        ev = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="flow_policy_observed",
            target=target,
            details={"reason": reason, "rule": rule},
            verdict=EventVerdict.INSIDE,
            risk_tier=RiskTier.HIGH,
            action_taken=TaskAction.ALERT,
            prevented=False,
            rule_matched=reason,
            boundary_version=boundary.version,
        )
        self._record(ev)

    def _check_flow_approval(
        self,
        task_id: str,
        agent_id: str,
        boundary: TaskBoundary,
        action_type: str,
        target: str,
    ) -> None:
        """Enforces Rule 1 (Secret data) and Rule 2 (Untrusted content)."""
        if not self._flow_rules_apply(task_id, boundary):
            return

        integ, conf = self.storage.get_task_context_label(task_id)
        is_secret = (conf == "secret")
        is_untrusted = (integ == "untrusted")

        if not is_secret and not is_untrusted:
            return

        reason = self._flow_reason(task_id, agent_id, action_type, target, is_secret)

        reqs = self.storage.list_expansion_requests(task_id=task_id)
        for r in reqs:
            # An earlier OK counts only for this same action on this same target, once.
            if (
                r.resource_type == "flow"
                and r.resource_target == target
                and r.justification == reason
                and r.status == ExpansionStatus.APPROVED
                and (r.used_count or 0) == 0
            ):
                r.used_count = (r.used_count or 0) + 1
                self.storage.save_expansion_request(r)
                return

        if boundary.enforcement_mode == EnforcementMode.OBSERVE:
            self._record_flow_observed(task_id, agent_id, boundary, target, reason, "Rule 1" if is_secret else "Rule 2")
            return

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        req_id = f"exp_req_flow_{uuid.uuid4().hex[:12]}"
        timeout_s = getattr(self, "default_approval_timeout", 2.0)
        req = ExpansionRequest(
            request_id=req_id,
            task_id=task_id,
            agent_id=agent_id,
            resource_type="flow",
            resource_target=target,
            justification=reason,
            baseline_risk_tier=RiskTier.HIGH,
            effective_risk_tier=RiskTier.HIGH,
            escalated_by_provenance=is_untrusted,
            status=ExpansionStatus.PENDING,
            created_at=now_utc,
            resolved_at=None,
            resolved_by=None,
            single_use=True,
            used_count=0,
            timeout_seconds=timeout_s,
            reason=reason,
        )
        self.storage.save_expansion_request(req)
        self.storage.record_task_step(
            task_id,
            kind="expansion",
            layer="broker",
            verdict="PENDING",
            summary=f"Flow approval requested: {reason}",
            detail=reason,
            source_label="broker",
        )

        if self.expansion_service and self.expansion_service.user_approval_hook is not None:
            if self.expansion_service.user_approval_hook(req):
                self.expansion_service.approve_request(req.request_id, approved_by="simulated_user")
                req.used_count = 1
                self.storage.save_expansion_request(req)
                return
            else:
                self.expansion_service.deny_request(req.request_id, denied_by="simulated_user", reason="Denied by user hook")
                raise PermissionError(f"Flow denied: {reason}")

        start_time = time.time()
        poll_interval = 0.05
        approved = False
        while (time.time() - start_time) < timeout_s:
            time.sleep(poll_interval)
            cur = self.storage.get_expansion_request(req.request_id)
            if not cur:
                break
            if cur.status == ExpansionStatus.APPROVED:
                cur.used_count = (cur.used_count or 0) + 1
                self.storage.save_expansion_request(cur)
                approved = True
                break
            if cur.status == ExpansionStatus.DENIED:
                approved = False
                break

        if not approved:
            if self.expansion_service:
                self.expansion_service.deny_request(req.request_id, denied_by="timeout_fail_closed", reason="Flow approval timed out")
            else:
                req.status = ExpansionStatus.DENIED
                req.resolved_by = "timeout_fail_closed"
                req.resolved_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                req.reason = "Flow approval timed out"
                self.storage.save_expansion_request(req)
            raise PermissionError(f"Flow denied by policy: {reason}")

    def call_agent(self, token: str, target_agent: str, message: dict[str, Any] | str) -> dict[str, Any]:
        """
        Tool: call_agent
        Checks peer agent boundary BEFORE message dispatch.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")
        self._check_agent_tool(task_id, agent_id, boundary, "call_agent")

        # Check tool granted
        tool_eval = self.evaluator.evaluate_tool(boundary, "call_agent")
        if tool_eval.verdict != EventVerdict.INSIDE:
            action, prevented = self.policy_engine.decide(boundary, tool_eval)
            event = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.TOOL_BROKER,
                task_id=task_id,
                agent_id=agent_id,
                pid=os.getpid(),
                kind="tool_invocation",
                target="call_agent",
                verdict=tool_eval.verdict,
                risk_tier=tool_eval.risk_tier,
                action_taken=action,
                prevented=prevented,
                rule_matched=tool_eval.rule_matched,
                boundary_version=boundary.version,
            )
            self._record(event)
            raise PermissionError(f"Tool call_agent not granted, denied by boundary: {tool_eval.rule_matched}")

        norm_target = str(target_agent).strip().lower()
        grant_state = self._get_grant_state(task_id)
        cache_key = ("call_agent", norm_target, boundary.version, grant_state)
        cached = self._policy_cache.get(task_id, {}).get(cache_key)

        if cached is not None:
            eval_res, action, prevented = cached
        else:
            eval_res = self.evaluator.evaluate_peer_agent(boundary, target_agent)
            action, prevented = self.policy_engine.decide(boundary, eval_res)
            if eval_res.verdict == EventVerdict.INSIDE and not prevented and action == TaskAction.ALLOW:
                if task_id not in self._policy_cache:
                    self._policy_cache[task_id] = {}
                self._policy_cache[task_id][cache_key] = (eval_res, action, prevented)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="peer_agent",
            target=target_agent,
            details={"message_summary": str(message)[:100]},
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self._record(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            task = self.storage.get_task(task_id)
            root_id = task.root_task_id or task_id if task else task_id
            msg_text = message.get("text", "") if isinstance(message, dict) else str(message)
            refused_msg = {
                "message_id": f"msg_{uuid.uuid4().hex[:16]}",
                "root_task_id": root_id,
                "parent_task_id": task_id,
                "child_task_id": None,
                "from_agent": agent_id,
                "to_agent": target_agent,
                "kind": "request",
                "fanout_group": None,
                "reply_to": None,
                "sent_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "text": msg_text[:8192],
                "verdict": "refused",
                "reason": eval_res.rule_matched,
                "integrity": "trusted",
                "forwarded_from": [],
                "contains_private": False,
            }
            self.storage.save_a2a_message(refused_msg)
            raise PermissionError(f"Communication with agent '{target_agent}' denied by boundary: {eval_res.rule_matched}")

        # Delegation pre-checks: profile exists, cycle, depth before flow check
        if getattr(boundary, "enforcement_mode", None) != EnforcementMode.OBSERVE:
            from .agent_profiles import load_agent_profile
            try:
                profile = load_agent_profile(target_agent)
            except Exception:
                raise PermissionError(f"Agent profile not found for '{target_agent}'")

            task = self.storage.get_task(task_id)
            chain = getattr(task, "chain", []) or [agent_id]
            if target_agent in chain:
                raise PermissionError(f"Cycle detected: agent '{target_agent}' already exists in delegation chain: {chain}")

            depth = getattr(task, "depth", 0)
            if depth + 1 > 4:
                raise PermissionError(f"Maximum delegation depth 4 exceeded: requested depth {depth + 1}")

        # Check flow rules: Rule 1 (Secret data) and Rule 2 (Untrusted content)
        self._check_flow_approval(task_id, agent_id, boundary, "call_agent", target_agent)

        dm = getattr(self, "delegation_manager", None)
        if dm is None:
            from .delegation import DelegationManager
            dm = DelegationManager(self.storage)
            self.delegation_manager = dm

        res = dm.delegate_single(token, target_agent, message)
        self._check_and_consume_single_use(boundary, "peer_agent", target_agent)

        reply_content = res.get("reply", "") if isinstance(res, dict) else str(res)
        reply_conf = res.get("confidentiality", "public") if isinstance(res, dict) else "public"
        self.storage.update_task_context_label(task_id, integrity="untrusted", confidentiality=reply_conf)
        if self.expansion_service:
            self.expansion_service.record_untrusted_read(
                task_id=task_id,
                source_type="peer_message",
                source_target=target_agent,
                content=reply_content,
            )

        return res

    def call_agents(self, token: str, calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Tool: call_agents
        Checks tool limit once for call_agent. Then runs the same per-target checks for each target
        before starting any child. Refused targets get a refused row; allowed ones run in parallel.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")
        self._check_agent_tool(task_id, agent_id, boundary, "call_agent")

        # Check tool granted
        tool_eval = self.evaluator.evaluate_tool(boundary, "call_agents")
        if tool_eval.verdict != EventVerdict.INSIDE:
            action, prevented = self.policy_engine.decide(boundary, tool_eval)
            event = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.TOOL_BROKER,
                task_id=task_id,
                agent_id=agent_id,
                pid=os.getpid(),
                kind="tool_invocation",
                target="call_agents",
                verdict=tool_eval.verdict,
                risk_tier=tool_eval.risk_tier,
                action_taken=action,
                prevented=prevented,
                rule_matched=tool_eval.rule_matched,
                boundary_version=boundary.version,
            )
            self._record(event)
            raise PermissionError(f"Tool call_agents not granted, denied by boundary: {tool_eval.rule_matched}")

        if len(calls) > MAX_CALLS_PER_FANOUT:
            raise PermissionError(
                f"call_agents accepts at most {MAX_CALLS_PER_FANOUT} calls per request; {len(calls)} were sent"
            )

        grant_state = self._get_grant_state(task_id)
        task = self.storage.get_task(task_id)
        root_id = task.root_task_id or task_id if task else task_id
        group_id = f"fanout_{uuid.uuid4().hex[:12]}"

        from .agent_profiles import load_agent_profile
        chain = getattr(task, "chain", []) or [agent_id]
        depth = getattr(task, "depth", 0)

        allowed_calls: list[tuple[int, dict[str, Any]]] = []
        indexed_results: dict[int, dict[str, Any]] = {}

        for idx, call_dict in enumerate(calls):
            tgt = call_dict.get("target") or call_dict.get("target_agent", "")
            msg = call_dict.get("message", {})
            norm_target = str(tgt).strip().lower()
            cache_key = ("call_agent", norm_target, boundary.version, grant_state)
            cached = self._policy_cache.get(task_id, {}).get(cache_key)

            if cached is not None:
                eval_res, action, prevented = cached
            else:
                eval_res = self.evaluator.evaluate_peer_agent(boundary, tgt)
                action, prevented = self.policy_engine.decide(boundary, eval_res)
                if eval_res.verdict == EventVerdict.INSIDE and not prevented and action == TaskAction.ALLOW:
                    if task_id not in self._policy_cache:
                        self._policy_cache[task_id] = {}
                    self._policy_cache[task_id][cache_key] = (eval_res, action, prevented)

            event = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.TOOL_BROKER,
                task_id=task_id,
                agent_id=agent_id,
                pid=os.getpid(),
                kind="peer_agent",
                target=tgt,
                details={"message_summary": str(msg)[:100]},
                verdict=eval_res.verdict,
                risk_tier=eval_res.risk_tier,
                action_taken=action,
                prevented=prevented,
                rule_matched=eval_res.rule_matched,
                boundary_version=boundary.version,
            )
            self._record(event)

            refused_reason = None
            if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
                refused_reason = f"Communication with agent '{tgt}' denied by boundary: {eval_res.rule_matched}"
            else:
                try:
                    profile = load_agent_profile(tgt)
                except Exception:
                    refused_reason = f"Agent profile not found for '{tgt}'"

                if not refused_reason and tgt in chain:
                    refused_reason = f"Cycle detected: agent '{tgt}' already exists in delegation chain: {chain}"

                if not refused_reason and depth + 1 > 4:
                    refused_reason = f"Maximum delegation depth 4 exceeded: requested depth {depth + 1}"

            if refused_reason:
                msg_text = msg.get("text", "") if isinstance(msg, dict) else str(msg)
                refused_msg = {
                    "message_id": f"msg_{uuid.uuid4().hex[:16]}",
                    "root_task_id": root_id,
                    "parent_task_id": task_id,
                    "child_task_id": None,
                    "from_agent": agent_id,
                    "to_agent": tgt,
                    "kind": "request",
                    "fanout_group": group_id,
                    "reply_to": None,
                    "sent_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "text": msg_text[:8192],
                    "verdict": "refused",
                    "reason": refused_reason,
                    "integrity": "trusted",
                    "forwarded_from": [],
                    "contains_private": False,
                }
                self.storage.save_a2a_message(refused_msg)
                indexed_results[idx] = {
                    "status": "refused",
                    "reply": refused_reason,
                    "child_task_id": None,
                    "target": tgt,
                }
            else:
                allowed_calls.append((idx, call_dict))

        if allowed_calls:
            targets_str = ", ".join(c.get("target") or c.get("target_agent", "") for _, c in allowed_calls)
            self._check_flow_approval(task_id, agent_id, boundary, "call_agents", targets_str)

            dm = getattr(self, "delegation_manager", None)
            if dm is None:
                from .delegation import DelegationManager
                dm = DelegationManager(self.storage)
                self.delegation_manager = dm

            def _worker(item: tuple[int, dict[str, Any]]) -> tuple[int, dict[str, Any]]:
                i, c = item
                t_agent = c.get("target") or c.get("target_agent", "")
                m = c.get("message", {})
                try:
                    res = dm.delegate_single(token, t_agent, m, fanout_group=group_id)
                    res["target"] = t_agent
                    return i, res
                except Exception as e:
                    return i, {
                        "status": "refused",
                        "reply": str(e),
                        "child_task_id": None,
                        "target": t_agent,
                    }

            with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(allowed_calls))) as executor:
                for idx_item, res_dict in executor.map(_worker, allowed_calls):
                    indexed_results[idx_item] = res_dict
                    tgt_name = res_dict.get("target", "")
                    self._check_and_consume_single_use(boundary, "peer_agent", tgt_name)
                    reply_str = res_dict.get("reply", "") if isinstance(res_dict, dict) else ""
                    reply_conf = res_dict.get("confidentiality", "public") if isinstance(res_dict, dict) else "public"
                    self.storage.update_task_context_label(task_id, integrity="untrusted", confidentiality=reply_conf)
                    if self.expansion_service:
                        self.expansion_service.record_untrusted_read(
                            task_id=task_id,
                            source_type="peer_message",
                            source_target=tgt_name,
                            content=reply_str,
                        )

        return [indexed_results[i] for i in range(len(calls))]

    def llm_complete(
        self,
        token: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        temperature: float = 0.0,
        provider: str | None = None,
        custom_provider: Any | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Tool: llm_complete (F13.2 / M5).
        Brokered LLM inference ensuring API keys are NEVER exposed to the agent process.
        The agent passes its task token and messages; the broker authenticates the task,
        validates boundary authorization, audits the call, and invokes the LLM provider
        using broker-held credentials or a local stub/mock provider.
        """
        import hashlib
        import json

        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

        eval_res = self.evaluator.evaluate_tool(boundary, "llm_complete")
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        prompt_str = json.dumps(messages, sort_keys=True, default=str)
        prompt_hash = hashlib.sha256(prompt_str.encode("utf-8")).hexdigest()[:16]

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="llm_complete",
            target=model or "default_llm",
            details={
                "prompt_hash": prompt_hash,
                "message_count": len(messages),
                "has_tools": bool(tools),
            },
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self._record(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"LLM inference denied by boundary: {eval_res.rule_matched}")

        self.llm_calls += 1
        self._llm_in_flight += 1
        try:
            res = self._dispatch_llm_complete(
                messages=messages,
                tools=tools,
                model=model,
                temperature=temperature,
                provider=provider,
                custom_provider=custom_provider,
                **kwargs,
            )
            self.llm_ok_calls += 1
            return res
        except Exception as e:
            self.last_llm_error = redact_llm_error(str(e), max_chars=300)
            raise
        finally:
            self._llm_in_flight = max(0, self._llm_in_flight - 1)

    def _dispatch_llm_complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        temperature: float = 0.0,
        provider: str | None = None,
        custom_provider: Any | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        # 1. Custom or broker-attached mock provider (for offline testing & benchmarks)
        eff_provider = custom_provider or getattr(self, "default_llm_provider", None)
        if eff_provider is not None:
            return eff_provider(
                messages=messages,
                tools=tools,
                model=model,
                temperature=temperature,
                **kwargs,
            )

        # 2. Hosted OpenAI-compatible provider dispatch (Groq, Cerebras, Gemini, openai_compat)
        from .llm_providers import parse_model_string, HOSTED_PROVIDERS

        hosted_provider = None
        target_model = model

        if model:
            hp, parsed_model = parse_model_string(model)
            if hp is not None:
                hosted_provider = hp
                target_model = parsed_model

        prov_name = (provider or os.environ.get("GOVERNANCE_LLM_PROVIDER") or "").lower()
        if hosted_provider is None and prov_name in HOSTED_PROVIDERS:
            hosted_provider = HOSTED_PROVIDERS[prov_name]
            target_model = target_model or hosted_provider.default_model

        if hosted_provider is not None:
            base_url = kwargs.get("base_url") or hosted_provider.get_base_url()
            api_key = kwargs.get("api_key") or hosted_provider.get_api_key()
            if not api_key:
                raise RuntimeError(f"{hosted_provider.env_var} not configured for provider {hosted_provider.id}")
            if not base_url:
                raise RuntimeError(f"Base URL not configured for provider {hosted_provider.id}")
            max_tokens = int(kwargs.get("max_tokens") or os.environ.get("OLLAMA_MAX_TOKENS") or 0)
            return self._call_openai_compat(
                messages=messages,
                tools=tools,
                model=target_model or hosted_provider.default_model,
                base_url=base_url,
                api_key=api_key,
                temperature=temperature,
                max_tokens=max_tokens,
                provider=hosted_provider.id,
            )

        # 3. Local Ollama provider dispatch (http://127.0.0.1:11434/v1)
        prov_name = (provider or os.environ.get("GOVERNANCE_LLM_PROVIDER") or "").lower()
        if prov_name == "ollama" or (not prov_name and os.environ.get("OLLAMA_MODEL")):
            ollama_model = model or os.environ.get("OLLAMA_MODEL") or "llama3.1:8b"
            num_ctx = int(kwargs.get("num_ctx") or os.environ.get("OLLAMA_NUM_CTX") or 8192)
            return self._call_ollama(
                messages=messages,
                tools=tools,
                model=ollama_model,
                temperature=temperature,
                seed=kwargs.get("seed", 42),
                num_ctx=num_ctx,
                base_url=kwargs.get("base_url"),
                max_tokens=int(kwargs.get("max_tokens") or os.environ.get("OLLAMA_MAX_TOKENS") or 0),
            )

        # 3. Live external hosted provider dispatch (OpenAI, Gemini, Anthropic)
        openai_key = os.environ.get("OPENAI_API_KEY")
        gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY")

        if prov_name == "gemini" or (not prov_name and gemini_key):
            if not gemini_key:
                raise RuntimeError("GEMINI_API_KEY not configured")
            return self._call_gemini(messages, tools, model or "gemini-3.8-flash", gemini_key, temperature)

        if prov_name == "anthropic" or (not prov_name and anthropic_key):
            if not anthropic_key:
                raise RuntimeError("ANTHROPIC_API_KEY not configured")
            return self._call_anthropic(messages, tools, model or "claude-3-5-sonnet", anthropic_key, temperature)

        if prov_name == "openai" or (not prov_name and openai_key):
            if not openai_key:
                raise RuntimeError("OPENAI_API_KEY not configured")
            return self._call_openai(messages, tools, model or "gpt-4o-mini", openai_key, temperature)

        raise RuntimeError(
            "No LLM provider configured (set GOVERNANCE_LLM_PROVIDER=ollama with running Ollama, "
            "or configure OPENAI_API_KEY, GEMINI_API_KEY, or ANTHROPIC_API_KEY, or supply a mock/stub provider)."
        )

    def _call_openai_compat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        model: str,
        base_url: str,
        api_key: str,
        temperature: float = 0.0,
        max_tokens: int = 0,
        timeout: float = 300.0,
        provider: str = "openai_compat",
    ) -> dict[str, Any]:
        """Invokes a hosted OpenAI-compatible provider (/chat/completions) with retry on 429/503.

        Standard OpenAI request payload only (model, messages, tools, temperature, max_tokens);
        no Ollama options or seed fields.
        """
        import httpx
        import time

        root_url = base_url.rstrip("/")
        if root_url.endswith("/chat/completions"):
            endpoint_url = root_url
        else:
            endpoint_url = f"{root_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
        if max_tokens and max_tokens > 0:
            payload["max_tokens"] = max_tokens

        max_tries = 5
        client_timeout = httpx.Timeout(timeout, connect=5.0)

        for attempt in range(max_tries):
            try:
                with httpx.Client(timeout=client_timeout) as client:
                    resp = client.post(endpoint_url, json=payload, headers=headers)
                    if resp.status_code in (429, 503):
                        self.llm_rate_limited += 1
                        if attempt < max_tries - 1:
                            retry_after_hdr = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
                            sleep_s = None
                            if retry_after_hdr:
                                try:
                                    sleep_s = float(retry_after_hdr)
                                except ValueError:
                                    sleep_s = None
                            if sleep_s is None:
                                sleep_s = min(max(2.0 * (2 ** attempt), 2.0), 30.0)
                            else:
                                sleep_s = min(max(sleep_s, 0.0), 30.0)
                            self.llm_wait_s += sleep_s
                            time.sleep(sleep_s)
                            continue
                        body = resp.text[:300] if resp.text else ""
                        body_redacted = redact_llm_error(body, max_chars=300) if body else ""
                        body_part = f": {body_redacted}" if body_redacted else ""
                        raise RuntimeError(f"{provider} rate limit exceeded: HTTP {resp.status_code} after {max_tries} attempts{body_part}")

                    if resp.status_code == 400:
                        recovered = _recover_tool_use_failed(resp.text or "")
                        if recovered is not None:
                            # Groq rejects a tool call to a tool that was not offered (HTTP 400
                            # tool_use_failed). Ollama returns such a call to the agent, which then
                            # answers "unknown tool". Hand the call back the same way so hosted and
                            # local runs behave alike, and count it.
                            self.llm_tool_use_recovered += 1
                            return {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [recovered],
                                "provider": provider,
                                "model": model,
                                "usage": None,
                                "recovered_tool_use_failed": True,
                            }

                    if resp.status_code >= 400:
                        body = resp.text[:300] if resp.text else ""
                        body_redacted = redact_llm_error(body, max_chars=300) if body else ""
                        body_part = f": {body_redacted}" if body_redacted else ""
                        raise RuntimeError(f"{provider} request failed with HTTP {resp.status_code}{body_part}")

                    resp.raise_for_status()
                    data = resp.json()
                    choices = data.get("choices") or []
                    choice = choices[0].get("message", {}) if choices else {}

                    return {
                        "role": choice.get("role", "assistant"),
                        "content": choice.get("content"),
                        "tool_calls": choice.get("tool_calls"),
                        "provider": provider,
                        "model": model,
                        "usage": data.get("usage"),
                    }
            except (httpx.ConnectError, httpx.TimeoutException) as ce:
                if attempt < max_tries - 1:
                    sleep_s = min(max(2.0 * (2 ** attempt), 2.0), 30.0)
                    self.llm_wait_s += sleep_s
                    time.sleep(sleep_s)
                    continue
                err_msg = str(ce).replace(api_key, "[REDACTED]") if api_key else str(ce)
                raise RuntimeError(
                    f"{provider} service is unreachable or timed out at {endpoint_url} after {max_tries} attempts: {err_msg}"
                ) from None
            except httpx.HTTPStatusError as hse:
                body = hse.response.text[:300] if (hse.response and hse.response.text) else ""
                body_redacted = redact_llm_error(body, max_chars=300) if body else ""
                body_part = f": {body_redacted}" if body_redacted else ""
                err_msg = str(hse).replace(api_key, "[REDACTED]") if api_key else str(hse)
                raise RuntimeError(f"{provider} request failed with HTTP {hse.response.status_code}{body_part}") from None
            except Exception as e:
                if "rate limit" in str(e).lower() or str(e).startswith(f"{provider} "):
                    raise
                err_msg = str(e).replace(api_key, "[REDACTED]") if api_key else str(e)
                raise RuntimeError(f"{provider} call failed: {err_msg}") from None

    def _call_ollama(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        model: str,
        temperature: float = 0.0,
        seed: int | None = 42,
        num_ctx: int = 8192,
        base_url: str | None = None,
        timeout: float = 300.0,
        max_tokens: int = 0,
    ) -> dict[str, Any]:
        """Invokes local Ollama via its OpenAI-compatible /v1/chat/completions endpoint with retry support.

        max_tokens > 0 caps one reply, so a model stuck repeating itself cannot run until the
        task timeout (0 = no cap, as in the recorded evaluation runs)."""
        import httpx
        import time
        root_url = (base_url or os.environ.get("OLLAMA_BASE_URL") or "http://127.0.0.1:11434").rstrip("/")
        if root_url.endswith("/v1"):
            api_base = root_url[:-3]
            v1_url = root_url + "/chat/completions"
        else:
            api_base = root_url
            v1_url = root_url + "/v1/chat/completions"

        options: dict[str, Any] = {
            "num_ctx": num_ctx,
            "temperature": temperature,
        }
        if seed is not None:
            options["seed"] = seed

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "options": options,
        }
        if seed is not None:
            payload["seed"] = seed
        if tools:
            payload["tools"] = tools
        if max_tokens and max_tokens > 0:
            payload["max_tokens"] = max_tokens

        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Bounded connect timeout: an unreachable Ollama (e.g. WSL mirrored
                # networking, which hangs instead of refusing) fails within seconds.
                with httpx.Client(timeout=httpx.Timeout(timeout, connect=5.0)) as client:
                    resp = client.post(v1_url, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    choice = data.get("choices", [{}])[0].get("message", {})

                    # Resolve model digest from /api/tags if available
                    model_digest = ""
                    try:
                        tag_resp = client.get(f"{api_base}/api/tags", timeout=httpx.Timeout(5.0, connect=5.0))
                        if tag_resp.status_code == 200:
                            for m in tag_resp.json().get("models", []):
                                if m.get("name") == model or m.get("model") == model or m.get("name", "").startswith(model):
                                    model_digest = m.get("digest", "")
                                    break
                    except Exception:
                        pass

                    return {
                        "role": choice.get("role", "assistant"),
                        "content": choice.get("content"),
                        "tool_calls": choice.get("tool_calls"),
                        "provider": "ollama",
                        "model": model,
                        "model_digest": model_digest,
                        "model_digest_or_tag": model_digest or data.get("model", model),
                        "num_ctx": num_ctx,
                        "temperature": temperature,
                        "seed": seed,
                        "usage": data.get("usage"),
                    }
            except (httpx.ConnectError, httpx.TimeoutException) as ce:
                if attempt < max_retries - 1:
                    time.sleep(3.0 * (attempt + 1))
                    continue
                raise RuntimeError(f"Ollama local service is unreachable or timed out at {v1_url} after {max_retries} attempts: {ce}. Ensure Ollama is running.") from ce
            except httpx.HTTPStatusError as hse:
                body = hse.response.text[:300] if (hse.response and hse.response.text) else ""
                body_redacted = redact_llm_error(body, max_chars=300) if body else ""
                body_part = f": {body_redacted}" if body_redacted else ""
                raise RuntimeError(f"Ollama inference failed with HTTP {hse.response.status_code}{body_part}") from hse
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(2.0)
                    continue
                raise RuntimeError(f"Ollama inference failed at {v1_url}: {e}") from e

    def _call_openai(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        model: str,
        api_key: str,
        temperature: float,
    ) -> dict[str, Any]:
        import httpx
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload: dict[str, Any] = {"model": model, "messages": messages, "temperature": temperature}
        if tools:
            payload["tools"] = tools
        with httpx.Client(timeout=60.0) as client:
            resp = client.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]["message"]
            return {
                "role": choice.get("role", "assistant"),
                "content": choice.get("content"),
                "tool_calls": choice.get("tool_calls"),
                "provider": "openai",
                "model": model,
                "usage": data.get("usage"),
            }

    def _call_gemini(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        model: str,
        api_key: str,
        temperature: float,
    ) -> dict[str, Any]:
        import httpx
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        contents = []
        for m in messages:
            role = "user" if m.get("role") in ("user", "system") else "model"
            contents.append({"role": role, "parts": [{"text": str(m.get("content", ""))}]})
        payload = {"contents": contents, "generationConfig": {"temperature": temperature}}
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            cand = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            return {
                "role": "assistant",
                "content": cand,
                "tool_calls": None,
                "provider": "gemini",
                "model": model,
            }

    def _call_anthropic(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        model: str,
        api_key: str,
        temperature: float,
    ) -> dict[str, Any]:
        import httpx
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        system_text = ""
        user_msgs = []
        for m in messages:
            if m.get("role") == "system":
                system_text += str(m.get("content", "")) + "\n"
            else:
                user_msgs.append({"role": m.get("role"), "content": m.get("content")})
        payload: dict[str, Any] = {
            "model": model,
            "messages": user_msgs,
            "max_tokens": 1024,
            "temperature": temperature,
        }
        if system_text.strip():
            payload["system"] = system_text.strip()
        with httpx.Client(timeout=60.0) as client:
            resp = client.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
            return {
                "role": "assistant",
                "content": text,
                "tool_calls": None,
                "provider": "anthropic",
                "model": model,
            }
