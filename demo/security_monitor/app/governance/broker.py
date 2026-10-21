"""Tool Broker (F5.1).

Mediates agent tool execution, validates scoped per-task tokens (F6), evaluates
the Task Boundary BEFORE execution (F7), enforces graduated policies (F9),
and emits normalized governance audit events.
"""
from __future__ import annotations

import datetime
import os
import uuid
from pathlib import Path
from typing import Any

from .models import (
    EventSource,
    GovernanceEvent,
    RiskTier,
    TaskAction,
    EventVerdict,
)
from .storage import GovernanceStorage
from .evaluator import BoundaryEvaluator
from .policy import TaskPolicyEngine


class ToolBroker:
    """Tool execution broker that intercepts and enforces task boundaries prior to execution."""

    def __init__(
        self,
        storage: GovernanceStorage,
        evaluator: BoundaryEvaluator | None = None,
        policy_engine: TaskPolicyEngine | None = None,
    ) -> None:
        self.storage = storage
        self.evaluator = evaluator or BoundaryEvaluator()
        self.policy_engine = policy_engine or TaskPolicyEngine()
        self._event_counter = 0

    def _generate_event_id(self) -> str:
        self._event_counter += 1
        return f"evt_broker_{self._event_counter:04d}_{uuid.uuid4().hex[:6]}"

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
            self.storage.record_event(event)
            raise PermissionError("Access denied: Invalid or revoked task token")
        return res

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
            self.storage.record_event(event)
            raise PermissionError(f"Tool read_file not granted in task boundary: {tool_eval.rule_matched}")

        # Evaluate target file path
        eval_res = self.evaluator.evaluate_file_access(boundary, file_path, is_write=False)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

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
        self.storage.record_event(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"Access to file '{file_path}' denied by boundary: {eval_res.rule_matched}")

        # REAL EXECUTION (Inside boundary)
        target = Path(file_path)
        if not target.is_absolute():
            target = Path(boundary.workspace_root) / target
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def write_file(self, token: str, file_path: str, content: str) -> int:
        """
        Tool: write_file
        Checks task boundary BEFORE writing content.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

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
            self.storage.record_event(event)
            raise PermissionError(f"Tool write_file not granted: {tool_eval.rule_matched}")

        eval_res = self.evaluator.evaluate_file_access(boundary, file_path, is_write=True)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

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
        self.storage.record_event(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"Write to file '{file_path}' denied by boundary: {eval_res.rule_matched}")

        target = Path(file_path)
        if not target.is_absolute():
            target = Path(boundary.workspace_root) / target
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            return f.write(content)

    def http_get(self, token: str, url: str) -> dict[str, Any]:
        """
        Tool: http_get
        Checks network destination BEFORE opening socket.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

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
        self.storage.record_event(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"Outbound network request to '{url}' denied by boundary: {eval_res.rule_matched}")

        # Local stub response
        return {"status": 200, "url": url, "body": "Mock response from authorized endpoint"}

    def run_command(self, token: str, command: str) -> dict[str, Any]:
        """
        Tool: run_command
        In M1, command execution is denied by default per security specification.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

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
        self.storage.record_event(event)
        raise PermissionError(f"Command execution denied: {eval_res.rule_matched}")

    def call_agent(self, token: str, target_agent: str, message: dict[str, Any]) -> dict[str, Any]:
        """
        Tool: call_agent
        Checks peer agent boundary BEFORE message dispatch.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

        eval_res = self.evaluator.evaluate_peer_agent(boundary, target_agent)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

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
        self.storage.record_event(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"Communication with agent '{target_agent}' denied by boundary: {eval_res.rule_matched}")

        return {"status": "ok", "target_agent": target_agent, "reply": "Authorized message delivered"}
