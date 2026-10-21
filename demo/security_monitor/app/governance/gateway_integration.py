"""A2A Gateway Integration (F5.3).

Checks peer agent boundaries against the caller task's peer_agents contract using
per-task tokens (never trusting self-declared caller headers). Discovers and flags
ungoverned / shadow agent calls.
"""
from __future__ import annotations

import datetime
from typing import Any
from fastapi import Request, HTTPException

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


class A2AGatewayGovernance:
    """Interceptors and boundary validation for the A2A Protocol Gateway."""

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
        return f"evt_a2a_{self._event_counter:04d}_{datetime.datetime.now().strftime('%f')}"

    def check_a2a_call(
        self,
        caller_token: str | None,
        target_agent_id: str,
        declared_caller_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """
        Validates whether an A2A call is authorized by the caller task's boundary.
        Returns (is_allowed, reason).
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Check if caller has a valid task token
        if not caller_token:
            # Caller is acting without an assigned task -> UNGOVERNED / SHADOW AGENT
            effective_agent = declared_caller_id or "unknown_shadow_agent"
            evt = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=now_utc,
                source=EventSource.A2A_GATEWAY,
                task_id=None,
                agent_id=effective_agent,
                pid=None,
                kind="peer_agent_call",
                target=target_agent_id,
                details={
                    "declared_caller_id": declared_caller_id,
                    "reason": "missing_task_token_ungoverned_agent",
                    **(details or {}),
                },
                verdict=EventVerdict.OUTSIDE,
                risk_tier=RiskTier.HIGH,
                action_taken=TaskAction.ALERT,
                prevented=False,  # Detected ungoverned agent
                rule_matched="ungoverned agent activity detected without active task boundary",
                boundary_version=None,
            )
            self.storage.record_event(evt)
            return True, "Ungoverned agent activity audited"

        # 2. Look up task by token
        lookup = self.storage.lookup_task_by_token(caller_token)
        if not lookup:
            evt = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=now_utc,
                source=EventSource.A2A_GATEWAY,
                task_id=None,
                agent_id="UNATTRIBUTED",
                pid=None,
                kind="peer_agent_call",
                target=target_agent_id,
                details={"reason": "invalid_or_revoked_token", **(details or {})},
                verdict=EventVerdict.OUTSIDE,
                risk_tier=RiskTier.HIGH,
                action_taken=TaskAction.BLOCK_ACTION,
                prevented=True,
                rule_matched="invalid or revoked task token on A2A gateway",
                boundary_version=None,
            )
            self.storage.record_event(evt)
            return False, "Invalid or revoked task token"

        task_id, agent_id = lookup
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            return False, f"Boundary not found for task {task_id}"

        # 3. Evaluate target peer agent against boundary
        eval_res = self.evaluator.evaluate_peer_agent(boundary, target_agent_id)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        evt = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=now_utc,
            source=EventSource.A2A_GATEWAY,
            task_id=task_id,
            agent_id=agent_id,
            pid=None,
            kind="peer_agent_call",
            target=target_agent_id,
            details=details or {},
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self.storage.record_event(evt)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            return False, f"Call to peer agent '{target_agent_id}' denied by boundary: {eval_res.rule_matched}"

        return True, "Authorized peer agent call"
