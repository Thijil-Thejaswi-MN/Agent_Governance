"""Graduated Response Engine for Runtime Task Governance (F9).

Maps evaluation verdicts to graduated enforcement actions and tracks violation escalation.
"""
from __future__ import annotations

from typing import Any
from .models import (
    EnforcementMode,
    EventVerdict,
    RiskTier,
    TaskAction,
    TaskBoundary,
)
from .evaluator import EvaluationResult


class TaskPolicyEngine:
    """Evaluates compliance verdicts and determines graduated enforcement responses."""

    def __init__(self) -> None:
        # Track task violation counts: {task_id: violation_count}
        self.task_violation_counts: dict[str, int] = {}

    def decide(
        self,
        boundary: TaskBoundary,
        eval_result: EvaluationResult,
        interactive: bool = False,
    ) -> tuple[TaskAction, bool]:
        """
        Returns (action_taken, prevented).
        
        CRITICAL RULE:
        - prevented = True ONLY when the operation is stopped BEFORE execution.
        - Under OBSERVE mode, prevented is ALWAYS False (detection/logging only).
        """
        task_id = boundary.task_id

        # 1. Benign / Inside Boundary
        if eval_result.verdict == EventVerdict.INSIDE:
            return TaskAction.ALLOW, False

        # 2. Outside Boundary
        count = self.task_violation_counts.get(task_id, 0) + 1
        self.task_violation_counts[task_id] = count

        # In OBSERVE mode, never block
        if boundary.enforcement_mode == EnforcementMode.OBSERVE:
            if eval_result.risk_tier == RiskTier.HIGH:
                return TaskAction.ALERT, False
            return TaskAction.LOG, False

        # In ENFORCE mode:
        # Check escalation thresholds
        if count >= 5:
            return TaskAction.KILL_TASK, True
        if count >= 3:
            return TaskAction.PAUSE_TASK, True

        # First or second violation: tiered graduated response
        if eval_result.risk_tier == RiskTier.LOW:
            return TaskAction.LOG, False

        if eval_result.risk_tier == RiskTier.MEDIUM:
            if interactive:
                return TaskAction.ASK_USER, True
            return TaskAction.BLOCK_ACTION, True

        # HIGH risk
        return TaskAction.BLOCK_ACTION, True
