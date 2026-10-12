from __future__ import annotations

from typing import Any
from ..core.models import SecurityViolation


class DelegationTracker:
    """
    In-memory stateful delegation tracker across A2A context sessions.
    
    Tracks the sequence of agents participating in an unclosed task context.
    Detects cycle loops (e.g., A -> B -> A) and delegation depth exhaustion.
    """

    def __init__(self, default_max_depth: int = 5) -> None:
        self.default_max_depth = default_max_depth
        self._contexts: dict[str, list[str]] = {}

    def get_chain(self, context_id: str) -> list[str]:
        return list(self._contexts.get(context_id, []))

    def reset_context(self, context_id: str) -> None:
        if context_id in self._contexts:
            del self._contexts[context_id]

    def record_hop(self, context_id: str, agent_id: str) -> list[str]:
        if context_id not in self._contexts:
            self._contexts[context_id] = []
        self._contexts[context_id].append(agent_id.strip().lower())
        return list(self._contexts[context_id])

    def check_violation(
        self,
        context_id: str,
        target_agent_id: str,
        explicit_chain: list[str] | None = None,
        max_depth: int | None = None,
    ) -> SecurityViolation | None:
        """
        Evaluate if forwarding a task to target_agent_id violates cycle or depth invariants.
        """
        limit = max_depth if max_depth is not None else self.default_max_depth
        norm_target = target_agent_id.strip().lower()

        # Chain from header or tracking
        current_chain = explicit_chain if explicit_chain is not None else self._contexts.get(context_id, [])

        # 1. Check Cycle Invariant: target agent already present in current delegation sequence
        if norm_target in current_chain:
            cycle_path = current_chain + [norm_target]
            return SecurityViolation(
                violation_code="CO_CYCLE_DETECTED",
                description=(
                    f"Cycle Overflow: Delegation cycle detected across context '{context_id}'. "
                    f"Path {cycle_path} attempts to re-enter agent '{target_agent_id}'."
                ),
                candidate_name=target_agent_id,
                candidate_endpoint=f"context://{context_id}",
                colliding_trusted_name=norm_target,
                colliding_trusted_endpoint=f"context://{context_id}",
                details={
                    "detection_type": "cycle_overflow_cycle",
                    "context_id": context_id,
                    "cycle_path": cycle_path,
                    "current_depth": len(current_chain) + 1,
                    "max_depth_budget": limit,
                },
            )

        # 2. Check Depth Budget Invariant: delegation chain length exceeds budget
        if len(current_chain) >= limit:
            chain_path = current_chain + [norm_target]
            return SecurityViolation(
                violation_code="CO_DEPTH_EXCEEDED",
                description=(
                    f"Cycle Overflow: Delegation depth budget exceeded for context '{context_id}'. "
                    f"Depth {len(chain_path)} exceeds maximum threshold of {limit}."
                ),
                candidate_name=target_agent_id,
                candidate_endpoint=f"context://{context_id}",
                colliding_trusted_name=norm_target,
                colliding_trusted_endpoint=f"context://{context_id}",
                details={
                    "detection_type": "cycle_overflow_depth",
                    "context_id": context_id,
                    "delegation_path": chain_path,
                    "current_depth": len(chain_path),
                    "max_depth_budget": limit,
                },
            )

        return None


# Global module singleton for monitor runtime
tracker = DelegationTracker()


def detect_cycle_overflow(
    context_id: str | None,
    target_agent_id: str,
    explicit_chain: list[str] | None = None,
    max_depth: int = 5,
    record_hop: bool = True,
) -> SecurityViolation | None:
    """
    Deterministic Cycle Overflow (CO) Detector.
    
    RESEARCH DISTINCTION & METHODOLOGICAL CLARIFICATION:
    - A2ASecBench CO evaluates whether an LLM coordinator or multi-agent orchestrator falls into
      an infinite delegation loop when attempting complex collaborative task plans.
    - Our detector operates as an inline gateway safety invariant: it inspects task context chains
      and prevents unbounded recursive forwarding by enforcing loop-freedom and depth limits.
    """
    if not context_id or not target_agent_id:
        return None

    cid = context_id.strip()
    violation = tracker.check_violation(cid, target_agent_id, explicit_chain=explicit_chain, max_depth=max_depth)

    if not violation and record_hop:
        tracker.record_hop(cid, target_agent_id)

    return violation
