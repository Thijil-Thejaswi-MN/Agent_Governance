"""Dynamic Expansion Requests and Provenance Escalation Engine (F8).

Enforces:
1. Exact-resource grants only (wildcards strictly forbidden).
2. Provenance tracking: The ONLY trusted input is the user's initial task request text.
   All reads at runtime (files, network GETs, peer messages) are untrusted.
3. Provenance-aware risk escalation: If an expansion request follows untrusted reads
   and was not explicitly anticipated by the user, escalate risk tier by one level.
4. Auto-approval for LOW; human approval (ASK_USER) for escalated/MEDIUM/HIGH.
5. Strict self-approval prohibition: agents can never approve their own requests.
6. Boundary versioning: approval creates version N+1 linked to parent_expansion_id.
7. Single-use enforcement for HIGH grants; all grants expire at task end.
8. Synchronous wait with timeout failing closed to DENY.
"""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import time
from pathlib import Path
from typing import Any

from .models import (
    ExpansionRequest,
    ExpansionStatus,
    ProvenanceRecord,
    RiskTier,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from .storage import GovernanceStorage


class ExpansionService:
    """Manages runtime boundary expansion requests, provenance analysis, and human approval."""

    def __init__(self, storage: GovernanceStorage, provenance_enabled: bool = True) -> None:
        self.storage = storage
        self.provenance_enabled = provenance_enabled
        self._request_counter = 0

    def _generate_request_id(self) -> str:
        self._request_counter += 1
        return f"exp_req_{self._request_counter:04d}_{int(time.time() * 1000) % 1000000}"

    def record_untrusted_read(
        self,
        task_id: str,
        source_type: str,
        source_target: str,
        content: str | bytes,
    ) -> ProvenanceRecord:
        """Records untrusted data read by the agent at runtime with a SHA-256 hash."""
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if isinstance(content, str):
            content_bytes = content.encode("utf-8", errors="replace")
        else:
            content_bytes = content

        content_hash = hashlib.sha256(content_bytes).hexdigest()
        record = ProvenanceRecord(
            task_id=task_id,
            timestamp=now_utc,
            source_type=source_type,
            source_target=source_target,
            content_hash=content_hash,
            content_len=len(content_bytes),
        )
        self.storage.record_provenance(record)
        return record

    def evaluate_request(
        self,
        task_id: str,
        agent_id: str,
        resource_type: str,
        resource_target: str,
        justification: str,
        provenance_enabled: bool | None = None,
        timeout_seconds: float = 5.0,
    ) -> ExpansionRequest:
        """
        Creates and evaluates a dynamic expansion request.
        Applies provenance escalation and determines baseline vs effective risk tier.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        request_id = self._generate_request_id()

        # 1. Enforce Exact Resource Scope (NO WILDCARDS ALLOWED)
        if any(c in resource_target for c in ("*", "?", "[", "]")):
            raise ValueError(
                f"Wildcards are strictly prohibited in expansion requests. "
                f"Resource target '{resource_target}' must be exact."
            )

        task = self.storage.get_task(task_id)
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")

        # 2. Determine Baseline Risk Tier
        target_norm = resource_target.strip().replace("\\", "/").lower()
        baseline_tier = RiskTier.LOW

        if resource_type in ("file_read", "file_write"):
            # Sensitive filename patterns are automatically HIGH
            sensitive_patterns = ("credential", "secret", "password", ".env", "id_rsa", "shadow")
            if any(p in target_norm for p in sensitive_patterns):
                baseline_tier = RiskTier.HIGH
            elif resource_type == "file_write" and not target_norm.startswith("output/"):
                baseline_tier = RiskTier.HIGH
            elif not (target_norm.startswith("input/") or target_norm.startswith("output/")):
                baseline_tier = RiskTier.MEDIUM
            else:
                baseline_tier = RiskTier.LOW

        elif resource_type == "network":
            # Local/private hosts are MEDIUM; external/unknown are HIGH
            if any(target_norm.startswith(h) for h in ("127.0.0.1", "localhost", "internal.")):
                baseline_tier = RiskTier.MEDIUM
            else:
                baseline_tier = RiskTier.HIGH

        elif resource_type == "peer_agent":
            baseline_tier = RiskTier.MEDIUM

        # 3. Check if explicitly anticipated by user original request text
        user_request_text = task.request_text.lower()
        target_basename = Path(target_norm).name.lower()
        # The user's original request text is the ONLY trusted source
        anticipated_by_user = (
            target_norm in user_request_text
            or (target_basename and target_basename in user_request_text)
            or (target_basename.split(".")[0] in user_request_text if "." in target_basename else False)
        )

        # 4. Provenance-Aware Escalation Analysis
        use_provenance = self.provenance_enabled if provenance_enabled is None else provenance_enabled
        escalated = False
        effective_tier = baseline_tier

        if use_provenance:
            # Check if agent has ingested ANY untrusted data during this task
            prior_reads = self.storage.get_provenance_for_task(task_id)
            if len(prior_reads) > 0:
                if not anticipated_by_user:
                    # Ingested untrusted inputs + requested resource was NOT anticipated by user
                    # Prompt injection risk -> escalate risk tier by one level!
                    escalated = True
                    if baseline_tier == RiskTier.LOW:
                        effective_tier = RiskTier.MEDIUM
                    elif baseline_tier == RiskTier.MEDIUM:
                        effective_tier = RiskTier.HIGH
                    elif baseline_tier == RiskTier.HIGH:
                        effective_tier = RiskTier.HIGH

        # 5. Determine Initial Status
        # LOW is auto-approved; MEDIUM/HIGH requires human approval (ASK_USER)
        is_auto_approved = (effective_tier == RiskTier.LOW)
        status = ExpansionStatus.APPROVED if is_auto_approved else ExpansionStatus.PENDING
        resolved_by = "auto_policy" if is_auto_approved else None
        resolved_at = now_utc if is_auto_approved else None
        single_use = (effective_tier == RiskTier.HIGH)

        req = ExpansionRequest(
            request_id=request_id,
            task_id=task_id,
            agent_id=agent_id,
            resource_type=resource_type,
            resource_target=resource_target,
            justification=justification,
            baseline_risk_tier=baseline_tier,
            effective_risk_tier=effective_tier,
            escalated_by_provenance=escalated,
            status=status,
            created_at=now_utc,
            resolved_at=resolved_at,
            resolved_by=resolved_by,
            single_use=single_use,
            used_count=0,
            timeout_seconds=timeout_seconds,
        )
        self.storage.save_expansion_request(req)

        # If auto-approved, create new boundary version N+1 immediately
        if is_auto_approved:
            self._apply_boundary_expansion(req)

        return req

    def approve_request(self, request_id: str, approved_by: str) -> TaskBoundary:
        """
        Approves a pending expansion request and applies version N+1 to the task boundary.
        STRICTLY PROHIBITS AGENT SELF-APPROVAL.
        """
        req = self.storage.get_expansion_request(request_id)
        if not req:
            raise ValueError(f"Expansion request '{request_id}' not found.")

        # Self-Approval Prohibition
        if approved_by.lower() in (req.agent_id.lower(), "agent", "caller", "self"):
            raise PermissionError(
                f"Agent '{approved_by}' is strictly prohibited from approving its own expansion request."
            )

        if req.status == ExpansionStatus.APPROVED:
            boundary = self.storage.get_boundary(req.task_id)
            if boundary:
                return boundary

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        req.status = ExpansionStatus.APPROVED
        req.resolved_by = approved_by
        req.resolved_at = now_utc
        self.storage.save_expansion_request(req)

        return self._apply_boundary_expansion(req)

    def deny_request(self, request_id: str, denied_by: str, reason: str = "") -> None:
        """Denies a pending expansion request."""
        req = self.storage.get_expansion_request(request_id)
        if not req:
            raise ValueError(f"Expansion request '{request_id}' not found.")

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        req.status = ExpansionStatus.DENIED
        req.resolved_by = denied_by
        req.resolved_at = now_utc
        self.storage.save_expansion_request(req)

    def _apply_boundary_expansion(self, req: ExpansionRequest) -> TaskBoundary:
        """Creates TaskBoundary version N+1 linked to request_id."""
        current_boundary = self.storage.get_boundary(req.task_id)
        if not current_boundary:
            raise ValueError(f"Boundary for task '{req.task_id}' not found.")

        new_version = current_boundary.version + 1
        new_boundary = TaskBoundary(
            task_id=current_boundary.task_id,
            version=new_version,
            workspace_root=current_boundary.workspace_root,
            files_read=list(current_boundary.files_read),
            files_write=list(current_boundary.files_write),
            network=list(current_boundary.network),
            tools=list(current_boundary.tools),
            peer_agents=list(current_boundary.peer_agents),
            max_duration_sec=current_boundary.max_duration_sec,
            max_processes=current_boundary.max_processes,
            enforcement_mode=current_boundary.enforcement_mode,
            derived_by=f"expansion_{req.request_id}",
            prompt_hash=current_boundary.prompt_hash,
            model_name=current_boundary.model_name,
            parent_expansion_id=req.request_id,
        )

        target = req.resource_target
        if req.resource_type == "file_read" and target not in new_boundary.files_read:
            new_boundary.files_read.append(target)
        elif req.resource_type == "file_write" and target not in new_boundary.files_write:
            new_boundary.files_write.append(target)
        elif req.resource_type == "network" and target not in new_boundary.network:
            new_boundary.network.append(target)
        elif req.resource_type == "peer_agent" and target not in new_boundary.peer_agents:
            new_boundary.peer_agents.append(target)

        self.storage.save_boundary(new_boundary)

        # Update task's current boundary version
        task = self.storage.get_task(req.task_id)
        if task:
            task.current_boundary_version = new_version
            self.storage.save_task(task)

        return new_boundary

    def request_and_wait(
        self,
        task_id: str,
        agent_id: str,
        resource_type: str,
        resource_target: str,
        justification: str,
        timeout_seconds: float = 2.0,
        provenance_enabled: bool | None = None,
    ) -> tuple[bool, str]:
        """
        Synchronous request and wait loop.
        If timeout expires while still PENDING, fails closed to DENY.
        """
        req = self.evaluate_request(
            task_id=task_id,
            agent_id=agent_id,
            resource_type=resource_type,
            resource_target=resource_target,
            justification=justification,
            provenance_enabled=provenance_enabled,
            timeout_seconds=timeout_seconds,
        )

        if req.status == ExpansionStatus.APPROVED:
            return True, f"Auto-approved under {req.effective_risk_tier.value} risk policy"

        # Polling wait loop up to timeout_seconds
        start_time = time.time()
        poll_interval = 0.05
        while (time.time() - start_time) < timeout_seconds:
            time.sleep(poll_interval)
            current = self.storage.get_expansion_request(req.request_id)
            if not current:
                break
            if current.status == ExpansionStatus.APPROVED:
                return True, f"Approved by {current.resolved_by}"
            if current.status == ExpansionStatus.DENIED:
                return False, f"Denied by {current.resolved_by}"

        # Timeout reached: Fail-closed to DENY
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.deny_request(req.request_id, denied_by="timeout_fail_closed", reason="Approval request timed out")
        return False, "Approval request timed out: denied (fail-closed)"
