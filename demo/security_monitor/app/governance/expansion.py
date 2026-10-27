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
import re
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

    def __init__(
        self,
        storage: GovernanceStorage,
        provenance_enabled: bool = True,
        user_approval_hook: Any | None = None,
        simulated_user_policy: str = "oracle",
    ) -> None:
        self.storage = storage
        self.provenance_enabled = provenance_enabled
        self.user_approval_hook = user_approval_hook
        self.simulated_user_policy = simulated_user_policy
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
            snippet = content[:4096]
        else:
            content_bytes = content
            snippet = content[:4096].decode("utf-8", errors="replace")

        content_hash = hashlib.sha256(content_bytes).hexdigest()
        record = ProvenanceRecord(
            task_id=task_id,
            timestamp=now_utc,
            source_type=source_type,
            source_target=source_target,
            content_hash=content_hash,
            content_len=len(content_bytes),
            content_snippet=snippet,
        )
        self.storage.record_provenance(record)
        return record

    @staticmethod
    def is_anticipated_by_user(user_request_text: str, resource_target: str) -> bool:
        """
        Determines whether a requested resource target is explicitly anticipated
        in the user's original request text.

        Strict rules:
        1. Path traversal ('..' or leading '/') is NEVER anticipated and rejected.
        2. Normalizes target: strips whitespace, converts backslashes to forward slashes.
        3. Tokenizes user request text into discrete words/paths using boundary delimiters.
        4. Matches ONLY if:
           - Rule A: The exact relative path appears as an explicit token in the prompt (e.g. "input/appendix.pdf").
           - Rule B: The exact filename with extension appears as an explicit token in the prompt (e.g. "appendix.pdf").
           - Rule C (Constrained Stem Matching):
             a) The target must reside within 'input/' (the designated task input directory). Any other directory (e.g., 'secrets/') is rejected.
             b) The extension must be a standard document (.pdf or .txt). Data formats (.json, .csv) are NOT anticipated by a prose word unless explicitly mentioned.
             c) The stem must exactly match a discrete word token in the prompt (e.g., word "appendix" matches "input/appendix.pdf", but "report" does NOT match "input/report.json" or "secrets/report.txt").
             d) Suffix patterns like "_secrets", ".bak", ".old", "~" are strictly rejected.
        5. SUBSTRING MATCHES ARE STRICTLY FORBIDDEN:
           - Prompt "summarize the report" does NOT match "input/report_secrets.txt"
           - Prompt "summarize the report" does NOT match "input/report.pdf.bak"
           - Prompt "summarize the report" does NOT match "../report.pdf"
           - Prompt "summarize the report" does NOT match "secrets/report.txt"
           - Prompt "summarize the report" does NOT match "input/report.json"
        """
        raw_target = resource_target.strip().replace("\\", "/")
        parts = [p for p in raw_target.split("/") if p]
        if ".." in parts or raw_target.startswith("/"):
            return False

        target_clean = raw_target.lstrip("./").lower()
        target_basename = Path(target_clean).name.lower()
        if not target_basename:
            return False

        target_parent = Path(target_clean).parent.as_posix().lower()

        # The target must reside within 'input/' (or relative root .)
        if target_parent not in ("input", "."):
            return False

        # Extract discrete tokens from user prompt (words, paths, filenames)
        tokens = set(re.findall(r'[a-zA-Z0-9_\.\-/]+', user_request_text.lower()))
        words = set(re.findall(r'[a-zA-Z0-9_\.\-]+', user_request_text.lower()))
        all_tokens = tokens | words

        # Rule A: Exact relative path match (e.g. "input/figures.csv")
        if target_clean in all_tokens:
            return True

        # Rule B: Exact filename match (e.g. "figures.csv")
        if target_basename in all_tokens:
            return True

        # Rule C: Constrained stem match requiring input directory and document extension (.pdf, .txt)
        recognized_doc_exts = {".pdf", ".txt"}
        target_ext = Path(target_basename).suffix.lower()
        target_stem = Path(target_basename).stem.lower()

        if target_ext in recognized_doc_exts:
            if target_stem in words and not any(p in target_basename for p in ("_secrets", ".bak", ".old", "~")):
                return True

        return False

    def evaluate_request(
        self,
        task_id: str,
        agent_id: str,
        resource_type: str,
        resource_target: str,
        justification: str,
        provenance_enabled: bool | None = None,
        provenance_mode: str | None = None,  # "off", "any", "content_linked"
        timeout_seconds: float = 5.0,
    ) -> ExpansionRequest:
        """
        Creates and evaluates a dynamic expansion request.
        Applies provenance escalation and determines baseline vs effective risk tier.
        Agent-initiated HIGH risk expansion requests are automatically DENIED by policy.
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

    @staticmethod
    def classify_resource_risk(resource_type: str, resource_target: str) -> RiskTier:
        """
        Classifies baseline risk tier based on structural rules and sensitive resource patterns.
        """
        if not resource_target or not str(resource_target).strip():
            raise ValueError("resource_target cannot be empty in expansion request")
        if not resource_type or not str(resource_type).strip():
            raise ValueError("resource_type cannot be empty in expansion request")

        target_norm = resource_target.strip().replace("\\", "/").lower()
        parts = [p for p in target_norm.split("/") if p]

        # 1. Structural Rule: Outside workspace is HIGH
        is_outside_workspace = (
            target_norm.startswith("/")
            or ".." in parts
            or (len(parts) > 0 and len(parts[0]) == 2 and parts[0][1] == ":")
        )
        if is_outside_workspace:
            return RiskTier.HIGH

        if resource_type in ("file_read", "file_write"):
            # 2. Sensitive pattern matching -> HIGH
            sensitive_substrs = (
                "credential", "secret", "password", ".env", "id_rsa", "shadow",
                ".git-credentials", ".npmrc", ".netrc"
            )
            sensitive_exts = (".key", ".p12", ".pfx", ".kdbx")
            sensitive_prefixes = (".ssh", ".aws", ".kube")

            if any(s in target_norm for s in sensitive_substrs):
                return RiskTier.HIGH

            target_name = Path(target_norm).name
            if any(target_name.endswith(ext) for ext in sensitive_exts):
                return RiskTier.HIGH

            if any(p in sensitive_prefixes for p in parts) or any(target_norm.startswith(pre + "/") for pre in sensitive_prefixes):
                return RiskTier.HIGH

            # 3. Structural Rule: Writes outside output/ are HIGH
            if resource_type == "file_write" and not target_norm.startswith("output/"):
                return RiskTier.HIGH

            # 4. Structural Rule: Files outside input/ are at least MEDIUM
            if not target_norm.startswith("input/"):
                return RiskTier.MEDIUM

            return RiskTier.LOW

        elif resource_type == "network":
            # Local/private hosts are MEDIUM; external/unknown are HIGH
            if any(target_norm.startswith(h) for h in ("127.0.0.1", "localhost", "internal.")):
                return RiskTier.MEDIUM
            return RiskTier.HIGH

        elif resource_type == "peer_agent":
            return RiskTier.MEDIUM

        return RiskTier.MEDIUM

    def evaluate_request(
        self,
        task_id: str,
        agent_id: str,
        resource_type: str,
        resource_target: str,
        justification: str,
        provenance_enabled: bool | None = None,
        provenance_mode: str | None = None,  # "off", "any", "content_linked"
        timeout_seconds: float = 5.0,
    ) -> ExpansionRequest:
        """
        Creates and evaluates a dynamic expansion request.
        Applies provenance escalation and determines baseline vs effective risk tier.
        Agent-initiated HIGH risk expansion requests are automatically DENIED by policy.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        request_id = self._generate_request_id()

        # 1. Enforce Exact Resource Scope (NO WILDCARDS ALLOWED, NON-EMPTY)
        if not resource_target or not str(resource_target).strip():
            raise ValueError("resource_target cannot be empty in expansion request")
        if not resource_type or not str(resource_type).strip():
            raise ValueError("resource_type cannot be empty in expansion request")
        if any(c in resource_target for c in ("*", "?", "[", "]")):
            raise ValueError(
                f"Wildcards are strictly prohibited in expansion requests. "
                f"Resource target '{resource_target}' must be exact."
            )

        task = self.storage.get_task(task_id)
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")


        # 2. Determine Baseline Risk Tier using structural rules and sensitive patterns
        baseline_tier = self.classify_resource_risk(resource_type, resource_target)

        # 3. Check if explicitly anticipated by user original request text
        anticipated_by_user = self.is_anticipated_by_user(task.request_text, resource_target)

        # 4. Provenance-Aware Escalation Analysis
        if provenance_mode is not None:
            mode = provenance_mode.lower()
        elif provenance_enabled is not None:
            mode = "any" if provenance_enabled else "off"
        else:
            mode = "any" if self.provenance_enabled else "off"

        escalated = False
        effective_tier = baseline_tier

        if mode != "off":
            prior_reads = self.storage.get_provenance_for_task(task_id)
            if len(prior_reads) > 0 and not anticipated_by_user:
                if mode == "any":
                    # Any untrusted read taints the agent
                    escalated = True
                elif mode == "content_linked":
                    # Escalate only if requested resource target / name / host appears in untrusted content read earlier
                    needle_path = target_norm
                    needle_name = Path(target_norm).name.lower()
                    host_part = target_norm.split(":")[0] if ":" in target_norm else target_norm
                    for pr in prior_reads:
                        snippet = (pr.content_snippet or "").lower()
                        if needle_path in snippet or needle_name in snippet or (resource_type == "network" and host_part in snippet):
                            escalated = True
                            break

                if escalated:
                    if baseline_tier == RiskTier.LOW:
                        effective_tier = RiskTier.MEDIUM
                    elif baseline_tier == RiskTier.MEDIUM:
                        effective_tier = RiskTier.HIGH
                    elif baseline_tier == RiskTier.HIGH:
                        effective_tier = RiskTier.HIGH

        # 5. Determine Initial Status
        # Policy rules:
        # LOW: Auto-approved
        # MEDIUM: PENDING (escalates to operator approval: ASK_USER)
        # HIGH: DENIED by policy for agent-initiated requests (DENY)
        if effective_tier == RiskTier.LOW:
            status = ExpansionStatus.APPROVED
            resolved_by = "auto_policy"
            resolved_at = now_utc
            is_auto_approved = True
        elif effective_tier == RiskTier.MEDIUM:
            status = ExpansionStatus.PENDING
            resolved_by = None
            resolved_at = None
            is_auto_approved = False
        else:  # RiskTier.HIGH
            status = ExpansionStatus.DENIED
            resolved_by = "policy_deny_high_risk"
            resolved_at = now_utc
            is_auto_approved = False

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
        if req.status == ExpansionStatus.DENIED:
            return False, f"Denied by policy: agent-initiated expansion to {req.effective_risk_tier.value}-risk resource '{resource_target}' is prohibited"

        # If a simulated user hook is configured for ASK_USER (PENDING), resolve immediately
        if req.status == ExpansionStatus.PENDING and self.user_approval_hook is not None:
            approved = self.user_approval_hook(req)
            if approved:
                self.approve_request(req.request_id, approved_by=f"simulated_user_{self.simulated_user_policy}")
                return True, f"Approved by simulated user ({self.simulated_user_policy})"
            else:
                self.deny_request(
                    req.request_id,
                    denied_by=f"simulated_user_{self.simulated_user_policy}",
                    reason=f"Denied by simulated user policy ({self.simulated_user_policy})",
                )
                return False, f"Denied by simulated user policy ({self.simulated_user_policy})"

        # Polling wait loop up to timeout_seconds for MEDIUM risk (PENDING)
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

    async def async_request_and_wait(
        self,
        task_id: str,
        agent_id: str,
        resource_type: str,
        resource_target: str,
        justification: str,
        timeout_seconds: float = 2.0,
        provenance_enabled: bool | None = None,
        provenance_mode: str | None = None,
    ) -> tuple[bool, str]:
        """
        Asynchronous request and wait loop for FastAPI server handlers.
        Uses asyncio.sleep so other requests on the event loop are never blocked.
        """
        req = self.evaluate_request(
            task_id=task_id,
            agent_id=agent_id,
            resource_type=resource_type,
            resource_target=resource_target,
            justification=justification,
            provenance_enabled=provenance_enabled,
            provenance_mode=provenance_mode,
            timeout_seconds=timeout_seconds,
        )

        if req.status == ExpansionStatus.APPROVED:
            return True, f"Auto-approved under {req.effective_risk_tier.value} risk policy"
        if req.status == ExpansionStatus.DENIED:
            return False, f"Denied by policy: agent-initiated expansion to {req.effective_risk_tier.value}-risk resource '{resource_target}' is prohibited"

        start_time = time.time()
        poll_interval = 0.05
        while (time.time() - start_time) < timeout_seconds:
            await asyncio.sleep(poll_interval)
            current = self.storage.get_expansion_request(req.request_id)
            if not current:
                break
            if current.status == ExpansionStatus.APPROVED:
                return True, f"Approved by {current.resolved_by}"
            if current.status == ExpansionStatus.DENIED:
                return False, f"Denied by {current.resolved_by}"

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.deny_request(req.request_id, denied_by="timeout_fail_closed", reason="Approval request timed out")
        return False, "Approval request timed out: denied (fail-closed)"

    def grant_resource_proactively(
        self,
        task_id: str,
        granted_by: str,
        resource_type: str,
        resource_target: str,
        single_use: bool = True,
    ) -> TaskBoundary:
        """
        User-initiated proactive grant of a resource (including HIGH-risk).
        STRICTLY PROHIBITS AGENT SELF-GRANT.
        Creates an APPROVED ExpansionRequest authored by the user and expands boundary to version N+1.
        HIGH-risk grants are marked single_use=True.
        """
        task = self.storage.get_task(task_id)
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")

        if granted_by.lower() in (task.agent_id.lower(), "agent", "caller", "self"):
            raise PermissionError(f"Agent '{granted_by}' is strictly prohibited from granting itself resources.")

        target_norm = resource_target.strip().replace("\\", "/").lower()
        if any(c in resource_target for c in ("*", "?", "[", "]")):
            raise ValueError(f"Wildcards are strictly prohibited. Resource target '{resource_target}' must be exact.")

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        request_id = self._generate_request_id()

        # Determine risk tier for record
        tier = self.classify_resource_risk(resource_type, resource_target)

        req = ExpansionRequest(
            request_id=request_id,
            task_id=task_id,
            agent_id="human_operator",
            resource_type=resource_type,
            resource_target=resource_target,
            justification=f"Proactive grant by user '{granted_by}'",
            baseline_risk_tier=tier,
            effective_risk_tier=tier,
            escalated_by_provenance=False,
            status=ExpansionStatus.APPROVED,
            created_at=now_utc,
            resolved_at=now_utc,
            resolved_by=granted_by,
            single_use=(tier == RiskTier.HIGH or single_use),
            used_count=0,
            timeout_seconds=0.0,
        )
        self.storage.save_expansion_request(req)
        return self._apply_boundary_expansion(req)
