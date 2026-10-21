"""Fast, Deterministic Boundary Evaluator (F7).

Performs strict, zero-LLM compliance evaluation of runtime actions against the TaskBoundary contract.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from urllib.parse import urlparse
from pydantic import BaseModel

from .models import TaskBoundary, EventVerdict, RiskTier


class EvaluationResult(BaseModel):
    verdict: EventVerdict
    risk_tier: RiskTier
    rule_matched: str


SENSITIVE_FILE_PATTERNS = [
    "credentials*",
    "*credential*",
    "*.pem",
    "id_rsa*",
    "id_ed25519*",
    "*.key",
    ".env*",
    "*token*",
    "*secret*",
    "shadow",
    "passwd",
]


class BoundaryEvaluator:
    """Evaluates agent actions deterministically against the task boundary."""

    def evaluate_file_access(self, boundary: TaskBoundary, path_str: str, is_write: bool) -> EvaluationResult:
        w_root = Path(boundary.workspace_root).resolve()
        raw_path = Path(path_str)

        # 1. Resolve canonical path
        if not raw_path.is_absolute():
            resolved = (w_root / raw_path).resolve()
        else:
            resolved = raw_path.resolve()

        resolved_str = str(resolved).replace("\\", "/")
        filename = resolved.name.lower()

        # 2. Check for sensitive credential-like file patterns -> HIGH RISK
        for pattern in SENSITIVE_FILE_PATTERNS:
            if fnmatch.fnmatch(filename, pattern):
                return EvaluationResult(
                    verdict=EventVerdict.OUTSIDE,
                    risk_tier=RiskTier.HIGH,
                    rule_matched=f"prohibited sensitive credential pattern: {pattern}",
                )

        # 3. Check workspace boundary containment -> HIGH RISK on escape
        try:
            rel_path = resolved.relative_to(w_root)
            rel_str = str(rel_path).replace("\\", "/")
        except ValueError:
            return EvaluationResult(
                verdict=EventVerdict.OUTSIDE,
                risk_tier=RiskTier.HIGH,
                rule_matched="path escapes task workspace_root",
            )

        # 4. Check against allowed read/write boundary list
        allowed_list = boundary.files_write if is_write else boundary.files_read
        mode_str = "files.write" if is_write else "files.read"

        for pattern in allowed_list:
            pat_clean = pattern.replace("\\", "/")
            # Match either relative path or base filename
            if fnmatch.fnmatch(rel_str, pat_clean) or fnmatch.fnmatch(filename, pat_clean):
                return EvaluationResult(
                    verdict=EventVerdict.INSIDE,
                    risk_tier=RiskTier.LOW,
                    rule_matched=f"matched allowed {mode_str} pattern: {pattern}",
                )

        # 5. File is inside workspace, but unlisted -> OUTSIDE (MEDIUM risk)
        return EvaluationResult(
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.MEDIUM,
            rule_matched=f"unlisted file path inside workspace: {rel_str}",
        )

    def evaluate_network(self, boundary: TaskBoundary, url_or_host: str) -> EvaluationResult:
        # Parse host and port
        if "://" in url_or_host:
            parsed = urlparse(url_or_host)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        elif ":" in url_or_host:
            parts = url_or_host.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = 80
        else:
            host = url_or_host
            port = 80

        target_hostport = f"{host}:{port}".lower()

        for allowed in boundary.network:
            allowed_clean = allowed.lower()
            if fnmatch.fnmatch(target_hostport, allowed_clean) or fnmatch.fnmatch(host.lower(), allowed_clean):
                return EvaluationResult(
                    verdict=EventVerdict.INSIDE,
                    risk_tier=RiskTier.LOW,
                    rule_matched=f"matched allowed network endpoint: {allowed}",
                )

        # Unknown network destination is high risk
        return EvaluationResult(
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.HIGH,
            rule_matched=f"unlisted outbound network destination: {target_hostport}",
        )

    def evaluate_peer_agent(self, boundary: TaskBoundary, target_agent_id: str) -> EvaluationResult:
        tid_lower = target_agent_id.lower().strip()
        for allowed in boundary.peer_agents:
            if tid_lower == allowed.lower().strip() or fnmatch.fnmatch(tid_lower, allowed.lower()):
                return EvaluationResult(
                    verdict=EventVerdict.INSIDE,
                    risk_tier=RiskTier.LOW,
                    rule_matched=f"matched allowed peer agent: {allowed}",
                )

        return EvaluationResult(
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.HIGH,
            rule_matched=f"unlisted peer agent: {target_agent_id}",
        )

    def evaluate_command(self, boundary: TaskBoundary, command: str) -> EvaluationResult:
        # In Milestone 1, unmediated command execution is denied by default per prompt specification
        return EvaluationResult(
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.HIGH,
            rule_matched="unmediated execution not supported until OS enforcement (M4)",
        )

    def evaluate_tool(self, boundary: TaskBoundary, tool_name: str) -> EvaluationResult:
        if tool_name in boundary.tools:
            return EvaluationResult(
                verdict=EventVerdict.INSIDE,
                risk_tier=RiskTier.LOW,
                rule_matched=f"tool granted in boundary: {tool_name}",
            )
        return EvaluationResult(
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.HIGH,
            rule_matched=f"tool not granted in task boundary: {tool_name}",
        )
