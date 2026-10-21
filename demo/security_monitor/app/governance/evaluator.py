"""Fast, Deterministic Boundary Evaluator (F7).

Performs strict, zero-LLM compliance evaluation of runtime actions against the TaskBoundary contract.
"""
from __future__ import annotations

import fnmatch
import os
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
        
        # Strip trailing dots and whitespace (Windows filesystem normalization evasion)
        cleaned_path = path_str.strip().rstrip(". ")
        if not cleaned_path:
            return EvaluationResult(
                verdict=EventVerdict.OUTSIDE,
                risk_tier=RiskTier.HIGH,
                rule_matched="empty or invalid path target",
            )

        raw_path = Path(cleaned_path)

        # 1. Resolve canonical path using realpath to dereference symlinks/junctions
        if not raw_path.is_absolute():
            full_path = w_root / raw_path
        else:
            full_path = raw_path

        try:
            # os.path.realpath resolves symlinks on both Linux and Windows
            resolved_real = Path(os.path.realpath(str(full_path)))
        except Exception:
            resolved_real = full_path.resolve()

        resolved_str = str(resolved_real).replace("\\", "/")
        filename = resolved_real.name.lower()

        # 2. Check for sensitive credential-like file patterns -> HIGH RISK (Case-Insensitive)
        for pattern in SENSITIVE_FILE_PATTERNS:
            if fnmatch.fnmatch(filename, pattern.lower()):
                return EvaluationResult(
                    verdict=EventVerdict.OUTSIDE,
                    risk_tier=RiskTier.HIGH,
                    rule_matched=f"prohibited sensitive credential pattern: {pattern}",
                )

        # 3. Check workspace boundary containment -> HIGH RISK on escape or symlink pointing outside
        try:
            rel_path = resolved_real.relative_to(w_root)
            rel_str = str(rel_path).replace("\\", "/")
        except ValueError:
            return EvaluationResult(
                verdict=EventVerdict.OUTSIDE,
                risk_tier=RiskTier.HIGH,
                rule_matched="path escapes task workspace_root (canonical target outside boundary)",
            )

        # 4. Check against allowed read/write boundary list (Strict relative path matching)
        allowed_list = boundary.files_write if is_write else boundary.files_read
        mode_str = "files.write" if is_write else "files.read"

        rel_lower = rel_str.lower()
        for pattern in allowed_list:
            pat_clean = pattern.replace("\\", "/").lower()
            # Match normalized relative path
            if fnmatch.fnmatch(rel_lower, pat_clean):
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
        raw = url_or_host.strip()
        
        # Ensure scheme for reliable urlparse handling of userinfo & IPv6
        if "://" not in raw:
            to_parse = "http://" + raw
        else:
            to_parse = raw

        parsed = urlparse(to_parse)
        
        # urlparse extracts the real hostname even if userinfo is present (e.g. http://allowed@evil.com)
        host = (parsed.hostname or "").lower()
        
        if not host:
            return EvaluationResult(
                verdict=EventVerdict.OUTSIDE,
                risk_tier=RiskTier.HIGH,
                rule_matched="invalid or empty network destination host",
            )

        # Determine effective port
        if parsed.port is not None:
            port = parsed.port
        else:
            port = 443 if parsed.scheme == "https" else 80

        target_hostport = f"{host}:{port}"

        for allowed in boundary.network:
            allowed_clean = allowed.lower().strip()
            # Allow wildcard port or explicit host:port or bare host matching default port
            if ":" in allowed_clean:
                if fnmatch.fnmatch(target_hostport, allowed_clean):
                    return EvaluationResult(
                        verdict=EventVerdict.INSIDE,
                        risk_tier=RiskTier.LOW,
                        rule_matched=f"matched allowed network endpoint: {allowed}",
                    )
            else:
                # Bare host in boundary matches on host regardless of port or on default ports
                if fnmatch.fnmatch(host, allowed_clean):
                    return EvaluationResult(
                        verdict=EventVerdict.INSIDE,
                        risk_tier=RiskTier.LOW,
                        rule_matched=f"matched allowed network host: {allowed}",
                    )

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
