from __future__ import annotations

from ..core.models import SecurityViolation, SecuritySeverity, PolicyAction


class PolicyEngine:
    """Deterministic policy resolution engine with configurable enforcement regimes."""

    def __init__(self, policy_mode: str = "GRADUATED") -> None:
        valid_modes = {"GRADUATED", "BINARY_QUARANTINE", "PERMISSIVE"}
        mode_upper = policy_mode.upper()
        if mode_upper not in valid_modes:
            raise ValueError(f"Invalid policy_mode '{policy_mode}'. Must be one of {valid_modes}")
        self.policy_mode = mode_upper

    def evaluate(self, violation: SecurityViolation | None) -> tuple[SecuritySeverity | None, PolicyAction]:
        """
        Map a detected security violation to severity and enforcement action.
        Supports three evaluation regimes:
        - PERMISSIVE: Detection occurs and severity is assigned, but action is always ALLOW.
        - BINARY_QUARANTINE: Any detected violation triggers immediate QUARANTINE.
        - GRADUATED (default): Tiered response (LOW -> RATE_LIMIT, MEDIUM -> RESTRICT, HIGH -> QUARANTINE).
        """
        if violation is None:
            return None, PolicyAction.ALLOW

        # Determine inherent violation severity
        if violation.violation_code == "RATE_LIMIT_EXCEEDED":
            severity = SecuritySeverity.LOW
            graduated_action = PolicyAction.RATE_LIMIT
        elif violation.violation_code in {
            "RESTRICTED_OPERATION_DENIED",
            "UNAPPROVED_INTERFACE_VARIANCE",
            "SUSPICIOUS_PAYLOAD_STRUCTURE",
        }:
            severity = SecuritySeverity.MEDIUM
            graduated_action = PolicyAction.RESTRICT
        elif violation.violation_code in {
            "AS_HOMOGLYPH_SPOOF",
            "AS_PROVENANCE_CONFLICT",
            "AS_TYPOSQUATTING_CLONE",
            "AS_TYPOSQUAT_SPOOF",
            "CC_UNDECLARED_CAPABILITY",
            "CO_CYCLE_DETECTED",
            "CO_DEPTH_EXCEEDED",
        }:
            severity = SecuritySeverity.HIGH
            graduated_action = PolicyAction.QUARANTINE
        else:
            severity = SecuritySeverity.MEDIUM
            graduated_action = PolicyAction.RESTRICT

        # Apply regime enforcement logic
        if self.policy_mode == "PERMISSIVE":
            return severity, PolicyAction.ALLOW
        if self.policy_mode == "BINARY_QUARANTINE":
            return severity, PolicyAction.QUARANTINE
        return severity, graduated_action
