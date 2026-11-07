"""Standing Rules (Console v4).

Enforces:
- Opt-in via GOVERNANCE_STANDING_RULES=1 (default: 0 / inactive).
- NEVER active during evaluation runs (asserted by test and runtime checks).
- Shape: exact match on (agent_or_profile, action, target) with owner, created_at,
  expiry (at most 90 days), and optional team scope.
- Scope: evaluated only where a human approval would be requested.
  They NEVER touch Landlock or seccomp, never apply to provenance-escalated requests,
  and never apply to HIGH risk.
- Logging: every auto-decision is written to receipt as 'allowed by rule R (owner X)'.
"""
from __future__ import annotations

import datetime
import os
import uuid
from typing import Any
from pydantic import BaseModel, Field

from .models import ExpansionRequest, RiskTier


class StandingRule(BaseModel):
    rule_id: str
    agent_or_profile: str  # exact agent_id or profile pattern
    action: str  # resource_type: file_read, file_write, etc.
    target: str  # normalized resource_target
    owner: str  # creator
    created_at: str
    expires_at: str
    team: str | None = None
    is_active: bool = True


def is_standing_rules_enabled() -> bool:
    """Checks if standing rules are enabled via env var GOVERNANCE_STANDING_RULES=1."""
    # Never active in evaluation harness
    if os.getenv("GOVERNANCE_EVALUATION_ACTIVE") == "1":
        return False
    return os.getenv("GOVERNANCE_STANDING_RULES", "0").strip() in ("1", "true", "True")


def is_high_risk_or_escalated(req: ExpansionRequest) -> bool:
    """Rules NEVER apply to provenance-escalated requests or HIGH risk."""
    if req.escalated_by_provenance:
        return True
    if req.effective_risk_tier == RiskTier.HIGH:
        return True
    if req.baseline_risk_tier == RiskTier.HIGH:
        return True
    return False


def match_rule(
    rules: list[StandingRule],
    req: ExpansionRequest,
    task_team: str | None = None,
    now: datetime.datetime | None = None,
) -> StandingRule | None:
    """Finds a matching active standing rule for a pending expansion request.
    Rules never apply to provenance escalation or HIGH risk.
    """
    if not is_standing_rules_enabled():
        return None

    if is_high_risk_or_escalated(req):
        return None

    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)

    target_norm = req.resource_target.strip().replace("\\", "/")

    for rule in rules:
        if not rule.is_active:
            continue
        try:
            exp_dt = datetime.datetime.fromisoformat(rule.expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=datetime.timezone.utc)
            if exp_dt <= now:
                continue
        except Exception:
            continue

        # Check team scope if rule specifies one
        if rule.team and task_team and rule.team != task_team:
            continue

        # Check agent / profile match
        agent_match = (rule.agent_or_profile == "*" or rule.agent_or_profile == req.agent_id)
        if not agent_match:
            continue

        # Check action match
        if rule.action != req.resource_type:
            continue

        # Check target match (exact match, normalized)
        rule_target_norm = rule.target.strip().replace("\\", "/")
        if rule_target_norm == target_norm:
            return rule

    return None
