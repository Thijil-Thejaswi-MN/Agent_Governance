"""Inbox Grouping and Pattern Detection (Console v4).

Groups pending requests by (agent_or_profile, action, normalized_target, provenance_escalated).
"""
from __future__ import annotations

from typing import Any
from .models import ExpansionRequest, RiskTier


def normalize_target(target: str) -> str:
    """Normalizes path / target for uniform grouping."""
    return (target or "").strip().replace("\\", "/").lower()


def group_pending(requests: list[ExpansionRequest]) -> list[dict[str, Any]]:
    """Groups pending requests by (agent_id, resource_type, normalized_target, escalated_by_provenance).

    Each group returns:
    - group_key: str tuple representation
    - count: number of requests in group
    - agent_id: str
    - action: str (resource_type)
    - target: str (normalized_target)
    - escalated_by_provenance: bool
    - risk_tier: str ("Look closely" if escalated or HIGH risk, else "Routine")
    - plain_reason: plain language summary
    - request_ids: list of request IDs in this group
    - requests: list of ExpansionRequest objects
    - can_batch_allow: bool (False if escalated_by_provenance or HIGH risk)
    """
    groups_dict: dict[tuple[str, str, str, bool], list[ExpansionRequest]] = {}

    for req in requests:
        norm_target = normalize_target(req.resource_target)
        key = (req.agent_id, req.resource_type, norm_target, req.escalated_by_provenance)
        groups_dict.setdefault(key, []).append(req)

    result = []
    for key, req_list in groups_dict.items():
        agent_id, action, target, escalated = key
        count = len(req_list)
        first = req_list[0]

        is_high_or_escalated = escalated or first.effective_risk_tier == RiskTier.HIGH
        risk_flag = "Look closely" if is_high_or_escalated else "Routine"

        if escalated:
            plain_reason = f"It only learned about this file from inside another file ({count} waiting)"
        elif action == "file_read":
            plain_reason = f"Wants to read {target} ({count} waiting)"
        elif action == "file_write":
            plain_reason = f"Wants to write {target} ({count} waiting)"
        elif action == "network":
            plain_reason = f"Wants to connect to {target} ({count} waiting)"
        else:
            plain_reason = f"Requested {action} on {target} ({count} waiting)"

        result.append({
            "group_key": f"{agent_id}:{action}:{target}:{escalated}",
            "count": count,
            "agent_id": agent_id,
            "action": action,
            "target": target,
            "escalated_by_provenance": escalated,
            "risk_flag": risk_flag,
            "plain_reason": plain_reason,
            "request_ids": [r.request_id for r in req_list],
            "requests": req_list,
            "can_batch_allow": not escalated,
        })

    # Sort groups with Look closely first, then highest count
    result.sort(key=lambda g: (0 if g["risk_flag"] == "Look closely" else 1, -g["count"]))
    return result
