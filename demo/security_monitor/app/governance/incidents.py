"""Incidents (Console v4): blocked actions, read only.

Each incident is one blocked event: what the agent tried, which layer stopped it, what
happened next (a later approval request for the same target, if any), and the line in a
file the agent read earlier in that task that mentions the target. That search runs only
inside the task's own workspace (workspace_read.find_mention); if no line is found the
answer is "unknown". Nothing here changes enforcement.
"""
from __future__ import annotations

from typing import Any

from .fleet import event_layer, is_blocked, parse_ts
from .task_report import decided_by_label
from .workspace_read import find_mention

RULE_ACTION_FOR_KIND = {
    "file_read": "file_read",
    "file_write": "file_write",
    "network": "network",
    "network_http": "network",
    "http_get": "network",
    "network_connect": "network",
    "connect": "network",
    "egress": "network",
    "peer_agent": "peer_agent",
}


def incident_id(event: dict[str, Any]) -> str:
    return str(event.get("event_id") or "")


def summarize(task: Any, event: dict[str, Any]) -> dict[str, Any]:
    kind = str(event.get("kind") or "")
    action = RULE_ACTION_FOR_KIND.get(kind)
    return {
        "incident_id": incident_id(event),
        "task_id": task.task_id,
        "agent_id": task.agent_id,
        "request_text": task.request_text,
        "timestamp": event.get("timestamp"),
        "kind": kind,
        "target": event.get("target") or "",
        "layer": event_layer(event),
        "rule_matched": event.get("rule_matched"),
        "result": "attempted_not_successful",
        "rule_action": action,
    }


def list_incidents(tasks: list[Any], events_for: Any, limit: int = 200) -> list[dict[str, Any]]:
    """Newest first. `events_for(task_id)` returns the task's unified events."""
    out: list[dict[str, Any]] = []
    for t in tasks:
        for e in events_for(t.task_id):
            if is_blocked(e) and incident_id(e):
                out.append(summarize(t, e))
    out.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    return out[:limit]


def _followup(expansions: list[Any], target: str, after_ts: str | None) -> dict[str, Any] | None:
    """The first approval request for the same target at or after the blocked event."""
    after = parse_ts(after_ts)
    norm = (target or "").strip().replace("\\", "/").lstrip("./")
    for r in sorted(expansions, key=lambda x: x.created_at or ""):
        rt = (r.resource_target or "").strip().replace("\\", "/").lstrip("./")
        if rt != norm:
            continue
        created = parse_ts(r.created_at)
        if after and created and created < after:
            continue
        status = getattr(r.status, "value", r.status)
        return {
            "request_id": r.request_id,
            "status": status,
            "decided_by": r.resolved_by,
            "decided_by_label": decided_by_label(r.resolved_by, status),
            "decided_at": r.resolved_at,
            "single_use": bool(r.single_use),
        }
    return None


def incident_detail(task: Any, event: dict[str, Any], provenance: list[Any], expansions: list[Any],
                    can_make_rule: bool) -> dict[str, Any]:
    base = summarize(task, event)
    ev_ts = parse_ts(event.get("timestamp"))
    earlier: list[str] = []
    for p in provenance:
        if p.source_type not in ("file_read",):
            continue
        pts = parse_ts(p.timestamp)
        if ev_ts and pts and pts > ev_ts:
            continue
        if p.source_target and p.source_target not in earlier:
            earlier.append(p.source_target)
    mention = find_mention(task.workspace_root, earlier, base["target"]) if earlier else None
    base.update({
        "mention": mention,  # None means unknown
        "files_searched": len(earlier),
        "followup": _followup(expansions, base["target"], event.get("timestamp")),
        "can_make_rule": bool(can_make_rule and base["rule_action"]),
        "rule_unavailable_reason": (
            None if base["rule_action"] and can_make_rule
            else "Rules cover files, addresses and agents only." if not base["rule_action"]
            else "Only a security reviewer or an admin can make a standing rule."
        ),
    })
    return base
