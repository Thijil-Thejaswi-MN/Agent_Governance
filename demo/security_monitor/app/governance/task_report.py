"""One-page task report (Console v4): requester, boundary, approvals, blocked actions and
the record's hash-chain check, built only from stored data. Read only.
"""
from __future__ import annotations

import csv
import io
from typing import Any

from .fleet import event_layer, is_blocked


def _val(x: Any) -> Any:
    return getattr(x, "value", x)


def decided_by_label(resolved_by: str | None, status: str) -> str:
    """Who decided, in plain words."""
    if not resolved_by:
        return "Waiting" if status == "PENDING" else "Unknown"
    if resolved_by == "auto_policy":
        return "Built-in policy (low risk)"
    if resolved_by == "policy_deny_high_risk":
        return "Built-in policy (high risk)"
    if resolved_by == "timeout_fail_closed":
        return "No one in time (stayed blocked)"
    if resolved_by.startswith("standing_rule:"):
        return f"Standing rule {resolved_by.split(':', 1)[1]}"
    if resolved_by.startswith("simulated_user_"):
        return "Simulated user"
    if ":" in resolved_by:
        role, name = resolved_by.split(":", 1)
        return f"{name} ({role.replace('_', ' ')})"
    return resolved_by


def _scope(req: Any) -> str:
    by = req.resolved_by or ""
    status = _val(req.status)
    if status == "PENDING":
        return "waiting"
    if by.startswith("standing_rule:"):
        return "rule"
    if by in ("auto_policy", "policy_deny_high_risk"):
        return "policy"
    if by == "timeout_fail_closed":
        return "timeout"
    if status == "APPROVED":
        return "once" if req.single_use else "run"
    return "blocked"


def _boundary_dict(b: Any) -> dict[str, Any] | None:
    if b is None:
        return None
    return {
        "version": b.version,
        "files_read": list(b.files_read),
        "files_write": list(b.files_write),
        "network": list(b.network),
        "tools": list(b.tools),
    }


def build_task_report(
    task: Any,
    first_boundary: Any,
    last_boundary: Any,
    expansions: list[Any],
    events: list[dict[str, Any]],
    record: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    approvals = []
    for r in sorted(expansions, key=lambda x: x.created_at or ""):
        status = _val(r.status)
        approvals.append({
            "request_id": r.request_id,
            "resource_type": r.resource_type,
            "target": r.resource_target,
            "status": status,
            "scope": _scope(r),
            "asked_at": r.created_at,
            "decided_at": r.resolved_at,
            "decided_by": r.resolved_by,
            "decided_by_label": decided_by_label(r.resolved_by, status),
            "risk_tier": _val(r.effective_risk_tier),
            "prompted_by_file": bool(r.escalated_by_provenance),
            "reason": r.reason,
        })
    blocked = []
    for e in sorted((e for e in events if is_blocked(e)), key=lambda x: x.get("timestamp") or ""):
        blocked.append({
            "timestamp": e.get("timestamp"),
            "kind": e.get("kind"),
            "target": e.get("target"),
            "layer": event_layer(e),
            "rule": e.get("rule_matched"),
        })
    return {
        "generated_at": generated_at,
        "task": {
            "task_id": task.task_id,
            "request_text": task.request_text,
            "agent_id": task.agent_id,
            "requester": task.owner,
            "team": task.team,
            "status": _val(task.status),
            "created_at": task.created_at,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
        },
        "boundary": {
            "initial": _boundary_dict(first_boundary),
            "final": _boundary_dict(last_boundary),
        },
        "approvals": approvals,
        "blocked": blocked,
        "record": record,
    }


CSV_COLUMNS = ["section", "time", "who_or_layer", "what", "target", "outcome", "detail"]


def report_to_csv(report: dict[str, Any]) -> str:
    """One row per fact; formulas are neutralised so the file is inert in spreadsheets."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)

    def row(*cells: Any) -> None:
        out = []
        for c in cells:
            s = "" if c is None else str(c)
            if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
                s = "'" + s
            out.append(s)
        w.writerow(out)

    t = report["task"]
    row("task", t["created_at"], t["requester"] or "", "request", t["task_id"], t["status"], t["request_text"])
    row("task", t["created_at"], t["agent_id"], "agent", "", "", t["team"] or "")
    for side in ("initial", "final"):
        b = report["boundary"].get(side)
        if not b:
            continue
        for kind in ("files_read", "files_write", "network", "tools"):
            for item in b[kind]:
                row("boundary", "", f"v{b['version']}", f"{side} {kind}", item, "", "")
    for a in report["approvals"]:
        row("approval", a["decided_at"] or a["asked_at"], a["decided_by_label"], a["resource_type"], a["target"],
            f"{a['status']} ({a['scope']})", a["reason"] or "")
    for b in report["blocked"]:
        row("blocked", b["timestamp"], b["layer"], b["kind"], b["target"], "attempted, not successful", b["rule"] or "")
    rec = report["record"]
    row("record", report["generated_at"], "hash-chain check", "", rec.get("final_hash") or "",
        "verified" if rec.get("verified") else ("no record" if not rec.get("available") else "does not verify"),
        rec.get("message") or "")
    return buf.getvalue()
