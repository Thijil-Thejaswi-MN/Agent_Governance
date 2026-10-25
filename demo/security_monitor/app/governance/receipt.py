"""Task Receipt v0 (M6.1).

A per-task JSON record of what the task was allowed, what it asked for, what it
did and what was prevented. It is *hash-chained*: every event entry includes
the hash of the previous entry, and the receipt carries the final hash, so a
recomputation (scripts/verify_receipt.py) detects edits to the event list that
were not followed by re-chaining. It is not signed and is not a guarantee
against a party who can rewrite the whole file.

Data minimisation: paths, operations and results only. No file contents, no
prompt text (only its SHA-256), secret-looking strings in commands redacted, no
environment variables.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any

from .models import EventSource, EventVerdict, TaskBoundary, TaskRecord
from .redaction import redact_command
from .storage import GovernanceStorage

RECEIPT_VERSION = "v0"
GENESIS_HASH = "0" * 64
_SAFE_BROKER_DETAIL_KEYS = ("execution", "check_only", "reason", "channel", "method", "dst_host", "dst_port")


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("ascii")


def chain_entries(entries: list[dict[str, Any]]) -> str:
    """Adds index/prev_hash/hash to each entry in place; returns the final hash."""
    prev = GENESIS_HASH
    for i, e in enumerate(entries):
        e.pop("hash", None)
        e["index"] = i
        e["prev_hash"] = prev
        e["hash"] = hashlib.sha256(canonical(e)).hexdigest()
        prev = e["hash"]
    return prev


def verify_chain(entries: list[dict[str, Any]]) -> tuple[bool, str, str]:
    """Recomputes the chain. Returns (ok, final_hash, message)."""
    prev = GENESIS_HASH
    for i, e in enumerate(entries):
        if e.get("index") != i:
            return False, prev, f"entry {i}: index mismatch ({e.get('index')})"
        if e.get("prev_hash") != prev:
            return False, prev, f"entry {i}: prev_hash does not match previous entry"
        body = {k: v for k, v in e.items() if k != "hash"}
        h = hashlib.sha256(canonical(body)).hexdigest()
        if h != e.get("hash"):
            return False, prev, f"entry {i}: hash mismatch"
        prev = h
    return True, prev, "ok"


def _broker_entry(ev: Any) -> dict[str, Any]:
    src = ev.source.value if hasattr(ev.source, "value") else str(ev.source)
    target = ev.target
    if ev.kind == "run_command":
        target = redact_command(target)
    prevented_by = "none"
    if ev.prevented:
        prevented_by = "proxy" if src == EventSource.EGRESS_PROXY.value else "broker"
    return {
        "timestamp": ev.timestamp,
        "source": src,
        "kind": ev.kind,
        "target": str(target)[:1000],
        "verdict": ev.verdict.value,
        "risk_tier": ev.risk_tier.value,
        "action_taken": ev.action_taken.value,
        "prevented": bool(ev.prevented),
        "prevented_by": prevented_by,
        "observed_by": ["egress_proxy" if src == EventSource.EGRESS_PROXY.value else "broker"],
        "channel": "tool",
        "rule_matched": ev.rule_matched,
        "boundary_version": ev.boundary_version,
        "details": {k: ev.details[k] for k in _SAFE_BROKER_DETAIL_KEYS if k in (ev.details or {})},
    }


def _os_entry(rec: dict[str, Any]) -> dict[str, Any]:
    keep = ("timestamp", "source", "kind", "syscall", "target", "target2", "result", "pid", "ppid", "cgroup_path",
            "attribution_method", "attributed_task_id", "phase", "channel", "verdict", "risk_tier",
            "rule_matched", "action_taken", "prevented", "prevented_by", "observed_by", "seq")
    out = {k: rec.get(k) for k in keep}
    if out.get("kind") == "process_exec":
        out["target"] = redact_command(str(out["target"]))
    return out


def build_receipt(
    *,
    task: TaskRecord,
    initial_boundary: TaskBoundary,
    requester: str,
    storage: GovernanceStorage,
    os_records: list[dict[str, Any]],
    deliveries: list[dict[str, Any]],
    sensor_status: dict[str, Any],
    isolation: dict[str, Any],
    freeze_events: list[dict[str, Any]],
    termination: dict[str, Any],
    wall_time_s: float,
    os_identity: dict[str, Any] | None,
    condition: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tool_events = [e for e in storage.get_events_for_task(task.task_id) if e.source != EventSource.OS_SENSOR]
    entries = [_broker_entry(e) for e in tool_events] + [_os_entry(r) for r in os_records]
    entries.sort(key=lambda e: (str(e.get("timestamp")), e.get("seq") or 0))

    counts = {v.value: 0 for v in EventVerdict}
    by_source: dict[str, dict[str, int]] = {}
    for e in entries:
        counts[e["verdict"]] = counts.get(e["verdict"], 0) + 1
        s = by_source.setdefault(e["source"], {v.value: 0 for v in EventVerdict})
        s[e["verdict"]] = s.get(e["verdict"], 0) + 1

    deliveries_by_req = {d.get("request_id"): d for d in deliveries if d.get("request_id")}
    provenance = storage.get_provenance_for_task(task.task_id)
    expansions = []
    for req in storage.list_expansion_requests(task_id=task.task_id):
        prior = [
            {"source_type": p.source_type, "source_target": p.source_target,
             "content_sha256": p.content_hash, "timestamp": p.timestamp}
            for p in provenance if p.timestamp < req.created_at
        ]
        expansions.append({
            "request_id": req.request_id,
            "requester": req.agent_id,
            "resource_type": req.resource_type,
            "resource": req.resource_target,
            "baseline_risk_tier": req.baseline_risk_tier.value,
            "risk_tier": req.effective_risk_tier.value,
            "escalated_by_provenance": req.escalated_by_provenance,
            "provenance_untrusted_reads_before_request": prior,
            "decision": req.status.value,
            "approver": req.resolved_by,
            "resolved_at": req.resolved_at,
            "single_use": req.single_use,
            "delivery": deliveries_by_req.get(req.request_id),
        })

    final_hash = chain_entries(entries)
    outside = [
        {k: e.get(k) for k in ("index", "timestamp", "source", "kind", "syscall", "target", "result", "channel",
                               "risk_tier", "action_taken", "prevented", "prevented_by", "observed_by", "rule_matched")}
        for e in entries if e["verdict"] == EventVerdict.OUTSIDE.value
    ]

    b = initial_boundary
    receipt = {
        "receipt_version": RECEIPT_VERSION,
        "integrity": "hash-chained (SHA-256 over canonical JSON entries; not signed)",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "task_id": task.task_id,
        "condition": condition,
        "requester": requester,
        "agent_id": task.agent_id,
        "prompt_sha256": task.request_hash,
        "created_at": task.created_at,
        "initial_boundary": {
            "version": b.version,
            "files_read": b.files_read,
            "files_write": b.files_write,
            "network": b.network,
            "tools": b.tools,
            "peer_agents": b.peer_agents,
            "enforcement_mode": b.enforcement_mode.value,
            "derived_by": b.derived_by,
            "max_duration_sec": b.max_duration_sec,
        },
        "final_boundary_version": (storage.get_boundary(task.task_id) or b).version,
        "os_identity": os_identity,
        "expansions": expansions,
        "deliveries": deliveries,
        "event_counts": {"total": len(entries), "by_verdict": counts, "by_source": by_source},
        "outside_events": outside,
        "sensor": sensor_status,
        "isolation_level": isolation.get("isolation_level"),
        "isolation": isolation,
        "freeze_events": freeze_events,
        "termination": termination,
        "wall_time_s": round(wall_time_s, 3),
        "events": entries,
        "hash_chain": {"algorithm": "sha256", "genesis": GENESIS_HASH, "count": len(entries), "final_hash": final_hash},
    }
    if extra:
        receipt["extra"] = extra
    return receipt
