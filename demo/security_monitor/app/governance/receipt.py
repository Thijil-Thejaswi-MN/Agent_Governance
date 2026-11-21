"""Task Receipt v2 (M6.1; v2 with Ed25519 signing).

A per-task JSON record of what the task was allowed, what it asked for, what it
did and what was prevented. Three integrity layers:

- the event list is *hash-chained*: every event entry includes the hash of the
  previous entry, and the receipt carries the final hash;
- since v1, `hash_chain.document_sha256` is a SHA-256 over the whole record
  (everything except that one field and signature), so approvals, approvers, deliveries, the
  initial boundary, termination and isolation level are covered too. In v0 only the
  event list was covered (independent audit, finding A3).
- since v2, an Ed25519 signature over document_sha256 binds the record to an organisation key.

`verify_receipt` (used by scripts/verify_receipt.py and the API) recomputes all checks and
rejects records that lack the required fields.

Data minimisation: paths, operations and results only. No file contents, no
prompt text (only its SHA-256), secret-looking strings in commands redacted, no
environment variables.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
from typing import Any

from .models import EventSource, EventVerdict, TaskBoundary, TaskRecord
from .redaction import redact_command
from .storage import GovernanceStorage

logger = logging.getLogger(__name__)

RECEIPT_VERSION = "v2"
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
            "attribution_method", "attributed_task_id", "phase", "channel", "tool_call", "verdict", "risk_tier",
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
    org_id: str = "default",
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
            "expires_at": req.expires_at,
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
        "integrity": "hash-chained events, whole-record SHA-256, and Ed25519 signature",
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
            # Grounded model derivation only: which entries were named, inferred or dropped, and why.
            **({"derivation": {k: b.metadata.get(k) for k in (
                "deriver", "model", "fallback_used", "fallback_reason", "named", "inferred", "dropped",
                "template_files_read", "keep_inferred_reads", "raw_output_sha256")}}
               if (b.metadata or {}).get("deriver") else {}),
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
        if extra.get("hosted_model_note"):
            receipt["hosted_model_note"] = extra["hosted_model_note"]
        if extra.get("llm_provider"):
            receipt["llm_provider"] = extra["llm_provider"]
        if extra.get("llm_model"):
            receipt["llm_model"] = extra["llm_model"]
        if extra.get("boundary_source"):
            receipt["boundary_source"] = extra["boundary_source"]
        if extra.get("org_id"):
            org_id = extra["org_id"]
    return seal(receipt, org_id=org_id)


REQUIRED_V0 = ("task_id", "events", "hash_chain")
REQUIRED_V1 = REQUIRED_V0 + ("receipt_version", "event_counts", "initial_boundary", "expansions", "deliveries",
                             "termination", "isolation_level")
REQUIRED_V2 = REQUIRED_V1 + ("signature",)


def document_hash(receipt: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of the whole record except hash_chain.document_sha256 and signature."""
    body = json.loads(json.dumps(receipt, default=str))
    (body.get("hash_chain") or {}).pop("document_sha256", None)
    body.pop("signature", None)
    return hashlib.sha256(canonical(body)).hexdigest()


def seal(receipt: dict[str, Any], org_id: str = "default", sign: bool | None = None) -> dict[str, Any]:
    """Adds the whole-record hash and Ed25519 signature. Returns the record as it will be stored (a JSON round trip,
    so the hash is computed over exactly what is written)."""
    out = json.loads(json.dumps(receipt, default=str))
    eff_org = (
        (out.get("signature") or {}).get("org_id")
        or (out.get("extra") or {}).get("org_id")
        or org_id
        or "default"
    )

    should_sign = (
        sign if sign is not None
        else (out.get("receipt_version") != "v1" and out.get("receipt_version") != "v0")
    )

    if should_sign:
        out["receipt_version"] = "v2"
        out["integrity"] = "hash-chained events, whole-record SHA-256, and Ed25519 signature"
        doc_hash = document_hash(out)
        out.setdefault("hash_chain", {})["document_sha256"] = doc_hash
        try:
            from .signing import sign_document_sha256
            sig = sign_document_sha256(doc_hash, org_id=eff_org)
            out["signature"] = sig
        except Exception as e:
            out["receipt_version"] = "v1"
            out["integrity"] = "hash-chained events and a SHA-256 over the whole record (not signed)"
            out.pop("signature", None)
            if "extra" not in out:
                out["extra"] = {}
            out["extra"]["signing"] = f"unavailable: {e}"
            out["hash_chain"]["document_sha256"] = document_hash(out)
    else:
        doc_hash = document_hash(out)
        out.setdefault("hash_chain", {})["document_sha256"] = doc_hash

    return out


def get_record_start_time(r: dict[str, Any]) -> str | None:
    """Extracts the start time or initial creation timestamp of a record."""
    if not isinstance(r, dict):
        return None
    if r.get("started_at"):
        return str(r["started_at"])
    if r.get("created_at"):
        return str(r["created_at"])
    events = r.get("events")
    if isinstance(events, list) and len(events) > 0 and isinstance(events[0], dict) and events[0].get("timestamp"):
        return str(events[0]["timestamp"])
    if r.get("generated_at"):
        return str(r["generated_at"])
    return None


def _parse_iso_datetime(ts: str | None) -> datetime.datetime | None:
    if not ts or not isinstance(ts, str):
        return None
    try:
        clean = ts.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        pass
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        except Exception:
            pass
    return None


def verify_receipt(r: Any, pubkey: Any = None, signing_enabled_since: str | None = None) -> dict[str, Any]:
    """Checks a stored record. Returns {ok, scope, message, final_hash}.

    scope "signed": chain OK, whole-record hash OK, AND signature valid for known public key (v2).
    scope "whole_record": events chained and the whole-record hash matches (v1).
    scope "events_only": an older v0 record; only the event list could be checked.
    scope "unknown_key": signature present and validly structured, but key is unknown.
    scope "unsigned_after_signing_enabled": no signature, but signing was active when made.
    scope "signing_unavailable": signing failed at write time; shown as a warning.
    """
    def fail(msg: str, final: str | None = None, scope: str | None = None) -> dict[str, Any]:
        return {"ok": False, "scope": scope, "message": msg, "final_hash": final}

    if not isinstance(r, dict):
        return fail("not a record")
    version = r.get("receipt_version", "v0")
    if version == "v0":
        required = REQUIRED_V0
    elif version == "v1":
        required = REQUIRED_V1
    else:
        required = REQUIRED_V2
    missing = [k for k in required if k not in r]
    if missing:
        return fail(f"missing fields: {', '.join(missing)}")
    events = r.get("events")
    hc = r.get("hash_chain")
    if not isinstance(events, list) or not isinstance(hc, dict):
        return fail("events or hash_chain has the wrong shape")
    ok, final, msg = verify_chain(events)
    if not ok:
        return fail(msg, final)
    if hc.get("count") != len(events):
        return fail(f"count mismatch: chain says {hc.get('count')}, list has {len(events)}", final)
    if hc.get("final_hash") != final:
        return fail("final_hash mismatch", final)
    if "event_counts" in r:
        counts: dict[str, int] = {}
        for e in events:
            counts[e.get("verdict")] = counts.get(e.get("verdict"), 0) + 1
        declared = {k: v for k, v in ((r.get("event_counts") or {}).get("by_verdict") or {}).items() if v}
        if declared != counts:
            return fail(f"verdict counts mismatch: declared {declared}, recomputed {counts}", final)
    doc = hc.get("document_sha256")
    if not doc and version != "v0":
        return fail("whole-record hash missing", final)
    if doc:
        if doc != document_hash(r):
            return fail("the record was changed after it was written (whole-record hash does not match)", final)

    # Check signature if present and non-empty
    sig = r.get("signature")
    if sig is not None and isinstance(sig, dict) and (sig.get("value") or sig.get("key_id")):
        if not sig.get("value") or not sig.get("key_id"):
            return fail("signature has the wrong shape", final)

        key_id = sig.get("key_id")
        org_id = sig.get("org_id", "default")

        target_key = None
        if pubkey is not None:
            try:
                from .signing import load_public_key_from_source
                candidate_keys = load_public_key_from_source(pubkey)
                target_key = candidate_keys.get(key_id)
            except Exception:
                pass

        if target_key is None and pubkey is None:
            try:
                from .signing import load_public_keys, parse_public_key
                registered = load_public_keys(org_id)
                for reg in registered:
                    if reg.get("key_id") == key_id:
                        target_key = parse_public_key(reg.get("public_key"))
                        break
            except Exception:
                pass

        if target_key is None:
            return fail(f"unknown key: {key_id}", final, scope="unknown_key")

        from .signing import verify_signature
        if not verify_signature(target_key, sig.get("value", ""), doc):
            return fail("signature does not match", final)

        return {
            "ok": True,
            "scope": "signed",
            "message": f"ok ({len(events)} entries; whole record checked; signature verified key {key_id})",
            "final_hash": final,
        }

    # Record has no valid signature: check for signing_unavailable or unsigned_after_signing_enabled
    extra = r.get("extra") if isinstance(r, dict) else {}
    signing_extra = str((extra or {}).get("signing") or "")
    if "unavailable" in signing_extra.lower():
        reason = signing_extra.split("unavailable:", 1)[1].strip() if "unavailable:" in signing_extra else signing_extra
        return {
            "ok": False,
            "scope": "signing_unavailable",
            "message": f"signing unavailable: {reason}",
            "signature_reason": reason,
            "final_hash": final,
        }

    eff_org = (
        (sig if isinstance(sig, dict) else {}).get("org_id")
        or (extra or {}).get("org_id")
        or "default"
    )
    enabled_since_str: str | None = signing_enabled_since
    if enabled_since_str is None and pubkey is None:
        try:
            from .signing import get_signing_enabled_since
            enabled_since_str = get_signing_enabled_since(eff_org)
        except Exception:
            enabled_since_str = None

    if enabled_since_str is not None:
        start_time_str = get_record_start_time(r)
        if start_time_str:
            start_dt = _parse_iso_datetime(start_time_str)
            enabled_dt = _parse_iso_datetime(enabled_since_str)
            if start_dt and enabled_dt and start_dt >= enabled_dt:
                return fail(
                    "No signature, but signing was enabled when this record was made",
                    final,
                    scope="unsigned_after_signing_enabled",
                )

    if doc:
        return {
            "ok": True,
            "scope": "whole_record",
            "message": f"ok ({len(events)} entries; whole record checked)",
            "final_hash": final,
        }
    return {
        "ok": True,
        "scope": "events_only",
        "message": f"ok ({len(events)} entries; older v0 record: only the event list is chained)",
        "final_hash": final,
    }
