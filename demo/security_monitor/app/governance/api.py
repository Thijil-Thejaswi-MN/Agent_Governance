"""Governance Dashboard and Operations REST API (F12).

Provides live task monitoring, boundary inspection, agent inventory querying,
compliance summaries, expansion decision endpoints, and receipt verification.
All data is derived from real stored records in governance.db.
"""
from __future__ import annotations

import json
import hashlib
import hmac
import ipaddress
import os
import secrets
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import Any

import asyncio
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .run_manager import (
    HOST_REQUIREMENT,
    PRESETS,
    RunPrerequisitesError,
    fetch_available_models,
    get_run_manager,
    preview_run_boundary,
)

from .expansion import ExpansionService
from .intake import TaskIntakeService
from .inventory import AgentInventoryService
from .models import EnforcementMode, TaskBoundary, TaskLifecycle, TaskRecord
from .storage import GovernanceStorage

_default_storage = GovernanceStorage()
_default_intake = TaskIntakeService(_default_storage)
_default_inventory = AgentInventoryService(_default_storage)
_default_expansion = ExpansionService(_default_storage)


def get_receipt_dir() -> Path:
    receipts_dir_env = os.getenv("RECEIPTS_DIR")
    if receipts_dir_env:
        return Path(receipts_dir_env)
    return Path.home() / "agent_workspaces" / "receipts"


def get_storage() -> GovernanceStorage:
    env_path = os.environ.get("GOVERNANCE_DB_PATH")
    if env_path and (_default_storage.db_path != env_path):
        return GovernanceStorage(Path(env_path))
    return _default_storage


def get_intake() -> TaskIntakeService:
    storage = get_storage()
    if storage.db_path != _default_storage.db_path:
        return TaskIntakeService(storage)
    return _default_intake


def get_inventory_service() -> AgentInventoryService:
    storage = get_storage()
    if storage.db_path != _default_storage.db_path:
        return AgentInventoryService(storage)
    return _default_inventory


def get_expansion_service() -> ExpansionService:
    storage = get_storage()
    if storage.db_path != _default_storage.db_path:
        return ExpansionService(storage)
    return _default_expansion


TOKEN_NOT_CONFIGURED = (
    "Operator token is not configured on the server. Set GOVERNANCE_OPERATOR_TOKEN environment variable "
    "to enable operator access."
)


def _header_token(authorization: str | None, x_operator_token: str | None) -> str | None:
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        return authorization
    return x_operator_token or None


def verify_operator_token(
    authorization: str | None = Header(None),
    x_operator_token: str | None = Header(None),
) -> str:
    """Verifies the operator token header (a session cookie is never enough here).

    Checked on every mutation: approve / deny / grant, POST /run, /run/{id}/stop,
    POST /auth/session.
    Refuses with 403 if GOVERNANCE_OPERATOR_TOKEN is unset in environment.
    Refuses with 401 if the supplied token does not match.
    """
    expected = os.getenv("GOVERNANCE_OPERATOR_TOKEN")
    if not expected:
        raise HTTPException(status_code=403, detail=TOKEN_NOT_CONFIGURED)

    token = _header_token(authorization, x_operator_token)
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing operator token.",
        )
    return token


# ---------------------------------------------------------------------------
# Operator sessions: an HttpOnly cookie so that EventSource and plain links
# (receipt download) can read without the token in the URL.
# ---------------------------------------------------------------------------

SESSION_COOKIE = "gov_session"
SESSION_TTL_S = 8 * 3600
_sessions: dict[str, float] = {}  # session id -> expiry (time.time())
_sessions_lock = threading.Lock()


def _session_valid(session_id: str | None) -> bool:
    if not session_id:
        return False
    now = time.time()
    with _sessions_lock:
        expiry = _sessions.get(session_id)
        if expiry is None:
            return False
        if expiry <= now:
            del _sessions[session_id]
            return False
        return True


_PUBLIC_ENDPOINTS: set[Any] = set()


def _public(endpoint: Any) -> Any:
    """Marks an endpoint that needs no credentials (it exposes no task data)."""
    _PUBLIC_ENDPOINTS.add(endpoint)
    return endpoint


def require_operator_access(
    request: Request,
    authorization: str | None = Header(None),
    x_operator_token: str | None = Header(None),
) -> None:
    """Router-wide guard: the token header, or (for reads only) a valid session cookie."""
    if request.scope.get("endpoint") in _PUBLIC_ENDPOINTS:
        return
    expected = os.getenv("GOVERNANCE_OPERATOR_TOKEN")
    if not expected:
        raise HTTPException(status_code=403, detail=TOKEN_NOT_CONFIGURED)
    token = _header_token(authorization, x_operator_token)
    if token is not None:
        if hmac.compare_digest(token, expected):
            return
        raise HTTPException(status_code=401, detail="Invalid or missing operator token.")
    if request.method in ("GET", "HEAD") and _session_valid(request.cookies.get(SESSION_COOKIE)):
        return
    raise HTTPException(
        status_code=401,
        detail="Invalid or missing operator token. Sign in required: send the operator token header, "
               "or sign in (POST /api/governance/auth/session).",
    )


def enforce_bind_policy(host: str) -> None:
    """Refuses to serve on a non-loopback address without an operator token."""
    if os.getenv("GOVERNANCE_OPERATOR_TOKEN"):
        return
    h = (host or "").strip().strip("[]")
    if h == "localhost":
        return
    try:
        if ipaddress.ip_address(h).is_loopback:
            return
    except ValueError:
        pass
    raise RuntimeError(
        f"Refusing to start: bind host {host!r} is not loopback and GOVERNANCE_OPERATOR_TOKEN is unset. "
        "Set GOVERNANCE_OPERATOR_TOKEN or bind to 127.0.0.1."
    )


governance_router = APIRouter(dependencies=[Depends(require_operator_access)])


class SubmitTaskRequest(BaseModel):
    request_text: str
    agent_id: str
    workspace_root: str = "demo/data/demo_workspace"
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE


@governance_router.get("/system/status")
@_public
async def get_system_status() -> dict[str, Any]:
    """Returns OS-level sandbox and enforcement status (Landlock ABI, seccomp, cgroups v2, sensor)."""
    landlock_abi = 0
    try:
        from demo.security_monitor.app.governance.os_layer.landlock import get_landlock_abi
        landlock_abi = get_landlock_abi()
    except Exception:
        pass

    seccomp_avail = False
    try:
        from demo.security_monitor.app.governance.os_layer.seccomp_filter import SeccompFilter
        seccomp_avail = SeccompFilter().is_available()
    except Exception:
        pass

    cgroup_v2 = False
    try:
        from demo.security_monitor.app.governance.os_layer.cgroup_ctl import CGROUP_ROOT
        cgroup_v2 = CGROUP_ROOT.exists() and (CGROUP_ROOT / "cgroup.controllers").exists()
    except Exception:
        pass

    sensor_bin = Path(__file__).parent / "os_layer" / "sensor"
    sensor_mode = "ptrace" if sensor_bin.exists() and os.access(sensor_bin, os.X_OK) else "unsupported"

    is_full = (landlock_abi > 0) and seccomp_avail and cgroup_v2
    status_label = "healthy" if is_full else ("partial" if (landlock_abi > 0 or seccomp_avail) else "unsupported")

    return {
        "status": status_label,
        "landlock_abi": landlock_abi,
        "seccomp_available": seccomp_avail,
        "cgroup_v2": cgroup_v2,
        "sensor_mode": sensor_mode,
        "enforcing": is_full,
    }


@governance_router.get("/auth/status")
@_public
async def get_auth_status(request: Request) -> dict[str, Any]:
    """Returns whether operator token authentication is configured and the caller's session is valid."""
    return {
        "operator_token_configured": bool(os.getenv("GOVERNANCE_OPERATOR_TOKEN")),
        "session_active": _session_valid(request.cookies.get(SESSION_COOKIE)),
        "auth_header_supported": ["Authorization: Bearer <token>", "X-Operator-Token: <token>"],
    }


@governance_router.post("/auth/session")
@_public
async def create_auth_session(
    request: Request,
    response: Response,
    _token: str = Depends(verify_operator_token),
) -> dict[str, Any]:
    """Exchanges the operator token (header) for an HttpOnly session cookie valid for 8 h.

    The cookie authorises reads only (including the SSE stream); mutations still
    need the token header.
    """
    session_id = secrets.token_urlsafe(32)
    now = time.time()
    with _sessions_lock:
        for sid in [s for s, exp in _sessions.items() if exp <= now]:
            del _sessions[sid]
        _sessions[session_id] = now + SESSION_TTL_S
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        max_age=SESSION_TTL_S,
        httponly=True,
        samesite="strict",
        path="/api",
        secure=request.url.scheme == "https",
    )
    return {
        "authenticated": True,
        "expires_at": datetime.fromtimestamp(now + SESSION_TTL_S).astimezone().isoformat(),
        "operator": os.getenv("GOVERNANCE_OPERATOR_NAME", "operator"),
    }


@governance_router.delete("/auth/session")
@_public
async def delete_auth_session(request: Request, response: Response) -> dict[str, Any]:
    """Logs out: forgets the caller's session server-side and clears the cookie."""
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        with _sessions_lock:
            _sessions.pop(session_id, None)
    response.delete_cookie(SESSION_COOKIE, path="/api", httponly=True, samesite="strict")
    return {"authenticated": False}


def _extract_os_receipt_events(task_id: str) -> list[dict[str, Any]]:
    """Extracts deduplicated OS-layer entries from the task receipt, defaulting prevented to False."""
    receipts_dir = get_receipt_dir()
    r_file = receipts_dir / f"{task_id}.json"
    if not r_file.exists():
        alt_file = Path(__file__).resolve().parents[3] / "data" / "evaluation_v3" / "checkpoint1" / "receipts" / f"{task_id}.json"
        if alt_file.exists():
            r_file = alt_file
        else:
            return []

    try:
        with open(r_file, encoding="utf-8") as f:
            r_data = json.load(f)
    except Exception:
        return []

    os_events: list[dict[str, Any]] = []
    seen_indices: set[int] = set()
    for o in r_data.get("outside_events", []):
        obs = [str(x).lower() for x in o.get("observed_by", [])]
        prev_by = str(o.get("prevented_by", "")).lower()
        src = str(o.get("source", "")).upper()

        # Take ONLY OS entries (observed_by sensor / prevented_by landlock or seccomp)
        is_os = ("os_sensor" in obs or "sensor" in obs or prev_by in ("landlock", "seccomp") or src == "OS_SENSOR")
        if not is_os:
            continue

        idx = o.get("index")
        if idx is not None:
            if idx in seen_indices:
                continue
            seen_indices.add(idx)

        # Default prevented to False (never True) when the field is missing
        prevented = bool(o.get("prevented", False))

        entry = dict(o)
        entry["prevented"] = prevented
        os_events.append(entry)

    return os_events


def _extract_llm_provider(task: Any, task_id: str) -> str:
    receipts_dir = get_receipt_dir()
    r_file = receipts_dir / f"{task_id}.json"
    if not r_file.exists():
        alt_file = Path(__file__).resolve().parents[3] / "data" / "evaluation_v3" / "checkpoint1" / "receipts" / f"{task_id}.json"
        if alt_file.exists():
            r_file = alt_file
    if r_file.exists():
        try:
            with open(r_file, encoding="utf-8") as f:
                r_data = json.load(f)
            p = r_data.get("extra", {}).get("llm_provider") or r_data.get("llm_provider")
            if p:
                return str(p)
        except Exception:
            pass
    if hasattr(task, "extra") and isinstance(task.extra, dict):
        p = task.extra.get("llm_provider")
        if p:
            return str(p)
    return "unknown"


def _build_unified_task_events(task_id: str, storage_events: list[Any]) -> list[dict[str, Any]]:
    events = [e.model_dump() for e in storage_events]
    os_receipt = _extract_os_receipt_events(task_id)
    existing_targets = {e.get("target") for e in events if e.get("target")}

    for idx, o in enumerate(os_receipt):
        target = o.get("target")
        if target and target in existing_targets:
            continue
        idx_val = o.get("index", idx)
        events.append({
            "event_id": f"evt_os_receipt_{task_id[:8]}_{idx_val:03d}",
            "timestamp": o.get("timestamp", ""),
            "source": o.get("source", "OS_SENSOR"),
            "task_id": task_id,
            "agent_id": "os_process",
            "pid": None,
            "kind": o.get("kind", "file_read"),
            "target": target or "",
            "details": {"syscall": o.get("syscall"), "result": o.get("result")},
            "verdict": "OUTSIDE",
            "risk_tier": o.get("risk_tier", "MEDIUM"),
            "action_taken": o.get("action_taken", "LOG"),
            "prevented": bool(o.get("prevented", False)),
            "rule_matched": o.get("rule_matched", "OS Landlock boundary enforcement"),
            "boundary_version": 1,
            "channel": o.get("channel", "shell"),
            "prevented_by": o.get("prevented_by", "landlock"),
        })
    return events


def _compute_task_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(events)
    inside = sum(1 for e in events if str(e.get("verdict", "")).endswith("INSIDE"))
    prevented = sum(1 for e in events if e.get("prevented"))
    actions_outside = total - inside
    compliance_pct = round((inside / total * 100), 1) if total > 0 else 100.0
    os_denials = sum(
        1 for e in events
        if e.get("prevented") and (
            e.get("source") == "OS_SENSOR"
            or str(e.get("details", {}).get("prevented_by", "")).lower() in ("landlock", "seccomp")
            or str(e.get("prevented_by", "")).lower() in ("landlock", "seccomp")
        )
    )
    return {
        "total_actions": total,
        "actions_inside": inside,
        "actions_outside": actions_outside,
        "prevented_count": prevented,
        "os_denials_count": os_denials,
        "compliance_pct": compliance_pct,
    }


def event_key(e: dict[str, Any]) -> str:
    return f"{e.get('timestamp') or ''}|{e.get('event_id') or ''}"


@governance_router.get("/events")
async def list_all_events(
    since: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    storage = get_storage()
    tasks = storage.list_tasks()
    all_events: list[dict[str, Any]] = []
    seen_ids = set()

    for t in tasks:
        storage_events = storage.get_events_for_task(t.task_id)
        evts = _build_unified_task_events(t.task_id, storage_events)
        for e in evts:
            eid = e.get("event_id")
            if eid and eid not in seen_ids:
                seen_ids.add(eid)
                all_events.append(e)

    if since is not None:
        if since == "":
            newer_events = list(all_events)
        elif "|" in since:
            since_ts, since_id = since.split("|", 1)
            newer_events = [
                e for e in all_events
                if (e.get("timestamp") or "", e.get("event_id") or "") > (since_ts, since_id)
            ]
        else:
            newer_events = [e for e in all_events if (e.get("timestamp") or "") > since]

        # Sort ascending (oldest to newest)
        newer_events.sort(key=lambda x: (x.get("timestamp") or "", x.get("event_id") or ""))

        # When more than limit events are newer than since, return the OLDEST limit of them (ascending)
        # and set the cursor to the last one returned, so polling never skips events.
        limited = newer_events[:limit]
        new_cursor = event_key(limited[-1]) if limited else since

        return {
            "events": limited,
            "cursor": new_cursor,
            "total": len(limited),
        }
    else:
        # Initial poll (since is None): return newest first up to limit
        all_events.sort(key=lambda x: (x.get("timestamp") or "", x.get("event_id") or ""), reverse=True)
        limited = all_events[:limit]
        newest_cursor = event_key(limited[0]) if limited else ""

        return {
            "events": limited,
            "cursor": newest_cursor,
            "total": len(limited),
        }


@governance_router.get("/tasks")
async def list_tasks() -> list[dict[str, Any]]:
    storage = get_storage()
    tasks = storage.list_tasks()
    output = []
    for t in tasks:
        storage_events = storage.get_events_for_task(t.task_id)
        evts = _build_unified_task_events(t.task_id, storage_events)
        summary = _compute_task_summary(evts)
        llm_provider = _extract_llm_provider(t, t.task_id)

        output.append({
            "task_id": t.task_id,
            "request_text": t.request_text,
            "request_hash": t.request_hash,
            "agent_id": t.agent_id,
            "workspace_root": t.workspace_root,
            "status": t.status.value,
            "created_at": t.created_at,
            "started_at": t.started_at,
            "completed_at": t.completed_at,
            "total_actions": summary["total_actions"],
            "actions_inside": summary["actions_inside"],
            "actions_outside": summary["actions_outside"],
            "prevented_count": summary["prevented_count"],
            "os_denials_count": summary["os_denials_count"],
            "compliance_pct": summary["compliance_pct"],
            "llm_provider": llm_provider,
        })
    return output


@governance_router.post("/tasks")
async def submit_task(req: SubmitTaskRequest) -> dict[str, Any]:
    task, boundary = get_intake().submit_task(
        request_text=req.request_text,
        agent_id=req.agent_id,
        workspace_root=req.workspace_root,
        enforcement_mode=req.enforcement_mode,
    )
    return {
        "task": task.model_dump(),
        "boundary": boundary.model_dump(),
    }


@governance_router.get("/tasks/{task_id}")
async def get_task_detail(task_id: str) -> dict[str, Any]:
    storage = get_storage()
    task = storage.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    boundary = storage.get_boundary(task_id)
    storage_events = storage.get_events_for_task(task_id)
    evts = _build_unified_task_events(task_id, storage_events)
    summary = _compute_task_summary(evts)
    llm_provider = _extract_llm_provider(task, task_id)

    task_dict = task.model_dump()
    task_dict["llm_provider"] = llm_provider

    return {
        "task": task_dict,
        "boundary": boundary.model_dump() if boundary else None,
        "summary": summary,
        "llm_provider": llm_provider,
    }


@governance_router.get("/tasks/{task_id}/events")
async def get_task_events(task_id: str) -> list[dict[str, Any]]:
    storage_events = get_storage().get_events_for_task(task_id)
    return _build_unified_task_events(task_id, storage_events)


@governance_router.get("/tasks/{task_id}/receipt")
async def get_task_receipt(task_id: str) -> dict[str, Any]:
    """Retrieves a stored task receipt and recomputes its SHA-256 hash chain (integrity only; not signed)."""
    storage = get_storage()
    task = storage.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    receipts_dir_env = os.getenv("RECEIPTS_DIR")
    if receipts_dir_env:
        receipts_dir = Path(receipts_dir_env)
    else:
        receipts_dir = Path.home() / "agent_workspaces" / "receipts"

    candidate_paths = [
        receipts_dir / f"{task_id}.json",
        Path(__file__).resolve().parents[3] / "data" / "evaluation_v3" / "checkpoint1" / "receipts" / f"{task_id}.json",
    ]

    receipt_data = None
    receipt_file = None
    for cp in candidate_paths:
        if cp.is_file():
            try:
                receipt_data = json.loads(cp.read_text(encoding="utf-8"))
                receipt_file = str(cp)
                break
            except Exception:
                pass

    if receipt_data is None:
        return {
            "task_id": task_id,
            "available": False,
            "verified": False,
            "verification_message": "No stored receipt",
            "receipt": None,
            "receipt_file": None,
        }

    from .receipt import verify_chain
    events = receipt_data.get("events", [])
    ok, final, msg = verify_chain(events)
    verified = ok
    verification_msg = msg
    if ok:
        hc = receipt_data.get("hash_chain", {})
        if hc.get("count") != len(events):
            verified = False
            verification_msg = f"count mismatch: chain says {hc.get('count')}, list has {len(events)}"
        elif hc.get("final_hash") != final:
            verified = False
            verification_msg = "final_hash mismatch"

    file_sha256 = None
    if receipt_file and Path(receipt_file).is_file():
        file_sha256 = hashlib.sha256(Path(receipt_file).read_bytes()).hexdigest()
    final_hash = receipt_data.get("hash_chain", {}).get("final_hash")

    return {
        "task_id": task_id,
        "available": True,
        "receipt": receipt_data,
        "verified": verified,
        "verification_message": verification_msg,
        "receipt_file": receipt_file,
        "file_sha256": file_sha256,
        "final_hash": final_hash,
    }


@governance_router.get("/tasks/{task_id}/receipt/raw")
async def get_task_receipt_raw(task_id: str) -> Response:
    storage = get_storage()
    task = storage.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    receipts_dir_env = os.getenv("RECEIPTS_DIR")
    if receipts_dir_env:
        receipts_dir = Path(receipts_dir_env)
    else:
        receipts_dir = Path.home() / "agent_workspaces" / "receipts"

    candidate_paths = [
        receipts_dir / f"{task_id}.json",
        Path(__file__).resolve().parents[3] / "data" / "evaluation_v3" / "checkpoint1" / "receipts" / f"{task_id}.json",
    ]

    raw_bytes = None
    for cp in candidate_paths:
        if cp.is_file():
            try:
                raw_bytes = cp.read_bytes()
                break
            except Exception:
                pass

    if raw_bytes is None:
        raise HTTPException(status_code=404, detail="No stored receipt file found")

    return Response(
        content=raw_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{task_id}_receipt.json"'},
    )


@governance_router.get("/inventory")
async def get_agent_inventory() -> list[dict[str, Any]]:
    items = get_inventory_service().get_inventory()
    return [i.model_dump() for i in items]


@governance_router.get("/alerts")
async def get_alerts() -> list[dict[str, Any]]:
    return get_inventory_service().get_alerts()


@governance_router.get("/config")
async def get_governance_config() -> dict[str, Any]:
    mode = os.getenv("GOVERNANCE_SYSTEM_MODE", "OBSERVE").upper()
    return {
        "system_mode": mode,
        "default_mode": "OBSERVE",
        "provenance_enabled": get_expansion_service().provenance_enabled,
        "description": "OBSERVE (audits shadow agents) | ENFORCE (blocks untokened/unauthorized callers)",
    }


class ExpansionSubmission(BaseModel):
    task_id: str
    agent_id: str
    resource_type: str
    resource_target: str
    justification: str
    timeout_seconds: float = 5.0
    provenance_enabled: bool = True


class ExpansionDecision(BaseModel):
    decided_by: str = "operator"  # Ignored by server, kept for client compatibility
    reason: str = ""


def _parse_iso_ts(ts: Any) -> datetime | None:
    if not ts:
        return None
    if isinstance(ts, datetime):
        return ts
    try:
        s = str(ts).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _enrich_expansion_dict(e: Any, storage: Any) -> dict[str, Any]:
    d = e.model_dump()
    task = storage.get_task(e.task_id)
    d["task_request_text"] = task.request_text if task else ""
    prov_records = storage.get_provenance_for_task(e.task_id)

    req_dt = _parse_iso_ts(getattr(e, "created_at", None))
    req_created_str = str(getattr(e, "created_at", "") or "")

    target_norm = (getattr(e, "resource_target", "") or "").strip().lower()
    needle_path = target_norm
    needle_name = Path(target_norm).name.lower() if target_norm else ""
    resource_type = getattr(e, "resource_type", "")
    host_part = target_norm.split(":")[0] if ":" in target_norm else target_norm

    prior_reads = []
    for p in prov_records:
        p_dt = _parse_iso_ts(getattr(p, "timestamp", None))
        p_ts_str = str(getattr(p, "timestamp", "") or "")

        # Include only provenance reads with timestamp < the request's created_at
        if req_dt and p_dt:
            if not (p_dt < req_dt):
                continue
        elif not (p_ts_str < req_created_str):
            continue

        p_dict = p.model_dump()
        snippet = (getattr(p, "content_snippet", "") or "").lower()

        # Mark each read linked: true if its snippet contains the requested path or file name
        # (same rule as content_linked escalation)
        is_linked = bool(
            snippet
            and (
                (needle_path and needle_path in snippet)
                or (needle_name and needle_name in snippet)
                or (resource_type == "network" and host_part in snippet)
            )
        )
        p_dict["linked"] = is_linked
        prior_reads.append(p_dict)

    d["prior_untrusted_reads"] = prior_reads
    return d


@governance_router.get("/expansions")
async def list_expansions(
    task_id: str | None = Query(None),
    status: str | None = Query(None),
) -> list[dict[str, Any]]:
    storage = get_storage()
    expansions = storage.list_expansion_requests(task_id=task_id, status=status)
    return [_enrich_expansion_dict(e, storage) for e in expansions]


@governance_router.get("/expansions/{request_id}")
async def get_expansion(request_id: str) -> dict[str, Any]:
    storage = get_storage()
    req = storage.get_expansion_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Expansion request not found")
    return _enrich_expansion_dict(req, storage)


@governance_router.post("/expansions/request")
async def request_expansion(payload: ExpansionSubmission) -> dict[str, Any]:
    try:
        req = get_expansion_service().evaluate_request(
            task_id=payload.task_id,
            agent_id=payload.agent_id,
            resource_type=payload.resource_type,
            resource_target=payload.resource_target,
            justification=payload.justification,
            provenance_enabled=payload.provenance_enabled,
            timeout_seconds=payload.timeout_seconds,
        )
        return req.model_dump()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@governance_router.post("/expansions/request_and_wait")
async def request_expansion_and_wait(payload: ExpansionSubmission) -> dict[str, Any]:
    """Non-blocking async request-and-wait endpoint. Uses asyncio.sleep so other requests are not blocked."""
    try:
        approved, message = await get_expansion_service().async_request_and_wait(
            task_id=payload.task_id,
            agent_id=payload.agent_id,
            resource_type=payload.resource_type,
            resource_target=payload.resource_target,
            justification=payload.justification,
            provenance_enabled=payload.provenance_enabled,
            timeout_seconds=payload.timeout_seconds,
        )
        return {
            "approved": approved,
            "message": message,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@governance_router.post("/expansions/{request_id}/approve")
async def approve_expansion(
    request_id: str,
    payload: ExpansionDecision,
    _token: str = Depends(verify_operator_token),
) -> dict[str, Any]:
    try:
        operator_name = os.getenv("GOVERNANCE_OPERATOR_NAME", "operator")
        approver = f"operator:{operator_name}"
        new_boundary = get_expansion_service().approve_request(
            request_id=request_id,
            approved_by=approver,
            reason=payload.reason,
        )
        req = get_storage().get_expansion_request(request_id)
        return {
            "status": "APPROVED",
            "request": req.model_dump() if req else None,
            "new_boundary": new_boundary.model_dump(),
        }
    except PermissionError as pe:
        # Agent self-approval attempt strictly forbidden
        raise HTTPException(status_code=403, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))


@governance_router.post("/expansions/{request_id}/deny")
async def deny_expansion(
    request_id: str,
    payload: ExpansionDecision,
    _token: str = Depends(verify_operator_token),
) -> dict[str, Any]:
    if not payload.reason or not payload.reason.strip():
        raise HTTPException(status_code=422, detail="A reason is required to deny an expansion request.")
    try:
        operator_name = os.getenv("GOVERNANCE_OPERATOR_NAME", "operator")
        denier = f"operator:{operator_name}"
        get_expansion_service().deny_request(
            request_id=request_id,
            denied_by=denier,
            reason=payload.reason.strip(),
        )
        req = get_storage().get_expansion_request(request_id)
        return {
            "status": "DENIED",
            "request": req.model_dump() if req else None,
        }
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))


class ProactiveGrantRequest(BaseModel):
    granted_by: str = Field(..., description="Operator identifier")
    resource_type: str = Field(..., description="file_read | file_write | network | peer_agent")
    resource_target: str = Field(..., description="Exact resource target (wildcards forbidden)")
    single_use: bool = Field(True, description="Single-use consumption for high-risk resources")


@governance_router.post("/tasks/{task_id}/grant")
async def grant_resource_proactively(
    task_id: str,
    payload: ProactiveGrantRequest,
    _token: str = Depends(verify_operator_token),
) -> dict[str, Any]:
    """Allows a human operator to proactively grant a resource (including HIGH risk) from the dashboard."""
    try:
        new_boundary = get_expansion_service().grant_resource_proactively(
            task_id=task_id,
            granted_by=payload.granted_by,
            resource_type=payload.resource_type,
            resource_target=payload.resource_target,
            single_use=payload.single_use,
        )
        return {
            "status": "APPROVED",
            "task_id": task_id,
            "new_boundary": new_boundary.model_dump(),
        }
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


# ---------------------------------------------------------------------------
# Run Page Endpoints (Interactive UI Task Execution)
# ---------------------------------------------------------------------------

class RunPreviewRequest(BaseModel):
    prompt: str
    preset: str | None = None
    files: dict[str, str] = Field(default_factory=dict)


class RunStartRequest(BaseModel):
    prompt: str
    preset: str | None = None
    model: str = "qwen2.5:7b"
    files: dict[str, str] = Field(default_factory=dict)


@governance_router.get("/run/models")
async def get_run_models() -> dict[str, Any]:
    """Lists available local models from Ollama."""
    return fetch_available_models()


@governance_router.get("/run/presets")
async def get_run_presets() -> list[dict[str, Any]]:
    """Returns task presets with prompt and synthetic input files."""
    return [
        {
            "id": p["id"],
            "name": p["name"],
            "description": p["description"],
            "prompt": p["prompt"],
            "files": p["files"],
        }
        for p in PRESETS.values()
    ]


@governance_router.get("/run/active")
async def get_active_run_status() -> dict[str, Any]:
    """Returns active task status."""
    return get_run_manager().get_active_info()


@governance_router.post("/run/preview")
async def preview_task_run(req: RunPreviewRequest) -> dict[str, Any]:
    """Derives boundary from prompt without starting task execution."""
    try:
        return preview_run_boundary(
            prompt=req.prompt,
            preset_id=req.preset,
            files=req.files,
        )
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Preview derivation failed: {e}")


@governance_router.post("/run")
async def start_governed_task_run(
    req: RunStartRequest,
    _token: str = Depends(verify_operator_token),
) -> dict[str, Any]:
    """Starts a governed agent task inside isolated Condition C evaluation sandbox.

    Requires operator token. Rejects concurrent runs with 409.
    Validates input files (under input/, <= 50 KB, text-only).
    """
    storage = get_storage()
    manager = get_run_manager()

    try:
        task_id = manager.start_run(
            prompt=req.prompt,
            storage=storage,
            preset_id=req.preset,
            model=req.model,
            files=req.files,
        )
        return {
            "task_id": task_id,
            "status": "preparing",
            "message": "Task execution initiated under Condition C sandbox.",
        }
    except ValueError as ve:
        raise HTTPException(status_code=422, detail=str(ve))
    except RunPrerequisitesError as pe:
        raise HTTPException(status_code=503, detail={"message": HOST_REQUIREMENT, "problems": pe.problems})
    except RuntimeError as re:
        raise HTTPException(status_code=409, detail=str(re))


@governance_router.post("/run/{task_id}/stop")
async def stop_governed_task_run(
    task_id: str,
    _token: str = Depends(verify_operator_token),
) -> dict[str, Any]:
    """Stops the active run at any stage (also during sandbox preparation).

    Requires operator token. If the task cgroup exists it is killed; otherwise the
    run is cancelled at its next checkpoint and the agent never starts.
    """
    manager = get_run_manager()
    try:
        result = manager.stop_run(task_id)
        return {
            "task_id": task_id,
            "status": "stopping",
            "killed": result["killed"],
            "cancelled_before_start": result["cancelled_before_start"],
            "message": ("Task cgroup killed by operator." if result["killed"]
                        else "Run cancelled by operator before the agent started."),
        }
    except RuntimeError as re:
        raise HTTPException(status_code=400, detail=str(re))


_TERMINAL_STATUS_STATE = {
    TaskLifecycle.COMPLETED: "completed",
    TaskLifecycle.FAILED: "failed",
    TaskLifecycle.TERMINATED: "stopped",
    TaskLifecycle.EXPIRED: "timed_out",
}


def _sse_end(task_id: str, state: str, reason: str) -> str:
    return "event: end\ndata: " + json.dumps({"task_id": task_id, "state": state, "reason": reason}) + "\n\n"


@governance_router.get("/run/{task_id}/stream")
async def stream_task_steps(task_id: str, request: Request) -> StreamingResponse:
    """Server-Sent Events stream: replays stored steps, then live ones.

    Always ends with an `end` event whose state is completed, stopped, failed or
    timed_out. The run's own terminal event is its 'finished' step; for runs that
    are not executing here (e.g. CLI launches) the stored task status decides.
    Steps are re-read from the database on every wake-up, so the stream does not
    depend on the launcher sharing this storage instance's subscriber queue.
    """
    storage = get_storage()
    queue = storage.subscribe_task_steps(task_id)

    async def event_generator():
        last_step = 0
        try:
            while True:
                for s in storage.get_task_steps(task_id, after_step=last_step):
                    last_step = max(last_step, s.get("step_number", 0))
                    yield f"data: {json.dumps(s)}\n\n"
                    if s.get("kind") == "finished":
                        yield _sse_end(task_id, str(s.get("verdict", "")).lower(), s.get("detail") or "")
                        return

                if get_run_manager().get_active_info().get("task_id") != task_id:
                    t = storage.get_task(task_id)
                    if t is None:
                        yield _sse_end(task_id, "failed", "no such task and no active run")
                        return
                    if t.status in _TERMINAL_STATUS_STATE:
                        # One more read: the launcher may have written its last steps.
                        for s in storage.get_task_steps(task_id, after_step=last_step):
                            last_step = max(last_step, s.get("step_number", 0))
                            yield f"data: {json.dumps(s)}\n\n"
                        yield _sse_end(task_id, _TERMINAL_STATUS_STATE[t.status], f"task status {t.status.value}")
                        return

                if await request.is_disconnected():
                    return
                try:
                    await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            storage.unsubscribe_task_steps(task_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@governance_router.get("/run/{task_id}/steps")
async def get_task_steps_poll(task_id: str, after: int = 0) -> list[dict[str, Any]]:
    """Polling fallback for live task steps."""
    storage = get_storage()
    return storage.get_task_steps(task_id, after_step=after)


@governance_router.get("/run/{task_id}/output")
async def get_task_output_files(task_id: str) -> dict[str, Any]:
    """Reads output files produced in workspace output/ directory."""
    storage = get_storage()
    task = storage.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    ws_root = task.workspace_root
    out_dir = Path(ws_root) / "output"
    files = []
    if out_dir.is_dir():
        for p in sorted(out_dir.glob("**/*")):
            if p.is_file():
                try:
                    rel = str(p.relative_to(Path(ws_root))).replace("\\", "/")
                except ValueError:
                    rel = p.name
                size = p.stat().st_size
                try:
                    raw = p.read_bytes()
                    content = raw[:20000].decode("utf-8", "replace")
                    truncated = len(raw) > 20000
                except Exception:
                    content = "[Binary or unreadable content]"
                    truncated = False
                files.append({
                    "path": rel,
                    "name": p.name,
                    "size": size,
                    "content": content,
                    "truncated": truncated,
                })

    return {
        "task_id": task_id,
        "files": files,
    }
