"""Governance Dashboard and Operations REST API (F12).

Provides live task monitoring, boundary inspection, agent inventory querying,
compliance summaries, expansion decision endpoints, and receipt verification.
All data is derived from real stored records in governance.db.
"""
from __future__ import annotations

import json
import hmac
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

from .expansion import ExpansionService
from .intake import TaskIntakeService
from .inventory import AgentInventoryService
from .models import EnforcementMode, TaskBoundary, TaskLifecycle, TaskRecord
from .storage import GovernanceStorage

governance_router = APIRouter()
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


def verify_operator_token(
    authorization: str | None = Header(None),
    x_operator_token: str | None = Header(None),
) -> str:
    """Verifies operator authorization token for high-privilege operations.

    Checked on POST /expansions/{id}/approve, /deny, and /tasks/{id}/grant.
    Refuses with 403 if GOVERNANCE_OPERATOR_TOKEN is unset in environment.
    Refuses with 401 if the supplied token does not match.
    """
    expected = os.getenv("GOVERNANCE_OPERATOR_TOKEN")
    if not expected:
        raise HTTPException(
            status_code=403,
            detail="Operator token is not configured on the server. Set GOVERNANCE_OPERATOR_TOKEN environment variable to enable operator decisions.",
        )

    token = None
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        else:
            token = authorization
    elif x_operator_token:
        token = x_operator_token

    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing operator token.",
        )
    return token


class SubmitTaskRequest(BaseModel):
    request_text: str
    agent_id: str
    workspace_root: str = "demo/data/demo_workspace"
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE


@governance_router.get("/system/status")
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
async def get_auth_status() -> dict[str, Any]:
    """Returns whether operator token authentication is configured."""
    return {
        "operator_token_configured": bool(os.getenv("GOVERNANCE_OPERATOR_TOKEN")),
        "auth_header_supported": ["Authorization: Bearer <token>", "X-Operator-Token: <token>"],
    }


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
    return "ollama"


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
    """Retrieves and cryptographically recomputes hash chain verification for a stored task receipt."""
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

    return {
        "task_id": task_id,
        "available": True,
        "receipt": receipt_data,
        "verified": verified,
        "verification_message": verification_msg,
        "receipt_file": receipt_file,
    }


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
    decided_by: str  # Must not be the requesting agent
    reason: str = ""


@governance_router.get("/expansions")
async def list_expansions(
    task_id: str | None = Query(None),
    status: str | None = Query(None),
) -> list[dict[str, Any]]:
    expansions = get_storage().list_expansion_requests(task_id=task_id, status=status)
    return [e.model_dump() for e in expansions]


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
        new_boundary = get_expansion_service().approve_request(
            request_id=request_id,
            approved_by=payload.decided_by,
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
    try:
        get_expansion_service().deny_request(
            request_id=request_id,
            denied_by=payload.decided_by,
            reason=payload.reason,
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
