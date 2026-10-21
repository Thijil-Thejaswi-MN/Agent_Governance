"""Governance Dashboard and Operations REST API (F12).

Provides live task monitoring, boundary inspection, agent inventory querying,
compliance summaries, and expansion decision endpoints.
All data is derived from real stored records in governance.db.
"""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .models import EnforcementMode, TaskLifecycle, TaskBoundary, TaskRecord
from .storage import GovernanceStorage
from pathlib import Path
import os
from .intake import TaskIntakeService
from .inventory import AgentInventoryService
from .expansion import ExpansionService

governance_router = APIRouter()
_default_storage = GovernanceStorage()
_default_intake = TaskIntakeService(_default_storage)
_default_inventory = AgentInventoryService(_default_storage)
_default_expansion = ExpansionService(_default_storage)


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


class SubmitTaskRequest(BaseModel):
    request_text: str
    agent_id: str
    workspace_root: str = "demo/data/demo_workspace"
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE


@governance_router.get("/tasks")
async def list_tasks() -> list[dict[str, Any]]:
    storage = get_storage()
    tasks = storage.list_tasks()
    output = []
    for t in tasks:
        events = storage.get_events_for_task(t.task_id)
        total = len(events)
        inside = sum(1 for e in events if e.verdict == "INSIDE")
        prevented = sum(1 for e in events if e.prevented)
        compliance_pct = round((inside / total * 100), 1) if total > 0 else 100.0

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
            "total_actions": total,
            "actions_inside": inside,
            "actions_outside": total - inside,
            "prevented_count": prevented,
            "compliance_pct": compliance_pct,
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
    events = storage.get_events_for_task(task_id)
    total = len(events)
    inside = sum(1 for e in events if e.verdict == "INSIDE")
    prevented = sum(1 for e in events if e.prevented)
    compliance_pct = round((inside / total * 100), 1) if total > 0 else 100.0

    return {
        "task": task.model_dump(),
        "boundary": boundary.model_dump() if boundary else None,
        "summary": {
            "total_actions": total,
            "actions_inside": inside,
            "actions_outside": total - inside,
            "prevented_count": prevented,
            "compliance_pct": compliance_pct,
        },
    }


@governance_router.get("/tasks/{task_id}/events")
async def get_task_events(task_id: str) -> list[dict[str, Any]]:
    events = get_storage().get_events_for_task(task_id)
    return [e.model_dump() for e in events]


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
async def approve_expansion(request_id: str, payload: ExpansionDecision) -> dict[str, Any]:
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
async def deny_expansion(request_id: str, payload: ExpansionDecision) -> dict[str, Any]:
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
