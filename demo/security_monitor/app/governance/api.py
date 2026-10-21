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
from .intake import TaskIntakeService
from .inventory import AgentInventoryService

governance_router = APIRouter()
_storage = GovernanceStorage()
_intake = TaskIntakeService(_storage)
_inventory_service = AgentInventoryService(_storage)


class SubmitTaskRequest(BaseModel):
    request_text: str
    agent_id: str
    workspace_root: str = "demo/data/demo_workspace"
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE


@governance_router.get("/tasks")
async def list_tasks() -> list[dict[str, Any]]:
    tasks = _storage.list_tasks()
    output = []
    for t in tasks:
        events = _storage.get_events_for_task(t.task_id)
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
    task, boundary = _intake.submit_task(
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
    task = _storage.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    boundary = _storage.get_boundary(task_id)
    events = _storage.get_events_for_task(task_id)
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
    events = _storage.get_events_for_task(task_id)
    return [e.model_dump() for e in events]


@governance_router.get("/inventory")
async def get_agent_inventory() -> list[dict[str, Any]]:
    items = _inventory_service.get_inventory()
    return [i.model_dump() for i in items]


@governance_router.get("/alerts")
async def get_alerts() -> list[dict[str, Any]]:
    return _inventory_service.get_alerts()


@governance_router.get("/expansions")
async def list_expansions(task_id: str | None = Query(None)) -> list[dict[str, Any]]:
    with _storage.get_connection() as conn:
        if task_id:
            rows = conn.execute("SELECT * FROM governance_expansions WHERE task_id = ?", (task_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM governance_expansions ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
