"""Agent Inventory and Discovery (F10).

Tracks registered and discovered agents across the organization, classifying each
as GOVERNED (bound to an active task) or UNGOVERNED / SHADOW (acting with no assigned task).
Calculates live compliance metrics and alerts from real stored events.
"""
from __future__ import annotations

import datetime
from typing import Any
from pydantic import BaseModel, Field

from .models import (
    EventSource,
    EventVerdict,
    TaskAction,
    TaskLifecycle,
)
from .storage import GovernanceStorage


class AgentInventoryItem(BaseModel):
    agent_id: str
    name: str
    owner: str = "Engineering"
    classification: str  # "GOVERNED" or "SHADOW"
    status: str          # "ACTIVE", "IDLE", "QUARANTINED"
    current_task_id: str | None = None
    boundary_version: int | None = None
    actions_inside: int = 0
    actions_outside: int = 0
    violations_count: int = 0
    last_seen_utc: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentInventoryService:
    """Maintains organizational inventory of governed and discovered agents."""

    def __init__(self, storage: GovernanceStorage) -> None:
        self.storage = storage

    def get_inventory(self) -> list[AgentInventoryItem]:
        """
        Builds the live agent inventory dynamically from:
        1. Registered tasks in governance_tasks
        2. Audit events in governance_events
        3. Egress proxy and A2A discovery logs
        """
        inventory: dict[str, AgentInventoryItem] = {}

        # 1. Inspect all tasks
        tasks = self.storage.list_tasks()
        active_task_by_agent: dict[str, tuple[str, int]] = {}
        for t in tasks:
            if t.status == TaskLifecycle.ACTIVE:
                active_task_by_agent[t.agent_id] = (t.task_id, t.current_boundary_version)

            if t.agent_id not in inventory:
                inventory[t.agent_id] = AgentInventoryItem(
                    agent_id=t.agent_id,
                    name=t.agent_id.replace("_", " ").title(),
                    classification="GOVERNED",
                    status="ACTIVE" if t.status == TaskLifecycle.ACTIVE else "IDLE",
                    current_task_id=t.task_id if t.status == TaskLifecycle.ACTIVE else None,
                    boundary_version=t.current_boundary_version if t.status == TaskLifecycle.ACTIVE else None,
                    last_seen_utc=t.started_at or t.created_at,
                )

        # 2. Inspect all recorded events to compute compliance and discover shadow agents
        with self.storage.get_connection() as conn:
            rows = conn.execute("SELECT * FROM governance_events ORDER BY timestamp ASC").fetchall()

            for r in rows:
                agent_id = r["agent_id"]
                if not agent_id or agent_id == "UNATTRIBUTED":
                    continue

                ts = r["timestamp"]
                verdict = r["verdict"]
                action = r["action_taken"]
                rule = r["rule_matched"]
                task_id = r["task_id"]

                # If agent was seen without a task or not yet in inventory, classify as SHADOW
                if agent_id not in inventory:
                    is_shadow = (task_id is None)
                    inventory[agent_id] = AgentInventoryItem(
                        agent_id=agent_id,
                        name=f"Discovered Agent ({agent_id})",
                        classification="SHADOW" if is_shadow else "GOVERNED",
                        status="ACTIVE",
                        current_task_id=task_id,
                        last_seen_utc=ts,
                    )

                item = inventory[agent_id]
                item.last_seen_utc = ts

                if verdict == EventVerdict.INSIDE.value:
                    item.actions_inside += 1
                else:
                    item.actions_outside += 1
                    if action in (TaskAction.BLOCK_ACTION.value, TaskAction.ALERT.value, TaskAction.KILL_TASK.value, TaskAction.PAUSE_TASK.value):
                        item.violations_count += 1

                # If agent triggered a quarantine or kill action
                if action == TaskAction.QUARANTINE_AGENT.value:
                    item.status = "QUARANTINED"

        # Update active task references
        for agent_id, item in inventory.items():
            if agent_id in active_task_by_agent:
                tid, bver = active_task_by_agent[agent_id]
                item.current_task_id = tid
                item.boundary_version = bver
                item.status = "ACTIVE"
                item.classification = "GOVERNED"

        return sorted(list(inventory.values()), key=lambda x: (x.classification != "SHADOW", x.agent_id))

    def get_alerts(self) -> list[dict[str, Any]]:
        """Returns live security and compliance alerts from stored events."""
        alerts = []
        with self.storage.get_connection() as conn:
            # Query violations and shadow detections
            rows = conn.execute(
                """
                SELECT * FROM governance_events 
                WHERE action_taken IN ('BLOCK_ACTION', 'ALERT', 'PAUSE_TASK', 'KILL_TASK', 'QUARANTINE_AGENT')
                ORDER BY timestamp DESC LIMIT 50
                """
            ).fetchall()

            for r in rows:
                alerts.append({
                    "event_id": r["event_id"],
                    "timestamp": r["timestamp"],
                    "source": r["source"],
                    "task_id": r["task_id"],
                    "agent_id": r["agent_id"],
                    "target": r["target"],
                    "severity": r["risk_tier"],
                    "action_taken": r["action_taken"],
                    "rule_matched": r["rule_matched"],
                    "is_shadow": (r["task_id"] is None),
                })
        return alerts
