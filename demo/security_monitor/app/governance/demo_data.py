"""Deterministic demo data seeder for Console v4.

When GOVERNANCE_DEMO_DATA=1 is set, seeds synthetic agents, teams, tasks,
expansion requests, and governance events into a separate SQLite database
(governance_demo.db). Never writes to the real production database.
"""
from __future__ import annotations

import datetime
import hashlib
import random
from pathlib import Path
from typing import Any

from .models import (
    TaskRecord,
    TaskBoundary,
    GovernanceEvent,
    ExpansionRequest,
    ExpansionStatus,
    RiskTier,
    TaskLifecycle,
    EventSource,
    EventVerdict,
    TaskAction,
)
from .storage import GovernanceStorage

TEAMS = [
    "Core Eng",
    "Finance",
    "Platform",
    "Support",
    "Data",
    "Security",
    "Legal",
    "Sales",
    "Operations",
    "Product",
    "Marketing",
    "Research",
]

AGENT_PREFIXES = [
    "report-bot",
    "triage-agent",
    "sync-worker",
    "pipeline-runner",
    "analyst-bot",
    "audit-crawler",
    "builder",
    "reviewer-bot",
    "notifier",
    "scraper",
]


def seed_demo_database(db_path: Path, size: int = 200, seed: int = 42) -> GovernanceStorage:
    """Seed deterministic synthetic demo data into a separate SQLite file.
    
    Sizes:
    - 5: small team, individual agents
    - 200: enterprise team nodes + sortable table
    - 2000: large-scale canvas map + exceptions only
    """
    rng = random.Random(seed)
    storage = GovernanceStorage(db_path)

    # Base timestamp
    base_time = datetime.datetime(2026, 11, 2, 10, 0, 0, tzinfo=datetime.timezone.utc)

    # Determine distribution
    num_agents = size
    num_teams = min(len(TEAMS), max(2, size // 20)) if size > 5 else 2
    active_teams = TEAMS[:num_teams]

    # Generate tasks/agents
    for i in range(num_agents):
        team = active_teams[i % len(active_teams)]
        agent_kind = AGENT_PREFIXES[i % len(AGENT_PREFIXES)]
        agent_id = f"{team.lower().replace(' ', '-')}-{agent_kind}-{i+1}"
        task_id = f"demo_task_{i+1:04d}"

        # Status distribution: mostly active/completed, some stopped/waiting
        status_roll = rng.random()
        if status_roll < 0.65:
            status = TaskLifecycle.ACTIVE
        elif status_roll < 0.85:
            status = TaskLifecycle.COMPLETED
        elif status_roll < 0.95:
            status = TaskLifecycle.FAILED
        else:
            status = TaskLifecycle.PENDING

        created_delta = datetime.timedelta(minutes=rng.randint(1, 1440))
        task_time = (base_time - created_delta).isoformat()

        req_text = f"Analyze and process operational metrics for {team} batch #{i+1}"
        req_hash = hashlib.sha256(req_text.encode()).hexdigest()[:16]

        task = TaskRecord(
            task_id=task_id,
            request_text=req_text,
            request_hash=req_hash,
            agent_id=agent_id,
            workspace_root=f"/home/demo/workspaces/{agent_id}",
            status=status,
            created_at=task_time,
            started_at=task_time if status != TaskLifecycle.PENDING else None,
            completed_at=(base_time - created_delta + datetime.timedelta(seconds=12)).isoformat() if status == TaskLifecycle.COMPLETED else None,
            owner=f"demo_user_{(i % 10) + 1}",
            team=team,
        )
        storage.save_task(task)

        # Boundary
        boundary = TaskBoundary(
            task_id=task_id,
            workspace_root=task.workspace_root,
            files_read=[f"input/data_{team.lower()}_{i%5}.csv"],
            files_write=[f"output/report_{i+1}.json"],
            network=[],
            tools=["read_file", "write_file"],
            peer_agents=[],
        )
        storage.save_boundary(boundary)

        # Generate some events
        if status in (TaskLifecycle.ACTIVE, TaskLifecycle.COMPLETED, TaskLifecycle.FAILED):
            # Allowed event
            storage.record_event(
                GovernanceEvent(
                    event_id=f"demo_ev_ok_{i+1}",
                    timestamp=task_time,
                    source=EventSource.TOOL_BROKER,
                    task_id=task_id,
                    agent_id=agent_id,
                    kind="file_read",
                    target=f"input/data_{team.lower()}_{i%5}.csv",
                    verdict=EventVerdict.INSIDE,
                    risk_tier=RiskTier.LOW,
                    action_taken=TaskAction.ALLOW,
                    prevented=False,
                    rule_matched="boundary match",
                )
            )

            # Stopped event for a subset
            if rng.random() < 0.25 or status == TaskLifecycle.FAILED:
                storage.record_event(
                    GovernanceEvent(
                        event_id=f"demo_ev_stop_{i+1}",
                        timestamp=task_time,
                        source=EventSource.OS_SENSOR,
                        task_id=task_id,
                        agent_id=agent_id,
                        kind="file_read",
                        target="/home/private/credentials.env",
                        verdict=EventVerdict.OUTSIDE,
                        risk_tier=RiskTier.HIGH,
                        action_taken=TaskAction.BLOCK_ACTION,
                        prevented=True,
                        rule_matched="kernel sandbox containment",
                    )
                )

        # Pending expansion request for waiting tasks
        if rng.random() < 0.08:
            exp_id = f"demo_exp_{i+1:04d}"
            req = ExpansionRequest(
                request_id=exp_id,
                task_id=task_id,
                agent_id=agent_id,
                resource_type="file_read",
                resource_target=f"input/extra_{team.lower()}_notes.txt",
                justification=f"Discovered reference table needed for {team} task",
                baseline_risk_tier=RiskTier.LOW,
                effective_risk_tier=RiskTier.MEDIUM if rng.random() < 0.3 else RiskTier.LOW,
                escalated_by_provenance=rng.random() < 0.15,
                status=ExpansionStatus.PENDING,
                created_at=task_time,
            )
            storage.save_expansion_request(req)

    return storage
