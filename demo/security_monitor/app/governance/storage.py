"""SQLite persistence for the Task-Aware Governance Layer.

Uses a dedicated database file (governance.db, configurable via GOVERNANCE_DB_PATH)
to maintain isolation from the existing A2A security gateway.
"""
from __future__ import annotations

import json
import os
import sqlite3
import hashlib
from pathlib import Path
from typing import Any

from .models import (
    TaskRecord,
    TaskBoundary,
    GovernanceEvent,
    ExpansionRequest,
    TaskLifecycle,
    EnforcementMode,
    EventSource,
    EventVerdict,
    RiskTier,
    TaskAction,
)


def get_default_governance_db_path() -> Path:
    env_path = os.environ.get("GOVERNANCE_DB_PATH")
    if env_path:
        return Path(env_path)
    p = Path(__file__).resolve()
    for parent in p.parents:
        if (parent / "demo" / "data").is_dir():
            return parent / "demo" / "data" / "governance.db"
    return Path.cwd() / "governance.db"


class GovernanceStorage:
    """Persistent storage manager for tasks, dynamic boundaries, tokens, and audit events."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path == ":memory:":
            self.db_path = ":memory:"
        else:
            self.db_path = str(db_path or get_default_governance_db_path())
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # 1. Tasks
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS governance_tasks (
                    task_id TEXT PRIMARY KEY,
                    request_text TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    workspace_root TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    current_boundary_version INTEGER DEFAULT 1,
                    pid INTEGER
                )
            """)

            # 2. Task Boundaries (versioned contracts)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS governance_boundaries (
                    task_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    workspace_root TEXT NOT NULL,
                    boundary_json TEXT NOT NULL,
                    enforcement_mode TEXT NOT NULL,
                    derived_by TEXT NOT NULL,
                    prompt_hash TEXT,
                    model_name TEXT,
                    parent_expansion_id TEXT,
                    created_at TEXT DEFAULT (datetime('now', 'utc')),
                    PRIMARY KEY (task_id, version)
                )
            """)

            # 3. Governance Tokens (Scoped per-task credentials)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS governance_tokens (
                    token_hash TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    created_at TEXT DEFAULT (datetime('now', 'utc')),
                    revoked_at TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)

            # 4. Normalized Governance Audit Events
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS governance_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    task_id TEXT,
                    agent_id TEXT NOT NULL,
                    pid INTEGER,
                    kind TEXT NOT NULL,
                    target TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_tier TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    prevented INTEGER NOT NULL,
                    rule_matched TEXT NOT NULL,
                    boundary_version INTEGER,
                    details_json TEXT
                )
            """)

            # 5. Dynamic Expansion Requests
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS governance_expansions (
                    request_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    requester TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    justification TEXT NOT NULL,
                    risk_tier TEXT NOT NULL,
                    status TEXT NOT NULL,
                    decision_by TEXT,
                    decided_at TEXT,
                    provenance_events_json TEXT,
                    created_at TEXT DEFAULT (datetime('now', 'utc'))
                )
            """)
            conn.commit()

    # --- Task Methods ---
    def save_task(self, task: TaskRecord) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO governance_tasks (
                    task_id, request_text, request_hash, agent_id, workspace_root,
                    status, created_at, started_at, completed_at, current_boundary_version, pid
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    status=excluded.status,
                    started_at=coalesce(excluded.started_at, governance_tasks.started_at),
                    completed_at=coalesce(excluded.completed_at, governance_tasks.completed_at),
                    current_boundary_version=excluded.current_boundary_version,
                    pid=coalesce(excluded.pid, governance_tasks.pid)
                """,
                (
                    task.task_id,
                    task.request_text,
                    task.request_hash,
                    task.agent_id,
                    task.workspace_root,
                    task.status.value,
                    task.created_at,
                    task.started_at,
                    task.completed_at,
                    task.current_boundary_version,
                    task.pid,
                ),
            )
            conn.commit()

    def get_task(self, task_id: str) -> TaskRecord | None:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM governance_tasks WHERE task_id = ?", (task_id,)).fetchone()
            if not row:
                return None
            return TaskRecord(
                task_id=row["task_id"],
                request_text=row["request_text"],
                request_hash=row["request_hash"],
                agent_id=row["agent_id"],
                workspace_root=row["workspace_root"],
                status=TaskLifecycle(row["status"]),
                created_at=row["created_at"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                current_boundary_version=row["current_boundary_version"],
                pid=row["pid"],
            )

    def list_tasks(self) -> list[TaskRecord]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM governance_tasks ORDER BY created_at DESC").fetchall()
            return [
                TaskRecord(
                    task_id=r["task_id"],
                    request_text=r["request_text"],
                    request_hash=r["request_hash"],
                    agent_id=r["agent_id"],
                    workspace_root=r["workspace_root"],
                    status=TaskLifecycle(r["status"]),
                    created_at=r["created_at"],
                    started_at=r["started_at"],
                    completed_at=r["completed_at"],
                    current_boundary_version=r["current_boundary_version"],
                    pid=r["pid"],
                )
                for r in rows
            ]

    # --- Boundary Methods ---
    def save_boundary(self, boundary: TaskBoundary) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO governance_boundaries (
                    task_id, version, workspace_root, boundary_json, enforcement_mode,
                    derived_by, prompt_hash, model_name, parent_expansion_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id, version) DO UPDATE SET
                    boundary_json=excluded.boundary_json,
                    enforcement_mode=excluded.enforcement_mode
                """,
                (
                    boundary.task_id,
                    boundary.version,
                    boundary.workspace_root,
                    boundary.model_dump_json(),
                    boundary.enforcement_mode.value,
                    boundary.derived_by,
                    boundary.prompt_hash,
                    boundary.model_name,
                    boundary.parent_expansion_id,
                ),
            )
            conn.commit()

    def get_boundary(self, task_id: str, version: int | None = None) -> TaskBoundary | None:
        with self.get_connection() as conn:
            if version is not None:
                row = conn.execute(
                    "SELECT boundary_json FROM governance_boundaries WHERE task_id = ? AND version = ?",
                    (task_id, version),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT boundary_json FROM governance_boundaries WHERE task_id = ? ORDER BY version DESC LIMIT 1",
                    (task_id,),
                ).fetchone()
            if not row:
                return None
            return TaskBoundary.model_validate_json(row["boundary_json"])

    # --- Token Management (F6 Token-Based Task Attribution) ---
    def save_token(self, token: str, task_id: str, agent_id: str) -> None:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO governance_tokens (token_hash, task_id, agent_id, is_active)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(token_hash) DO NOTHING
                """,
                (token_hash, task_id, agent_id),
            )
            conn.commit()

    def lookup_task_by_token(self, token: str) -> tuple[str, str] | None:
        """Returns (task_id, agent_id) if token is valid and active, else None."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT task_id, agent_id FROM governance_tokens WHERE token_hash = ? AND is_active = 1",
                (token_hash,),
            ).fetchone()
            if not row:
                return None
            return row["task_id"], row["agent_id"]

    def revoke_token(self, token: str) -> None:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE governance_tokens SET is_active = 0, revoked_at = datetime('now', 'utc') WHERE token_hash = ?",
                (token_hash,),
            )
            conn.commit()

    # --- Event Recording ---
    def record_event(self, event: GovernanceEvent) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO governance_events (
                    event_id, timestamp, source, task_id, agent_id, pid,
                    kind, target, verdict, risk_tier, action_taken, prevented,
                    rule_matched, boundary_version, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO NOTHING
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.source.value,
                    event.task_id,
                    event.agent_id,
                    event.pid,
                    event.kind,
                    event.target,
                    event.verdict.value,
                    event.risk_tier.value,
                    event.action_taken.value,
                    1 if event.prevented else 0,
                    event.rule_matched,
                    event.boundary_version,
                    json.dumps(event.details),
                ),
            )
            conn.commit()

    def get_events_for_task(self, task_id: str) -> list[GovernanceEvent]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM governance_events WHERE task_id = ? ORDER BY timestamp ASC",
                (task_id,),
            ).fetchall()
            return [
                GovernanceEvent(
                    event_id=r["event_id"],
                    timestamp=r["timestamp"],
                    source=EventSource(r["source"]),
                    task_id=r["task_id"],
                    agent_id=r["agent_id"],
                    pid=r["pid"],
                    kind=r["kind"],
                    target=r["target"],
                    verdict=EventVerdict(r["verdict"]),
                    risk_tier=RiskTier(r["risk_tier"]),
                    action_taken=TaskAction(r["action_taken"]),
                    prevented=bool(r["prevented"]),
                    rule_matched=r["rule_matched"],
                    boundary_version=r["boundary_version"],
                    details=json.loads(r["details_json"] or "{}"),
                )
                for r in rows
            ]
