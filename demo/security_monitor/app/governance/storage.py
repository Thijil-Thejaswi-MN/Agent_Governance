"""SQLite persistence for the Task-Aware Governance Layer.

Uses a dedicated database file (governance.db, configurable via GOVERNANCE_DB_PATH)
to maintain isolation from the existing A2A security gateway.
"""
from __future__ import annotations

import json
import os
import sqlite3
import asyncio
import datetime
import hashlib
import threading
from pathlib import Path
from typing import Any

from .models import (
    TaskRecord,
    TaskBoundary,
    GovernanceEvent,
    ExpansionRequest,
    ExpansionStatus,
    ProvenanceRecord,
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


class _ClosingConnection:
    """Wrapper around sqlite3.Connection that ensures the connection is closed upon exiting a with block."""
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)

    def __enter__(self) -> sqlite3.Connection:
        self._conn.__enter__()
        return self._conn

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        try:
            return self._conn.__exit__(exc_type, exc_val, exc_tb)
        finally:
            self._conn.close()


class GovernanceStorage:
    """Persistent storage manager for tasks, dynamic boundaries, tokens, and audit events."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path == ":memory:":
            self.db_path = ":memory:"
        else:
            self.db_path = str(db_path or get_default_governance_db_path())
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._step_subscribers: dict[str, list[Any]] = {}
        self._step_lock = threading.Lock()
        self._init_schema()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return _ClosingConnection(conn)  # type: ignore[return-value]

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
                    agent_id TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_target TEXT NOT NULL,
                    justification TEXT NOT NULL,
                    baseline_risk_tier TEXT NOT NULL,
                    effective_risk_tier TEXT NOT NULL,
                    escalated_by_provenance INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    resolved_by TEXT,
                    single_use INTEGER NOT NULL DEFAULT 0,
                    used_count INTEGER NOT NULL DEFAULT 0,
                    timeout_seconds REAL NOT NULL DEFAULT 5.0,
                    reason TEXT
                )
            """)

            # 6. Provenance Events (All untrusted reads during task execution)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS governance_provenance (
                    task_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_target TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    content_len INTEGER NOT NULL,
                    content_snippet TEXT
                )
            """)
            try:
                cursor.execute("ALTER TABLE governance_provenance ADD COLUMN content_snippet TEXT")
            except Exception:
                pass

            try:
                cursor.execute("ALTER TABLE governance_expansions ADD COLUMN reason TEXT")
            except Exception:
                pass

            # 7. Task OS identity (M6): task_id <-> cgroup path read from /proc/<pid>/cgroup
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS task_os_identity (
                    task_id TEXT PRIMARY KEY,
                    cgroup_path TEXT NOT NULL UNIQUE,
                    unit_name TEXT NOT NULL,
                    scope_pid INTEGER NOT NULL,
                    recorded_at TEXT NOT NULL,
                    source TEXT NOT NULL
                )
            """)

            # 8. Task Live Steps (Run page): timeline of execution steps
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS task_steps (
                    step_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    step_number INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    layer TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    detail TEXT,
                    source_label TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_task_steps_task ON task_steps (task_id, step_number)")
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

    def record_events(self, events: list[GovernanceEvent]) -> None:
        """Bulk insert (one transaction) for high-volume OS sensor streams."""
        if not events:
            return
        with self.get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO governance_events (
                    event_id, timestamp, source, task_id, agent_id, pid,
                    kind, target, verdict, risk_tier, action_taken, prevented,
                    rule_matched, boundary_version, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO NOTHING
                """,
                [
                    (
                        e.event_id, e.timestamp, e.source.value, e.task_id, e.agent_id, e.pid,
                        e.kind, e.target, e.verdict.value, e.risk_tier.value, e.action_taken.value,
                        1 if e.prevented else 0, e.rule_matched, e.boundary_version, json.dumps(e.details),
                    )
                    for e in events
                ],
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

    # --- Task OS Identity Methods (M6) ---
    def save_task_cgroup(self, task_id: str, cgroup_path: str, unit_name: str, scope_pid: int, source: str = "proc_pid_cgroup") -> None:
        import datetime
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                "INSERT INTO task_os_identity (task_id, cgroup_path, unit_name, scope_pid, recorded_at, source) VALUES (?, ?, ?, ?, ?, ?)",
                (task_id, cgroup_path, unit_name, scope_pid, now_utc, source),
            )
            conn.commit()

    def lookup_task_by_cgroup(self, cgroup_path: str) -> str | None:
        with self.get_connection() as conn:
            row = conn.execute("SELECT task_id FROM task_os_identity WHERE cgroup_path = ?", (cgroup_path,)).fetchone()
            return row["task_id"] if row else None

    def get_task_cgroup(self, task_id: str) -> dict[str, Any] | None:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM task_os_identity WHERE task_id = ?", (task_id,)).fetchone()
            return dict(row) if row else None

    def list_task_cgroups(self) -> dict[str, str]:
        """Returns {cgroup_path: task_id}."""
        with self.get_connection() as conn:
            rows = conn.execute("SELECT task_id, cgroup_path FROM task_os_identity").fetchall()
            return {r["cgroup_path"]: r["task_id"] for r in rows}

    # --- Provenance Tracking Methods ---
    def record_provenance(self, record: ProvenanceRecord) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO governance_provenance (
                    task_id, timestamp, source_type, source_target, content_hash, content_len, content_snippet
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.task_id,
                    record.timestamp,
                    record.source_type,
                    record.source_target,
                    record.content_hash,
                    record.content_len,
                    record.content_snippet,
                ),
            )
            conn.commit()

    def get_provenance_for_task(self, task_id: str) -> list[ProvenanceRecord]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM governance_provenance WHERE task_id = ? ORDER BY timestamp ASC",
                (task_id,),
            ).fetchall()
            return [
                ProvenanceRecord(
                    task_id=r["task_id"],
                    timestamp=r["timestamp"],
                    source_type=r["source_type"],
                    source_target=r["source_target"],
                    content_hash=r["content_hash"],
                    content_len=r["content_len"],
                    content_snippet=r["content_snippet"] if "content_snippet" in r.keys() else None,
                )
                for r in rows
            ]

    # --- Expansion Request Methods ---
    def save_expansion_request(self, req: ExpansionRequest) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO governance_expansions (
                    request_id, task_id, agent_id, resource_type, resource_target,
                    justification, baseline_risk_tier, effective_risk_tier,
                    escalated_by_provenance, status, created_at, resolved_at,
                    resolved_by, single_use, used_count, timeout_seconds, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                    status=excluded.status,
                    resolved_at=coalesce(excluded.resolved_at, governance_expansions.resolved_at),
                    resolved_by=coalesce(excluded.resolved_by, governance_expansions.resolved_by),
                    used_count=excluded.used_count,
                    reason=coalesce(excluded.reason, governance_expansions.reason)
                """,
                (
                    req.request_id,
                    req.task_id,
                    req.agent_id,
                    req.resource_type,
                    req.resource_target,
                    req.justification,
                    req.baseline_risk_tier.value,
                    req.effective_risk_tier.value,
                    1 if req.escalated_by_provenance else 0,
                    req.status.value,
                    req.created_at,
                    req.resolved_at,
                    req.resolved_by,
                    1 if req.single_use else 0,
                    req.used_count,
                    req.timeout_seconds,
                    req.reason,
                ),
            )
            conn.commit()

    def get_expansion_request(self, request_id: str) -> ExpansionRequest | None:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM governance_expansions WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_expansion(row)

    def list_expansion_requests(
        self, task_id: str | None = None, status: str | None = None
    ) -> list[ExpansionRequest]:
        query = "SELECT * FROM governance_expansions WHERE 1=1"
        params: list[Any] = []
        if task_id:
            query += " AND task_id = ?"
            params.append(task_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_expansion(r) for r in rows]

    def update_expansion_status(
        self, request_id: str, status: ExpansionStatus, resolved_by: str, resolved_at: str
    ) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE governance_expansions SET
                    status = ?, resolved_by = ?, resolved_at = ?
                WHERE request_id = ?
                """,
                (status.value, resolved_by, resolved_at, request_id),
            )
            conn.commit()

    def increment_expansion_usage(self, request_id: str) -> int:
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE governance_expansions SET used_count = used_count + 1 WHERE request_id = ?",
                (request_id,),
            )
            conn.commit()
            row = conn.execute(
                "SELECT used_count FROM governance_expansions WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            return int(row["used_count"]) if row else 1

    def _row_to_expansion(self, r: sqlite3.Row) -> ExpansionRequest:
        return ExpansionRequest(
            request_id=r["request_id"],
            task_id=r["task_id"],
            agent_id=r["agent_id"],
            resource_type=r["resource_type"],
            resource_target=r["resource_target"],
            justification=r["justification"],
            baseline_risk_tier=RiskTier(r["baseline_risk_tier"]),
            effective_risk_tier=RiskTier(r["effective_risk_tier"]),
            escalated_by_provenance=bool(r["escalated_by_provenance"]),
            status=ExpansionStatus(r["status"]),
            created_at=r["created_at"],
            resolved_at=r["resolved_at"],
            resolved_by=r["resolved_by"],
            single_use=bool(r["single_use"]),
            used_count=r["used_count"],
            timeout_seconds=float(r["timeout_seconds"]),
            reason=r["reason"] if "reason" in r.keys() else None,
        )


    # --- Task Live Steps Methods (Run Page) ---
    def record_task_step(
        self,
        task_id: str,
        kind: str,
        layer: str,
        verdict: str,
        summary: str,
        detail: str = "",
        source_label: str = "",
        step_number: int | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if not source_label:
            if kind == "model":
                source_label = "model output (untrusted)"
            elif kind == "sensor" and verdict in ("ALLOW", "INSIDE"):
                source_label = "observed by OS sensor"
            elif summary.lower().startswith("command output") or "in-sandbox shim" in summary.lower():
                source_label = "reported by the in-sandbox shim"
            else:
                source_label = "enforced"

        # Truncate detail to <= 2 KB (2048 chars)
        if detail and len(detail) > 2048:
            detail = detail[:2045] + "..."

        with self.get_connection() as conn:
            if step_number is None:
                row = conn.execute(
                    "SELECT COALESCE(MAX(step_number), 0) + 1 FROM task_steps WHERE task_id = ?",
                    (task_id,),
                ).fetchone()
                step_number = int(row[0]) if row else 1

            conn.execute(
                """
                INSERT INTO task_steps (
                    task_id, step_number, timestamp, kind, layer, verdict, summary, detail, source_label
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    step_number,
                    timestamp,
                    kind,
                    layer,
                    verdict,
                    summary,
                    detail or "",
                    source_label,
                ),
            )
            conn.commit()

        step_dict = {
            "task_id": task_id,
            "step_number": step_number,
            "timestamp": timestamp,
            "kind": kind,
            "layer": layer,
            "verdict": verdict,
            "summary": summary,
            "detail": detail or "",
            "source_label": source_label,
        }
        self._dispatch_step(task_id, step_dict)
        return step_dict

    def _dispatch_step(self, task_id: str, step_dict: dict[str, Any]) -> None:
        with self._step_lock:
            queues = list(self._step_subscribers.get(task_id, []))
        for q in queues:
            try:
                loop = getattr(q, "_loop", None)
                if loop and loop.is_running():
                    loop.call_soon_threadsafe(q.put_nowait, step_dict)
                else:
                    q.put_nowait(step_dict)
            except Exception:
                pass

    def subscribe_task_steps(self, task_id: str) -> Any:
        import asyncio
        q = asyncio.Queue()
        with self._step_lock:
            if task_id not in self._step_subscribers:
                self._step_subscribers[task_id] = []
            self._step_subscribers[task_id].append(q)
        return q

    def unsubscribe_task_steps(self, task_id: str, q: Any) -> None:
        with self._step_lock:
            if task_id in self._step_subscribers:
                if q in self._step_subscribers[task_id]:
                    self._step_subscribers[task_id].remove(q)
                if not self._step_subscribers[task_id]:
                    del self._step_subscribers[task_id]

    def get_task_steps(self, task_id: str, after_step: int = 0) -> list[dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT step_number, timestamp, kind, layer, verdict, summary, detail, source_label
                FROM task_steps
                WHERE task_id = ? AND step_number > ?
                ORDER BY step_number ASC
                """,
                (task_id, after_step),
            ).fetchall()
            return [
                {
                    "task_id": task_id,
                    "step_number": r["step_number"],
                    "timestamp": r["timestamp"],
                    "kind": r["kind"],
                    "layer": r["layer"],
                    "verdict": r["verdict"],
                    "summary": r["summary"],
                    "detail": r["detail"] or "",
                    "source_label": r["source_label"] or "",
                }
                for r in rows
            ]
