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
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable

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
from .discovery.models import (
    DiscoveredAgent,
    DiscoveryScanRecord,
    EvidenceItem,
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


logger = logging.getLogger(__name__)


class GovernanceStorage:
    """Persistent storage manager for tasks, dynamic boundaries, tokens, and audit events."""

    _instances: dict[str, GovernanceStorage] = {}
    _instance_lock = threading.Lock()

    def __new__(cls, db_path: str | Path | None = None) -> GovernanceStorage:
        if db_path == ":memory:":
            return super().__new__(cls)
        norm_path = str(Path(db_path or get_default_governance_db_path()).resolve())
        with cls._instance_lock:
            if norm_path in cls._instances:
                inst = cls._instances[norm_path]
                if getattr(inst, "_writer_thread", None) and inst._writer_thread.is_alive():
                    return inst
            inst = super().__new__(cls)
            cls._instances[norm_path] = inst
            return inst

    def __init__(self, db_path: str | Path | None = None) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        if db_path == ":memory:":
            self.db_path = ":memory:"
        else:
            self.db_path = str(Path(db_path or get_default_governance_db_path()).resolve())
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._step_subscribers: dict[str, list[Any]] = {}
        self._step_lock = threading.Lock()
        self._boundary_change_callbacks: list[Callable[[str | None], None]] = []
        self._task_queues: dict[str, list[tuple[str, Any]]] = {}
        self._step_counters: dict[str, int] = {}
        self._writer_lock = threading.Lock()
        self._writer_cond = threading.Condition(self._writer_lock)
        self._flush_done_cond = threading.Condition(self._writer_lock)
        self._force_flush = False
        # Items the writer has taken off the queues but not yet committed. flush() waits for
        # these too, so a read right after flush() sees every write queued before it.
        self._inflight = 0
        self.dropped_writes = 0
        self._writer_stop = threading.Event()
        self._writer_thread = threading.Thread(target=self._writer_loop, daemon=True, name="gov-batch-writer")
        self._writer_thread.start()
        self._init_schema()

    def register_boundary_change_callback(self, cb: Callable[[str | None], None]) -> None:
        self._boundary_change_callbacks.append(cb)

    def _notify_boundary_change(self, task_id: str | None = None) -> None:
        for cb in self._boundary_change_callbacks:
            try:
                cb(task_id)
            except Exception:
                pass

    def _get_raw_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=60.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout=60000;")
        except Exception:
            pass
        return _ClosingConnection(conn)  # type: ignore[return-value]

    def get_connection(self) -> sqlite3.Connection:
        if hasattr(self, "_task_queues"):
            self.flush()
        return self._get_raw_connection()

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
                    pid INTEGER,
                    owner TEXT,
                    team TEXT,
                    condition TEXT,
                    requested_by TEXT,
                    model TEXT
                )
            """)

            # 2. Task Boundaries (versioned contracts)
            for _col in ("condition", "requested_by", "model", "org"):
                try:
                    cursor.execute(f"ALTER TABLE governance_tasks ADD COLUMN {_col} TEXT")
                except Exception:
                    pass
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
            try:
                cursor.execute("ALTER TABLE governance_expansions ADD COLUMN expires_at TEXT")
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
            # 9. Standing rules (Console v4): saved so they survive a restart
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS governance_standing_rules (
                    rule_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    rule_json TEXT NOT NULL
                )
            """)

            # 10. Discovered Agents (Tenant-aware agent inventory)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS discovered_agents (
                    org_id TEXT NOT NULL DEFAULT 'default',
                    discovery_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    name TEXT NOT NULL,
                    frameworks_json TEXT NOT NULL DEFAULT '[]',
                    llm_endpoints_json TEXT NOT NULL DEFAULT '[]',
                    key_names_json TEXT NOT NULL DEFAULT '[]',
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'shadow',
                    owner TEXT,
                    purpose TEXT,
                    linked_agent_id TEXT,
                    retired_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (org_id, discovery_id)
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovered_agents_org_status ON discovered_agents (org_id, status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovered_agents_org_kind ON discovered_agents (org_id, kind)")

            # 11. Discovery Scans
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS discovery_scans (
                    scan_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL DEFAULT 'default',
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    findings_count INTEGER DEFAULT 0,
                    unreadable_count INTEGER DEFAULT 0,
                    details_json TEXT NOT NULL DEFAULT '{}'
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovery_scans_org ON discovery_scans (org_id, started_at)")
            try:
                cursor.execute("ALTER TABLE governance_tasks ADD COLUMN owner TEXT")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE governance_tasks ADD COLUMN team TEXT")
            except Exception:
                pass
            conn.commit()

    # --- Task Methods ---
    def save_task(self, task: TaskRecord) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO governance_tasks (
                    task_id, request_text, request_hash, agent_id, workspace_root,
                    status, created_at, started_at, completed_at, current_boundary_version, pid, owner, team, condition, requested_by, model, org
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    status=excluded.status,
                    started_at=coalesce(excluded.started_at, governance_tasks.started_at),
                    completed_at=coalesce(excluded.completed_at, governance_tasks.completed_at),
                    current_boundary_version=excluded.current_boundary_version,
                    pid=coalesce(excluded.pid, governance_tasks.pid),
                    owner=coalesce(excluded.owner, governance_tasks.owner),
                    team=coalesce(excluded.team, governance_tasks.team),
                    condition=coalesce(excluded.condition, governance_tasks.condition),
                    requested_by=coalesce(excluded.requested_by, governance_tasks.requested_by),
                    model=coalesce(excluded.model, governance_tasks.model),
                    org=coalesce(excluded.org, governance_tasks.org)
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
                    task.owner,
                    task.team,
                    getattr(task, "condition", None),
                    getattr(task, "requested_by", None),
                    getattr(task, "model", None),
                    getattr(task, "org", None) or "default",
                ),
            )
            conn.commit()

    def get_task(self, task_id: str) -> TaskRecord | None:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM governance_tasks WHERE task_id = ?", (task_id,)).fetchone()
            if not row:
                return None
            keys = row.keys()
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
                owner=row["owner"] if "owner" in keys else None,
                team=row["team"] if "team" in keys else None,
                condition=row["condition"] if "condition" in keys else None,
                requested_by=row["requested_by"] if "requested_by" in keys else None,
                model=row["model"] if "model" in keys else None,
                org=row["org"] if "org" in keys and row["org"] else "default",
            )

    def list_tasks(self) -> list[TaskRecord]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM governance_tasks ORDER BY created_at DESC").fetchall()
            out = []
            for r in rows:
                k = r.keys()
                out.append(
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
                        owner=r["owner"] if "owner" in k else None,
                        team=r["team"] if "team" in k else None,
                        condition=r["condition"] if "condition" in k else None,
                        requested_by=r["requested_by"] if "requested_by" in k else None,
                        model=r["model"] if "model" in k else None,
                        org=r["org"] if "org" in k and r["org"] else "default",
                    )
                )
            return out

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
        self._notify_boundary_change(boundary.task_id)

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

    def _writer_loop(self) -> None:
        while not self._writer_stop.is_set():
            batch_items: list[tuple[str, Any]] = []
            with self._writer_cond:
                total_pending = sum(len(q) for q in self._task_queues.values())
                if total_pending < 50 and not self._force_flush:
                    self._writer_cond.wait(timeout=0.1)

                max_collect = 50 if not self._force_flush else 10000
                collected = 0
                for tid, q in list(self._task_queues.items()):
                    if not q:
                        continue
                    take = q[:(max_collect - collected)]
                    batch_items.extend(take)
                    del q[:len(take)]
                    collected += len(take)
                    if collected >= max_collect:
                        break
                self._inflight += len(batch_items)

            if batch_items:
                self._write_batch_with_retry(batch_items)

            with self._writer_cond:
                self._inflight -= len(batch_items)
                total_pending = sum(len(q) for q in self._task_queues.values())
                if total_pending == 0 and self._force_flush:
                    self._force_flush = False
                self._flush_done_cond.notify_all()

    def _write_batch_with_retry(self, items: list[tuple[str, Any]]) -> None:
        """Writes one batch; on failure retries twice, then logs what was lost (never silently)."""
        for attempt in range(3):
            try:
                self._write_batch_to_db(items)
                return
            except Exception:
                if attempt == 2:
                    self.dropped_writes += len(items)
                    logger.exception("Batched write failed after 3 attempts; %d step/event rows not stored "
                                     "(dropped_writes=%d)", len(items), self.dropped_writes)
                    return
                time.sleep(0.05 * (attempt + 1))

    def _write_batch_to_db(self, items: list[tuple[str, Any]]) -> None:
        steps = [it[1] for it in items if it[0] == "step"]
        events = [it[1] for it in items if it[0] == "event"]
        if not steps and not events:
            return
        with self._get_raw_connection() as conn:
                if steps:
                    conn.executemany(
                        """
                        INSERT INTO task_steps (
                            task_id, step_number, timestamp, kind, layer, verdict, summary, detail, source_label
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            (
                                s["task_id"],
                                s["step_number"],
                                s["timestamp"],
                                s["kind"],
                                s["layer"],
                                s["verdict"],
                                s["summary"],
                                s["detail"] or "",
                                s["source_label"],
                            )
                            for s in steps
                        ],
                    )
                if events:
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
                                e.event_id,
                                e.timestamp,
                                e.source.value,
                                e.task_id,
                                e.agent_id,
                                e.pid,
                                e.kind,
                                e.target,
                                e.verdict.value,
                                e.risk_tier.value,
                                e.action_taken.value,
                                1 if e.prevented else 0,
                                e.rule_matched,
                                e.boundary_version,
                                json.dumps(e.details),
                            )
                            for e in events
                        ],
                    )
                conn.commit()

    def flush(self, task_id: str | None = None) -> None:
        """Flushes queued in-memory database writes to disk synchronously."""
        if threading.current_thread() is getattr(self, "_writer_thread", None):
            return
        with self._writer_cond:
            def _pending() -> bool:
                if self._inflight:
                    return True
                if task_id:
                    return bool(self._task_queues.get(task_id))
                return any(self._task_queues.values())

            if not _pending():
                return
            self._force_flush = True
            self._writer_cond.notify()
            while _pending():
                if not self._writer_thread.is_alive():
                    drain: list[tuple[str, Any]] = []
                    for q in self._task_queues.values():
                        drain.extend(q)
                        q.clear()
                    if drain:
                        self._write_batch_with_retry(drain)
                    self._inflight = 0
                    self._force_flush = False
                    break
                self._flush_done_cond.wait(timeout=0.05)

    def close(self) -> None:
        self.flush()
        self._writer_stop.set()
        with self._writer_cond:
            self._writer_cond.notify()
        if self._writer_thread.is_alive():
            self._writer_thread.join(timeout=1.0)
        with self._instance_lock:
            self._instances.pop(self.db_path, None)

    # --- Event Recording ---
    def record_event(self, event: GovernanceEvent) -> None:
        if not event.task_id:
            self._write_batch_with_retry([("event", event)])
            return
        tid = event.task_id
        with self._writer_lock:
            if tid not in self._task_queues:
                self._task_queues[tid] = []
            self._task_queues[tid].append(("event", event))
            if sum(len(q) for q in self._task_queues.values()) >= 50:
                self._writer_cond.notify()

    def record_events(self, events: list[GovernanceEvent]) -> None:
        """Bulk insert (one transaction) for high-volume OS sensor streams."""
        if not events:
            return
        unattributed = [e for e in events if not e.task_id]
        if unattributed:
            self._write_batch_with_retry([("event", e) for e in unattributed])
        attributed = [e for e in events if e.task_id]
        if not attributed:
            return
        with self._writer_lock:
            for e in attributed:
                tid = e.task_id
                if tid not in self._task_queues:
                    self._task_queues[tid] = []
                self._task_queues[tid].append(("event", e))
            if sum(len(q) for q in self._task_queues.values()) >= 50:
                self._writer_cond.notify()

    def get_events_for_task(self, task_id: str) -> list[GovernanceEvent]:
        self.flush(task_id)
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
        self.flush(req.task_id)
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO governance_expansions (
                    request_id, task_id, agent_id, resource_type, resource_target,
                    justification, baseline_risk_tier, effective_risk_tier,
                    escalated_by_provenance, status, created_at, resolved_at,
                    resolved_by, single_use, used_count, timeout_seconds, reason, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                    status=excluded.status,
                    resolved_at=coalesce(excluded.resolved_at, governance_expansions.resolved_at),
                    resolved_by=coalesce(excluded.resolved_by, governance_expansions.resolved_by),
                    used_count=excluded.used_count,
                    reason=coalesce(excluded.reason, governance_expansions.reason),
                    expires_at=coalesce(excluded.expires_at, governance_expansions.expires_at)
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
                    req.expires_at,
                ),
            )
            conn.commit()
        self._notify_boundary_change(req.task_id)

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
        self._notify_boundary_change()

    def increment_expansion_usage(self, request_id: str) -> int:
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE governance_expansions SET used_count = used_count + 1 WHERE request_id = ?",
                (request_id,),
            )
            conn.commit()
            row = conn.execute(
                "SELECT used_count, task_id FROM governance_expansions WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            tid = row["task_id"] if row else None
            self._notify_boundary_change(tid)
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
            expires_at=r["expires_at"] if "expires_at" in r.keys() else None,
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

        with self._writer_lock:
            if step_number is None:
                if task_id not in self._step_counters:
                    with self._get_raw_connection() as conn:
                        row = conn.execute(
                            "SELECT COALESCE(MAX(step_number), 0) FROM task_steps WHERE task_id = ?",
                            (task_id,),
                        ).fetchone()
                        self._step_counters[task_id] = int(row[0]) if row else 0
                self._step_counters[task_id] += 1
                step_number = self._step_counters[task_id]
            else:
                if task_id not in self._step_counters or step_number > self._step_counters[task_id]:
                    self._step_counters[task_id] = step_number

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
            if task_id not in self._task_queues:
                self._task_queues[task_id] = []
            self._task_queues[task_id].append(("step", step_dict))
            if sum(len(q) for q in self._task_queues.values()) >= 50:
                self._writer_cond.notify()

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
        self.flush(task_id)
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

    # --- Standing Rules (stored as JSON; matched only by standing_rules.match_rule) ---
    def save_standing_rule(self, rule: dict[str, Any]) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO governance_standing_rules (rule_id, created_at, rule_json) VALUES (?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET rule_json=excluded.rule_json
                """,
                (rule["rule_id"], rule.get("created_at", ""), json.dumps(rule)),
            )
            conn.commit()
        self._notify_boundary_change()

    def list_standing_rules(self) -> list[dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT rule_json FROM governance_standing_rules ORDER BY created_at, rule_id"
            ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            try:
                out.append(json.loads(r["rule_json"]))
            except (TypeError, ValueError):
                continue
        return out

    def mark_expansion_expiry(self, request_id: str, expires_at: str) -> None:
        """Gives a still-pending request an end time before it is approved ("Allow for N minutes")."""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE governance_expansions SET expires_at = ? WHERE request_id = ? AND status = 'PENDING'",
                (expires_at, request_id),
            )
            conn.commit()
        self._notify_boundary_change()

    def mark_expansion_single_use(self, request_id: str) -> None:
        """Marks a still-pending request as single-use before it is approved ("Allow once")."""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE governance_expansions SET single_use = 1 WHERE request_id = ? AND status = 'PENDING'",
                (request_id,),
            )
            conn.commit()
        self._notify_boundary_change()

    # --- Discovered Agents and Scans ---
    def _row_to_discovered_agent(self, r: sqlite3.Row | dict[str, Any]) -> DiscoveredAgent:
        frameworks = json.loads(r["frameworks_json"]) if r["frameworks_json"] else []
        llm_endpoints = json.loads(r["llm_endpoints_json"]) if r["llm_endpoints_json"] else []
        key_names = json.loads(r["key_names_json"]) if r["key_names_json"] else []
        raw_evidence = json.loads(r["evidence_json"]) if r["evidence_json"] else []
        evidence = [EvidenceItem(**ev) if isinstance(ev, dict) else ev for ev in raw_evidence]
        return DiscoveredAgent(
            org_id=r["org_id"],
            discovery_id=r["discovery_id"],
            host=r["host"],
            kind=r["kind"],
            name=r["name"],
            frameworks=frameworks,
            llm_endpoints=llm_endpoints,
            key_names=key_names,
            evidence=evidence,
            status=r["status"],
            owner=r["owner"],
            purpose=r["purpose"],
            linked_agent_id=r["linked_agent_id"],
            retired_at=r["retired_at"],
            created_at=r["created_at"],
            updated_at=r["updated_at"],
        )

    def save_discovered_agent(self, agent: DiscoveredAgent) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        created_at = agent.created_at or now
        updated_at = agent.updated_at or now
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO discovered_agents (
                    org_id, discovery_id, host, kind, name,
                    frameworks_json, llm_endpoints_json, key_names_json, evidence_json,
                    status, owner, purpose, linked_agent_id, retired_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    agent.org_id,
                    agent.discovery_id,
                    agent.host,
                    agent.kind,
                    agent.name,
                    json.dumps(agent.frameworks),
                    json.dumps(agent.llm_endpoints),
                    json.dumps(agent.key_names),
                    json.dumps([e.model_dump() for e in agent.evidence]),
                    agent.status,
                    agent.owner,
                    agent.purpose,
                    agent.linked_agent_id,
                    agent.retired_at,
                    created_at,
                    updated_at,
                ),
            )
            conn.commit()

    def upsert_discovered_agent(self, agent: DiscoveredAgent) -> DiscoveredAgent:
        existing = self.get_discovered_agent(agent.org_id, agent.discovery_id)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if existing:
            merged_frameworks = sorted(list(set(existing.frameworks) | set(agent.frameworks)))
            merged_endpoints = sorted(list(set(existing.llm_endpoints) | set(agent.llm_endpoints)))
            merged_keys = sorted(list(set(existing.key_names) | set(agent.key_names)))

            ev_map: dict[tuple[str, str], EvidenceItem] = {}
            for e in existing.evidence:
                ev_map[(e.signal, e.detail)] = e
            for e in agent.evidence:
                k = (e.signal, e.detail)
                if k in ev_map:
                    ev_map[k].last_seen = e.last_seen
                else:
                    ev_map[k] = e
            merged_evidence = list(ev_map.values())

            # Status precedence: known > governed > shadow
            status = existing.status
            if status == "shadow" and agent.status != "shadow":
                status = agent.status

            owner = existing.owner or agent.owner
            purpose = existing.purpose or agent.purpose
            linked = existing.linked_agent_id or agent.linked_agent_id
            retired = existing.retired_at or agent.retired_at

            updated = DiscoveredAgent(
                org_id=agent.org_id,
                discovery_id=agent.discovery_id,
                host=agent.host,
                kind=agent.kind,
                name=agent.name or existing.name,
                frameworks=merged_frameworks,
                llm_endpoints=merged_endpoints,
                key_names=merged_keys,
                evidence=merged_evidence,
                status=status,
                owner=owner,
                purpose=purpose,
                linked_agent_id=linked,
                retired_at=retired,
                created_at=existing.created_at,
                updated_at=now,
            )
            self.save_discovered_agent(updated)
            return updated
        else:
            self.save_discovered_agent(agent)
            return agent

    def get_discovered_agent(self, org_id: str, discovery_id: str) -> DiscoveredAgent | None:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM discovered_agents WHERE org_id = ? AND discovery_id = ?",
                (org_id, discovery_id),
            ).fetchone()
        return self._row_to_discovered_agent(row) if row else None

    def list_discovered_agents(
        self,
        org_id: str = "default",
        status: str | None = None,
        kind: str | None = None,
        host: str | None = None,
        include_retired: bool = False,
    ) -> list[DiscoveredAgent]:
        query = "SELECT * FROM discovered_agents WHERE org_id = ?"
        params: list[Any] = [org_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        if kind:
            query += " AND kind = ?"
            params.append(kind)
        if host:
            query += " AND host = ?"
            params.append(host)
        if not include_retired:
            query += " AND retired_at IS NULL"
        query += " ORDER BY updated_at DESC"
        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_discovered_agent(r) for r in rows]

    def patch_discovered_agent(
        self,
        org_id: str,
        discovery_id: str,
        owner: str | None = None,
        purpose: str | None = None,
        status: str | None = None,
        linked_agent_id: str | None = None,
    ) -> DiscoveredAgent | None:
        existing = self.get_discovered_agent(org_id, discovery_id)
        if not existing:
            return None
        new_owner = owner if owner is not None else existing.owner
        new_purpose = purpose if purpose is not None else existing.purpose
        new_linked = linked_agent_id if linked_agent_id is not None else existing.linked_agent_id
        new_status = status if status is not None else existing.status
        if (new_owner and new_purpose) and new_status == "shadow":
            new_status = "known"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE discovered_agents
                SET owner = ?, purpose = ?, status = ?, linked_agent_id = ?, updated_at = ?
                WHERE org_id = ? AND discovery_id = ?
                """,
                (new_owner, new_purpose, new_status, new_linked, now, org_id, discovery_id),
            )
            conn.commit()
        return self.get_discovered_agent(org_id, discovery_id)

    def retire_discovered_agent(
        self,
        org_id: str,
        discovery_id: str,
        retired_at: str | None = None,
        retired_by: str = "operator",
    ) -> DiscoveredAgent | None:
        existing = self.get_discovered_agent(org_id, discovery_id)
        if not existing:
            return None
        now = retired_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE discovered_agents SET retired_at = ?, updated_at = ? WHERE org_id = ? AND discovery_id = ?",
                (now, now, org_id, discovery_id),
            )
            # If linked to a configured agent, mark inactive and revoke active grants
            if existing.linked_agent_id:
                target_agent = existing.linked_agent_id
                # 1. Deactivate tokens
                conn.execute(
                    "UPDATE governance_tokens SET is_active = 0, revoked_at = ? WHERE agent_id = ?",
                    (now, target_agent),
                )
                # 2. Revoke active/pending grants for this agent's tasks
                task_rows = conn.execute(
                    "SELECT task_id FROM governance_tasks WHERE agent_id = ?",
                    (target_agent,),
                ).fetchall()
                task_ids = [r["task_id"] for r in task_rows]
                for tid in task_ids:
                    conn.execute(
                        """
                        UPDATE governance_expansions
                        SET status = 'REVOKED', resolved_at = ?, resolved_by = ?, reason = 'Agent retired'
                        WHERE task_id = ? AND status IN ('PENDING', 'APPROVED')
                        """,
                        (now, retired_by, tid),
                    )
            conn.commit()
        return self.get_discovered_agent(org_id, discovery_id)

    def save_discovery_scan(self, scan: DiscoveryScanRecord) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO discovery_scans (
                    scan_id, org_id, started_at, completed_at, status, findings_count, unreadable_count, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.scan_id,
                    scan.org_id,
                    scan.started_at,
                    scan.completed_at,
                    scan.status,
                    scan.findings_count,
                    scan.unreadable_count,
                    json.dumps(scan.details),
                ),
            )
            conn.commit()

    def get_discovery_scan(self, scan_id: str, org_id: str = "default") -> DiscoveryScanRecord | None:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM discovery_scans WHERE scan_id = ? AND org_id = ?",
                (scan_id, org_id),
            ).fetchone()
        if not row:
            return None
        details = json.loads(row["details_json"]) if row["details_json"] else {}
        return DiscoveryScanRecord(
            scan_id=row["scan_id"],
            org_id=row["org_id"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            status=row["status"],
            findings_count=row["findings_count"],
            unreadable_count=row["unreadable_count"],
            details=details,
        )

    def list_discovery_scans(self, org_id: str = "default", limit: int = 20) -> list[DiscoveryScanRecord]:
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM discovery_scans WHERE org_id = ? ORDER BY started_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        scans = []
        for row in rows:
            details = json.loads(row["details_json"]) if row["details_json"] else {}
            scans.append(DiscoveryScanRecord(
                scan_id=row["scan_id"],
                org_id=row["org_id"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                status=row["status"],
                findings_count=row["findings_count"],
                unreadable_count=row["unreadable_count"],
                details=details,
            ))
        return scans
