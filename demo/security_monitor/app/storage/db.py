from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


import os


def get_default_db_path() -> Path:
    """Resolve database path in demo/data/security_monitor.db relative to repository root."""
    env_path = os.environ.get("SECMON_DB_PATH")
    if env_path:
        return Path(env_path)
    p = Path(__file__).resolve()
    for parent in p.parents:
        if (parent / "demo" / "data").is_dir():
            return parent / "demo" / "data" / "security_monitor.db"
    return Path.cwd() / "security_monitor.db"


class SQLiteManager:
    """Manages SQLite schema and persistent queries for the A2A Security Monitor."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path == ":memory:":
            self.db_path = ":memory:"
        else:
            self.db_path = str(db_path or get_default_db_path())
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # 1. Trusted agents
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS trusted_agents (
                    agent_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    endpoint_url TEXT NOT NULL,
                    version TEXT,
                    protocol_version TEXT,
                    protocol_binding TEXT,
                    skills_json TEXT,
                    security_schemes_json TEXT,
                    raw_card_json TEXT,
                    status TEXT DEFAULT 'TRUSTED',
                    updated_at TEXT DEFAULT (datetime('now', 'utc'))
                )
            """)

            # 2. Quarantine store
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_store (
                    identity TEXT PRIMARY KEY,
                    reason TEXT,
                    violation_json TEXT,
                    quarantined_at TEXT DEFAULT (datetime('now', 'utc')),
                    is_active INTEGER DEFAULT 1
                )
            """)

            # 3. Restriction store
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS restriction_store (
                    identity TEXT PRIMARY KEY,
                    reason TEXT,
                    allowed_operations_json TEXT,
                    restricted_at TEXT DEFAULT (datetime('now', 'utc')),
                    is_active INTEGER DEFAULT 1
                )
            """)

            # 4. Security audit events
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp_utc TEXT,
                    candidate_id TEXT,
                    candidate_name TEXT,
                    candidate_endpoint TEXT,
                    violation_code TEXT,
                    severity TEXT,
                    action_taken TEXT,
                    timing_json TEXT,
                    details_json TEXT
                )
            """)
            conn.commit()

    # --- Agent persistence ---
    def save_agent(self, agent_id: str, card_dict: dict[str, Any], status: str = "TRUSTED") -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO trusted_agents (
                    agent_id, name, endpoint_url, version, protocol_version,
                    protocol_binding, skills_json, security_schemes_json, raw_card_json, status, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'utc'))
                ON CONFLICT(agent_id) DO UPDATE SET
                    name=excluded.name,
                    endpoint_url=excluded.endpoint_url,
                    version=excluded.version,
                    protocol_version=excluded.protocol_version,
                    protocol_binding=excluded.protocol_binding,
                    skills_json=excluded.skills_json,
                    security_schemes_json=excluded.security_schemes_json,
                    raw_card_json=excluded.raw_card_json,
                    status=excluded.status,
                    updated_at=datetime('now', 'utc')
                """,
                (
                    agent_id,
                    card_dict.get("name", ""),
                    card_dict.get("endpoint_url", ""),
                    card_dict.get("version", "0.0.1"),
                    card_dict.get("protocol_version", "1.0"),
                    card_dict.get("protocol_binding", "JSONRPC"),
                    json.dumps(card_dict.get("skills", [])),
                    json.dumps(card_dict.get("security_schemes", {})),
                    json.dumps(card_dict.get("raw_card", {})),
                    status,
                ),
            )
            conn.commit()

    def load_agents(self) -> dict[str, dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM trusted_agents WHERE status = 'TRUSTED'").fetchall()
            result: dict[str, dict[str, Any]] = {}
            for r in rows:
                result[r["agent_id"]] = {
                    "name": r["name"],
                    "endpoint_url": r["endpoint_url"],
                    "version": r["version"],
                    "protocol_version": r["protocol_version"],
                    "protocol_binding": r["protocol_binding"],
                    "skills": json.loads(r["skills_json"] or "[]"),
                    "security_schemes": json.loads(r["security_schemes_json"] or "{}"),
                    "raw_card": json.loads(r["raw_card_json"] or "{}"),
                }
            return result

    # --- Quarantine persistence ---
    def set_quarantine(self, identity: str, reason: str, violation_dict: dict[str, Any] | None = None) -> None:
        key = identity.strip().lower()
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO quarantine_store (identity, reason, violation_json, quarantined_at, is_active)
                VALUES (?, ?, ?, datetime('now', 'utc'), 1)
                ON CONFLICT(identity) DO UPDATE SET
                    reason=excluded.reason,
                    violation_json=excluded.violation_json,
                    quarantined_at=datetime('now', 'utc'),
                    is_active=1
                """,
                (key, reason, json.dumps(violation_dict) if violation_dict else None),
            )
            conn.commit()

    def release_quarantine(self, identity: str) -> None:
        key = identity.strip().lower()
        with self.get_connection() as conn:
            conn.execute("UPDATE quarantine_store SET is_active = 0 WHERE identity = ?", (key,))
            conn.commit()

    def load_quarantined_records(self) -> dict[str, dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM quarantine_store WHERE is_active = 1").fetchall()
            return {
                r["identity"]: {
                    "identity": r["identity"],
                    "reason": r["reason"],
                    "violation": json.loads(r["violation_json"]) if r["violation_json"] else None,
                    "quarantined_at": r["quarantined_at"],
                }
                for r in rows
            }

    # --- Restriction persistence ---
    def set_restriction(
        self,
        identity: str,
        reason: str,
        allowed_operations: list[str] | None = None,
    ) -> None:
        key = identity.strip().lower()
        ops = allowed_operations if allowed_operations is not None else [".well-known/agent-card.json", ".well-known/agent.json", "status"]
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO restriction_store (identity, reason, allowed_operations_json, restricted_at, is_active)
                VALUES (?, ?, ?, datetime('now', 'utc'), 1)
                ON CONFLICT(identity) DO UPDATE SET
                    reason=excluded.reason,
                    allowed_operations_json=excluded.allowed_operations_json,
                    restricted_at=datetime('now', 'utc'),
                    is_active=1
                """,
                (key, reason, json.dumps(ops)),
            )
            conn.commit()

    def release_restriction(self, identity: str) -> None:
        key = identity.strip().lower()
        with self.get_connection() as conn:
            conn.execute("UPDATE restriction_store SET is_active = 0 WHERE identity = ?", (key,))
            conn.commit()

    def load_restriction_records(self) -> dict[str, dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM restriction_store WHERE is_active = 1").fetchall()
            return {
                r["identity"]: {
                    "identity": r["identity"],
                    "reason": r["reason"],
                    "allowed_operations": json.loads(r["allowed_operations_json"] or "[]"),
                    "restricted_at": r["restricted_at"],
                }
                for r in rows
            }

    # --- Event persistence ---
    def save_event(self, event_dict: dict[str, Any]) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO security_events (
                    event_id, timestamp_utc, candidate_id, candidate_name,
                    candidate_endpoint, violation_code, severity, action_taken, timing_json, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO NOTHING
                """,
                (
                    event_dict.get("event_id"),
                    event_dict.get("timestamp_utc"),
                    event_dict.get("candidate_id"),
                    event_dict.get("candidate_name"),
                    event_dict.get("candidate_endpoint"),
                    event_dict.get("violation", {}).get("violation_code") if event_dict.get("violation") else None,
                    event_dict.get("severity"),
                    event_dict.get("action_taken"),
                    json.dumps(event_dict.get("timing", {})),
                    json.dumps(event_dict.get("violation", {})),
                ),
            )
            conn.commit()

    def load_events(self) -> list[dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM security_events ORDER BY timestamp_utc ASC").fetchall()
            return [
                {
                    "event_id": r["event_id"],
                    "timestamp_utc": r["timestamp_utc"],
                    "candidate_id": r["candidate_id"],
                    "candidate_name": r["candidate_name"],
                    "candidate_endpoint": r["candidate_endpoint"],
                    "violation": json.loads(r["details_json"]) if r["details_json"] else None,
                    "severity": r["severity"],
                    "action_taken": r["action_taken"],
                    "timing": json.loads(r["timing_json"]) if r["timing_json"] else {},
                }
                for r in rows
            ]
