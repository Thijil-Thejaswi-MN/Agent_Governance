from __future__ import annotations

from pathlib import Path
import pytest
from app.cards.normalizer import normalize_agent_card
from app.core.models import SecurityViolation, SecuritySeverity, PolicyAction, TimingBreakdown
from app.storage.db import SQLiteManager
from app.inventory.store import InMemoryAgentInventory
from app.telemetry.metrics import EventStore


def test_sqlite_schema_initialization(tmp_path):
    db_file = tmp_path / "schema_test.db"
    manager = SQLiteManager(db_file)
    with manager.get_connection() as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        table_names = [r["name"] for r in tables]
    assert "trusted_agents" in table_names
    assert "quarantine_store" in table_names
    assert "restriction_store" in table_names
    assert "security_events" in table_names


def test_agent_persistence_across_restarts(tmp_path):
    db_file = tmp_path / "agents_test.db"
    storage1 = SQLiteManager(db_file)
    inv1 = InMemoryAgentInventory(storage=storage1)

    raw_card = {
        "name": "Persistent Test Agent",
        "url": "http://127.0.0.1:9099",
        "version": "1.2.3",
        "protocolVersion": "1.0",
        "protocolBinding": "JSONRPC",
        "skills": [{"id": "ping", "name": "Ping Skill"}],
    }
    card = normalize_agent_card(raw_card)
    inv1.register_trusted("test_agent_p1", card)
    assert inv1.get_trusted_agent("test_agent_p1") is not None

    # Simulate Gateway restart with fresh instance pointing to same SQLite database
    storage2 = SQLiteManager(db_file)
    inv2 = InMemoryAgentInventory(storage=storage2)
    loaded_agent = inv2.get_trusted_agent("test_agent_p1")
    assert loaded_agent is not None
    assert loaded_agent.name == "Persistent Test Agent"
    assert loaded_agent.skills[0].id == "ping"


def test_quarantine_persistence_and_release(tmp_path):
    db_file = tmp_path / "quarantine_test.db"
    storage1 = SQLiteManager(db_file)
    inv1 = InMemoryAgentInventory(storage=storage1)

    violation = SecurityViolation(
        violation_code="AS_HOMOGLYPH_SPOOF",
        description="Homoglyph detected",
        candidate_name="Spoofed Agent",
    )
    inv1.quarantine("bad_actor_99", reason="Adversarial spoof", violation=violation)
    assert inv1.is_quarantined("bad_actor_99") is True

    # Restart gateway
    storage2 = SQLiteManager(db_file)
    inv2 = InMemoryAgentInventory(storage=storage2)
    assert inv2.is_quarantined("bad_actor_99") is True
    assert "bad_actor_99" in [r["identity"] for r in inv2.get_quarantined_records()]

    # Release quarantine
    assert inv2.release_quarantine("bad_actor_99") is True
    assert inv2.is_quarantined("bad_actor_99") is False

    # Restart again and verify release persisted
    storage3 = SQLiteManager(db_file)
    inv3 = InMemoryAgentInventory(storage=storage3)
    assert inv3.is_quarantined("bad_actor_99") is False


def test_restriction_persistence_and_release(tmp_path):
    db_file = tmp_path / "restriction_test.db"
    storage1 = SQLiteManager(db_file)
    inv1 = InMemoryAgentInventory(storage=storage1)

    inv1.restrict(
        "restricted_actor_01",
        reason="Suspicious capability variance",
        allowed_operations=[".well-known/agent-card.json", "status"],
    )
    assert inv1.is_restricted("restricted_actor_01") is True
    assert inv1.is_operation_allowed_when_restricted("restricted_actor_01", "status") is True
    assert inv1.is_operation_allowed_when_restricted("restricted_actor_01", "SendMessage") is False

    # Restart gateway
    storage2 = SQLiteManager(db_file)
    inv2 = InMemoryAgentInventory(storage=storage2)
    assert inv2.is_restricted("restricted_actor_01") is True
    assert inv2.is_operation_allowed_when_restricted("restricted_actor_01", "status") is True
    assert inv2.is_operation_allowed_when_restricted("restricted_actor_01", "SendMessage") is False

    # Release restriction
    assert inv2.release_restriction("restricted_actor_01") is True
    assert inv2.is_restricted("restricted_actor_01") is False

    # Restart again and verify release persisted
    storage3 = SQLiteManager(db_file)
    inv3 = InMemoryAgentInventory(storage=storage3)
    assert inv3.is_restricted("restricted_actor_01") is False


def test_security_events_persistence(tmp_path):
    db_file = tmp_path / "events_test.db"
    storage1 = SQLiteManager(db_file)
    store1 = EventStore(storage=storage1)

    timing = TimingBreakdown(
        t_recv_ns=100, t_detect_ns=200, t_decide_ns=300, t_enforce_ns=400,
        detection_latency_ms=0.1, decision_latency_ms=0.1, enforcement_latency_ms=0.1, total_pipeline_latency_ms=0.3
    )
    store1.record_event(
        candidate_id="attacker_1",
        candidate_name="Attacker",
        candidate_endpoint="http://attacker.local",
        violation=SecurityViolation(violation_code="AS_HOMOGLYPH_SPOOF", description="Homoglyph"),
        severity=SecuritySeverity.HIGH,
        action_taken=PolicyAction.QUARANTINE,
        timing=timing,
    )
    assert len(store1.get_events()) == 1

    # Restart gateway and reload events
    storage2 = SQLiteManager(db_file)
    store2 = EventStore(storage=storage2)
    events = store2.get_events()
    assert len(events) == 1
    assert events[0].candidate_id == "attacker_1"
    assert events[0].severity == SecuritySeverity.HIGH
    assert events[0].action_taken == PolicyAction.QUARANTINE
    assert events[0].violation.violation_code == "AS_HOMOGLYPH_SPOOF"

    metrics = store2.get_metrics_summary()
    assert metrics["total_events"] == 1
    assert metrics["quarantined_count"] == 1
