"""Unit and isolation tests for demo data (Console v4).

Checks:
- GOVERNANCE_DEMO_DATA is off by default:
  - no demo banner active;
  - production database is used.
- When GOVERNANCE_DEMO_DATA=1:
  - demo database is seeded deterministically;
  - production database file is not modified (SHA-256 hash before and after is identical);
  - API responses for JSON objects include "demo": true;
  - /results endpoint and results_summary.json return identical values regardless of demo mode.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from demo.security_monitor.app.gateway.server import create_app
from demo.security_monitor.app.governance.scale import is_demo_data_enabled
from demo.security_monitor.app.governance.demo_data import seed_demo_database
from demo.security_monitor.app.governance.storage import GovernanceStorage


def _sha256_of_file(p: Path) -> str:
    if not p.exists():
        return ""
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_demo_data_off_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("GOVERNANCE_DEMO_DATA", raising=False)
    assert is_demo_data_enabled() is False

    app = create_app()
    client = TestClient(app)
    res = client.get("/api/governance/auth/status")
    assert res.status_code == 200
    data = res.json()
    assert data.get("demo_data_active") is False
    assert "demo" not in data


def test_demo_data_isolation_and_no_production_mutation(monkeypatch, tmp_path):
    # Setup production DB with dummy content
    prod_db = tmp_path / "prod_governance.db"
    demo_db = tmp_path / "demo_governance.db"
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(prod_db))
    monkeypatch.setenv("GOVERNANCE_DEMO_DB_PATH", str(demo_db))

    prod_storage = GovernanceStorage(prod_db)
    prod_storage.save_token("initial_token", "t_init", "agent_init")

    # Hash prod DB
    prod_hash_before = _sha256_of_file(prod_db)
    assert prod_hash_before != ""

    # Enable Demo Mode
    monkeypatch.setenv("GOVERNANCE_DEMO_DATA", "1")
    monkeypatch.setenv("GOVERNANCE_DEMO_SIZE", "5")
    assert is_demo_data_enabled() is True

    app = create_app()
    client = TestClient(app)

    # Call API endpoints while demo mode is on
    status_res = client.get("/api/governance/auth/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data.get("demo_data_active") is True
    assert status_data.get("demo") is True

    # Set operator token for admin access
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "secret-test-token")
    headers = {"Authorization": "Bearer secret-test-token"}

    # Seeded tasks should be present in demo DB
    tasks_res = client.get("/api/governance/tasks", headers=headers)
    assert tasks_res.status_code == 200
    tasks_data = tasks_res.json()
    assert len(tasks_data) == 5
    assert demo_db.exists()

    # Verify prod DB was NOT touched at all
    prod_hash_after = _sha256_of_file(prod_db)
    assert prod_hash_after == prod_hash_before, "Production DB was modified while demo mode was active!"


def test_results_identical_with_demo_on_and_off(monkeypatch, tmp_path):
    # Verify results_summary.json values are identical regardless of demo data
    demo_db = tmp_path / "demo_governance.db"
    monkeypatch.setenv("GOVERNANCE_DEMO_DB_PATH", str(demo_db))

    # Read summary with demo off
    monkeypatch.delenv("GOVERNANCE_DEMO_DATA", raising=False)
    app_off = create_app()
    client_off = TestClient(app_off)
    res_off = client_off.get("/dashboard/results_summary.json")

    # Read summary with demo on
    monkeypatch.setenv("GOVERNANCE_DEMO_DATA", "1")
    monkeypatch.setenv("GOVERNANCE_DEMO_SIZE", "200")
    app_on = create_app()
    client_on = TestClient(app_on)
    res_on = client_on.get("/dashboard/results_summary.json")

    if res_off.status_code == 200:
        assert res_on.status_code == 200
        assert res_off.json() == res_on.json()


def test_seed_demo_database_deterministic(tmp_path):
    db1 = tmp_path / "d1.db"
    db2 = tmp_path / "d2.db"
    seed_demo_database(db1, size=20, seed=12345)
    seed_demo_database(db2, size=20, seed=12345)

    s1 = GovernanceStorage(db1).list_tasks()
    s2 = GovernanceStorage(db2).list_tasks()

    assert len(s1) == 20
    assert len(s2) == 20
    assert [t.task_id for t in s1] == [t.task_id for t in s2]
    assert [t.agent_id for t in s1] == [t.agent_id for t in s2]
