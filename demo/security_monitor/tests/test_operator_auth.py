"""Tests for Operator Authentication (Phase 1).

Verifies that POST /expansions/{id}/approve, /deny, and /tasks/{id}/grant
strictly require GOVERNANCE_OPERATOR_TOKEN, rejecting requests when unset (403)
or invalid (401), and accepting matching Bearer / X-Operator-Token headers.
"""
from __future__ import annotations

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.gateway.server import create_app
from app.governance.models import TaskLifecycle, TaskBoundary, EnforcementMode, TaskRecord, ExpansionRequest, ExpansionStatus, RiskTier
from app.governance.storage import GovernanceStorage


@pytest.fixture
def auth_test_env(tmp_path: Path):
    db_path = tmp_path / "test_auth_gov.db"
    storage = GovernanceStorage(db_path)

    # Seed a task and an expansion request
    task = TaskRecord(
        task_id="task_auth_01",
        request_text="Analyze Q3 budget",
        request_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        agent_id="test_agent",
        workspace_root=str(tmp_path),
        status=TaskLifecycle.ACTIVE,
        enforcement_mode=EnforcementMode.ENFORCE,
        created_at="2026-10-27T10:00:00Z",
    )
    boundary = TaskBoundary(
        task_id="task_auth_01",
        workspace_root=str(tmp_path),
        files_read=["input/budget.csv"],
        files_write=["output/summary.txt"],
        tools=["read_file", "write_file", "request_access"],
    )
    storage.save_task(task)
    storage.save_boundary(boundary)

    exp = ExpansionRequest(
        request_id="exp_auth_01",
        task_id="task_auth_01",
        agent_id="test_agent",
        resource_type="file_read",
        resource_target="reference/guidelines.txt",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.LOW,
        justification="Need company accounting guidelines",
        status=ExpansionStatus.PENDING,
        created_at="2026-10-27T10:00:01Z",
    )
    storage.save_expansion_request(exp)

    # Point governance db to our test instance
    old_db = os.environ.get("GOVERNANCE_DB_PATH")
    os.environ["GOVERNANCE_DB_PATH"] = str(db_path)

    app = create_app(governance_storage=storage)
    client = TestClient(app)

    yield {"client": client, "storage": storage, "db_path": db_path}

    if old_db is not None:
        os.environ["GOVERNANCE_DB_PATH"] = old_db
    else:
        os.environ.pop("GOVERNANCE_DB_PATH", None)


def test_operator_token_unset_refuses_requests(auth_test_env):
    """When GOVERNANCE_OPERATOR_TOKEN is unset, decision endpoints refuse with HTTP 403."""
    old_token = os.environ.pop("GOVERNANCE_OPERATOR_TOKEN", None)
    try:
        client = auth_test_env["client"]

        # 1. Approve
        resp = client.post(
            "/api/governance/expansions/exp_auth_01/approve",
            json={"decided_by": "human_operator", "reason": "Approved for audit"}
        )
        assert resp.status_code == 403
        assert "not configured" in resp.json()["detail"].lower()

        # 2. Deny
        resp = client.post(
            "/api/governance/expansions/exp_auth_01/deny",
            json={"decided_by": "human_operator", "reason": "Out of scope"}
        )
        assert resp.status_code == 403
        assert "not configured" in resp.json()["detail"].lower()

        # 3. Grant
        resp = client.post(
            "/api/governance/tasks/task_auth_01/grant",
            json={
                "granted_by": "human_operator",
                "resource_type": "file_read",
                "resource_target": "reference/policy.pdf",
                "single_use": True,
            }
        )
        assert resp.status_code == 403
        assert "not configured" in resp.json()["detail"].lower()
    finally:
        if old_token is not None:
            os.environ["GOVERNANCE_OPERATOR_TOKEN"] = old_token


def test_operator_token_invalid_or_missing_refuses(auth_test_env):
    """When token is configured, requests without token or with wrong token receive HTTP 401."""
    os.environ["GOVERNANCE_OPERATOR_TOKEN"] = "secret_operator_token_xyz123"
    try:
        client = auth_test_env["client"]

        # Missing token -> 401
        resp_missing = client.post(
            "/api/governance/expansions/exp_auth_01/approve",
            json={"decided_by": "human_operator", "reason": "Approved"}
        )
        assert resp_missing.status_code == 401
        assert "invalid or missing" in resp_missing.json()["detail"].lower()

        # Wrong token -> 401
        resp_wrong = client.post(
            "/api/governance/expansions/exp_auth_01/approve",
            headers={"Authorization": "Bearer wrong_token"},
            json={"decided_by": "human_operator", "reason": "Approved"}
        )
        assert resp_wrong.status_code == 401
        assert "invalid or missing" in resp_wrong.json()["detail"].lower()
    finally:
        os.environ.pop("GOVERNANCE_OPERATOR_TOKEN", None)


def test_operator_token_valid_accepts_requests(auth_test_env):
    """When matching token is provided via Bearer or X-Operator-Token header, request succeeds."""
    token = "secure_token_456"
    os.environ["GOVERNANCE_OPERATOR_TOKEN"] = token
    try:
        client = auth_test_env["client"]

        # 1. Approve via Authorization: Bearer
        resp_app = client.post(
            "/api/governance/expansions/exp_auth_01/approve",
            headers={"Authorization": f"Bearer {token}"},
            json={"decided_by": "human_operator", "reason": "Approved for workflow"}
        )
        assert resp_app.status_code == 200
        assert resp_app.json()["status"] == "APPROVED"

        # 2. Grant via X-Operator-Token
        resp_grant = client.post(
            "/api/governance/tasks/task_auth_01/grant",
            headers={"X-Operator-Token": token},
            json={
                "granted_by": "human_operator",
                "resource_type": "file_read",
                "resource_target": "reference/policy.pdf",
                "single_use": True,
            }
        )
        assert resp_grant.status_code == 200
        assert resp_grant.json()["status"] == "APPROVED"
        assert "reference/policy.pdf" in resp_grant.json()["new_boundary"]["files_read"]
    finally:
        os.environ.pop("GOVERNANCE_OPERATOR_TOKEN", None)


def test_task_receipt_endpoint(auth_test_env):
    """GET /api/governance/tasks/{task_id}/receipt returns receipt and hash chain verification."""
    client = auth_test_env["client"]
    resp = client.get("/api/governance/tasks/task_auth_01/receipt")
    assert resp.status_code == 200
    data = resp.json()
    assert data["task_id"] == "task_auth_01"
    assert "receipt" in data
    assert "verified" in data
    assert data["verified"] is True
