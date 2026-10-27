"""Tests for Operator Authentication, Receipt retrieval, and Dashboard Path Traversal (Phase 1 Review).

Verifies:
1. POST /expansions/{id}/approve, /deny, and /tasks/{id}/grant strictly require GOVERNANCE_OPERATOR_TOKEN,
   rejecting requests when unset (403) or invalid (401), and accepting matching Bearer / X-Operator-Token headers
   via constant-time hmac.compare_digest.
2. GET /tasks/{id}/receipt returns {"available": false} when no stored receipt exists,
   and {"available": true, "verified": true} when a valid receipt exists in RECEIPTS_DIR.
3. GET /dashboard/%2e%2e/... and /dashboard/..%2f... via RAW TCP socket cannot traverse outside dist.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import threading
import time
import pytest
from fastapi.testclient import TestClient

from app.gateway.server import create_app
from app.governance.models import (
    EnforcementMode,
    ExpansionRequest,
    ExpansionStatus,
    RiskTier,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from app.governance.receipt import chain_entries, GENESIS_HASH
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

    old_db = os.environ.get("GOVERNANCE_DB_PATH")
    os.environ["GOVERNANCE_DB_PATH"] = str(db_path)

    app = create_app(governance_storage=storage)
    client = TestClient(app)

    yield {"client": client, "storage": storage, "db_path": db_path, "tmp_path": tmp_path, "app": app}

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


def test_receipt_endpoint_both_cases(auth_test_env):
    """Tests GET /tasks/{id}/receipt:

    Case 1: No stored receipt -> available=False, verified=False, no synthetic fallback.
    Case 2: Stored receipt in RECEIPTS_DIR -> available=True, verified=True with valid hash chain.
    """
    client = auth_test_env["client"]
    tmp_path = auth_test_env["tmp_path"]

    # Case 1: No stored receipt exists anywhere
    empty_receipts_dir = tmp_path / "empty_receipts"
    empty_receipts_dir.mkdir(parents=True, exist_ok=True)
    old_receipts_dir = os.environ.get("RECEIPTS_DIR")
    os.environ["RECEIPTS_DIR"] = str(empty_receipts_dir)

    try:
        resp1 = client.get("/api/governance/tasks/task_auth_01/receipt")
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["task_id"] == "task_auth_01"
        assert data1["available"] is False
        assert data1["verified"] is False
        assert data1["receipt"] is None
        assert data1["verification_message"] == "No stored receipt"

        # Case 2: Create a real receipt in RECEIPTS_DIR
        populated_receipts_dir = tmp_path / "custom_receipts"
        populated_receipts_dir.mkdir(parents=True, exist_ok=True)
        os.environ["RECEIPTS_DIR"] = str(populated_receipts_dir)

        # Build a valid single-event hash chain
        event = {
            "timestamp": "2026-10-27T10:00:00Z",
            "source": "TOOL_BROKER",
            "kind": "file_read",
            "target": "input/budget.csv",
            "verdict": "INSIDE",
        }
        events = [event]
        final_hash = chain_entries(events)

        receipt_payload = {
            "task_id": "task_auth_01",
            "events": events,
            "hash_chain": {
                "algorithm": "sha256",
                "count": 1,
                "genesis": GENESIS_HASH,
                "final_hash": final_hash,
            },
        }

        receipt_file = populated_receipts_dir / "task_auth_01.json"
        receipt_file.write_text(json.dumps(receipt_payload), encoding="utf-8")

        resp2 = client.get("/api/governance/tasks/task_auth_01/receipt")
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["task_id"] == "task_auth_01"
        assert data2["available"] is True
        assert data2["verified"] is True
        assert data2["receipt"] is not None
        assert data2["receipt"]["hash_chain"]["count"] == 1
    finally:
        if old_receipts_dir is not None:
            os.environ["RECEIPTS_DIR"] = old_receipts_dir
        else:
            os.environ.pop("RECEIPTS_DIR", None)


def test_dashboard_path_traversal_raw_socket(auth_test_env):
    """Raw TCP socket test to confirm path traversal is blocked and strictly contained.

    Tests:
    1. /dashboard/%2e%2e/
    2. /dashboard/..%2f...
    3. /dashboard//etc/passwd (absolute path variant)
    Ensures no host files outside dist are ever leaked, returning index.html fallback.
    """
    import uvicorn

    app = auth_test_env["app"]

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to listen
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.05)

    def send_raw(path: str) -> str:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            req = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode("latin-1"))
            response_chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_chunks.append(chunk)
            return b"".join(response_chunks).decode("latin-1", errors="replace")

    try:
        # 1. /dashboard/%2e%2e/etc/passwd
        resp1 = send_raw("/dashboard/%2e%2e/etc/passwd")
        assert "root:" not in resp1, "Path traversal succeeded with %2e%2e!"
        assert "HTTP/1.1 200" in resp1
        assert "<html" in resp1.lower() or "<!doctype" in resp1.lower()

        # 2. /dashboard/..%2f..%2fetc/passwd
        resp2 = send_raw("/dashboard/..%2f..%2fetc/passwd")
        assert "root:" not in resp2, "Path traversal succeeded with ..%2f!"
        assert "HTTP/1.1 200" in resp2
        assert "<html" in resp2.lower() or "<!doctype" in resp2.lower()

        # 3. Absolute path variant /dashboard//etc/passwd
        resp3 = send_raw("/dashboard//etc/passwd")
        assert "root:" not in resp3, "Path traversal succeeded with absolute path variant!"
        assert "HTTP/1.1 200" in resp3
        assert "<html" in resp3.lower() or "<!doctype" in resp3.lower()

    finally:
        server.should_exit = True
