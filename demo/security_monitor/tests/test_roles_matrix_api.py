import os
import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from demo.security_monitor.app.gateway.server import create_app
from demo.security_monitor.app.governance.models import (
    TaskRecord,
    TaskBoundary,
    TaskLifecycle,
    ExpansionRequest,
    ExpansionStatus,
    RiskTier,
    EnforcementMode,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.receipt import chain_entries, GENESIS_HASH


USERS_FILE_CONTENT = [
    {
        "name": "Alex Dev",
        "role": "developer",
        "team": "core",
        "token_sha256": "2613c47e0e16fe1daacdfd39f13528d0b16aa28e217499d849ec6f80ef5ac4d2" # dev_token_123
    },
    {
        "name": "Sarah Lead",
        "role": "team_lead",
        "team": "core",
        "token_sha256": "70402017231072d01f04d1e13301489faad442cc49d71ca9958d114d58992441" # lead_token_123
    },
    {
        "name": "Morgan Reviewer",
        "role": "security_reviewer",
        "team": "secops",
        "token_sha256": "3c054e6961ed618645599c9c8c074cbf77cca26ae2daf6584f2fcd35b9d11f9b" # reviewer_token_123
    },
    {
        "name": "Dana Admin",
        "role": "admin",
        "team": None,
        "token_sha256": "88b949c014cbe7bd30eb360094830e8689a453ca8034ccdb8bf204bf80664554" # admin_token_123
    },
    {
        "name": "Riley Auditor",
        "role": "auditor",
        "team": "compliance",
        "token_sha256": "9e5cfbf4a1fd1a7991f93dc5483ecf2dd6234da75974a498f4a0fc140244b501" # auditor_token_123
    }
]


@pytest.fixture
def role_env(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "roles_gov.db"
    users_file = tmp_path / "users.json"
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    users_file.write_text(json.dumps(USERS_FILE_CONTENT), encoding="utf-8")

    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db_path))
    monkeypatch.setenv("GOVERNANCE_USERS_FILE", str(users_file))
    monkeypatch.setenv("RECEIPTS_DIR", str(receipts_dir))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "fallback_admin_token")

    storage = GovernanceStorage(db_path)

    # Task 1: owned by Alex Dev, team core
    t1 = TaskRecord(
        task_id="task_alex_core",
        request_text="Alex task",
        request_hash="hash1",
        agent_id="agent1",
        workspace_root=str(tmp_path / "ws1"),
        status=TaskLifecycle.ACTIVE,
        created_at="2026-11-02T10:00:00Z",
        owner="Alex Dev",
        team="core",
    )
    b1 = TaskBoundary(
        task_id="task_alex_core",
        workspace_root=str(tmp_path / "ws1"),
        files_read=["input/data.csv"],
        files_write=["output/out.txt"],
        tools=["read_file"],
    )
    storage.save_task(t1)
    storage.save_boundary(b1)

    # Task 2: owned by Other Dev, team finance
    t2 = TaskRecord(
        task_id="task_other_finance",
        request_text="Finance task",
        request_hash="hash2",
        agent_id="agent2",
        workspace_root=str(tmp_path / "ws2"),
        status=TaskLifecycle.ACTIVE,
        created_at="2026-11-02T10:05:00Z",
        owner="Other Dev",
        team="finance",
    )
    b2 = TaskBoundary(
        task_id="task_other_finance",
        workspace_root=str(tmp_path / "ws2"),
        files_read=["input/finance.csv"],
        files_write=["output/fin.txt"],
        tools=["read_file"],
    )
    storage.save_task(t2)
    storage.save_boundary(b2)

    # Expansions
    # Routine expansion on task 1 (team core)
    e1 = ExpansionRequest(
        request_id="exp_routine_core",
        task_id="task_alex_core",
        agent_id="agent1",
        resource_type="file_read",
        resource_target="input/extra.csv",
        justification="more data",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.LOW,
        escalated_by_provenance=False,
        status=ExpansionStatus.PENDING,
        created_at="2026-11-02T10:01:00Z",
    )
    storage.save_expansion_request(e1)

    # Provenance-escalated expansion on task 1 (team core)
    e2 = ExpansionRequest(
        request_id="exp_escalated_core",
        task_id="task_alex_core",
        agent_id="agent1",
        resource_type="file_read",
        resource_target="input/discovered.csv",
        justification="untrusted read reference",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.MEDIUM,
        escalated_by_provenance=True,
        status=ExpansionStatus.PENDING,
        created_at="2026-11-02T10:02:00Z",
    )
    storage.save_expansion_request(e2)

    # Routine expansion on task 2 (team finance)
    e3 = ExpansionRequest(
        request_id="exp_routine_finance",
        task_id="task_other_finance",
        agent_id="agent2",
        resource_type="file_read",
        resource_target="input/fin_extra.csv",
        justification="finance extra",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.LOW,
        escalated_by_provenance=False,
        status=ExpansionStatus.PENDING,
        created_at="2026-11-02T10:06:00Z",
    )
    storage.save_expansion_request(e3)

    # Stored receipt for task 1
    ev = {
        "timestamp": "2026-11-02T10:00:00Z",
        "source": "TOOL_BROKER",
        "kind": "file_read",
        "target": "input/data.csv",
        "verdict": "INSIDE",
    }
    final_h = chain_entries([ev])
    r_payload = {
        "task_id": "task_alex_core",
        "events": [ev],
        "hash_chain": {
            "algorithm": "sha256",
            "count": 1,
            "genesis": GENESIS_HASH,
            "final_hash": final_h,
        },
    }
    (receipts_dir / "task_alex_core.json").write_text(json.dumps(r_payload), encoding="utf-8")

    app = create_app()
    client = TestClient(app)

    return {
        "client": client,
        "storage": storage,
        "tmp_path": tmp_path,
        "tokens": {
            "dev": "dev_token_123",
            "lead": "lead_token_123",
            "reviewer": "reviewer_token_123",
            "admin": "admin_token_123",
            "auditor": "auditor_token_123",
        }
    }


def test_auth_session_returns_user_and_landing_routes(role_env):
    client = role_env["client"]
    tokens = role_env["tokens"]

    # Developer sign in
    resp = client.post("/api/governance/auth/session", headers={"X-Operator-Token": tokens["dev"]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["user"]["role"] == "developer"
    assert data["landing_route"] == "/run"

    # Team lead sign in
    resp = client.post("/api/governance/auth/session", headers={"X-Operator-Token": tokens["lead"]})
    assert resp.status_code == 200
    assert resp.json()["landing_route"] == "/team"

    # Security reviewer sign in
    resp = client.post("/api/governance/auth/session", headers={"X-Operator-Token": tokens["reviewer"]})
    assert resp.status_code == 200
    assert resp.json()["landing_route"] == "/inbox"

    # Admin sign in
    resp = client.post("/api/governance/auth/session", headers={"X-Operator-Token": tokens["admin"]})
    assert resp.status_code == 200
    assert resp.json()["landing_route"] == "/"

    # Auditor sign in
    resp = client.post("/api/governance/auth/session", headers={"X-Operator-Token": tokens["auditor"]})
    assert resp.status_code == 200
    assert resp.json()["landing_route"] == "/records"


def test_view_tasks_scoping(role_env):
    client = role_env["client"]
    tokens = role_env["tokens"]

    # Developer sees only own runs (task_alex_core)
    resp = client.get("/api/governance/tasks", headers={"X-Operator-Token": tokens["dev"]})
    assert resp.status_code == 200
    task_ids = [t["task_id"] for t in resp.json()]
    assert "task_alex_core" in task_ids
    assert "task_other_finance" not in task_ids

    # Team lead sees all runs of own team "core" (task_alex_core)
    resp = client.get("/api/governance/tasks", headers={"X-Operator-Token": tokens["lead"]})
    assert resp.status_code == 200
    task_ids = [t["task_id"] for t in resp.json()]
    assert "task_alex_core" in task_ids
    assert "task_other_finance" not in task_ids

    # Reviewer, Admin, Auditor see all runs
    for role_name in ("reviewer", "admin", "auditor"):
        resp = client.get("/api/governance/tasks", headers={"X-Operator-Token": tokens[role_name]})
        assert resp.status_code == 200
        task_ids = [t["task_id"] for t in resp.json()]
        assert "task_alex_core" in task_ids
        assert "task_other_finance" in task_ids


def test_task_detail_permissions_and_403(role_env):
    client = role_env["client"]
    tokens = role_env["tokens"]

    # Developer requesting own task -> 200
    assert client.get("/api/governance/tasks/task_alex_core", headers={"X-Operator-Token": tokens["dev"]}).status_code == 200
    # Developer requesting other task -> 403
    assert client.get("/api/governance/tasks/task_other_finance", headers={"X-Operator-Token": tokens["dev"]}).status_code == 403


def test_approval_permissions_and_provenance_restriction(role_env):
    client = role_env["client"]
    tokens = role_env["tokens"]

    # 1. Developer cannot approve (403)
    resp = client.post("/api/governance/expansions/exp_routine_core/approve",
                       headers={"X-Operator-Token": tokens["dev"]},
                       json={"reason": "dev approve"})
    assert resp.status_code == 403

    # 2. Auditor cannot approve (403)
    resp = client.post("/api/governance/expansions/exp_routine_core/approve",
                       headers={"X-Operator-Token": tokens["auditor"]},
                       json={"reason": "auditor approve"})
    assert resp.status_code == 403

    # 3. Team lead can approve routine expansion of own team
    resp = client.post("/api/governance/expansions/exp_routine_core/approve",
                       headers={"X-Operator-Token": tokens["lead"]},
                       json={"reason": "lead routine approve"})
    assert resp.status_code == 200

    # 4. Team lead CANNOT approve expansion of other team (403)
    resp = client.post("/api/governance/expansions/exp_routine_finance/approve",
                       headers={"X-Operator-Token": tokens["lead"]},
                       json={"reason": "lead cross team"})
    assert resp.status_code == 403

    # 5. Team lead CANNOT approve provenance-escalated expansion even in own team! (403)
    resp = client.post("/api/governance/expansions/exp_escalated_core/approve",
                       headers={"X-Operator-Token": tokens["lead"]},
                       json={"reason": "lead escalated"})
    assert resp.status_code == 403

    # 6. Security reviewer CAN approve provenance-escalated expansion
    resp = client.post("/api/governance/expansions/exp_escalated_core/approve",
                       headers={"X-Operator-Token": tokens["reviewer"]},
                       json={"reason": "reviewer escalated approve"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "APPROVED"


def test_batch_decision_permissions_and_rejections(role_env):
    client = role_env["client"]
    tokens = role_env["tokens"]

    # Developer and Team Lead cannot batch decide (403)
    assert client.post("/api/governance/expansions/batch-approve",
                       headers={"X-Operator-Token": tokens["dev"]},
                       json={"request_ids": ["exp_routine_finance"]}).status_code == 403
    assert client.post("/api/governance/expansions/batch-approve",
                       headers={"X-Operator-Token": tokens["lead"]},
                       json={"request_ids": ["exp_routine_finance"]}).status_code == 403
    assert client.post("/api/governance/expansions/batch-approve",
                       headers={"X-Operator-Token": tokens["auditor"]},
                       json={"request_ids": ["exp_routine_finance"]}).status_code == 403

    # Provenance-escalated request in batch MUST be rejected with HTTP 400
    resp_esc = client.post("/api/governance/expansions/batch-approve",
                           headers={"X-Operator-Token": tokens["reviewer"]},
                           json={"request_ids": ["exp_escalated_core"]})
    assert resp_esc.status_code == 400
    assert "provenance-escalated" in resp_esc.json()["detail"].lower()

    # Routine batch approval succeeds for Reviewer and Admin
    resp_ok = client.post("/api/governance/expansions/batch-approve",
                          headers={"X-Operator-Token": tokens["reviewer"]},
                          json={"request_ids": ["exp_routine_finance"], "reason": "batch ok"})
    assert resp_ok.status_code == 200
    assert resp_ok.json()["approved_count"] == 1


def test_receipt_download_and_verify_scoping(role_env):
    client = role_env["client"]
    tokens = role_env["tokens"]

    # Developer can download / verify own task receipt
    resp = client.get("/api/governance/tasks/task_alex_core/receipt", headers={"X-Operator-Token": tokens["dev"]})
    assert resp.status_code == 200
    assert resp.json()["verified"] is True

    # Developer cannot download / verify other task receipt (403)
    resp_403 = client.get("/api/governance/tasks/task_other_finance/receipt", headers={"X-Operator-Token": tokens["dev"]})
    assert resp_403.status_code == 403

    # Auditor, Reviewer, Admin can verify any receipt
    assert client.get("/api/governance/tasks/task_alex_core/receipt", headers={"X-Operator-Token": tokens["auditor"]}).status_code == 200
    assert client.get("/api/governance/tasks/task_other_finance/receipt", headers={"X-Operator-Token": tokens["auditor"]}).status_code == 200
