"""Unit and integration tests for tenant-aware agent discovery."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
import pytest
from fastapi.testclient import TestClient

from demo.security_monitor.app.governance.discovery.host_scan import HostScanner
from demo.security_monitor.app.governance.discovery.repo_scan import RepoScanner
from demo.security_monitor.app.governance.discovery.models import (
    DiscoveredAgent,
    EvidenceItem,
    compute_discovery_id,
)
from demo.security_monitor.app.governance.inventory import AgentInventoryService
from demo.security_monitor.app.governance.models import (
    ExpansionRequest,
    ExpansionStatus,
    RiskTier,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.roles import Role, UserRecord, hash_token
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.gateway.server import create_app


@pytest.fixture
def test_storage(tmp_path: Path) -> GovernanceStorage:
    db_file = tmp_path / "test_governance.db"
    return GovernanceStorage(db_file)


def test_host_scan_fake_proc_and_privacy_rules(tmp_path: Path) -> None:
    proc_root = tmp_path / "proc"
    proc_root.mkdir()

    # PID 101: LangChain process with planted secrets
    p101 = proc_root / "101"
    p101.mkdir()
    cmdline_bytes = (
        b"python3\x00agent_worker.py\x00--token=PLANTED_TOKEN_SECRET_987\x00"
        b"--key=PLANTED_API_KEY_VAL_456\x00"
    )
    (p101 / "cmdline").write_bytes(cmdline_bytes)
    (p101 / "maps").write_text(
        "7f123000-7f124000 r-xp 00000000 08:01 12345 /usr/local/lib/python3.11/dist-packages/langchain/chains.py\n",
        encoding="utf-8",
    )
    environ_bytes = (
        b"OPENAI_API_KEY=sk-PLANTED_SECRET_OPENAI_KEY_VAL_12345\x00"
        b"ANTHROPIC_API_KEY=sk-ant-PLANTED_SECRET_ANTHROPIC_KEY_VAL_67890\x00"
        b"PATH=/usr/bin:/bin\x00"
    )
    (p101 / "environ").write_bytes(environ_bytes)
    fd_dir = p101 / "fd"
    fd_dir.mkdir()

    # PID 102: Unreadable process
    p102 = proc_root / "102"
    p102.mkdir()
    # No readable files in p102 to trigger unreadable handling

    # Fake home with MCP config containing secrets
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    mcp_data = {
        "mcpServers": {
            "sqlite-srv": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-sqlite", "--key", "SECRET_ARG_VALUE_999"],
                "env": {
                    "OPENAI_API_KEY": "sk-PLANTED_IN_MCP_CONFIG_111",
                    "DB_PASSWORD": "SECRET_PASSWORD_222",
                },
            }
        }
    }
    (fake_home / ".mcp.json").write_text(json.dumps(mcp_data), encoding="utf-8")

    scanner = HostScanner(
        proc_root=proc_root,
        home_dir=fake_home,
        host_name="test-host",
    )
    agents, unreadable, note = scanner.scan(org_id="tenant-alpha")

    # Assert unreadable process tracked
    assert unreadable >= 1
    assert scanner.unreadable_count >= 1

    # Verify kinds and frameworks
    kinds = {a.kind for a in agents}
    assert "process" in kinds
    assert "mcp_server" in kinds

    proc_agent = next(a for a in agents if a.kind == "process")
    assert "langchain" in proc_agent.frameworks
    assert "OPENAI_API_KEY" in proc_agent.key_names
    assert "ANTHROPIC_API_KEY" in proc_agent.key_names

    # PRIVACY CHECKS: Planted secret values must NEVER appear anywhere
    all_json = json.dumps([a.model_dump() for a in agents])
    forbidden_secret_values = [
        "PLANTED_TOKEN_SECRET_987",
        "PLANTED_API_KEY_VAL_456",
        "sk-PLANTED_SECRET_OPENAI_KEY_VAL_12345",
        "sk-ant-PLANTED_SECRET_ANTHROPIC_KEY_VAL_67890",
        "SECRET_ARG_VALUE_999",
        "sk-PLANTED_IN_MCP_CONFIG_111",
        "SECRET_PASSWORD_222",
    ]
    for secret in forbidden_secret_values:
        assert secret not in all_json, f"Secret leaked in output: {secret}"

    # Assert command lines capped at 300 chars
    for a in agents:
        for ev in a.evidence:
            if ev.signal == "process_cmdline":
                assert len(ev.detail) <= 300


def test_repo_scan_and_manifest_detection(tmp_path: Path) -> None:
    repo_dir = tmp_path / "sample_agent_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    # Requirements file
    reqs = "langgraph>=0.1.0\ncrewai==0.28.0\nrequests==2.31.0\n"
    (repo_dir / "requirements.txt").write_text(reqs, encoding="utf-8")

    # Package json
    pkg = {
        "name": "node-agent-hub",
        "dependencies": {
            "@modelcontextprotocol/sdk": "^0.6.0",
        },
    }
    (repo_dir / "package.json").write_text(json.dumps(pkg), encoding="utf-8")

    # Agent card
    card_dir = repo_dir / ".well-known"
    card_dir.mkdir()
    card_data = {
        "name": "Repo Agent Card",
        "description": "Card in repo",
        "skills": ["data_analysis"],
    }
    (card_dir / "agent.json").write_text(json.dumps(card_data), encoding="utf-8")

    scanner = RepoScanner(host_name="test-host")
    agents = scanner.scan_path(repo_dir, org_id="tenant-beta")

    assert len(agents) == 1
    agent = agents[0]
    assert agent.kind == "repo"
    assert agent.name == "sample_agent_repo"
    assert "langgraph" in agent.frameworks
    assert "crewai" in agent.frameworks
    assert "mcp" in agent.frameworks
    assert "a2a_agent" in agent.frameworks


def test_stable_fingerprints_across_rescans(tmp_path: Path, test_storage: GovernanceStorage) -> None:
    repo_dir = tmp_path / "fingerprint_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()
    (repo_dir / "requirements.txt").write_text("crewai==0.28.0\n", encoding="utf-8")

    scanner = RepoScanner(host_name="test-host")
    run1 = scanner.scan_path(repo_dir, org_id="default")
    run2 = scanner.scan_path(repo_dir, org_id="default")

    assert run1[0].discovery_id == run2[0].discovery_id

    # Upserting twice into database maintains one entry
    test_storage.upsert_discovered_agent(run1[0])
    test_storage.upsert_discovered_agent(run2[0])

    items = test_storage.list_discovered_agents(org_id="default")
    assert len(items) == 1
    assert items[0].discovery_id == run1[0].discovery_id


def test_tenant_org_id_scoping(test_storage: GovernanceStorage) -> None:
    agent_a = DiscoveredAgent(
        org_id="org_alpha",
        discovery_id="disc_alpha_1",
        host="host-a",
        kind="process",
        name="Alpha Bot",
        frameworks=["langchain"],
        status="shadow",
    )
    agent_b = DiscoveredAgent(
        org_id="org_beta",
        discovery_id="disc_beta_1",
        host="host-b",
        kind="process",
        name="Beta Bot",
        frameworks=["autogen"],
        status="shadow",
    )
    test_storage.save_discovered_agent(agent_a)
    test_storage.save_discovered_agent(agent_b)

    alpha_list = test_storage.list_discovered_agents(org_id="org_alpha")
    beta_list = test_storage.list_discovered_agents(org_id="org_beta")

    assert len(alpha_list) == 1
    assert alpha_list[0].discovery_id == "disc_alpha_1"
    assert alpha_list[0].name == "Alpha Bot"

    assert len(beta_list) == 1
    assert beta_list[0].discovery_id == "disc_beta_1"
    assert beta_list[0].name == "Beta Bot"


def test_retire_revoking_grants_and_tokens(test_storage: GovernanceStorage) -> None:
    # 1. Setup a task and registered tokens
    task_id = "task_retire_100"
    agent_id = "finance_runner"

    task = TaskRecord(
        task_id=task_id,
        agent_id=agent_id,
        request_text="Process financial reports",
        request_hash="req_hash_123",
        created_at="2026-11-20T10:00:00Z",
        workspace_root="/tmp/demo",
        status=TaskLifecycle.ACTIVE,
    )
    test_storage.save_task(task)

    # Issue an active token
    token_str = "tok_finance_123"
    test_storage.save_token(token_str, task_id, agent_id)

    # Create an approved expansion grant
    req = ExpansionRequest(
        request_id="req_grant_1",
        task_id=task_id,
        agent_id=agent_id,
        resource_type="file_read",
        resource_target="/etc/secret_data",
        justification="reading financial info",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.LOW,
        status=ExpansionStatus.APPROVED,
        created_at="2026-11-20T10:00:00Z",
    )
    test_storage.save_expansion_request(req)

    # Create discovered agent linked to finance_runner
    disc_agent = DiscoveredAgent(
        org_id="default",
        discovery_id="disc_fin_1",
        host="cluster-1",
        kind="process",
        name="Finance Runner Process",
        frameworks=["langchain"],
        status="governed",
        linked_agent_id=agent_id,
    )
    test_storage.save_discovered_agent(disc_agent)

    # 2. Retire the discovered agent
    retired = test_storage.retire_discovered_agent(
        org_id="default",
        discovery_id="disc_fin_1",
        retired_by="sec_admin",
    )

    assert retired is not None
    assert retired.retired_at is not None

    # Check tokens revoked (is_active == 0)
    with test_storage.get_connection() as conn:
        tok_row = conn.execute(
            "SELECT is_active, revoked_at FROM governance_tokens WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        assert tok_row is not None
        assert tok_row["is_active"] == 0
        assert tok_row["revoked_at"] is not None

    # Check expansion grant marked REVOKED
    exp = test_storage.get_expansion_request("req_grant_1")
    assert exp is not None
    assert exp.status == ExpansionStatus.REVOKED
    assert exp.reason == "Agent retired"


def test_api_roles_and_endpoints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_file = tmp_path / "api_gov.db"
    storage = GovernanceStorage(db_file)

    users_file = tmp_path / "users.json"
    users_data = [
        {"name": "DevUser", "role": "developer", "token_sha256": hash_token("dev-token")},
        {"name": "SecReviewer", "role": "security_reviewer", "token_sha256": hash_token("sec-token")},
        {"name": "AdminUser", "role": "admin", "token_sha256": hash_token("admin-token")},
    ]
    users_file.write_text(json.dumps(users_data), encoding="utf-8")

    monkeypatch.setenv("GOVERNANCE_USERS_FILE", str(users_file))
    monkeypatch.setenv("GOVERNANCE_STORAGE_PATH", str(db_file))
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db_file))

    from demo.security_monitor.app.governance import api as gov_api
    monkeypatch.setattr(gov_api, "_default_storage", storage)
    monkeypatch.setattr(gov_api, "_default_inventory", AgentInventoryService(storage))

    app = create_app()
    client = TestClient(app)

    # Seed an agent
    seed_agent = DiscoveredAgent(
        org_id="default",
        discovery_id="disc_api_test",
        host="localhost",
        kind="process",
        name="Seed Process",
        frameworks=["langgraph"],
        status="shadow",
    )
    storage.save_discovered_agent(seed_agent)

    # 1. Developer: can view agents
    res = client.get("/api/governance/discovery/agents", headers={"Authorization": "Bearer dev-token"})
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["discovery_id"] == "disc_api_test"

    # 2. Developer: cannot trigger scan (403)
    res = client.post("/api/governance/discovery/scan", headers={"Authorization": "Bearer dev-token"})
    assert res.status_code == 403

    # 3. Developer: cannot patch agent (403)
    res = client.patch(
        "/api/governance/discovery/agents/disc_api_test",
        headers={"Authorization": "Bearer dev-token"},
        json={"owner": "DevOps"},
    )
    assert res.status_code == 403

    # 4. Developer: cannot retire agent (403)
    res = client.post(
        "/api/governance/discovery/agents/disc_api_test/retire",
        headers={"Authorization": "Bearer dev-token"},
    )
    assert res.status_code == 403

    # 5. Security Reviewer: can patch agent
    res = client.patch(
        "/api/governance/discovery/agents/disc_api_test",
        headers={"Authorization": "Bearer sec-token"},
        json={"owner": "SecOps", "purpose": "Testing", "status": "known"},
    )
    assert res.status_code == 200
    patched = res.json()
    assert patched["owner"] == "SecOps"
    assert patched["purpose"] == "Testing"
    assert patched["status"] == "known"

    # 6. Admin: can trigger scan
    res = client.post("/api/governance/discovery/scan", headers={"Authorization": "Bearer admin-token"})
    assert res.status_code == 200
    scan_info = res.json()
    assert "scan_id" in scan_info
    assert scan_info["status"] == "RUNNING"

    # 7. Admin: can retire agent
    res = client.post(
        "/api/governance/discovery/agents/disc_api_test/retire",
        headers={"Authorization": "Bearer admin-token"},
        json={"reason": "Testing decommission"},
    )
    assert res.status_code == 200
    ret_agent = res.json()
    assert ret_agent["retired_at"] is not None
