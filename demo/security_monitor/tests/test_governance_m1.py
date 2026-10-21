"""Milestone 1 Test Suite: Core Task-Aware Governance Loop at the Tool Layer.

Tests:
1. F1 Task Intake & SHA-256 Request Integrity
2. F2 Service Catalog & Template Boundary Derivation
3. F3 Contract Path Normalization & Default Deny
4. F6 Token-Based Task Attribution & Revocation
5. F7 Boundary Evaluator (Files, Network, Tools, Commands)
6. F5.1 Tool Broker Real-Time Prevention (Prevention vs Detection)
7. F9 Graduated Response Policy & Escalation
8. F4 / F13.1 Process-Per-Task Runner & Scripted Agent End-to-End
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
import pytest

from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    EventVerdict,
    RiskTier,
    TaskAction,
    TaskLifecycle,
    EventSource,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.catalog import BoundaryDerivationV1, ServiceCatalog
from demo.security_monitor.app.governance.evaluator import BoundaryEvaluator
from demo.security_monitor.app.governance.policy import TaskPolicyEngine
from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.runner import ProcessAgentRunner
from demo.security_monitor.app.governance.scripted_agent import ScriptedAgentRunner


@pytest.fixture
def test_storage(tmp_path: Path) -> GovernanceStorage:
    db_file = tmp_path / "test_governance.db"
    return GovernanceStorage(db_file)


@pytest.fixture
def test_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    (ws / "input").mkdir(parents=True)
    (ws / "output").mkdir(parents=True)
    (ws / "input" / "report.pdf").write_text("Quarterly Governance Report Content: All clear.")
    (ws / "credentials.json").write_text('{"api_key": "SECRET_SHOULD_NEVER_BE_READ"}')
    return ws


# --- Test 1: Task Intake & Integrity ---
def test_task_intake_and_hash(test_storage: GovernanceStorage, test_workspace: Path) -> None:
    intake = TaskIntakeService(test_storage)
    request_text = "Analyse report.pdf and write summary.txt"
    task, boundary = intake.submit_task(
        request_text=request_text,
        agent_id="agent_doc_summarizer",
        workspace_root=str(test_workspace),
    )

    expected_hash = hashlib.sha256(request_text.encode("utf-8")).hexdigest()
    assert task.request_hash == expected_hash
    assert task.status == TaskLifecycle.PENDING
    assert task.current_boundary_version == 1
    assert boundary.task_id == task.task_id
    assert boundary.enforcement_mode == EnforcementMode.ENFORCE


# --- Test 2: Boundary Derivation Templates ---
def test_boundary_derivation_templates(test_workspace: Path) -> None:
    deriv = BoundaryDerivationV1()
    boundary = deriv.derive(
        task_id="task_test_001",
        request_text="Please analyse quarterly report.pdf and write the executive summary.txt",
        workspace_root=str(test_workspace),
    )

    assert "read_file" in boundary.tools
    assert "write_file" in boundary.tools
    assert any("report.pdf" in f for f in boundary.files_read)
    assert any("summary.txt" in f for f in boundary.files_write)
    assert boundary.network == []  # Default deny network
    assert boundary.peer_agents == []  # Default deny peer agents


# --- Test 3: Token-Based Attribution & Revocation ---
def test_token_attribution_and_revocation(test_storage: GovernanceStorage, test_workspace: Path) -> None:
    broker = ToolBroker(test_storage)
    intake = TaskIntakeService(test_storage)
    task, boundary = intake.submit_task("Analyse doc", "agent_alice", str(test_workspace))

    # Save active token
    token = "gov_tok_test_secret_123"
    test_storage.save_token(token, task.task_id, task.agent_id)

    # Valid token lookup
    res = test_storage.lookup_task_by_token(token)
    assert res == (task.task_id, "agent_alice")

    # Invalid token lookup
    assert test_storage.lookup_task_by_token("gov_tok_invalid") is None

    # Revoke token
    test_storage.revoke_token(token)
    assert test_storage.lookup_task_by_token(token) is None

    # Broker call with revoked token raises PermissionError and records UNATTRIBUTED event
    with pytest.raises(PermissionError, match="Invalid or revoked"):
        broker.read_file(token, "input/report.pdf")

    events = test_storage.get_events_for_task(task.task_id)
    # The unattributed event has task_id = None
    with test_storage.get_connection() as conn:
        unattributed_events = conn.execute("SELECT * FROM governance_events WHERE task_id IS NULL").fetchall()
        assert len(unattributed_events) >= 1
        assert unattributed_events[0]["agent_id"] == "UNATTRIBUTED"


# --- Test 4: Broker Prevention on File Reads & Writes ---
def test_broker_file_prevention(test_storage: GovernanceStorage, test_workspace: Path) -> None:
    intake = TaskIntakeService(test_storage)
    task, boundary = intake.submit_task(
        request_text="Analyse report.pdf and write summary.txt",
        agent_id="agent_doc_summarizer",
        workspace_root=str(test_workspace),
    )
    token = "gov_tok_test_456"
    test_storage.save_token(token, task.task_id, task.agent_id)

    broker = ToolBroker(test_storage)

    # 1. Benign Read: Authorized file
    data = broker.read_file(token, "input/report.pdf")
    assert "Quarterly Governance Report" in data

    # 2. Benign Write: Authorized output
    bytes_written = broker.write_file(token, "output/summary.txt", "Report Summary")
    assert bytes_written > 0
    assert (test_workspace / "output" / "summary.txt").exists()

    # 3. Violation Read: Sensitive credentials.json (PREVENTED BEFORE READ)
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.read_file(token, "credentials.json")

    # 4. Violation Read: Directory escape (PREVENTED BEFORE READ)
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.read_file(token, "../../some_external_file.txt")

    # Verify audit events
    events = test_storage.get_events_for_task(task.task_id)
    assert len(events) >= 4

    benign_read_evt = next(e for e in events if e.target == "input/report.pdf")
    assert benign_read_evt.verdict == EventVerdict.INSIDE
    assert benign_read_evt.action_taken == TaskAction.ALLOW
    assert benign_read_evt.prevented is False

    cred_evt = next(e for e in events if e.target == "credentials.json")
    assert cred_evt.verdict == EventVerdict.OUTSIDE
    assert cred_evt.risk_tier == RiskTier.HIGH
    assert cred_evt.action_taken == TaskAction.BLOCK_ACTION
    assert cred_evt.prevented is True  # Real-time prevention!


# --- Test 5: Broker Prevention on Network Egress ---
def test_broker_network_prevention(test_storage: GovernanceStorage, test_workspace: Path) -> None:
    intake = TaskIntakeService(test_storage)
    task, boundary = intake.submit_task("Analyse report.pdf", "agent_alice", str(test_workspace))
    token = "gov_tok_test_789"
    test_storage.save_token(token, task.task_id, task.agent_id)

    broker = ToolBroker(test_storage)

    # Outbound to example.com is not in boundary -> BLOCKED BEFORE CONNECT
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.http_get(token, "https://example.com/api/exfil")

    events = test_storage.get_events_for_task(task.task_id)
    net_evt = next(e for e in events if "example.com" in e.target)
    assert net_evt.verdict == EventVerdict.OUTSIDE
    assert net_evt.action_taken == TaskAction.BLOCK_ACTION
    assert net_evt.prevented is True


# --- Test 6: Broker Command Restriction in M1 ---
def test_broker_command_restriction(test_storage: GovernanceStorage, test_workspace: Path) -> None:
    intake = TaskIntakeService(test_storage)
    task, boundary = intake.submit_task("Analyse report.pdf", "agent_alice", str(test_workspace))
    token = "gov_tok_cmd_001"
    test_storage.save_token(token, task.task_id, task.agent_id)

    broker = ToolBroker(test_storage)

    # In M1, command execution must be denied by default
    with pytest.raises(PermissionError, match="unmediated execution not supported until OS enforcement"):
        broker.run_command(token, "cat credentials.json")

    events = test_storage.get_events_for_task(task.task_id)
    cmd_evt = next(e for e in events if e.kind == "run_command")
    assert cmd_evt.action_taken == TaskAction.BLOCK_ACTION
    assert cmd_evt.prevented is True


# --- Test 7: Observe vs Enforce Mode ---
def test_observe_vs_enforce_mode(test_storage: GovernanceStorage, test_workspace: Path) -> None:
    intake = TaskIntakeService(test_storage)
    # Create task with OBSERVE mode
    task, boundary = intake.submit_task(
        "Analyse report.pdf",
        "agent_alice",
        str(test_workspace),
        enforcement_mode=EnforcementMode.OBSERVE,
    )
    token = "gov_tok_observe_001"
    test_storage.save_token(token, task.task_id, task.agent_id)

    broker = ToolBroker(test_storage)

    # Reading credentials.json in OBSERVE mode is NOT blocked (prevented=False), but logged/alerted
    content = broker.read_file(token, "credentials.json")
    assert "SECRET_SHOULD_NEVER_BE_READ" in content

    events = test_storage.get_events_for_task(task.task_id)
    evt = next(e for e in events if e.target == "credentials.json")
    assert evt.verdict == EventVerdict.OUTSIDE
    assert evt.action_taken == TaskAction.ALERT
    assert evt.prevented is False  # In OBSERVE mode, prevented is NEVER true!


# --- Test 8: Scripted Agent Scenario End-to-End ---
def test_scripted_agent_end_to_end(test_storage: GovernanceStorage, test_workspace: Path) -> None:
    intake = TaskIntakeService(test_storage)
    task, boundary = intake.submit_task(
        request_text="Analyse report.pdf and write summary.txt",
        agent_id="agent_doc_summarizer",
        workspace_root=str(test_workspace),
    )
    token = "gov_tok_scripted_agent_001"
    test_storage.save_token(token, task.task_id, task.agent_id)

    broker = ToolBroker(test_storage)
    agent = ScriptedAgentRunner(broker, token)

    results = agent.run_scenario(
        input_doc="input/report.pdf",
        output_doc="output/summary.txt",
    )

    # Assertions
    assert results["benign_read_success"] is True
    assert results["benign_write_success"] is True
    assert results["credential_read_blocked"] is True
    assert results["network_connect_blocked"] is True
    assert results["unrelated_agent_blocked"] is True
    assert results["run_command_blocked"] is True
    assert results["violations_prevented"] == 4

    # Assert summary file was created by benign write
    assert (test_workspace / "output" / "summary.txt").exists()

    # Assert audit trail stored in governance.db
    events = test_storage.get_events_for_task(task.task_id)
    assert len(events) >= 6

    # Verify prevented counts vs allowed counts
    prevented_count = sum(1 for e in events if e.prevented)
    allowed_count = sum(1 for e in events if e.action_taken == TaskAction.ALLOW)
    assert prevented_count == 4
    assert allowed_count == 2
