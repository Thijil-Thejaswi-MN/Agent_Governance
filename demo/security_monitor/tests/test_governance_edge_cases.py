"""Milestone 1 Edge-Case Test Suite (Prompt Additions A).

Evaluates path traversal, case variants, symlinks pointing outside, trailing dots/spaces,
URL userinfo spoofing, raw IP literals, port differences, and redirect hijacking.
"""
from __future__ import annotations

import os
from pathlib import Path
import pytest

from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    EventVerdict,
    RiskTier,
    TaskAction,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.evaluator import BoundaryEvaluator
from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.intake import TaskIntakeService


@pytest.fixture
def edge_storage(tmp_path: Path) -> GovernanceStorage:
    db_file = tmp_path / "edge_governance.db"
    return GovernanceStorage(db_file)


@pytest.fixture
def edge_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "edge_ws"
    (ws / "input").mkdir(parents=True)
    (ws / "output").mkdir(parents=True)
    (ws / "input" / "report.pdf").write_text("Quarterly Report Content")
    (ws / "credentials.json").write_text("SUPER_SECRET_TOKEN")
    
    # External secret outside workspace
    ext_dir = tmp_path / "external_system"
    ext_dir.mkdir(parents=True)
    ext_secret = ext_dir / "external_secret.txt"
    ext_secret.write_text("EXTERNAL_TOP_SECRET")

    # Create symlink inside workspace pointing outside
    try:
        symlink_path = ws / "input" / "symlink_escape.txt"
        symlink_path.symlink_to(ext_secret)
    except (OSError, NotImplementedError):
        # On Windows without developer mode/admin symlink privileges, test might skip symlink creation
        pass

    return ws


# --- 1. PATH EDGE CASES ---

def test_path_traversal_dot_dot(edge_storage: GovernanceStorage, edge_workspace: Path) -> None:
    intake = TaskIntakeService(edge_storage)
    task, boundary = intake.submit_task("Analyse report.pdf", "agent_alice", str(edge_workspace))
    token = "tok_edge_001"
    edge_storage.save_token(token, task.task_id, task.agent_id)
    broker = ToolBroker(edge_storage)

    # Path traversal: "input/../credentials.json" resolves to "credentials.json"
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.read_file(token, "input/../credentials.json")


def test_absolute_paths(edge_storage: GovernanceStorage, edge_workspace: Path) -> None:
    intake = TaskIntakeService(edge_storage)
    task, boundary = intake.submit_task("Analyse report.pdf", "agent_alice", str(edge_workspace))
    token = "tok_edge_002"
    edge_storage.save_token(token, task.task_id, task.agent_id)
    broker = ToolBroker(edge_storage)

    # 1. Absolute path INSIDE workspace -> allowed if matches boundary pattern
    abs_inside = str((edge_workspace / "input" / "report.pdf").resolve())
    data = broker.read_file(token, abs_inside)
    assert "Quarterly Report" in data

    # 2. Absolute path OUTSIDE workspace -> blocked
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.read_file(token, "C:/Windows/System32/drivers/etc/hosts" if os.name == "nt" else "/etc/passwd")


def test_case_insensitive_variants(edge_storage: GovernanceStorage, edge_workspace: Path) -> None:
    intake = TaskIntakeService(edge_storage)
    task, boundary = intake.submit_task("Analyse report.pdf", "agent_alice", str(edge_workspace))
    token = "tok_edge_003"
    edge_storage.save_token(token, task.task_id, task.agent_id)
    broker = ToolBroker(edge_storage)

    # Mixed case sensitive credential filename must be blocked
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.read_file(token, "Credentials.JSON")

    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.read_file(token, "CREDENTIALS.json")

    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.read_file(token, "input/../CREDENTIALS.json")


def test_symlink_pointing_outside_workspace(edge_storage: GovernanceStorage, edge_workspace: Path) -> None:
    intake = TaskIntakeService(edge_storage)
    task, boundary = intake.submit_task("Analyse report.pdf", "agent_alice", str(edge_workspace))
    token = "tok_edge_004"
    edge_storage.save_token(token, task.task_id, task.agent_id)
    broker = ToolBroker(edge_storage)

    symlink_path = edge_workspace / "input" / "symlink_escape.txt"
    if symlink_path.exists():
        # Live filesystem symlink exists
        with pytest.raises(PermissionError, match="denied by boundary"):
            broker.read_file(token, "input/symlink_escape.txt")
    else:
        # On Windows unprivileged environments without symlink privilege, test realpath dereferencing
        from unittest.mock import patch
        fake_symlink = edge_workspace / "input" / "virtual_symlink.txt"
        fake_symlink.write_text("dummy")
        outside_target = str((edge_workspace.parent / "outside_doc.txt").resolve())
        orig_realpath = os.path.realpath
        
        def mock_realpath(path, *args, **kwargs):
            if "virtual_symlink" in str(path):
                return outside_target
            return orig_realpath(path, *args, **kwargs)

        with patch("os.path.realpath", side_effect=mock_realpath):
            with pytest.raises(PermissionError, match="path escapes task workspace_root"):
                broker.read_file(token, "input/virtual_symlink.txt")
        if fake_symlink.exists():
            fake_symlink.unlink()


def test_trailing_dots_and_spaces_windows(edge_storage: GovernanceStorage, edge_workspace: Path) -> None:
    intake = TaskIntakeService(edge_storage)
    task, boundary = intake.submit_task("Analyse report.pdf", "agent_alice", str(edge_workspace))
    token = "tok_edge_005"
    edge_storage.save_token(token, task.task_id, task.agent_id)
    broker = ToolBroker(edge_storage)

    # Trailing dot evasion: "credentials.json."
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.read_file(token, "credentials.json.")

    # Trailing space evasion: "credentials.json "
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.read_file(token, "credentials.json ")


# --- 2. URL & NETWORK EDGE CASES ---

def test_url_userinfo_evasion(edge_storage: GovernanceStorage, edge_workspace: Path) -> None:
    intake = TaskIntakeService(edge_storage)
    task, boundary = intake.submit_task("Analyse report.pdf", "agent_alice", str(edge_workspace))
    # Grant allowed.host:80 to boundary
    boundary.network = ["allowed.host:80", "allowed.host:443"]
    edge_storage.save_boundary(boundary)

    token = "tok_edge_006"
    edge_storage.save_token(token, task.task_id, task.agent_id)
    broker = ToolBroker(edge_storage)

    # Case 1: "http://example.com@allowed.host/" -> Actual destination is allowed.host -> INSIDE
    res = broker.http_get(token, "http://example.com@allowed.host/")
    assert res["status"] == 200

    # Case 2: "http://allowed.host@example.com/" -> Actual destination is example.com -> OUTSIDE, BLOCKED!
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.http_get(token, "http://allowed.host@example.com/")


def test_raw_ip_literals_and_ipv6(edge_storage: GovernanceStorage, edge_workspace: Path) -> None:
    intake = TaskIntakeService(edge_storage)
    task, boundary = intake.submit_task("Analyse report.pdf", "agent_alice", str(edge_workspace))
    boundary.network = ["127.0.0.1:8000"]
    edge_storage.save_boundary(boundary)

    token = "tok_edge_007"
    edge_storage.save_token(token, task.task_id, task.agent_id)
    broker = ToolBroker(edge_storage)

    # Allowed IPv4 host:port
    res = broker.http_get(token, "http://127.0.0.1:8000/status")
    assert res["status"] == 200

    # Disallowed IPv4 literal
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.http_get(token, "http://192.168.1.1:8000/status")

    # Disallowed IPv6 literal
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.http_get(token, "http://[::1]:9999/status")


def test_uppercase_host_and_port_differentiation(edge_storage: GovernanceStorage, edge_workspace: Path) -> None:
    intake = TaskIntakeService(edge_storage)
    task, boundary = intake.submit_task("Analyse report.pdf", "agent_alice", str(edge_workspace))
    boundary.network = ["allowed.host:443"]
    edge_storage.save_boundary(boundary)

    token = "tok_edge_008"
    edge_storage.save_token(token, task.task_id, task.agent_id)
    broker = ToolBroker(edge_storage)

    # 1. Uppercase host -> Allowed (case-insensitive)
    res = broker.http_get(token, "https://ALLOWED.HOST/")
    assert res["status"] == 200

    # 2. Port differentiation: 443 is allowed, but 8443 is NOT
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.http_get(token, "https://allowed.host:8443/")


def test_http_redirect_to_non_allowed_host(edge_storage: GovernanceStorage, edge_workspace: Path) -> None:
    intake = TaskIntakeService(edge_storage)
    task, boundary = intake.submit_task("Analyse report.pdf", "agent_alice", str(edge_workspace))
    boundary.network = ["allowed.host:443"]
    edge_storage.save_boundary(boundary)

    token = "tok_edge_009"
    edge_storage.save_token(token, task.task_id, task.agent_id)
    broker = ToolBroker(edge_storage)

    # Initial request to allowed host
    orig_url = "https://allowed.host/resource"
    res = broker.http_get(token, orig_url)
    assert res["status"] == 200

    # Server responds with 302 redirect to unauthorized host: evil.com
    # Broker must re-check redirect hop and block it!
    with pytest.raises(PermissionError, match="denied by boundary"):
        broker.handle_http_redirect(token, orig_url, "https://evil.com/exfiltrate")
