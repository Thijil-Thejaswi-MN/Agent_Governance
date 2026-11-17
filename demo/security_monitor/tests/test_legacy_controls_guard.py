"""Audit finding A1: the older A2A monitor's control routes (/api/v1/*) changed state with
no credentials even when an operator token was configured (which is also what allows a
non-loopback bind). They now need the operator token header once a token is configured."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

CHANGES = [
    ("/api/v1/quarantine/apply", {"identity": "agent_victim", "reason": "x"}),
    ("/api/v1/quarantine/release", {"identity": "agent_victim"}),
    ("/api/v1/restriction/release", {"identity": "agent_victim"}),
    ("/api/v1/agents/agent_victim/monitoring", {"enabled": False}),
]


def _client(tmp_path: Path, monkeypatch, token: str | None) -> TestClient:
    from demo.security_monitor.app.gateway.server import create_app

    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(tmp_path / "g.db"))
    monkeypatch.setenv("RECEIPTS_DIR", str(tmp_path / "r"))
    monkeypatch.delenv("GOVERNANCE_USERS_FILE", raising=False)
    if token:
        monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", token)
    else:
        monkeypatch.delenv("GOVERNANCE_OPERATOR_TOKEN", raising=False)
    return TestClient(create_app())


def test_with_a_token_configured_changes_need_it(tmp_path: Path, monkeypatch) -> None:
    c = _client(tmp_path, monkeypatch, "tok_legacy")
    for path, body in CHANGES:
        assert c.post(path, json=body).status_code == 401, path
        assert c.post(path, json=body, headers={"X-Operator-Token": "wrong"}).status_code == 401, path
        assert c.post(path, json=body, headers={"X-Operator-Token": "tok_legacy"}).status_code != 401, path
    assert c.get("/api/v1/status").status_code == 200  # reads are unchanged


def test_without_a_token_the_loopback_only_server_is_unchanged(tmp_path: Path, monkeypatch) -> None:
    c = _client(tmp_path, monkeypatch, None)
    for path, body in CHANGES:
        assert c.post(path, json=body).status_code != 401, path
