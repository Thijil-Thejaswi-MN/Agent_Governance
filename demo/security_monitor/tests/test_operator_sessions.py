"""Read endpoints require credentials: the operator token header or a session cookie.

- POST /auth/session (token header) sets an HttpOnly, SameSite=Strict, path=/api cookie
  holding a random server-side session id that expires after 8 h; DELETE logs out.
- Every /api/governance route needs the token header or (reads only) a valid session;
  /auth/status, /auth/session and /system/status are public.
- Mutations need the token header: a cookie alone is refused.
- A non-loopback bind without GOVERNANCE_OPERATOR_TOKEN refuses to start.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from demo.security_monitor.app.gateway.server import create_app, resolve_bind_host
from demo.security_monitor.app.governance import api as gov_api
from demo.security_monitor.app.governance.models import TaskLifecycle, TaskRecord
from demo.security_monitor.app.governance.storage import GovernanceStorage

TOKEN = "test_session_token"
HEADERS = {"X-Operator-Token": TOKEN}

READ_PATHS = [
    "/api/governance/tasks",
    "/api/governance/tasks/task_sess/events",
    "/api/governance/tasks/task_sess/receipt",
    "/api/governance/events",
    "/api/governance/expansions",
    "/api/governance/inventory",
    "/api/governance/alerts",
    "/api/governance/config",
    "/api/governance/run/presets",
    "/api/governance/run/active",
    "/api/governance/run/task_sess/steps",
    "/api/governance/run/task_sess/output",
]


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    db = tmp_path / "gov.db"
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db))
    monkeypatch.setenv("RECEIPTS_DIR", str(tmp_path / "receipts"))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", TOKEN)
    storage = GovernanceStorage(db)
    storage.save_task(TaskRecord(task_id="task_sess", request_text="secret prompt", request_hash="h",
                                 agent_id="a", workspace_root=str(tmp_path), status=TaskLifecycle.COMPLETED,
                                 created_at="2026-10-28T10:00:00Z"))
    storage.record_task_step("task_sess", kind="phase", layer="intake", verdict="ALLOW",
                             summary="Boundary derived", source_label="enforced")
    yield TestClient(create_app())
    with gov_api._sessions_lock:
        gov_api._sessions.clear()


def _sign_in(client: TestClient):
    resp = client.post("/api/governance/auth/session", headers=HEADERS)
    assert resp.status_code == 200
    return resp


@pytest.mark.parametrize("path", READ_PATHS)
def test_reads_without_credentials_are_401(client, path):
    resp = client.get(path)
    assert resp.status_code == 401, (path, resp.text)


def test_reads_with_session_cookie_are_200(client):
    _sign_in(client)
    for path in READ_PATHS:
        resp = client.get(path)
        assert resp.status_code == 200, (path, resp.text)
    assert client.get("/api/governance/tasks").json()[0]["request_text"] == "secret prompt"


def test_session_cookie_attributes(client):
    resp = _sign_in(client)
    cookie = resp.headers["set-cookie"]
    attrs = [a.strip().lower() for a in cookie.split(";")]
    assert attrs[0].startswith(f"{gov_api.SESSION_COOKIE}=")
    session_id = cookie.split(";")[0].split("=", 1)[1]
    assert len(session_id) >= 32 and session_id != TOKEN
    assert "httponly" in attrs
    assert "samesite=strict" in attrs
    assert "path=/api" in attrs
    assert f"max-age={8 * 3600}" in attrs
    assert session_id in gov_api._sessions


def test_session_requires_valid_token_header(client):
    assert client.post("/api/governance/auth/session").status_code == 401
    assert client.post("/api/governance/auth/session", headers={"X-Operator-Token": "wrong"}).status_code == 401
    assert gov_api._sessions == {}


def test_reads_with_token_header_are_200(client):
    assert client.get("/api/governance/tasks", headers=HEADERS).status_code == 200
    assert client.get("/api/governance/tasks", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200
    assert client.get("/api/governance/tasks", headers={"X-Operator-Token": "wrong"}).status_code == 401


def test_sse_stream_with_cookie_streams(client):
    assert client.get("/api/governance/run/task_sess/stream").status_code == 401
    _sign_in(client)
    with client.stream("GET", "/api/governance/run/task_sess/stream") as resp:
        assert resp.status_code == 200
        lines = [line for line in resp.iter_lines() if line.startswith(("data: ", "event: "))]
    assert json.loads(lines[0][6:])["summary"] == "Boundary derived"
    assert "event: end" in lines


def test_mutation_with_cookie_but_no_header_is_401(client):
    _sign_in(client)
    assert client.get("/api/governance/tasks").status_code == 200  # cookie works for reads
    for path, body in [
        ("/api/governance/run", {"prompt": "x", "model": "scripted"}),
        ("/api/governance/run/task_sess/stop", None),
        ("/api/governance/run/preview", {"prompt": "x"}),
        ("/api/governance/expansions/exp_x/approve", {"reason": "r"}),
        ("/api/governance/expansions/exp_x/deny", {"reason": "r"}),
        ("/api/governance/tasks/task_sess/grant", {"granted_by": "o", "resource_type": "file_read",
                                                    "resource_target": "input/a.txt"}),
        ("/api/governance/tasks", {"request_text": "x", "agent_id": "a"}),
        ("/api/governance/expansions/request", {"task_id": "t", "agent_id": "a", "resource_type": "file_read",
                                                "resource_target": "input/a.txt", "justification": "j"}),
    ]:
        resp = client.post(path, json=body)
        assert resp.status_code == 401, (path, resp.text)


def test_expired_session_is_401(client):
    _sign_in(client)
    assert client.get("/api/governance/tasks").status_code == 200
    with gov_api._sessions_lock:
        for sid in gov_api._sessions:
            gov_api._sessions[sid] = time.time() - 1
    assert client.get("/api/governance/tasks").status_code == 401
    assert gov_api._sessions == {}


def test_logout_invalidates_session(client):
    _sign_in(client)
    assert client.get("/api/governance/tasks").status_code == 200
    sid = client.cookies.get(gov_api.SESSION_COOKIE)
    resp = client.delete("/api/governance/auth/session")
    assert resp.status_code == 200
    assert sid not in gov_api._sessions
    # Even if a client kept the old cookie value, the server no longer knows it.
    client.cookies.set(gov_api.SESSION_COOKIE, sid, path="/api")
    assert client.get("/api/governance/tasks").status_code == 401


def test_public_endpoints_need_no_credentials(client):
    assert client.get("/api/governance/auth/status").status_code == 200
    assert client.get("/api/governance/system/status").status_code == 200
    assert client.get("/api/governance/auth/status").json()["session_active"] is False
    _sign_in(client)
    assert client.get("/api/governance/auth/status").json()["session_active"] is True


def test_reads_refused_when_token_not_configured(client, monkeypatch):
    monkeypatch.delenv("GOVERNANCE_OPERATOR_TOKEN")
    assert client.get("/api/governance/tasks").status_code == 403
    assert client.get("/api/governance/auth/status").json()["operator_token_configured"] is False


# ---------------------------------------------------------------------------
# Startup bind policy
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "127.0.0.5"])
def test_loopback_bind_without_token_is_allowed(host, monkeypatch):
    monkeypatch.delenv("GOVERNANCE_OPERATOR_TOKEN", raising=False)
    gov_api.enforce_bind_policy(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.20", "example.org"])
def test_non_loopback_bind_without_token_refuses(host, monkeypatch):
    monkeypatch.delenv("GOVERNANCE_OPERATOR_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="not loopback"):
        gov_api.enforce_bind_policy(host)
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "set")
    gov_api.enforce_bind_policy(host)


def test_resolve_bind_host_reads_uvicorn_cli_and_env(monkeypatch):
    monkeypatch.delenv("GATEWAY_HOST", raising=False)
    assert resolve_bind_host(["uvicorn", "app:app", "--host", "0.0.0.0"]) == "0.0.0.0"
    assert resolve_bind_host(["uvicorn", "app:app", "--host=::"]) == "::"
    assert resolve_bind_host(["uvicorn", "app:app"]) == "127.0.0.1"
    monkeypatch.setenv("GATEWAY_HOST", "10.0.0.2")
    assert resolve_bind_host(["python"]) == "10.0.0.2"


def test_app_startup_refuses_open_bind_without_token(monkeypatch):
    monkeypatch.delenv("GOVERNANCE_OPERATOR_TOKEN", raising=False)
    monkeypatch.setenv("GATEWAY_HOST", "0.0.0.0")
    monkeypatch.setattr("sys.argv", ["pytest"])
    with pytest.raises(RuntimeError, match="Refusing to start"):
        with TestClient(create_app()):
            pass
