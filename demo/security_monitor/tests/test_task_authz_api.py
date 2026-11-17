"""Who may ask, grant and read for a task through the web API (independent audit #2).

F-01: POST /expansions/request and /expansions/request_and_wait need the right to control
the task, and the agent named must be the task's agent. POST /tasks/{id}/grant records the
signed-in user, never a name from the body, and a HIGH-risk grant needs an admin or a
security reviewer.
F-05: the reads that list task data (events, fleet, requests, inbox, steps) show only the
runs the user may see.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from demo.security_monitor.app.gateway.server import create_app
from demo.security_monitor.app.governance import api as gov_api
from demo.security_monitor.app.governance.models import (
    EventSource,
    EventVerdict,
    ExpansionRequest,
    ExpansionStatus,
    GovernanceEvent,
    RiskTier,
    TaskAction,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage

ADMIN = {"X-Operator-Token": "admin_tok_authz"}
USERS = {
    "lead_core": ("Lee Lead", "team_lead", "core"),
    "lead_other": ("Olga Other", "team_lead", "other"),
    "dev_owner": ("Dev Owner", "developer", "core"),
    "dev_else": ("Dev Else", "developer", "core"),
    "auditor": ("Ada Auditor", "auditor", None),
    "reviewer": ("Rae Reviewer", "security_reviewer", None),
}


def H(who: str) -> dict[str, str]:
    return {"X-Operator-Token": f"tok_{who}"}


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "input").mkdir(parents=True)
    (ws / "output").mkdir()
    users = tmp_path / "users.json"
    users.write_text(json.dumps([
        {"name": n, "role": r, "team": t, "token_sha256": hashlib.sha256(f"tok_{k}".encode()).hexdigest()}
        for k, (n, r, t) in USERS.items()
    ]))
    db = tmp_path / "gov.db"
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db))
    monkeypatch.setenv("RECEIPTS_DIR", str(tmp_path / "receipts"))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", ADMIN["X-Operator-Token"])
    monkeypatch.setenv("GOVERNANCE_OPERATOR_NAME", "admin_ana")
    monkeypatch.setenv("GOVERNANCE_USERS_FILE", str(users))
    monkeypatch.delenv("GOVERNANCE_STANDING_RULES", raising=False)
    storage = GovernanceStorage(db)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for tid, team, owner in (("t_core", "core", "Dev Owner"), ("t_other", "other", "Someone")):
        storage.save_task(TaskRecord(task_id=tid, request_text="Summarise input/a.txt", request_hash="h",
                                     agent_id="notes_bot", workspace_root=str(ws), status=TaskLifecycle.ACTIVE,
                                     created_at=now, team=team, owner=owner))
        storage.save_boundary(TaskBoundary(task_id=tid, workspace_root=str(ws)))
        storage.record_event(GovernanceEvent(
            event_id=f"ev_{tid}", timestamp=now, source=EventSource.TOOL_BROKER, task_id=tid, agent_id="notes_bot",
            kind="file_read", target=f"input/{tid}.txt", details={}, verdict=EventVerdict.INSIDE,
            risk_tier=RiskTier.LOW, action_taken=TaskAction.LOG, prevented=False, rule_matched="test"))
        storage.save_expansion_request(ExpansionRequest(
            request_id=f"exp_{tid}", task_id=tid, agent_id="notes_bot", resource_type="file_read",
            resource_target="docs/notes.txt", justification="j", baseline_risk_tier=RiskTier.MEDIUM,
            effective_risk_tier=RiskTier.MEDIUM, escalated_by_provenance=False, status=ExpansionStatus.PENDING,
            created_at=now))
    with gov_api._standing_rules_lock:
        gov_api._standing_rules.clear()
        gov_api._standing_rules_loaded_from.clear()
    yield TestClient(create_app()), storage
    with gov_api._sessions_lock:
        gov_api._sessions.clear()


def _ask(c, headers, task_id="t_core", agent_id="notes_bot", target="docs/other.txt"):
    return c.post("/api/governance/expansions/request", headers=headers,
                  json={"task_id": task_id, "agent_id": agent_id, "resource_type": "file_read",
                        "resource_target": target, "justification": "j", "provenance_enabled": False})


# --- F-01: asking on a task's behalf -----------------------------------------------------

def test_request_needs_control_of_the_task(env):
    c, _ = env
    assert _ask(c, ADMIN).status_code == 200
    assert _ask(c, H("lead_core")).status_code == 200
    assert _ask(c, H("dev_owner")).status_code == 200
    for who in ("lead_other", "dev_else", "auditor", "reviewer"):
        assert _ask(c, H(who)).status_code == 403, who


def test_request_names_the_tasks_own_agent(env):
    c, _ = env
    r = _ask(c, ADMIN, agent_id="other_bot")
    assert r.status_code == 400 and "not the agent" in r.json()["detail"]
    assert _ask(c, ADMIN, task_id="t_missing").status_code == 404


def test_request_and_wait_has_the_same_check(env):
    c, _ = env
    r = c.post("/api/governance/expansions/request_and_wait", headers=H("lead_other"),
               json={"task_id": "t_core", "agent_id": "notes_bot", "resource_type": "file_read",
                     "resource_target": "input/a.txt", "justification": "j", "timeout_seconds": 0.1})
    assert r.status_code == 403


# --- F-01: granting before the agent asks ------------------------------------------------

def _grant(c, headers, target="docs/plan.txt", task_id="t_core", granted_by="someone_else"):
    return c.post(f"/api/governance/tasks/{task_id}/grant", headers=headers,
                  json={"granted_by": granted_by, "resource_type": "file_read", "resource_target": target})


def test_grant_records_the_signed_in_user_not_the_body(env):
    c, storage = env
    r = _grant(c, H("lead_core"))
    assert r.status_code == 200, r.text
    grants = [x for x in storage.list_expansion_requests(task_id="t_core") if x.resource_target == "docs/plan.txt"]
    assert grants and grants[-1].resolved_by == "team_lead:Lee Lead"
    assert "someone_else" not in grants[-1].justification
    r = _grant(c, ADMIN, target="docs/plan2.txt", granted_by=None)
    assert r.status_code == 200
    grants = [x for x in storage.list_expansion_requests(task_id="t_core") if x.resource_target == "docs/plan2.txt"]
    assert grants[-1].resolved_by == "operator:admin_ana"


def test_grant_needs_the_right_to_decide(env):
    c, _ = env
    for who in ("lead_other", "dev_owner", "auditor"):
        assert _grant(c, H(who)).status_code == 403, who
    assert _grant(c, H("reviewer")).status_code == 200


def test_high_risk_grant_needs_admin_or_reviewer(env):
    c, _ = env
    assert _grant(c, H("lead_core"), target=".ssh/id_rsa").status_code == 403
    assert _grant(c, H("reviewer"), target=".ssh/id_rsa").status_code == 200
    assert _grant(c, ADMIN, target="input/.env").status_code == 200


# --- F-05: reads show only the runs the user may see -------------------------------------

def _tasks_in(items, key="task_id"):
    return {i.get(key) for i in items}


def test_events_are_scoped(env):
    c, _ = env
    assert _tasks_in(c.get("/api/governance/events", headers=ADMIN).json()["events"]) >= {"t_core", "t_other"}
    seen = _tasks_in(c.get("/api/governance/events", headers=H("lead_core")).json()["events"])
    assert "t_core" in seen and "t_other" not in seen
    assert c.get("/api/governance/tasks/t_other/events", headers=H("lead_core")).status_code == 403
    assert c.get("/api/governance/tasks/t_core/events", headers=H("lead_core")).status_code == 200
    assert c.get("/api/governance/run/t_other/steps", headers=H("lead_core")).status_code == 403


def test_requests_and_inbox_are_scoped(env):
    c, _ = env
    assert _tasks_in(c.get("/api/governance/expansions", headers=H("lead_core")).json()) == {"t_core"}
    assert _tasks_in(c.get("/api/governance/expansions", headers=H("auditor")).json()) == {"t_core", "t_other"}
    assert c.get("/api/governance/expansions/exp_t_other", headers=H("lead_core")).status_code == 403
    assert c.get("/api/governance/expansions/exp_t_other/preview", headers=H("lead_core")).status_code == 403
    assert c.get("/api/governance/expansions/exp_t_core/preview", headers=H("lead_core")).status_code == 200
    assert c.get("/api/governance/inbox/pending", headers=H("lead_core")).json()["total_waiting"] == 1
    assert c.get("/api/governance/inbox/pending", headers=H("reviewer")).json()["total_waiting"] == 2


def test_fleet_is_scoped(env):
    c, _ = env
    body = json.dumps(c.get("/api/governance/fleet/summary", headers=H("lead_core")).json())
    assert "t_core" in body and "t_other" not in body
    body = json.dumps(c.get("/api/governance/fleet/summary", headers=ADMIN).json())
    assert "t_core" in body and "t_other" in body


def test_only_starters_submit_tasks(env):
    c, _ = env
    body = {"request_text": "Summarise input/a.txt", "agent_id": "notes_bot"}
    assert c.post("/api/governance/tasks", headers=H("auditor"), json=body).status_code == 403
    assert c.post("/api/governance/tasks", headers=H("reviewer"), json=body).status_code == 403
