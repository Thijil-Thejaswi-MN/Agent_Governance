"""Approval card API: the read-only preview and the four decisions.

- GET /expansions/{id}/preview gives name, folder and size, looked up only inside the
  task's workspace. Path escapes ('..', absolute paths, home, drive letters, symlinks out
  of the workspace) report the size as unknown and never touch the outside file.
- POST /expansions/{id}/approve with scope once | run | always:
  once marks the request single-use, run is the old behaviour, always also saves an
  allow rule for this agent and this exact resource (reviewer/admin only, never for
  HIGH-risk or provenance-escalated requests).
- POST /expansions/request with rules on goes through the watcher's code path.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from demo.security_monitor.app.gateway.server import create_app
from demo.security_monitor.app.governance import api as gov_api
from demo.security_monitor.app.governance.models import (
    ExpansionRequest,
    ExpansionStatus,
    RiskTier,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.workspace_read import file_preview, resolve_inside

ADMIN = {"X-Operator-Token": "admin_tok_card"}
LEAD_TOKEN = "lead_tok_card"
LEAD = {"X-Operator-Token": LEAD_TOKEN}


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "docs").mkdir(parents=True)
    (ws / "docs" / "notes.txt").write_text("x" * 1234)
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("do not touch")
    os.symlink(outside, ws / "docs" / "link_out.txt")
    users = tmp_path / "users.json"
    users.write_text(json.dumps([{"name": "Lee Lead", "role": "team_lead", "team": "core",
                                  "token_sha256": hashlib.sha256(LEAD_TOKEN.encode()).hexdigest()}]))
    db = tmp_path / "gov.db"
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db))
    monkeypatch.setenv("RECEIPTS_DIR", str(tmp_path / "receipts"))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", ADMIN["X-Operator-Token"])
    monkeypatch.setenv("GOVERNANCE_OPERATOR_NAME", "admin_ana")
    monkeypatch.setenv("GOVERNANCE_USERS_FILE", str(users))
    monkeypatch.delenv("GOVERNANCE_STANDING_RULES", raising=False)
    storage = GovernanceStorage(db)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    storage.save_task(TaskRecord(task_id="t1", request_text="Summarise the notes", request_hash="h", agent_id="notes_bot",
                                 workspace_root=str(ws), status=TaskLifecycle.ACTIVE, created_at=now, team="core"))
    storage.save_boundary(TaskBoundary(task_id="t1", workspace_root=str(ws)))
    with gov_api._standing_rules_lock:
        gov_api._standing_rules.clear()
        gov_api._standing_rules_loaded_from.clear()
    yield TestClient(create_app()), storage, ws, outside
    with gov_api._standing_rules_lock:
        gov_api._standing_rules.clear()
        gov_api._standing_rules_loaded_from.clear()
    with gov_api._sessions_lock:
        gov_api._sessions.clear()


_n = 0


def _req(storage: GovernanceStorage, target: str, *, escalated: bool = False, tier: RiskTier = RiskTier.MEDIUM,
         rtype: str = "file_read") -> str:
    global _n
    _n += 1
    rid = f"exp_card_{_n}"
    storage.save_expansion_request(ExpansionRequest(
        request_id=rid, task_id="t1", agent_id="notes_bot", resource_type=rtype, resource_target=target,
        justification="need it", baseline_risk_tier=RiskTier.LOW if escalated else tier, effective_risk_tier=tier,
        escalated_by_provenance=escalated, status=ExpansionStatus.PENDING,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), timeout_seconds=600))
    return rid


# --- preview -----------------------------------------------------------------------------

def test_preview_names_folder_and_size(env):
    c, storage, _, _ = env
    rid = _req(storage, "docs/notes.txt")
    r = c.get(f"/api/governance/expansions/{rid}/preview", headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "notes.txt" and body["folder"] == "docs"
    assert body["size_bytes"] == 1234 and body["exists"] is True and body["inside_workspace"] is True
    assert body["risk_tier"] == "MEDIUM" and body["escalated"] is False and body["rule_possible"] is True


def test_preview_missing_file(env):
    c, storage, _, _ = env
    body = c.get(f"/api/governance/expansions/{_req(storage, 'docs/none.txt')}/preview", headers=ADMIN).json()
    assert body["exists"] is False and body["size_bytes"] is None and body["inside_workspace"] is True


@pytest.mark.parametrize("target", [
    "../outside_secret.txt",
    "docs/../../outside_secret.txt",
    "docs/link_out.txt",          # symlink pointing outside the workspace
    "~/outside_secret.txt",
    "C:/outside_secret.txt",
])
def test_preview_path_escape_reports_unknown(env, target):
    c, storage, _, _ = env
    body = c.get(f"/api/governance/expansions/{_req(storage, target)}/preview", headers=ADMIN).json()
    assert body["inside_workspace"] is False
    assert body["size_bytes"] is None and body["exists"] is None


def test_preview_absolute_path_reports_unknown(env):
    c, storage, _, outside = env
    body = c.get(f"/api/governance/expansions/{_req(storage, str(outside))}/preview", headers=ADMIN).json()
    assert body["inside_workspace"] is False and body["size_bytes"] is None


def test_preview_escalated_learned_from_and_no_rule(env):
    c, storage, _, _ = env
    from demo.security_monitor.app.governance.models import ProvenanceRecord
    storage.record_provenance(ProvenanceRecord(task_id="t1", timestamp="2026-11-12T00:00:00Z", source_type="file_read",
                                               source_target="input/briefing.txt", content_hash="x", content_len=10,
                                               content_snippet="see docs/notes.txt for more"))
    body = c.get(f"/api/governance/expansions/{_req(storage, 'docs/notes.txt', escalated=True)}/preview", headers=ADMIN).json()
    assert body["escalated"] is True and body["learned_from"] == "input/briefing.txt" and body["rule_possible"] is False


def test_preview_network_has_no_size(env):
    c, storage, _, _ = env
    body = c.get(f"/api/governance/expansions/{_req(storage, 'localhost:9000', rtype='network')}/preview", headers=ADMIN).json()
    assert body["kind"] == "address" and body["size_bytes"] is None and body["inside_workspace"] is None


def test_preview_needs_credentials_and_known_id(env):
    c, storage, _, _ = env
    assert c.get(f"/api/governance/expansions/{_req(storage, 'docs/notes.txt')}/preview").status_code in (401, 403)
    assert c.get("/api/governance/expansions/nope/preview", headers=ADMIN).status_code == 404


def test_resolve_inside_unit(tmp_path):
    (tmp_path / "a").mkdir()
    assert resolve_inside(tmp_path, "a/b.txt") == (tmp_path / "a" / "b.txt").resolve()
    for bad in ["", "..", "a/../../x", "/etc/passwd", "~/x", "C:\\x", "a/\x00b", None]:
        assert resolve_inside(tmp_path, bad) is None
    assert resolve_inside(None, "a") is None
    assert resolve_inside(tmp_path / "missing", "a") is None
    assert file_preview(tmp_path, "file_read", "../x")["inside_workspace"] is False
    gone = file_preview(tmp_path / "missing", "file_read", "a/b.txt")
    assert gone["inside_workspace"] is None and gone["size_bytes"] is None and gone["exists"] is None


# --- decisions -----------------------------------------------------------------------------

def test_allow_once_marks_single_use(env):
    c, storage, _, _ = env
    rid = _req(storage, "docs/notes.txt")
    r = c.post(f"/api/governance/expansions/{rid}/approve", headers=ADMIN, json={"scope": "once"})
    assert r.status_code == 200, r.text
    after = storage.get_expansion_request(rid)
    assert after.status == ExpansionStatus.APPROVED and after.single_use is True
    assert after.resolved_by == "operator:admin_ana" and after.reason == "Allowed once in the console"
    assert r.json()["standing_rule"] is None


def test_allow_for_this_run_is_unchanged(env):
    c, storage, _, _ = env
    rid = _req(storage, "docs/notes.txt")
    r = c.post(f"/api/governance/expansions/{rid}/approve", headers=ADMIN, json={"decided_by": "operator", "reason": "ok"})
    assert r.status_code == 200 and r.json()["scope"] == "run"
    after = storage.get_expansion_request(rid)
    assert after.status == ExpansionStatus.APPROVED and after.single_use is False and after.reason == "ok"


def test_always_for_this_agent_saves_an_allow_rule(env):
    c, storage, _, _ = env
    rid = _req(storage, "docs/notes.txt")
    r = c.post(f"/api/governance/expansions/{rid}/approve", headers=ADMIN, json={"scope": "always"})
    assert r.status_code == 200, r.text
    rule = r.json()["standing_rule"]
    assert rule["agent_or_profile"] == "notes_bot" and rule["action"] == "file_read"
    assert rule["target"] == "docs/notes.txt" and rule["response"] == "allow" and rule["owner"] == "admin_ana"
    assert storage.get_expansion_request(rid).status == ExpansionStatus.APPROVED
    assert [x["rule_id"] for x in storage.list_standing_rules()] == [rule["rule_id"]]


@pytest.mark.parametrize("escalated,tier", [(True, RiskTier.MEDIUM), (False, RiskTier.HIGH)])
def test_always_refused_for_escalated_or_high(env, escalated, tier):
    c, storage, _, _ = env
    rid = _req(storage, "docs/notes.txt", escalated=escalated, tier=tier)
    r = c.post(f"/api/governance/expansions/{rid}/approve", headers=ADMIN, json={"scope": "always"})
    assert r.status_code == 422
    assert storage.get_expansion_request(rid).status == ExpansionStatus.PENDING
    assert storage.list_standing_rules() == []


def test_always_needs_reviewer_or_admin(env):
    c, storage, _, _ = env
    rid = _req(storage, "docs/notes.txt")
    r = c.post(f"/api/governance/expansions/{rid}/approve", headers=LEAD, json={"scope": "always"})
    assert r.status_code == 403
    assert storage.get_expansion_request(rid).status == ExpansionStatus.PENDING
    # The same team lead may still allow it for this run.
    assert c.post(f"/api/governance/expansions/{rid}/approve", headers=LEAD, json={"scope": "run"}).status_code == 200


def test_bad_scope_and_already_decided(env):
    c, storage, _, _ = env
    rid = _req(storage, "docs/notes.txt")
    assert c.post(f"/api/governance/expansions/{rid}/approve", headers=ADMIN, json={"scope": "forever"}).status_code == 422
    assert c.post(f"/api/governance/expansions/{rid}/approve", headers=ADMIN, json={"scope": "run"}).status_code == 200
    assert c.post(f"/api/governance/expansions/{rid}/approve", headers=ADMIN, json={"scope": "once"}).status_code == 409


def test_request_endpoint_with_rules_on_uses_the_watcher(env, monkeypatch):
    c, storage, _, _ = env
    monkeypatch.setenv("GOVERNANCE_STANDING_RULES", "1")
    r = c.post("/api/governance/standing-rules", headers=ADMIN,
               json={"agent_or_profile": "notes_bot", "action": "file_read", "target": "docs/notes.txt"})
    rule_id = r.json()["rule_id"]
    r = c.post("/api/governance/expansions/request", headers=ADMIN,
               json={"task_id": "t1", "agent_id": "notes_bot", "resource_type": "file_read",
                     "resource_target": "docs/notes.txt", "justification": "need it", "provenance_enabled": False})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "APPROVED" and r.json()["resolved_by"] == f"standing_rule:{rule_id}"


def test_allow_once_unavailable_while_another_one_time_grant_is_unused(env):
    c, storage, _, _ = env
    first = _req(storage, "docs/notes.txt")
    second = _req(storage, "docs/other.txt")
    assert c.get(f"/api/governance/expansions/{second}/preview", headers=ADMIN).json()["once_possible"] is True
    assert c.post(f"/api/governance/expansions/{first}/approve", headers=ADMIN, json={"scope": "once"}).status_code == 200
    body = c.get(f"/api/governance/expansions/{second}/preview", headers=ADMIN).json()
    assert body["once_possible"] is False and body["once_blocked_by"] == "docs/notes.txt"
    r = c.post(f"/api/governance/expansions/{second}/approve", headers=ADMIN, json={"scope": "once"})
    assert r.status_code == 409 and "docs/notes.txt" in r.json()["detail"]
    assert storage.get_expansion_request(second).status == ExpansionStatus.PENDING
    # Once the first grant has been used, Allow once is available again.
    storage.increment_expansion_usage(first)
    assert c.get(f"/api/governance/expansions/{second}/preview", headers=ADMIN).json()["once_possible"] is True
    assert c.post(f"/api/governance/expansions/{second}/approve", headers=ADMIN, json={"scope": "once"}).status_code == 200
