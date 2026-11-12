"""Standing-rule watcher: decides waiting requests through the normal approve/deny calls.

- Off unless GOVERNANCE_STANDING_RULES=1, and off during evaluations.
- Never decides HIGH risk or provenance-escalated requests.
- Every decision names the rule ID and owner.
- Strictest matching response wins (block, then ask, then allow).
- Rules are saved and come back after a restart.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from demo.security_monitor.app.governance import api as gov_api
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.models import (
    ExpansionRequest,
    ExpansionStatus,
    RiskTier,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.rule_watcher import StandingRuleWatcher, decide_with_rules
from demo.security_monitor.app.governance.standing_rules import StandingRule
from demo.security_monitor.app.governance.storage import GovernanceStorage

MEDIUM_TARGET = "docs/notes.txt"  # outside input/, not sensitive -> MEDIUM, waits for a person


def _rule(response: str = "allow", target: str = MEDIUM_TARGET, rule_id: str = "rule_t1", agent: str = "agent-1") -> StandingRule:
    now = datetime.now(timezone.utc)
    return StandingRule(
        rule_id=rule_id,
        agent_or_profile=agent,
        action="file_read",
        target=target,
        owner="rev_ana",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(days=1)).isoformat(),
        response=response,
    )


@pytest.fixture
def world(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GOVERNANCE_STANDING_RULES", "1")
    monkeypatch.delenv("GOVERNANCE_EVALUATION_ACTIVE", raising=False)
    storage = GovernanceStorage(tmp_path / "gov.db")
    storage.save_task(TaskRecord(task_id="task-1", request_text="summarise the report", request_hash="h",
                                 agent_id="agent-1", workspace_root=str(tmp_path), status=TaskLifecycle.ACTIVE,
                                 created_at="2026-11-12T00:00:00Z"))
    storage.save_boundary(TaskBoundary(task_id="task-1", version=1, workspace_root=str(tmp_path)))
    service = ExpansionService(storage, provenance_enabled=False)
    return storage, service


def _pending(service: ExpansionService, target: str = MEDIUM_TARGET) -> ExpansionRequest:
    req = service.evaluate_request(task_id="task-1", agent_id="agent-1", resource_type="file_read",
                                   resource_target=target, justification="need it")
    assert req.status == ExpansionStatus.PENDING
    return req


def _save_pending(storage: GovernanceStorage, request_id: str, baseline: RiskTier, effective: RiskTier,
                  escalated: bool) -> None:
    storage.save_expansion_request(ExpansionRequest(
        request_id=request_id, task_id="task-1", agent_id="agent-1", resource_type="file_read",
        resource_target=MEDIUM_TARGET, justification="need it", baseline_risk_tier=baseline,
        effective_risk_tier=effective, escalated_by_provenance=escalated, status=ExpansionStatus.PENDING,
        created_at="2026-11-12T00:00:01Z",
    ))


def test_allow_rule_approves_and_records_rule_and_owner(world):
    storage, service = world
    req = _pending(service)
    decided = decide_with_rules(storage, service, [_rule("allow")])
    assert [d["status"] for d in decided] == ["APPROVED"]
    after = storage.get_expansion_request(req.request_id)
    assert after.status == ExpansionStatus.APPROVED
    assert after.resolved_by == "standing_rule:rule_t1"
    assert "rule_t1" in after.reason and "rev_ana" in after.reason
    steps = storage.get_task_steps("task-1")
    assert any("standing_rule:rule_t1" in s["summary"] and "rev_ana" in s["detail"] for s in steps)
    assert MEDIUM_TARGET in storage.get_boundary("task-1").files_read


def test_block_rule_denies_and_records_rule_and_owner(world):
    storage, service = world
    req = _pending(service)
    decide_with_rules(storage, service, [_rule("block")])
    after = storage.get_expansion_request(req.request_id)
    assert after.status == ExpansionStatus.DENIED
    assert after.resolved_by == "standing_rule:rule_t1"
    assert "Blocked by rule rule_t1 (owner rev_ana)" == after.reason
    assert MEDIUM_TARGET not in storage.get_boundary("task-1").files_read


def test_ask_rule_leaves_it_for_a_person_and_beats_allow(world):
    storage, service = world
    req = _pending(service)
    assert decide_with_rules(storage, service, [_rule("allow", rule_id="r_allow"), _rule("ask", rule_id="r_ask")]) == []
    assert storage.get_expansion_request(req.request_id).status == ExpansionStatus.PENDING


def test_block_beats_allow(world):
    storage, service = world
    req = _pending(service)
    decide_with_rules(storage, service, [_rule("allow", rule_id="r_allow"), _rule("block", rule_id="r_block")])
    after = storage.get_expansion_request(req.request_id)
    assert after.status == ExpansionStatus.DENIED and after.resolved_by == "standing_rule:r_block"


@pytest.mark.parametrize("response", ["allow", "block"])
@pytest.mark.parametrize(
    "baseline,effective,escalated",
    [
        (RiskTier.HIGH, RiskTier.HIGH, False),      # HIGH risk
        (RiskTier.LOW, RiskTier.MEDIUM, True),      # escalated by provenance
        (RiskTier.MEDIUM, RiskTier.HIGH, True),     # both
        (RiskTier.MEDIUM, RiskTier.MEDIUM, True),   # escalated, tier unchanged
    ],
)
def test_never_decides_high_risk_or_provenance_escalated(world, response, baseline, effective, escalated):
    storage, service = world
    _save_pending(storage, "exp_guard", baseline, effective, escalated)
    rules = [_rule(response), _rule(response, agent="*", rule_id="rule_any")]
    assert decide_with_rules(storage, service, rules) == []
    after = storage.get_expansion_request("exp_guard")
    assert after.status == ExpansionStatus.PENDING and after.resolved_by is None


def test_off_without_flag(world, monkeypatch):
    storage, service = world
    monkeypatch.delenv("GOVERNANCE_STANDING_RULES")
    req = _pending(service)
    assert decide_with_rules(storage, service, [_rule("allow")]) == []
    assert storage.get_expansion_request(req.request_id).status == ExpansionStatus.PENDING


def test_off_during_evaluations(world, monkeypatch):
    storage, service = world
    monkeypatch.setenv("GOVERNANCE_EVALUATION_ACTIVE", "1")
    req = _pending(service)
    assert decide_with_rules(storage, service, [_rule("allow")]) == []
    assert storage.get_expansion_request(req.request_id).status == ExpansionStatus.PENDING


def test_non_matching_and_expired_rules_do_nothing(world):
    storage, service = world
    req = _pending(service)
    expired = _rule("allow", rule_id="r_old")
    expired.expires_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    other_agent = _rule("allow", agent="agent-2", rule_id="r_other")
    other_file = _rule("allow", target="docs/other.txt", rule_id="r_file")
    assert decide_with_rules(storage, service, [expired, other_agent, other_file]) == []
    assert storage.get_expansion_request(req.request_id).status == ExpansionStatus.PENDING


def test_watcher_thread_decides_while_broker_waits(world):
    """The broker's own wait loop sees the watcher's decision; the broker code is unchanged."""
    storage, service = world
    watcher = StandingRuleWatcher(lambda: storage, lambda: service, lambda: [_rule("allow")], interval=0.05)
    watcher.start()
    try:
        approved, message = service.request_and_wait(task_id="task-1", agent_id="agent-1", resource_type="file_read",
                                                     resource_target=MEDIUM_TARGET, justification="need it",
                                                     timeout_seconds=3.0)
    finally:
        watcher.stop()
    assert approved is True
    assert message == "Approved by standing_rule:rule_t1"


# --- API: create, save, reload, expire -------------------------------------------------

TOKEN = "test_rules_token"
HEADERS = {"X-Operator-Token": TOKEN}


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    db = tmp_path / "gov.db"
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db))
    monkeypatch.setenv("RECEIPTS_DIR", str(tmp_path / "receipts"))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", TOKEN)
    monkeypatch.delenv("GOVERNANCE_STANDING_RULES", raising=False)
    with gov_api._standing_rules_lock:
        gov_api._standing_rules.clear()
        gov_api._standing_rules_loaded_from.clear()
    yield TestClient(create_app_for_test()), db
    with gov_api._standing_rules_lock:
        gov_api._standing_rules.clear()
        gov_api._standing_rules_loaded_from.clear()
    with gov_api._sessions_lock:
        gov_api._sessions.clear()


def create_app_for_test():
    from demo.security_monitor.app.gateway.server import create_app
    return create_app()


def test_rules_are_saved_and_reloaded(client):
    c, db = client
    r = c.post("/api/governance/standing-rules", headers=HEADERS,
               json={"agent_or_profile": "agent-1", "action": "file_read", "target": MEDIUM_TARGET, "response": "block"})
    assert r.status_code == 200, r.text
    rule_id = r.json()["rule_id"]
    assert r.json()["response"] == "block"
    # Simulate a restart: the in-memory list is empty, the saved rule comes back.
    with gov_api._standing_rules_lock:
        gov_api._standing_rules.clear()
        gov_api._standing_rules_loaded_from.clear()
    body = c.get("/api/governance/standing-rules", headers=HEADERS).json()
    assert body["enabled"] is False and body["can_manage"] is True
    assert [x["rule_id"] for x in body["rules"]] == [rule_id]
    assert c.post(f"/api/governance/standing-rules/{rule_id}/expire", headers=HEADERS).status_code == 200
    with gov_api._standing_rules_lock:
        gov_api._standing_rules.clear()
        gov_api._standing_rules_loaded_from.clear()
    listed = c.get("/api/governance/standing-rules", headers=HEADERS).json()["rules"]
    assert listed[0]["is_active"] is False
    assert GovernanceStorage(db).list_standing_rules()[0]["is_active"] is False


@pytest.mark.parametrize(
    "body",
    [
        {"agent_or_profile": "agent-1", "action": "file_read", "target": "docs/*.txt"},
        {"agent_or_profile": "agent-1", "action": "file_read", "target": "  "},
        {"agent_or_profile": "agent-1", "action": "run_anything", "target": "x"},
        {"agent_or_profile": "agent-1", "action": "file_read", "target": "x", "response": "maybe"},
        {"agent_or_profile": " ", "action": "file_read", "target": "x"},
    ],
)
def test_bad_rules_are_refused(client, body):
    c, _ = client
    assert c.post("/api/governance/standing-rules", headers=HEADERS, json=body).status_code == 422


def test_watcher_not_started_without_flag(client):
    assert gov_api._rule_watcher is None
