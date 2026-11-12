"""Task report: JSON and CSV built from stored data, with the record's hash-chain check.

- Requester, initial and final boundary, every approval with who and when (plain label),
  blocked actions with the layer that stopped them.
- The record check is the same as the receipt endpoint's: verified, broken, or no record.
- Same permission as the record (a developer sees only their own runs); unknown task -> 404.
- CSV: one row per fact; cells that would start a spreadsheet formula are neutralised.
"""
from __future__ import annotations

import csv
import hashlib
import io
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
from demo.security_monitor.app.governance.receipt import GENESIS_HASH, chain_entries
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.task_report import decided_by_label

ADMIN = {"X-Operator-Token": "admin_tok_report"}
DEV_TOKEN = "dev_tok_report"
DEV = {"X-Operator-Token": DEV_TOKEN}


def _exp(rid, target, status, by, *, single_use=False, escalated=False, asked="2026-11-12T10:01:00+00:00",
         decided="2026-11-12T10:02:00+00:00", reason=None):
    return ExpansionRequest(
        request_id=rid, task_id="t_rep", agent_id="notes_bot", resource_type="file_read", resource_target=target,
        justification="j", baseline_risk_tier=RiskTier.MEDIUM, effective_risk_tier=RiskTier.MEDIUM,
        escalated_by_provenance=escalated, status=status, created_at=asked,
        resolved_at=decided if by else None, resolved_by=by, single_use=single_use, reason=reason)


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    users = tmp_path / "users.json"
    users.write_text(json.dumps([{"name": "Dev Other", "role": "developer", "team": "core",
                                  "token_sha256": hashlib.sha256(DEV_TOKEN.encode()).hexdigest()}]))
    db = tmp_path / "gov.db"
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db))
    monkeypatch.setenv("RECEIPTS_DIR", str(receipts))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", ADMIN["X-Operator-Token"])
    monkeypatch.setenv("GOVERNANCE_USERS_FILE", str(users))
    s = GovernanceStorage(db)
    s.save_task(TaskRecord(task_id="t_rep", request_text="=SUM(A1) summarise the minutes", request_hash="h",
                           agent_id="notes_bot", workspace_root=str(tmp_path), status=TaskLifecycle.COMPLETED,
                           created_at="2026-11-12T10:00:00+00:00", completed_at="2026-11-12T10:05:00+00:00",
                           owner="Ana Dev", team="core"))
    s.save_boundary(TaskBoundary(task_id="t_rep", version=1, workspace_root=str(tmp_path),
                                 files_read=["input/minutes.txt"], files_write=["output/summary.md"], tools=["read_file"]))
    s.save_boundary(TaskBoundary(task_id="t_rep", version=2, workspace_root=str(tmp_path),
                                 files_read=["input/minutes.txt", "docs/notes.txt"], files_write=["output/summary.md"],
                                 tools=["read_file"]))
    s.save_expansion_request(_exp("e1", "docs/notes.txt", ExpansionStatus.APPROVED, "operator:ana", reason="ok"))
    s.save_expansion_request(_exp("e2", "docs/once.txt", ExpansionStatus.APPROVED, "security_reviewer:sam", single_use=True,
                                  asked="2026-11-12T10:01:30+00:00"))
    s.save_expansion_request(_exp("e3", "docs/rule.txt", ExpansionStatus.APPROVED, "standing_rule:rule_ab12",
                                  asked="2026-11-12T10:01:40+00:00"))
    s.save_expansion_request(_exp("e4", "docs/late.txt", ExpansionStatus.DENIED, "timeout_fail_closed",
                                  asked="2026-11-12T10:01:50+00:00", reason="Approval request timed out"))
    s.record_event(GovernanceEvent(
        event_id="ev_blk", timestamp="2026-11-12T10:03:00+00:00", source=EventSource.TOOL_BROKER, task_id="t_rep",
        agent_id="notes_bot", kind="file_read", target="input/payroll.csv", verdict=EventVerdict.OUTSIDE,
        risk_tier=RiskTier.MEDIUM, action_taken=TaskAction.BLOCK_ACTION, prevented=True, rule_matched="not in boundary"))
    s.record_event(GovernanceEvent(
        event_id="ev_ok", timestamp="2026-11-12T10:02:30+00:00", source=EventSource.TOOL_BROKER, task_id="t_rep",
        agent_id="notes_bot", kind="file_read", target="input/minutes.txt", verdict=EventVerdict.INSIDE,
        risk_tier=RiskTier.LOW, action_taken=TaskAction.LOG, prevented=False, rule_matched="in boundary"))
    with gov_api._sessions_lock:
        gov_api._sessions.clear()
    yield TestClient(create_app()), s, receipts


def _write_receipt(receipts: Path, broken: bool = False) -> str:
    events = [{"timestamp": "2026-11-12T10:00:00Z", "kind": "file_read", "target": "input/minutes.txt"},
              {"timestamp": "2026-11-12T10:03:00Z", "kind": "file_read", "target": "input/payroll.csv"}]
    final = chain_entries(events)
    if broken:
        events[1]["target"] = "changed.csv"
    (receipts / "t_rep.json").write_text(json.dumps({
        "task_id": "t_rep", "events": events,
        "hash_chain": {"algorithm": "sha256", "count": 2, "genesis": GENESIS_HASH, "final_hash": final}}))
    return final


def test_report_has_every_section(env):
    c, _, receipts = env
    final = _write_receipt(receipts)
    r = c.get("/api/governance/tasks/t_rep/report", headers=ADMIN)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["task"]["requester"] == "Ana Dev" and rep["task"]["agent_id"] == "notes_bot"
    assert rep["boundary"]["initial"]["files_read"] == ["input/minutes.txt"]
    assert rep["boundary"]["final"]["version"] == 2 and "docs/notes.txt" in rep["boundary"]["final"]["files_read"]
    by_id = {a["request_id"]: a for a in rep["approvals"]}
    assert [a["request_id"] for a in rep["approvals"]] == ["e1", "e2", "e3", "e4"]
    assert by_id["e1"]["decided_by_label"] == "ana (operator)" and by_id["e1"]["scope"] == "run"
    assert by_id["e1"]["decided_at"] == "2026-11-12T10:02:00+00:00"
    assert by_id["e2"]["scope"] == "once" and by_id["e2"]["decided_by_label"] == "sam (security reviewer)"
    assert by_id["e3"]["scope"] == "rule" and by_id["e3"]["decided_by_label"] == "Standing rule rule_ab12"
    assert by_id["e4"]["scope"] == "timeout" and by_id["e4"]["decided_by_label"] == "No one in time (stayed blocked)"
    assert rep["blocked"] == [{"timestamp": "2026-11-12T10:03:00+00:00", "kind": "file_read",
                               "target": "input/payroll.csv", "layer": "broker", "rule": "not in boundary"}]
    assert rep["record"] == {"available": True, "verified": True, "message": "ok", "final_hash": final, "event_count": 2}


def test_report_record_states(env):
    c, _, receipts = env
    rec = c.get("/api/governance/tasks/t_rep/report", headers=ADMIN).json()["record"]
    assert rec["available"] is False and rec["verified"] is False
    _write_receipt(receipts, broken=True)
    rec = c.get("/api/governance/tasks/t_rep/report", headers=ADMIN).json()["record"]
    assert rec["available"] is True and rec["verified"] is False and "hash mismatch" in rec["message"]


def test_report_permissions(env):
    c, _, _ = env
    assert c.get("/api/governance/tasks/t_rep/report").status_code in (401, 403)
    assert c.get("/api/governance/tasks/t_rep/report", headers=DEV).status_code == 403  # not their run
    assert c.get("/api/governance/tasks/t_rep/report.csv", headers=DEV).status_code == 403
    assert c.get("/api/governance/tasks/nope/report", headers=ADMIN).status_code == 404


def test_report_csv(env):
    c, _, receipts = env
    _write_receipt(receipts)
    r = c.get("/api/governance/tasks/t_rep/report.csv", headers=ADMIN)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert 'filename="task_report_t_rep.csv"' in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    sections = [x["section"] for x in rows]
    assert sections.count("approval") == 4 and sections.count("blocked") == 1 and sections.count("record") == 1
    task_row = next(x for x in rows if x["section"] == "task" and x["what"] == "request")
    assert task_row["detail"].startswith("'=SUM")  # formula neutralised
    blocked = next(x for x in rows if x["section"] == "blocked")
    assert blocked["outcome"] == "attempted, not successful" and blocked["who_or_layer"] == "broker"
    assert next(x for x in rows if x["section"] == "record")["outcome"] == "verified"


def test_csv_filename_is_sanitised(env):
    c, s, _ = env
    s.save_task(TaskRecord(task_id='t"x;y', request_text="r", request_hash="h", agent_id="a", workspace_root="/tmp",
                           status=TaskLifecycle.COMPLETED, created_at="2026-11-12T10:00:00+00:00"))
    r = c.get('/api/governance/tasks/t"x;y/report.csv', headers=ADMIN)
    assert r.status_code == 200 and 'filename="task_report_txy.csv"' in r.headers["content-disposition"]


def test_decided_by_labels():
    assert decided_by_label(None, "PENDING") == "Waiting"
    assert decided_by_label("auto_policy", "APPROVED") == "Built-in policy (low risk)"
    assert decided_by_label("policy_deny_high_risk", "DENIED") == "Built-in policy (high risk)"
    assert decided_by_label("team_lead:lee", "APPROVED") == "lee (team lead)"
