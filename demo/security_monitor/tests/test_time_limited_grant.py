"""\"Allow for N minutes\": a grant that ends by itself while the run is still going."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.broker_rpc import BrokerRPCServer
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.launcher import ExpansionDelivery, TaskLauncher
from demo.security_monitor.app.governance.models import ExpansionStatus
from demo.security_monitor.app.governance.resolved_boundary import ResolvedBoundaryEvaluator
from demo.security_monitor.app.governance.storage import GovernanceStorage

UTC = dt.timezone.utc


@pytest.fixture
def run(tmp_path: Path):
    ws = tmp_path / "ws"
    for d in ("input", "output", "granted", "staged"):
        (ws / d).mkdir(parents=True)
    (ws / "input" / "sales.csv").write_text("q,rev\n")
    (ws / "input" / "targets.csv").write_text("metric,target\n")
    storage = GovernanceStorage(tmp_path / "g.db")
    task, _ = TaskIntakeService(storage).submit_task("Read input/sales.csv and write output/summary.txt",
                                                     "finance_bot", str(ws))
    storage.save_token("tok_timed", task.task_id, task.agent_id)
    exp = ExpansionService(storage, user_approval_hook=lambda req: True)
    broker = ToolBroker(storage, expansion_service=exp, evaluator=ResolvedBoundaryEvaluator(storage))
    delivery = ExpansionDelivery(ws, storage, staging=True)
    srv = BrokerRPCServer(broker, tmp_path / "b.sock", task.task_id, delivery=delivery)
    launcher = TaskLauncher(storage, workspace_base=tmp_path)
    launcher.live = {"task_id": task.task_id, "expansion": exp, "delivery": delivery}
    return {"storage": storage, "ws": ws, "task": task, "srv": srv, "launcher": launcher}


def _ask(run, target: str = "input/targets.csv") -> dict:
    return run["srv"]._h_request_access("tok_timed", {"resource_type": "file_read", "resource_target": target,
                                                      "justification": "needed"})


def _latest(run, target: str = "input/targets.csv"):
    return max((r for r in run["storage"].list_expansion_requests(task_id=run["task"].task_id)
                if r.resource_target == target), key=lambda r: r.created_at)


def test_expiry_is_stored_only_on_a_pending_request(run) -> None:
    storage = run["storage"]
    _ask(run)
    req = _latest(run)
    storage.mark_expansion_expiry(req.request_id, "2026-11-17T10:00:00+00:00")
    assert storage.get_expansion_request(req.request_id).expires_at is None  # already approved
    req.status = ExpansionStatus.PENDING
    storage.save_expansion_request(req)
    storage.mark_expansion_expiry(req.request_id, "2026-11-17T10:00:00+00:00")
    assert storage.get_expansion_request(req.request_id).expires_at == "2026-11-17T10:00:00+00:00"


def test_a_grant_past_its_time_ends_and_its_copy_is_removed(run) -> None:
    storage, task = run["storage"], run["task"]
    assert _ask(run)["granted"] is True
    req = _latest(run)
    copy = run["ws"] / "granted" / "input" / "targets.csv"
    assert copy.is_file()
    req.expires_at = (dt.datetime.now(UTC) + dt.timedelta(minutes=10)).isoformat()
    storage.save_expansion_request(req)

    assert run["launcher"].expire_due_grants(task.task_id) == []  # not yet
    assert copy.is_file()
    later = dt.datetime.now(UTC) + dt.timedelta(minutes=11)
    assert run["launcher"].expire_due_grants(task.task_id, now=later) == [req.request_id]
    assert not copy.exists()
    ended = storage.get_expansion_request(req.request_id)
    assert ended.status == ExpansionStatus.EXPIRED and "Time limit" in ended.reason
    b = storage.get_boundary(task.task_id)
    assert "input/targets.csv" not in b.files_read and b.derived_by.startswith("expiry_")
    steps = [s["summary"] for s in storage.get_task_steps(task.task_id)] if hasattr(storage, "get_task_steps") else []
    assert not steps or any("time limit was reached" in s for s in steps)
    assert run["launcher"].expire_due_grants(task.task_id, now=later) == []  # once


def test_after_expiry_the_agent_may_ask_again_and_a_person_decides(run) -> None:
    _ask(run)
    req = _latest(run)
    req.expires_at = (dt.datetime.now(UTC) - dt.timedelta(seconds=1)).isoformat()
    run["storage"].save_expansion_request(req)
    run["launcher"].expire_due_grants(run["task"].task_id)
    again = _ask(run)
    assert again["granted"] is True and ":revoked" not in str(again.get("status"))
    assert _latest(run).request_id != req.request_id
    # The new approval is the one delivered (not the expired one): the copy is back.
    assert again["delivery"]["type"] == "file_copy"
    assert (run["ws"] / "granted" / "input" / "targets.csv").is_file()


def test_untimed_grants_and_writes_are_left_alone(run) -> None:
    _ask(run)
    assert run["launcher"].expire_due_grants(run["task"].task_id, now=dt.datetime(2100, 1, 1, tzinfo=UTC)) == []
    assert (run["ws"] / "granted" / "input" / "targets.csv").is_file()


def test_the_expiry_loop_stops_when_the_run_ends(run) -> None:
    import threading

    stop = threading.Event()
    run["launcher"].live.pop("expansion")
    t = threading.Thread(target=run["launcher"]._expire_grants_loop, args=(run["task"].task_id, stop, 0.01))
    t.start()
    t.join(timeout=2)
    assert not t.is_alive()


def test_timed_scope_in_the_api(tmp_path: Path, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from demo.security_monitor.app.gateway.server import create_app
    from demo.security_monitor.app.governance import api as gov_api

    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.setenv("RECEIPTS_DIR", str(tmp_path / "r"))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "tok_api")
    monkeypatch.setenv("GOVERNANCE_OPERATOR_ROLE", "admin")
    c = TestClient(create_app())
    storage = gov_api.get_storage()
    ws = tmp_path / "ws2"
    (ws / "input").mkdir(parents=True)
    task, _ = TaskIntakeService(storage).submit_task("Read input/a.csv", "finance_bot", str(ws))
    svc = ExpansionService(storage)
    pending = svc.evaluate_request(task.task_id, "finance_bot", "file_read", "docs/notes.txt", "needed")
    write = svc.evaluate_request(task.task_id, "finance_bot", "file_write", "output/extra.txt", "needed")
    assert pending.status == ExpansionStatus.PENDING and write.status == ExpansionStatus.PENDING
    h = {"X-Operator-Token": "tok_api"}
    assert c.post(f"/api/governance/expansions/{write.request_id}/approve", json={"scope": "timed"}, headers=h).status_code == 422
    assert c.post(f"/api/governance/expansions/{pending.request_id}/approve", json={"scope": "timed", "minutes": 0},
                  headers=h).status_code == 422
    before = dt.datetime.now(UTC)
    r = c.post(f"/api/governance/expansions/{pending.request_id}/approve", json={"scope": "timed"}, headers=h)
    assert r.status_code == 200, r.text
    got = storage.get_expansion_request(pending.request_id)
    assert got.status == ExpansionStatus.APPROVED and got.reason == "Allowed for 10 minutes"
    ends = dt.datetime.fromisoformat(got.expires_at)
    assert dt.timedelta(minutes=9) < ends - before < dt.timedelta(minutes=11)
