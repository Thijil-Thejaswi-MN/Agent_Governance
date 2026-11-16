"""Cancelling an approved grant while the run is still going (roadmap item 4: revocation)."""
from __future__ import annotations

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


@pytest.fixture
def run(tmp_path: Path):
    ws = tmp_path / "ws"
    for d in ("input", "output", "granted", "staged"):
        (ws / d).mkdir(parents=True)
    (ws / "input" / "sales.csv").write_text("q,rev\nQ1,1\n")
    (ws / "input" / "targets.csv").write_text("metric,target\nrevenue,9\n")
    storage = GovernanceStorage(tmp_path / "g.db")
    task, boundary = TaskIntakeService(storage).submit_task(
        "Read input/sales.csv and write output/summary.txt", "finance_bot", str(ws))
    boundary.metadata["agent_tool_limit"] = ["read_file", "request_access", "write_file"]
    storage.save_boundary(boundary)
    token = "gov_tok_revoke_1"
    storage.save_token(token, task.task_id, task.agent_id)
    exp = ExpansionService(storage, user_approval_hook=lambda req: True)
    broker = ToolBroker(storage, expansion_service=exp, evaluator=ResolvedBoundaryEvaluator(storage))
    delivery = ExpansionDelivery(ws, storage, staging=True)
    srv = BrokerRPCServer(broker, tmp_path / "b.sock", task.task_id, delivery=delivery)
    return {"storage": storage, "ws": ws, "task": task, "token": token, "exp": exp, "delivery": delivery, "srv": srv}


def _grant(run, target: str = "input/targets.csv") -> str:
    res = run["srv"]._h_request_access(run["token"], {"resource_type": "file_read", "resource_target": target,
                                                      "justification": "needed for the comparison"})
    assert res["granted"] is True
    return [r for r in run["storage"].list_expansion_requests(task_id=run["task"].task_id)
            if r.resource_target == target][-1].request_id


def _approved(run, target: str) -> str:
    """An approved read request made straight through the expansion service."""
    ok, _ = run["exp"].request_and_wait(run["task"].task_id, run["task"].agent_id, "file_read", target, "needed")
    assert ok
    return [r for r in run["storage"].list_expansion_requests(task_id=run["task"].task_id)
            if r.resource_target == target][-1].request_id


def test_revoke_removes_the_copy_and_the_grant(run) -> None:
    rid = _grant(run)
    copy = run["ws"] / "granted" / "input" / "targets.csv"
    assert copy.is_file()
    before = run["storage"].get_boundary(run["task"].task_id)
    assert "input/targets.csv" in before.files_read

    launcher = TaskLauncher(run["storage"], workspace_base=run["ws"].parent)
    launcher.live = {"task_id": run["task"].task_id, "expansion": run["exp"], "delivery": run["delivery"]}
    out = launcher.revoke_grant(rid, "operator:ana", "no longer needed")
    assert out["status"] == "REVOKED" and out["removed"] == ["granted/input/targets.csv"]
    assert not copy.exists()

    req = run["storage"].get_expansion_request(rid)
    assert req.status == ExpansionStatus.REVOKED and "operator:ana" in req.reason
    after = run["storage"].get_boundary(run["task"].task_id)
    assert after.version == before.version + 1 and "input/targets.csv" not in after.files_read
    assert after.metadata["agent_tool_limit"] == ["read_file", "request_access", "write_file"]
    # The broker no longer reads it: the delivered copy is gone and the grant is not active.
    with pytest.raises((PermissionError, FileNotFoundError, OSError)):
        run["srv"].broker.read_file(run["token"], "granted/input/targets.csv")
    rec = [r for r in run["delivery"].records if r.get("delivered_path") == "granted/input/targets.csv"][0]
    assert rec["removed_reason"] == "revoked_by:operator:ana"


def test_after_revoke_the_agent_is_not_asked_again(run) -> None:
    rid = _grant(run)
    run["exp"].revoke_request(rid, "operator:ana")
    run["delivery"].revoke("file_read", "input/targets.csv", "operator:ana")
    res = run["srv"]._h_request_access(run["token"], {"resource_type": "file_read", "resource_target": "input/targets.csv",
                                                      "justification": "again"})
    assert res["granted"] is False and res["status"].endswith(":revoked")
    assert "cancelled" in res["message"]
    assert not (run["ws"] / "granted" / "input" / "targets.csv").exists()


def test_what_cannot_be_revoked(run) -> None:
    exp, storage, task = run["exp"], run["storage"], run["task"]
    with pytest.raises(RuntimeError, match="Only an approved grant"):
        rid = _grant(run)
        exp.revoke_request(rid, "operator:ana")
        exp.revoke_request(rid, "operator:ana")  # already revoked
    with pytest.raises(PermissionError):
        exp.revoke_request(_approved(run, "input/other.csv"), task.agent_id)
    # A saved write cannot be taken back.
    (run["ws"] / "staged" / "output").mkdir(parents=True)
    (run["ws"] / "staged" / "output" / "note.txt").write_text("hi")
    res = run["srv"]._h_request_access(run["token"], {"resource_type": "file_write", "resource_target": "output/note.txt",
                                                      "justification": "a note"})
    assert res["granted"] is True
    wid = [r for r in storage.list_expansion_requests(task_id=task.task_id) if r.resource_type == "file_write"][-1].request_id
    with pytest.raises(RuntimeError, match="already been saved"):
        exp.revoke_request(wid, "operator:ana")


def test_revoke_never_takes_away_what_the_request_named(run) -> None:
    rid = _approved(run, "input/sales.csv")  # already in boundary version 1
    run["exp"].revoke_request(rid, "operator:ana")
    assert "input/sales.csv" in run["storage"].get_boundary(run["task"].task_id).files_read


def test_a_finished_run_has_nothing_to_cancel(run) -> None:
    launcher = TaskLauncher(run["storage"], workspace_base=run["ws"].parent)
    with pytest.raises(RuntimeError, match="not running"):
        launcher.revoke_grant("exp_x", "operator:ana")
