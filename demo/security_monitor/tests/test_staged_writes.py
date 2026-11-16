"""Content-reviewed writes (roadmap item 4): stage, review the exact bytes, land the snapshot."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.broker_rpc import BrokerRPCServer
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.launcher import ExpansionDelivery
from demo.security_monitor.app.governance.models import EventVerdict, ExpansionStatus
from demo.security_monitor.app.governance.resolved_boundary import ResolvedBoundaryEvaluator, resolve_boundary
from demo.security_monitor.app.governance.staged_writes import (
    MAX_STAGED_BYTES,
    land_snapshot,
    normalize_write_target,
    snapshot_staged,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage


def _ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    for d in ("input", "output", "granted", "staged"):
        (ws / d).mkdir(parents=True, exist_ok=True)
    (ws / "input" / "data.csv").write_text("a,b\n1,2\n")
    return ws


def _stage(ws: Path, target: str, data: bytes) -> Path:
    p = ws / "staged" / target
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


# --- targets --------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("output/extra.txt", "output/extra.txt"),
    ("./output/extra.txt", "output/extra.txt"),
    ("staged/output/extra.txt", "output/extra.txt"),
    ("output\\extra.txt", "output/extra.txt"),
    ("/etc/passwd", None), ("../x.txt", None), ("output/../input/data.csv", None), ("C:/x.txt", None),
    ("granted/x.txt", None), ("tmp/x.txt", None), ("runtime/x.py", None), ("staged/staged/x", None),
    ("output/", None), ("", None), ("output/*.txt", None),
])
def test_normalize_write_target(raw: str, expected: str | None) -> None:
    assert normalize_write_target(raw) == expected


# --- snapshot -------------------------------------------------------------

def test_snapshot_reads_the_staged_bytes_once(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _stage(ws, "output/extra.txt", b"total=22\n")
    snap = snapshot_staged(ws, "output/extra.txt")
    assert snap["ok"] and snap["data"] == b"total=22\n" and snap["preview"] == "total=22\n"
    assert snap["staged_path"] == "staged/output/extra.txt" and snap["size_bytes"] == 9
    assert len(snap["content_sha256"]) == 64 and not snap["binary"] and not snap["truncated"]


def test_snapshot_refuses_what_could_smuggle_a_secret(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET")
    assert snapshot_staged(ws, "output/missing.txt")["reason"] == "not_staged"
    # A symlink as the staged file.
    (ws / "staged" / "output").mkdir()
    os.symlink(secret, ws / "staged" / "output" / "link.txt")
    assert snapshot_staged(ws, "output/link.txt")["reason"] == "staged_file_is_a_link"
    # A symlinked folder on the way.
    os.symlink(tmp_path, ws / "staged" / "sub")
    assert snapshot_staged(ws, "sub/secret.txt")["reason"] == "staged_path_not_a_plain_folder"
    # A hard link to a file outside.
    os.link(secret, ws / "staged" / "output" / "hard.txt")
    assert snapshot_staged(ws, "output/hard.txt")["reason"] == "staged_file_has_links"
    # Not a regular file.
    os.mkfifo(ws / "staged" / "output" / "pipe.txt")
    assert snapshot_staged(ws, "output/pipe.txt")["reason"] == "staged_file_not_regular"
    # Too large.
    _stage(ws, "output/big.bin", b"x" * (MAX_STAGED_BYTES + 1))
    assert snapshot_staged(ws, "output/big.bin")["reason"] == "staged_file_too_large"
    assert snapshot_staged(ws, "../secret.txt")["reason"] == "invalid_target"


def test_snapshot_marks_binary_and_truncates_the_preview(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    _stage(ws, "output/a.bin", b"\x00\x01\x02")
    assert snapshot_staged(ws, "output/a.bin")["binary"] is True
    _stage(ws, "output/long.txt", b"y" * 5000)
    snap = snapshot_staged(ws, "output/long.txt")
    assert snap["truncated"] is True and len(snap["preview"]) == 2000


# --- landing --------------------------------------------------------------

def test_land_creates_exclusively_and_never_through_a_link(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    res = land_snapshot(ws, "output/reports/extra.txt", b"ok\n")
    assert res["ok"] and (ws / "output/reports/extra.txt").read_bytes() == b"ok\n"
    assert land_snapshot(ws, "output/reports/extra.txt", b"again")["reason"] == "target_exists"
    assert (ws / "output/reports/extra.txt").read_bytes() == b"ok\n"
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, ws / "output" / "linkdir")
    assert land_snapshot(ws, "output/linkdir/x.txt", b"x")["reason"] == "target_folder_not_a_plain_folder"
    assert not (outside / "x.txt").exists()
    os.symlink(tmp_path / "victim.txt", ws / "output" / "dangling.txt")
    assert land_snapshot(ws, "output/dangling.txt", b"x")["reason"] in ("target_exists", "target_not_writable")
    assert not (tmp_path / "victim.txt").exists()


# --- delivery: the snapshot, not the staged file as it is later ------------

def test_delivery_lands_the_reviewed_snapshot(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    storage = GovernanceStorage(tmp_path / "g.db")
    task, _ = TaskIntakeService(storage).submit_task("Summarise input/data.csv into output/summary.txt", "finance_bot", str(ws))
    exp = ExpansionService(storage, user_approval_hook=lambda req: True)
    delivery = ExpansionDelivery(ws, storage, staging=True)
    staged = _stage(ws, "output/extra.txt", b"reviewed\n")
    assert delivery.stage_snapshot("output/extra.txt")["ok"]
    staged.write_bytes(b"swapped after review\n")  # the agent changes it after the snapshot
    ok, _ = exp.request_and_wait(task.task_id, task.agent_id, "file_write", "output/extra.txt", "needed")
    assert ok
    out = delivery.deliver(task.task_id, "file_write", "output/extra.txt", True)
    assert out["type"] == "file_land" and out["landed_path"] == "output/extra.txt"
    assert (ws / "output/extra.txt").read_bytes() == b"reviewed\n"
    # A second approval of the same target does not overwrite it.
    _stage(ws, "output/extra.txt", b"second\n")
    delivery.stage_snapshot("output/extra.txt")
    assert delivery.deliver(task.task_id, "file_write", "output/extra.txt", True)["reason"] == "target_exists"


def test_delivery_without_staging_keeps_the_old_behaviour(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    storage = GovernanceStorage(tmp_path / "g.db")
    task, _ = TaskIntakeService(storage).submit_task("Summarise input/data.csv", "finance_bot", str(ws))
    ExpansionService(storage, user_approval_hook=lambda req: True).request_and_wait(
        task.task_id, task.agent_id, "file_write", "output/extra.txt", "needed")
    out = ExpansionDelivery(ws, storage).deliver(task.task_id, "file_write", "output/extra.txt", True)
    assert out["type"] == "broker_tool_only"
    assert not (ws / "output/extra.txt").exists()


# --- both layers: staged/ is writable, the target never is -----------------

def test_resolver_and_broker_agree_on_staged(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    storage = GovernanceStorage(tmp_path / "g.db")
    task, boundary = TaskIntakeService(storage).submit_task(
        "Summarise input/data.csv into output/summary.txt", "finance_bot", str(ws))
    rb = resolve_boundary(boundary, ws)
    staged = [e for e in rb.entries if e.path == os.path.realpath(ws / "staged")]
    assert staged and staged[0].kind == "dir" and {"write", "create"} <= set(staged[0].access)
    ev = ResolvedBoundaryEvaluator(storage)
    assert ev.evaluate_file_access(boundary, "staged/output/extra.txt", True).verdict == EventVerdict.INSIDE
    assert ev.evaluate_file_access(boundary, "output/extra.txt", True).verdict == EventVerdict.OUTSIDE
    # Even after a person approves the write, the agent cannot write the target itself.
    ExpansionService(storage, user_approval_hook=lambda req: True).request_and_wait(
        task.task_id, task.agent_id, "file_write", "output/extra.txt", "needed")
    current = storage.get_boundary(task.task_id)
    assert ev.evaluate_file_access(current, "output/extra.txt", True).verdict == EventVerdict.OUTSIDE
    # A boundary entry may not name the staging folder.
    boundary.files_write.append("staged/x.txt")
    assert ("staged/x.txt", "reserved_runtime_path") in resolve_boundary(boundary, ws).skipped


# --- the agent-facing request ----------------------------------------------

def _server(tmp_path: Path, approve: bool) -> tuple[BrokerRPCServer, GovernanceStorage, Path, str]:
    ws = _ws(tmp_path)
    storage = GovernanceStorage(tmp_path / "g.db")
    task, _ = TaskIntakeService(storage).submit_task(
        "Summarise input/data.csv into output/summary.txt", "finance_bot", str(ws))
    token = "gov_tok_staged_1"
    storage.save_token(token, task.task_id, task.agent_id)
    exp = ExpansionService(storage, user_approval_hook=lambda req: approve)
    broker = ToolBroker(storage, expansion_service=exp, evaluator=ResolvedBoundaryEvaluator(storage))
    srv = BrokerRPCServer(broker, tmp_path / "b.sock", task.task_id,
                          delivery=ExpansionDelivery(ws, storage, staging=True))
    return srv, storage, ws, token


def test_request_without_staged_content_asks_to_stage_first(tmp_path: Path) -> None:
    srv, storage, ws, token = _server(tmp_path, approve=True)
    res = srv._h_request_access(token, {"resource_type": "file_write", "resource_target": "output/extra.txt",
                                        "justification": "a second summary"})
    assert res["granted"] is False and res["status"] == "STAGE_FIRST"
    assert "staged/output/extra.txt" in res["message"]
    assert storage.list_expansion_requests(task_id=srv.task_id) == []  # no card for nothing to review
    assert not (ws / "output/extra.txt").exists()


def test_approved_request_lands_the_staged_content(tmp_path: Path) -> None:
    srv, storage, ws, token = _server(tmp_path, approve=True)
    srv.broker.write_file(token, "staged/output/extra.txt", "Total: 22\n")  # through the broker, like write_file
    res = srv._h_request_access(token, {"resource_type": "file_write", "resource_target": "staged/output/extra.txt",
                                        "justification": "a second summary"})
    assert res["granted"] is True and res["delivery"]["type"] == "file_land"
    assert (ws / "output/extra.txt").read_text() == "Total: 22\n"
    staged_events = [e for e in storage.get_events_for_task(srv.task_id) if e.kind == "staged_write"]
    assert staged_events and staged_events[-1].details["preview"] == "Total: 22\n"
    assert staged_events[-1].details["content_sha256"] == res["delivery"]["content_sha256"]
    req = storage.list_expansion_requests(task_id=srv.task_id)[-1]
    assert req.resource_target == "output/extra.txt" and req.status == ExpansionStatus.APPROVED


def test_denied_request_lands_nothing(tmp_path: Path) -> None:
    srv, storage, ws, token = _server(tmp_path, approve=False)
    _stage(ws, "output/extra.txt", b"Total: 22\n")
    res = srv._h_request_access(token, {"resource_type": "file_write", "resource_target": "output/extra.txt",
                                        "justification": "a second summary"})
    assert res["granted"] is False
    assert not (ws / "output/extra.txt").exists()


def test_write_over_an_input_is_high_risk_and_never_lands(tmp_path: Path) -> None:
    srv, storage, ws, token = _server(tmp_path, approve=True)
    _stage(ws, "input/data.csv", b"tampered\n")
    res = srv._h_request_access(token, {"resource_type": "file_write", "resource_target": "input/data.csv",
                                        "justification": "fix the data"})
    assert res["granted"] is False
    assert (ws / "input/data.csv").read_text() == "a,b\n1,2\n"


# --- provenance: a reviewed write goes to a person, an unreviewed one stays denied ----

def test_write_after_reading_files_goes_to_a_person_only_when_content_is_reviewed(tmp_path: Path) -> None:
    srv, storage, ws, token = _server(tmp_path, approve=True)
    exp = srv.broker.expansion_service
    exp.user_approval_hook = None  # leave it waiting, to read the decision before a person acts
    exp.record_untrusted_read(srv.task_id, "file_read", "input/data.csv", "a,b\n1,2\n")
    # Without a reviewed snapshot: MEDIUM escalated to HIGH, denied by policy (unchanged).
    plain = exp.evaluate_request(srv.task_id, "finance_bot", "file_write", "output/plain.txt", "x")
    assert plain.status == ExpansionStatus.DENIED and plain.effective_risk_tier.value == "HIGH"
    # With a reviewed snapshot: flagged as escalated, but a person decides.
    _stage(ws, "output/note.txt", b"note\n")
    assert srv._stage_for_review("output/note.txt") is None
    reviewed = exp.evaluate_request(srv.task_id, "finance_bot", "file_write", "output/note.txt", "x")
    assert reviewed.status == ExpansionStatus.PENDING and reviewed.escalated_by_provenance is True
    assert reviewed.effective_risk_tier.value == "MEDIUM"
    # A HIGH baseline is never lowered, even when staged.
    _stage(ws, "input/data.csv", b"tampered\n")
    assert srv._stage_for_review("input/data.csv") is None
    over = exp.evaluate_request(srv.task_id, "finance_bot", "file_write", "input/data.csv", "x")
    assert over.status == ExpansionStatus.DENIED


def test_save_extra_file_example_needs_a_reviewed_write() -> None:
    from demo.security_monitor.app.governance import run_manager as rm
    p = rm.PRESETS["save_extra_file"]
    assert p["agent"] == "finance_bot" and "finance_note" not in p["prompt"]
    steps = p["scripted_steps"]
    staged = [s for s in steps if s.get("tool") == "write_file" and s["args"]["path"].startswith("staged/")]
    asked = [s for s in steps if s.get("tool") == "request_access"]
    assert staged[0]["args"]["path"] == "staged/output/finance_note.txt"
    assert asked[0]["args"] == {"resource_type": "file_write", "resource_target": "output/finance_note.txt",
                                "justification": asked[0]["args"]["justification"]}
    assert steps.index(staged[0]) < steps.index(asked[0])
