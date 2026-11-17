"""Prompt-to-task attribution (roadmap item 3): each command a tool call runs gets its own
child cgroup (call_NNN) under the task scope, so every OS event is linked to the exact tool
call that caused it, including background jobs and double forks.

The unit tests here run anywhere. The end-to-end tests (real sensor, real cgroups, two
tasks at once) are marked os_layer and run in CI.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from demo.security_monitor.app.governance import broker_rpc as rpc_mod
from demo.security_monitor.app.governance.correlator import tool_call_of
from demo.security_monitor.app.governance.os_layer import cgroup_ctl
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.measure_attribution import os_events as _os_events
from demo.security_monitor.measure_attribution import run_batch, run_task, score_attribution

TASK_CG = "/user.slice/user-1000.slice/user@1000.service/app.slice/gov-task_ab12.scope"


# --- labelling events ----------------------------------------------------------------

def test_tool_call_label_comes_from_where_the_cgroup_sits_under_the_task() -> None:
    assert tool_call_of(TASK_CG, TASK_CG) == "task_root"
    assert tool_call_of(TASK_CG + "/call_007", TASK_CG) == "call_007"
    assert tool_call_of(TASK_CG + "/call_007/deeper", TASK_CG) == "call_007"
    assert tool_call_of(TASK_CG + "/something_else", TASK_CG) == "task_root_subtree"
    assert tool_call_of(TASK_CG, None) is None and tool_call_of(None, TASK_CG) is None


# --- cgroup helpers (on a stand-in cgroup tree) ------------------------------------------

@pytest.fixture
def fake_cgroupfs(tmp_path: Path, monkeypatch):
    root = tmp_path / "cgroup"
    (root / TASK_CG.lstrip("/")).mkdir(parents=True)
    where: dict[int, str] = {}

    def read_proc_cgroup(pid: int):
        return where.get(pid)

    monkeypatch.setattr(cgroup_ctl, "CGROUP_ROOT", root)
    monkeypatch.setattr(cgroup_ctl, "read_proc_cgroup", read_proc_cgroup)
    return root, where


def test_place_in_child_moves_only_a_process_of_the_task(fake_cgroupfs) -> None:
    root, where = fake_cgroupfs
    where[4242] = TASK_CG
    # A real cgroupfs moves the process when its pid is written; the stand-in records it.
    orig_write = Path.write_text

    def write_text(self, data, *a, **kw):
        if self.name == "cgroup.procs":
            where[int(data)] = "/" + str(self.parent.relative_to(root))
        return orig_write(self, data, *a, **kw)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(Path, "write_text", write_text)
        assert cgroup_ctl.place_in_child(TASK_CG, "call_001", 4242) == TASK_CG + "/call_001"
        where[5151] = "/some/other/task.scope"
        with pytest.raises(RuntimeError, match="not in the task cgroup"):
            cgroup_ctl.place_in_child(TASK_CG, "call_002", 5151)
        for bad in ("../escape", "call_1", "call_001/x", "tasks"):
            with pytest.raises(RuntimeError, match="bad child cgroup name"):
                cgroup_ctl.place_in_child(TASK_CG, bad, 4242)
    assert (root / TASK_CG.lstrip("/") / "call_001" / "cgroup.procs").read_text() == "4242"
    assert not (root / TASK_CG.lstrip("/") / "call_002").exists()


def test_a_move_that_did_not_happen_is_reported_and_cleaned_up(fake_cgroupfs) -> None:
    root, where = fake_cgroupfs
    where[4242] = TASK_CG  # the stand-in never moves it
    with pytest.raises(RuntimeError, match="after the move"):
        cgroup_ctl.place_in_child(TASK_CG, "call_001", 4242)


def test_pids_are_counted_in_call_cgroups_too(fake_cgroupfs) -> None:
    """'Is anything still running in this task' must look in call_NNN: a detached
    background job there must not be missed by the leftover-process check."""
    root, _ = fake_cgroupfs
    task = root / TASK_CG.lstrip("/")
    (task / "cgroup.procs").write_text("10\n")
    (task / "call_001").mkdir()
    (task / "call_001" / "cgroup.procs").write_text("11\n12\n")
    assert sorted(cgroup_ctl.cgroup_pids(TASK_CG)) == [10, 11, 12]
    assert cgroup_ctl.cgroup_pids(TASK_CG, recursive=False) == [10]
    (task / "call_001" / "cgroup.procs").unlink()
    assert cgroup_ctl.remove_children(TASK_CG) == []
    assert not (task / "call_001").exists()


# --- the broker RPC endpoint -------------------------------------------------------------

class _FakeBroker:
    def __init__(self, storage: GovernanceStorage) -> None:
        self.storage = storage

    def run_command_check(self, token: str, command: str) -> dict:
        if "forbidden" in command:
            raise PermissionError("Command execution denied")
        return {"allowed": True, "rule_matched": "tool run_command in boundary"}


@pytest.fixture
def rpc(tmp_path: Path):
    storage = GovernanceStorage(tmp_path / "g.db")
    placed: list[tuple[int, str]] = []

    def placer(pid: int, call_id: str) -> dict:
        placed.append((pid, call_id))
        return {"ok": True, "cgroup": f"{TASK_CG}/{call_id}"}

    parents = {501: 100, 502: 100, 503: 999}
    srv = rpc_mod.BrokerRPCServer(_FakeBroker(storage), tmp_path / "b.sock", "task_x",
                                  call_placer=placer, ppid_reader=parents.get)
    return srv, placed


def test_each_allowed_command_gets_its_own_numbered_call(rpc) -> None:
    srv, placed = rpc
    a = srv._h_run_command_check("tok", {"command": "wc -l input/a.csv"})
    b = srv._h_run_command_check("tok", {"command": "curl -H 'Authorization: Bearer abcdefghijklmnop' x"})
    assert (a["call_id"], b["call_id"]) == ("call_001", "call_002") and a["allowed"] is True
    assert srv._h_run_command_begin("tok", {"call_id": "call_002", "pid": 502, "_peer_pid": 100}) == {
        "call_id": "call_002", "placed": True}
    assert placed == [(502, "call_002")]
    calls = {c["call_id"]: c for c in srv.tool_calls}
    assert calls["call_002"]["cgroup"] == f"{TASK_CG}/call_002" and calls["call_002"]["pid"] == 502
    assert "abcdefghijklmnop" not in calls["call_002"]["command"]  # stored redacted
    assert calls["call_001"]["started_at"] is None


def test_a_blocked_command_gets_no_call(rpc) -> None:
    srv, _ = rpc
    with pytest.raises(PermissionError):
        srv._h_run_command_check("tok", {"command": "forbidden thing"})
    assert srv.tool_calls == []


def test_begin_needs_a_checked_call_used_once_and_a_child_of_the_caller(rpc) -> None:
    srv, placed = rpc
    cid = srv._h_run_command_check("tok", {"command": "ls"})["call_id"]
    with pytest.raises(PermissionError, match="unknown or already used"):
        srv._h_run_command_begin("tok", {"call_id": "call_999", "pid": 501, "_peer_pid": 100})
    with pytest.raises(PermissionError, match="not a child"):
        srv._h_run_command_begin("tok", {"call_id": cid, "pid": 503, "_peer_pid": 100})
    with pytest.raises(PermissionError, match="unknown or already used"):  # one try per call
        srv._h_run_command_begin("tok", {"call_id": cid, "pid": 501, "_peer_pid": 100})
    for bad in (True, -5, 1, "501", None):
        cid2 = srv._h_run_command_check("tok", {"command": "ls"})["call_id"]
        with pytest.raises(ValueError):
            srv._h_run_command_begin("tok", {"call_id": cid2, "pid": bad, "_peer_pid": 100})
    assert placed == []
    assert srv.tool_calls[0]["reason"] == "pid_not_a_child_of_caller"


def test_a_failed_placement_still_lets_the_command_run_labelled_task_root(tmp_path: Path) -> None:
    storage = GovernanceStorage(tmp_path / "g.db")

    def placer(_pid: int, _cid: str) -> dict:
        raise OSError("Permission denied")

    srv = rpc_mod.BrokerRPCServer(_FakeBroker(storage), tmp_path / "b.sock", "task_x",
                                  call_placer=placer, ppid_reader=lambda _p: 100)
    cid = srv._h_run_command_check("tok", {"command": "ls"})["call_id"]
    assert srv._h_run_command_begin("tok", {"call_id": cid, "pid": 501, "_peer_pid": 100})["placed"] is False
    assert "Permission denied" in srv.tool_calls[0]["reason"]


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX") or sys.platform != "linux", reason="needs AF_UNIX + /proc")
def test_the_peer_pid_comes_from_the_socket_not_the_request(tmp_path: Path) -> None:
    """An agent cannot claim to be another process: _peer_pid is overwritten from SO_PEERCRED."""
    from demo.security_monitor.app.governance.llm_agent import AgentBrokerClient

    storage = GovernanceStorage(tmp_path / "g.db")
    storage.save_token("gov_tok_attr", "task_x", "agent_a")
    seen: list[int | None] = []
    srv = rpc_mod.BrokerRPCServer(_FakeBroker(storage), Path("/tmp") / f"attr_{os.getpid()}_{time.time_ns()}.sock",
                                  "task_x", call_placer=lambda p, c: {"ok": True, "cgroup": c},
                                  ppid_reader=lambda p: (seen.append(p), os.getpid())[1])
    srv.start()
    srv.armed.set()
    try:
        client = AgentBrokerClient(token="gov_tok_attr", uds_path=str(srv.socket_path), uds_timeout=5)
        cid = client.run_command_check("ls")["call_id"]
        child = subprocess.Popen(["sleep", "5"])
        try:
            res = client._remote_call("run_command_begin", {"call_id": cid, "pid": child.pid, "_peer_pid": 1})
        finally:
            child.kill()
        assert res == {"call_id": cid, "placed": True} and seen == [child.pid]
    finally:
        srv.stop()


def test_ppid_is_read_from_proc_stat() -> None:
    if sys.platform != "linux":
        pytest.skip("needs /proc")
    child = subprocess.Popen(["sleep", "5"])
    try:
        assert rpc_mod._proc_ppid(child.pid) == os.getpid()
    finally:
        child.kill()


# --- the shim's gated spawn ---------------------------------------------------------------

def test_the_shim_holds_the_command_until_it_has_been_placed(tmp_path: Path, monkeypatch) -> None:
    """The command must not start before the control plane has moved it."""
    sys.path.insert(0, str(Path(rpc_mod.__file__).parent))
    from demo.security_monitor.app.governance import agent_shim

    (tmp_path / "tmp").mkdir()
    marker = tmp_path / "tmp" / "ran"
    order: list[str] = []

    class Client(agent_shim.SandboxedBrokerClient):
        def run_command_check(self, command):
            return {"allowed": True, "call_id": "call_001"}

        def run_command_begin(self, call_id, pid):
            time.sleep(0.3)
            order.append("placed" if not marker.exists() else "already_ran")
            return {"call_id": call_id, "placed": True}

    c = Client(token="t", uds_path="/nonexistent", workspace=str(tmp_path), command_timeout=10)
    out = c.run_command("touch tmp/ran; printf 'a\\r\\nb'; read x; echo \"stdin=[$x]\" >&2; exit 3")
    assert order == ["placed"] and marker.exists()
    assert out == {"stdout": "a\nb", "stderr": "stdin=[]\n", "exit_code": 3, "truncated": False}

    t0 = time.time()
    c.command_timeout = 0.5
    out = c.run_command("sleep 10")
    assert out["exit_code"] == -1 and "timed out" in out["stderr"] and time.time() - t0 < 8


# --- end to end: real sensor, real cgroups ---------------------------------------------------

def _cleanup(res) -> None:
    import shutil

    shutil.rmtree(res.workspace, ignore_errors=True)
    shutil.rmtree(res.control_dir, ignore_errors=True)


def test_the_scorer_counts_wrong_and_missing_labels() -> None:
    ev = [
        {"target": "/w/tmp/m1_fg", "tool_call": "call_001", "attributed_task_id": "t"},
        {"target": "/w/tmp/m2_bg", "tool_call": "call_003", "attributed_task_id": "t"},   # wrong call
        {"target": "/w/tmp/m3_ds", "tool_call": "call_003", "attributed_task_id": "other"},  # wrong task
        {"target": "/w/input/sales.csv", "tool_call": "task_root", "attributed_task_id": "t"},  # not a marker
    ]
    s = score_attribution(ev, "t")
    assert s["marker_events"] == 3 and s["correct"] == 1
    assert s["precision"] == 0.5 and round(s["recall"], 3) == 0.333


@pytest.mark.os_layer
def test_every_marker_event_is_linked_to_the_tool_call_that_caused_it(tmp_path: Path) -> None:
    storage = GovernanceStorage(tmp_path / "g.db")
    res = run_task(storage, tmp_path / "receipts", "one")
    try:
        r = res.receipt
        att = r["extra"]["tool_call_attribution"]
        assert att["placed"] == 5 and att["not_placed"] == 0, att
        assert [c["call_id"] for c in att["calls"]] == [f"call_{i:03d}" for i in range(1, 6)]
        assert all(c["cgroup"].endswith("/" + c["call_id"]) for c in att["calls"])
        score = score_attribution(_os_events(r), res.task_id)
        assert score["marker_events"] >= 7, score
        assert score["precision"] == 1.0 and score["recall"] == 1.0, score
        # The agent process's own events are the task root, never a call.
        agent_labels = {e["tool_call"] for e in _os_events(r)
                        if e.get("channel") == "agent_process" and e.get("phase") == "agent"}
        assert agent_labels == {"task_root"}
        assert cgroup_ctl.cgroup_pids(r["os_identity"]["cgroup_path"]) == []
    finally:
        _cleanup(res)


@pytest.mark.os_layer
def test_two_tasks_at_once_never_share_a_label(tmp_path: Path) -> None:
    storage = GovernanceStorage(tmp_path / "g.db")
    ra, rb = run_batch(storage, tmp_path / "receipts", "two", 2)
    try:
        assert ra.task_id != rb.task_id
        for res in (ra, rb):
            score = score_attribution(_os_events(res.receipt), res.task_id)
            assert score["precision"] == 1.0 and score["recall"] == 1.0, score
            assert res.receipt["sensor"]["cross_attributions"] == 0
    finally:
        _cleanup(ra)
        _cleanup(rb)
