"""Milestone 6.1 tests: boundary-compiled sandbox, broker RPC, launcher, freeze, receipts.

Linux/WSL2-only tests are skipped elsewhere. Tests that need an LLM use the
ScriptedLLMProvider MOCK (the tool calls are scripted; the OS layer, broker,
sensor and correlator are real).
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from demo.security_monitor.app.governance.llm_agent import (
    AgentBrokerClient,
    rpc_recv_frame,
    rpc_send_frame,
)
from demo.security_monitor.app.governance.models import TaskBoundary
from demo.security_monitor.app.governance.receipt import chain_entries, verify_chain
from demo.security_monitor.app.governance.redaction import redact_command
from demo.security_monitor.app.governance.storage import GovernanceStorage

IS_LINUX = sys.platform == "linux"
linux_only = pytest.mark.skipif(not IS_LINUX, reason="M6 OS layer requires Linux (WSL2)")
ROOT = Path(__file__).resolve().parents[3]
OS_LAYER = ROOT / "demo" / "security_monitor" / "app" / "governance" / "os_layer"


def _have_systemd_user() -> bool:
    if not IS_LINUX or not shutil.which("systemd-run"):
        return False
    r = subprocess.run(["systemctl", "--user", "is-system-running"], capture_output=True, text=True)
    return r.stdout.strip() in ("running", "degraded")


needs_scope = pytest.mark.skipif(not _have_systemd_user(), reason="needs systemd --user and systemd-run --scope")


# ---------------------------------------------------------------------------
# Platform-independent unit tests
# ---------------------------------------------------------------------------

def test_redaction_masks_secret_shapes() -> None:
    cmd = 'curl -H "Authorization: Bearer abcdefghijklmnop" -d api_key=xyz123 http://x CANARY-abc12345 gov_tok_deadbeef'
    out = redact_command(cmd)
    for leaked in ("abcdefghijklmnop", "xyz123", "CANARY-abc12345", "gov_tok_deadbeef"):
        assert leaked not in out
    assert redact_command("wc -l input/sales.csv") == "wc -l input/sales.csv"


def test_receipt_hash_chain_detects_edits() -> None:
    entries = [{"verdict": "INSIDE", "target": "a"}, {"verdict": "OUTSIDE", "target": "b"}, {"verdict": "INSIDE", "target": "c"}]
    final = chain_entries(entries)
    ok, recomputed, _ = verify_chain(entries)
    assert ok and recomputed == final
    entries[1]["target"] = "edited"
    ok, _, msg = verify_chain(entries)
    assert not ok and "entry 1" in msg
    entries[1]["target"] = "b"
    del entries[0]
    ok, _, _ = verify_chain(entries)
    assert not ok


@linux_only
def test_compile_rules_per_file_from_boundary(tmp_path: Path) -> None:
    from demo.security_monitor.app.governance.os_layer.sandbox_spec import compile_landlock_rules, is_access_permitted

    ws = tmp_path / "ws"
    (ws / "input").mkdir(parents=True)
    (ws / "input" / "sales.csv").write_text("a\n")
    (ws / "input" / "private.txt").write_text("secret\n")
    (ws / "input" / "credentials.json").write_text("{}")
    b = TaskBoundary(task_id="t1", workspace_root=str(ws), files_read=["input/sales.csv"],
                     files_write=["output/summary.txt"], tools=["read_file", "run_command"])
    spec = compile_landlock_rules(b, ws, proxy_port=12345)
    paths = {r["path"]: r["access"] for r in spec["rules"]}
    real_ws = os.path.realpath(ws)
    assert paths[f"{real_ws}/input/sales.csv"] == ["read_file"]
    assert f"{real_ws}/input" not in paths, "must not grant the whole input/ directory"
    assert f"{real_ws}/input/private.txt" not in paths
    # output/ is task-owned: one directory-level read-write rule, no per-file pre-creation.
    assert "make_reg" in paths[f"{real_ws}/output"] and "remove_file" in paths[f"{real_ws}/output"]
    assert f"{real_ws}/output/summary.txt" not in paths
    assert spec["tcp_connect_ports"] == [12345]
    assert "/tmp" not in paths
    assert is_access_permitted(spec, f"{real_ws}/input/private.txt", ["read_file"]) is False
    assert is_access_permitted(spec, f"{real_ws}/input/sales.csv", ["read_file"]) is True

    # Globs expand per file at launch and exclude sensitive-pattern files.
    b2 = b.model_copy(update={"files_read": ["input/*"]})
    spec2 = compile_landlock_rules(b2, ws, proxy_port=None)
    p2 = {r["path"] for r in spec2["rules"]}
    assert f"{real_ws}/input/private.txt" in p2
    assert f"{real_ws}/input/credentials.json" not in p2
    assert any(s["reason"] == "sensitive_pattern_excluded_from_glob" for s in spec2["_compile_report"]["skipped"])


# ---------------------------------------------------------------------------
# Broker RPC (UDS): no self-approval, size limits, token binding
# ---------------------------------------------------------------------------

@pytest.fixture
def rpc_env(tmp_path: Path):
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("AF_UNIX not available")
    from demo.security_monitor.app.governance.broker import ToolBroker
    from demo.security_monitor.app.governance.broker_rpc import BrokerRPCServer
    from demo.security_monitor.app.governance.expansion import ExpansionService
    from demo.security_monitor.app.governance.intake import TaskIntakeService

    storage = GovernanceStorage(tmp_path / "gov.db")
    ws = tmp_path / "ws"
    (ws / "input").mkdir(parents=True)
    (ws / "input" / "report.txt").write_text("hello")
    task, boundary = TaskIntakeService(storage).submit_task("Read input/report.txt", "agent_rpc", str(ws))
    token = "gov_tok_rpc_test_1"
    storage.save_token(token, task.task_id, task.agent_id)
    exp = ExpansionService(storage, user_approval_hook=None)
    broker = ToolBroker(storage, expansion_service=exp)
    sock_path = Path("/tmp") / f"m6rpc_{os.getpid()}_{time.time_ns()}.sock" if IS_LINUX else tmp_path / "b.sock"
    srv = BrokerRPCServer(broker, sock_path, task.task_id, read_timeout=2.0, call_timeout=5.0, max_request_bytes=64 * 1024)
    srv.start()
    srv.armed.set()
    yield {"storage": storage, "srv": srv, "token": token, "task": task, "sock": str(sock_path), "exp": exp}
    srv.stop()


def _raw_call(sock_path: str, frame: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    rpc_send_frame(s, frame)
    resp = rpc_recv_frame(s, 1 << 22)
    s.close()
    return resp


def test_rpc_exposes_only_agent_endpoints_no_self_approval(rpc_env) -> None:
    from demo.security_monitor.app.governance.broker_rpc import AGENT_ENDPOINTS
    from demo.security_monitor.app.governance.models import ExpansionStatus

    assert set(AGENT_ENDPOINTS) == {"read_file", "write_file", "http_get", "call_agent",
                                    "request_access", "run_command_check", "llm_complete"}
    client = AgentBrokerClient(token=rpc_env["token"], uds_path=rpc_env["sock"], uds_timeout=10)
    # Agent requests something MEDIUM (pending -> times out -> denied); then tries to approve it itself.
    res = client.request_access("file_read", "notes/other.txt", "need it")
    assert res["granted"] is False
    reqs = rpc_env["storage"].list_expansion_requests(task_id=rpc_env["task"].task_id)
    req_id = reqs[-1].request_id
    for method in ("approve_request", "deny_request", "grant_resource_proactively", "approve", "grant",
                   "_authenticate", "expansion_service", "__class__", "run_command", "storage"):
        resp = _raw_call(rpc_env["sock"], {"token": rpc_env["token"], "method": method,
                                           "params": {"request_id": req_id, "approved_by": "human_user"}})
        assert resp["ok"] is False and resp["error_type"] == "PermissionError", method
    assert rpc_env["storage"].get_expansion_request(req_id).status != ExpansionStatus.APPROVED
    assert {r["reason"] for r in rpc_env["srv"].rejections} == {"endpoint_not_exposed"}


def test_rpc_rejects_oversized_and_wrong_token(rpc_env) -> None:
    resp = _raw_call(rpc_env["sock"], {"token": rpc_env["token"], "method": "write_file",
                                       "params": {"file_path": "output/x.txt", "content": "A" * (128 * 1024)}})
    assert resp["ok"] is False and resp["error_type"] == "ValueError"
    resp = _raw_call(rpc_env["sock"], {"token": "gov_tok_forged", "method": "read_file", "params": {"file_path": "input/report.txt"}})
    assert resp["ok"] is False and resp["error_type"] == "PermissionError"
    client = AgentBrokerClient(token=rpc_env["token"], uds_path=rpc_env["sock"], uds_timeout=10)
    assert client.read_file("input/report.txt") == "hello"
    with pytest.raises(PermissionError):
        client.read_file("../outside.txt")


def test_rpc_llm_complete_ignores_agent_model_choice(rpc_env) -> None:
    seen = {}

    def provider(messages, tools=None, model=None, **kw):
        seen["model"] = model
        seen["kw"] = kw
        return {"role": "assistant", "content": "ok", "tool_calls": None}

    rpc_env["srv"].broker.default_llm_provider = provider
    rpc_env["srv"].llm_model = "launcher-fixed-model"
    resp = _raw_call(rpc_env["sock"], {"token": rpc_env["token"], "method": "llm_complete",
                                       "params": {"messages": [{"role": "user", "content": "hi"}], "model": "evil",
                                                  "base_url": "http://attacker", "custom_provider": "x"}})
    assert resp["ok"] is True
    assert seen["model"] == "launcher-fixed-model"
    assert "base_url" not in seen["kw"]


# ---------------------------------------------------------------------------
# Landlock rules mode (real kernel)
# ---------------------------------------------------------------------------

@linux_only
def test_boundary_rules_out_of_boundary_input_unreadable_in_sandbox(tmp_path: Path) -> None:
    """A file in input/ that is not in the boundary is unreadable from a shell inside the sandbox;
    control: the same file is readable outside the sandbox."""
    from demo.security_monitor.app.governance.os_layer.sandbox_spec import compile_landlock_rules, write_rules_file

    base = Path(os.environ["HOME"]) / "agent_workspaces"
    ws = base / f"pytest_m6_rules_{os.getpid()}_{time.time_ns()}"
    (ws / "input").mkdir(parents=True)
    try:
        (ws / "input" / "sales.csv").write_text("id,amount\n1,5\n")
        (ws / "input" / "private.txt").write_text("OUT_OF_BOUNDARY_7711\n")
        b = TaskBoundary(task_id="t_rules", workspace_root=str(ws), files_read=["input/sales.csv"],
                         files_write=["output/summary.txt"], tools=["run_command"])
        rules = write_rules_file(compile_landlock_rules(b, ws, proxy_port=None), tmp_path / "rules.json")

        control = subprocess.run(["/bin/sh", "-c", "cat input/private.txt"], cwd=ws, capture_output=True, text=True)
        assert control.returncode == 0 and "OUT_OF_BOUNDARY_7711" in control.stdout

        r = subprocess.run(
            [str(OS_LAYER / "landlock_enforcer"), "--rules", str(rules), "--mode", "enforce", "--",
             "/bin/sh", "-c", "cat input/sales.csv; cat input/private.txt; echo rc=$?; echo done > output/summary.txt; echo w=$?; cat /etc/hostname >/dev/null; echo x > input/new.txt; echo n=$?"],
            cwd=ws, capture_output=True, text=True, timeout=30,
        )
        assert "id,amount" in r.stdout
        assert "OUT_OF_BOUNDARY_7711" not in r.stdout
        assert "Permission denied" in r.stderr
        assert "rc=1" in r.stdout and "w=0" in r.stdout and "n=2" in r.stdout
        assert (ws / "output" / "summary.txt").read_text() == "done\n"
    finally:
        shutil.rmtree(ws, ignore_errors=True)


@linux_only
def test_enforcer_rules_mode_fails_closed_on_bad_rules(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    for content in ('{"version":1,"task_tmp":"/tmp","rules":[{"path":"/usr","access":["fly"]}]}',
                    '{"version":2,"task_tmp":"/tmp","rules":[]}',
                    '{"version":1,"task_tmp":"/tmp","rules":[{"path":"/does/not/exist","access":["read_file"]}]}',
                    'not json'):
        bad.write_text(content)
        r = subprocess.run([str(OS_LAYER / "landlock_enforcer"), "--rules", str(bad), "--", "/bin/true"],
                           capture_output=True, text=True)
        assert r.returncode != 0 and "SECURITY_ERROR" in r.stderr, content


@linux_only
def test_sensor_reports_return_values_and_keeps_signals() -> None:
    r = subprocess.run([str(OS_LAYER / "sensor"), "/bin/sh", "-c",
                        "cat /nonexistent_m6 2>/dev/null; trap 'echo TERM_OK' TERM; kill -TERM $$; (exit 3) & wait $!; echo bg=$?"],
                       capture_output=True, text=True, timeout=30)
    lines = [json.loads(l) for l in r.stdout.splitlines() if l.startswith('{"source":"os_sensor"')]
    assert lines[0]["type"] == "start" and lines[-1]["type"] == "exit"
    assert "TERM_OK" in r.stdout and "bg=3" in r.stdout
    sys_ev = [e for e in lines if e.get("type") == "syscall"]
    assert all({"pid", "ppid", "syscall", "target", "ret", "result", "cgroup_id", "cgroup_status"} <= set(e) for e in sys_ev)
    assert any(e["syscall"] == "execve" and e["result"] == "ok" for e in sys_ev)


# ---------------------------------------------------------------------------
# Launcher end-to-end (scripted MOCK LLM; real scope, sensor, seccomp, Landlock)
# ---------------------------------------------------------------------------

def _launch(tmp_path: Path, steps: list[dict], test_hooks: dict | None = None, **spec_kw):
    from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec

    storage = GovernanceStorage(tmp_path / "gov.db")
    base = Path(os.environ["HOME"]) / "agent_workspaces"
    launcher = TaskLauncher(storage, workspace_base=base, receipts_dir=tmp_path / "receipts", test_hooks=test_hooks)
    spec = TaskSpec(
        prompt="Count the rows of input/sales.csv and write the count to output/summary.txt",
        inputs={"input/sales.csv": "id,amount\n1,10\n2,20\n", "input/private_notes.txt": "CANARY-pytest-notes\n"},
        output_targets=["output/summary.txt"],
        llm={"provider": "scripted", "steps": steps},
        timeout_s=90,
        freeze_timeout_s=1.0,
        **spec_kw,
    )
    res = launcher.run(spec)
    return res, storage, launcher


def _cleanup(res) -> None:
    shutil.rmtree(res.workspace, ignore_errors=True)
    shutil.rmtree(res.control_dir, ignore_errors=True)


@linux_only
@needs_scope
def test_launcher_vertical_slice_landlock_prevents_shell_read(tmp_path: Path) -> None:
    steps = [
        {"tool": "run_command", "args": {"command": "wc -l input/sales.csv"}},
        {"tool": "run_command", "args": {"command": "cat input/private_notes.txt"}},
        {"tool": "write_file", "args": {"file_path": "output/summary.txt", "content": "rows=2"}},
        {"final": "done"},
    ]
    res, storage, _ = _launch(tmp_path, steps)
    try:
        r = res.receipt
        assert res.aborted is None
        assert r["isolation_level"] == "landlock+ns+seccomp+sensor"
        assert r["freeze_events"] == []
        assert r["os_identity"]["cgroup_path"].endswith(".scope")
        hist = res.shim_result["tool_history"]
        assert "3 input/sales.csv" in hist[0]["output"]["stdout"]  # header + 2 rows
        assert "CANARY-pytest-notes" not in json.dumps(res.model_inputs)
        landlock_reads = [e for e in r["outside_events"] if e["prevented_by"] == "landlock"
                          and e["target"].endswith("input/private_notes.txt") and e["channel"] == "shell"]
        assert landlock_reads, r["outside_events"]
        assert (res.workspace / "output" / "summary.txt").read_text() == "rows=2"
        assert r["event_counts"]["by_verdict"]["UNATTRIBUTED"] == 0
        # Receipt verifies and holds no file contents / prompt text
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "verify_receipt.py"), str(res.receipt_path)],
                             capture_output=True, text=True)
        assert out.returncode == 0, out.stdout
        raw = res.receipt_path.read_text()
        assert "CANARY-pytest-notes" not in raw and "id,amount" not in raw and "Count the rows" not in raw
    finally:
        _cleanup(res)


@linux_only
@needs_scope
def test_sandboxed_agent_cannot_signal_sensor(tmp_path: Path) -> None:
    steps = [
        {"tool": "run_command", "args": {"command": "kill -9 $(awk '{print $4}' /proc/$PPID/stat); echo kill_rc=$?"}},
        {"final": "done"},
    ]
    res, _, _ = _launch(tmp_path, steps)
    try:
        out = res.shim_result["tool_history"][0]["output"]
        assert "kill_rc=1" in out["stdout"], out
        assert res.receipt["sensor"]["exit_trailer_seen"] is True
        assert res.receipt["freeze_events"] == []
    finally:
        _cleanup(res)


@linux_only
@needs_scope
def test_direct_tcp_connect_prevented_by_landlock(tmp_path: Path) -> None:
    steps = [
        {"tool": "run_command", "args": {"command": "python3 -c \"import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 11434))\""}},
        {"final": "done"},
    ]
    res, _, _ = _launch(tmp_path, steps)
    try:
        assert "PermissionError" in res.shim_result["tool_history"][0]["output"]["stderr"]
        ev = [e for e in res.receipt["outside_events"] if e["kind"] == "network_connect"]
        assert ev and ev[0]["prevented_by"] == "landlock" and ev[0]["result"] == "EACCES"
    finally:
        _cleanup(res)


@linux_only
@needs_scope
def test_expansion_by_delivery_into_granted(tmp_path: Path) -> None:
    steps = [
        {"tool": "run_command", "args": {"command": "cat input/appendix.txt"}},
        {"tool": "request_access", "args": {"resource_type": "file_read", "resource_target": "input/appendix.txt", "justification": "user mentioned the appendix"}},
        {"tool": "run_command", "args": {"command": "cat granted/input/appendix.txt"}},
        {"final": "done"},
    ]
    from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec

    storage = GovernanceStorage(tmp_path / "gov.db")
    launcher = TaskLauncher(storage, workspace_base=Path(os.environ["HOME"]) / "agent_workspaces", receipts_dir=tmp_path / "r")
    spec = TaskSpec(prompt="Summarise input/sales.csv; the appendix may help", inputs={
        "input/sales.csv": "a\n", "input/appendix.txt": "APPENDIX_BODY_42\n"},
        output_targets=["output/summary.txt"], llm={"provider": "scripted", "steps": steps},
        approval_policy="oracle", oracle_allowed=["input/appendix.txt"], timeout_s=90, freeze_timeout_s=1.0)
    res = launcher.run(spec)
    try:
        hist = res.shim_result["tool_history"]
        assert "APPENDIX_BODY_42" not in hist[0]["output"]["stdout"]
        assert hist[1]["output"]["granted"] is True
        assert hist[1]["output"]["delivery"]["delivered_path"] == "granted/input/appendix.txt"
        assert "APPENDIX_BODY_42" in hist[2]["output"]["stdout"]
        exp = res.receipt["expansions"][0]
        assert exp["decision"] == "APPROVED" and exp["delivery"]["type"] == "file_copy"
        assert exp["delivery"]["removed_reason"] == "task_end"
        assert not any((res.workspace / "granted").iterdir())
    finally:
        _cleanup(res)


@linux_only
@needs_scope
def test_freeze_when_sensor_exits_early(tmp_path: Path) -> None:
    killed = {}

    def during(launcher) -> None:
        pid = launcher.live.get("sensor_pid")
        if pid and not killed and launcher.live.get("rpc") and launcher.live["rpc"].call_counts.get("run_command_check"):
            time.sleep(0.3)
            os.kill(pid, 9)
            killed["at"] = time.time()

    steps = [{"tool": "run_command", "args": {"command": "sleep 20"}}, {"final": "done"}]
    t = time.time()
    res, _, _ = _launch(tmp_path, steps, test_hooks={"during_run": during})
    try:
        reasons = [f["reason"] for f in res.receipt["freeze_events"]]
        assert "sensor_exited_early" in reasons
        assert res.receipt["sensor"]["exited_early"] is True
        assert res.receipt["termination"]["reason"].startswith("frozen_then_killed")
        assert time.time() - t < 20, "sleep must have been killed, not run to completion"
    finally:
        _cleanup(res)


@linux_only
@needs_scope
def test_freeze_when_broker_socket_dies(tmp_path: Path) -> None:
    done = {}

    def during(launcher) -> None:
        rpc = launcher.live.get("rpc")
        if rpc and not done and rpc.call_counts.get("run_command_check"):
            time.sleep(0.3)
            rpc.stop()
            done["x"] = 1

    steps = [{"tool": "run_command", "args": {"command": "sleep 20"}}, {"final": "done"}]
    t = time.time()
    res, _, _ = _launch(tmp_path, steps, test_hooks={"during_run": during})
    try:
        first = res.receipt["freeze_events"][0]
        assert first["reason"] == "broker_socket_died"
        assert first["method"] == "cgroup.freeze" and first["frozen_confirmed"] is True
        assert time.time() - t < 20
    finally:
        _cleanup(res)


@linux_only
@needs_scope
def test_freeze_when_isolation_below_enforce(tmp_path: Path) -> None:
    steps = [{"tool": "run_command", "args": {"command": "echo should_not_run"}}, {"final": "done"}]
    res, _, _ = _launch(tmp_path, steps, test_hooks={"enforcer_mode": "observe", "simulate_unshare_fail": True})
    try:
        r = res.receipt
        assert r["freeze_events"][0]["reason"] == "isolation_below_enforce_requirement"
        assert "isolation_level=landlock_only" in r["freeze_events"][0]["detail"]
        # The broker never armed: the agent got no LLM step and ran nothing.
        assert r["extra"]["rpc_call_counts"].get("run_command_check") is None
    finally:
        _cleanup(res)


@linux_only
@needs_scope
def test_freeze_on_unprevented_outside_access(tmp_path: Path) -> None:
    """If an OUTSIDE OS access succeeds under ENFORCE, the task freezes. A test hook
    simulates mis-compiled rules by adding one extra rule granting read on the whole
    workspace, so the out-of-boundary read is not prevented by Landlock."""
    steps = [{"tool": "run_command", "args": {"command": "cat input/private_notes.txt; sleep 20"}}, {"final": "done"}]
    t = time.time()
    res, _, _ = _launch(tmp_path, steps, test_hooks={"rules_override": "allow_workspace_read"})
    try:
        reasons = [f["reason"] for f in res.receipt["freeze_events"]]
        assert "unprevented_outside_os_event" in reasons
        assert time.time() - t < 20
    finally:
        _cleanup(res)


# ---------------------------------------------------------------------------
# M6.1b: sensor coverage per syscall family
# ---------------------------------------------------------------------------

def _sensor_events(script: str, cwd: Path) -> list[dict]:
    r = subprocess.run([str(OS_LAYER / "sensor"), "/usr/bin/python3", "-c", script],
                       cwd=cwd, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return [e for e in (json.loads(l) for l in r.stdout.splitlines() if l.startswith('{"source":"os_sensor"'))
            if e.get("type") == "syscall"]


def _one(events: list[dict], names: tuple[str, ...], needle: str) -> dict:
    hits = [e for e in events if e["syscall"] in names and needle in (e.get("abs_target", "") + e.get("abs_target2", ""))]
    assert hits, f"no {names} event for {needle}: {[e['syscall'] for e in events]}"
    return hits[0]


@linux_only
@pytest.mark.parametrize("family,script,names,needle,expect", [
    ("rename", "import os; open('a','w').close(); os.rename('a','b'); os.rename('missing','c') if False else None",
     ("rename", "renameat", "renameat2"), "/b", "ok"),
    ("unlink", "import os; open('u','w').close(); os.unlink('u')", ("unlink", "unlinkat"), "/u", "ok"),
    ("mkdir", "import os; os.mkdir('dd'); os.rmdir('dd')", ("mkdir", "mkdirat"), "/dd", "ok"),
    ("link", "import os; open('l1','w').close(); os.link('l1','l2')", ("link", "linkat"), "/l2", "ok"),
    ("symlink", "import os; os.symlink('nowhere','sl')", ("symlink", "symlinkat"), "/sl", "ok"),
    ("truncate", "import os; open('t','w').write('abc'); os.truncate('t', 1)", ("truncate",), "/t", "ok"),
    ("ftruncate", "f=open('ft','w'); f.write('abc'); f.flush(); f.truncate(1); f.close()", ("ftruncate",), "/ft", "ok"),
    ("unlink_fail", "import os\ntry: os.unlink('nope')\nexcept OSError: pass", ("unlink", "unlinkat"), "/nope", "ENOENT"),
])
def test_sensor_fsmod_families(tmp_path: Path, family, script, names, needle, expect) -> None:
    ev = _one(_sensor_events(script, tmp_path), names, needle)
    assert ev["result"] == expect and isinstance(ev["ret"], int)
    assert ev["cgroup_status"] == "ok" and ev["ppid"] > 0
    if family in ("rename", "link", "symlink"):
        assert ev["abs_target2"].startswith(str(tmp_path))


@linux_only
def test_sensor_send_with_destination(tmp_path: Path) -> None:
    script = ("import socket\nu=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
              "u.sendto(b'x', ('127.0.0.1', 9))\nu.sendmsg([b'y'], [], 0, ('127.0.0.1', 9))\n"
              "c=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.connect(('127.0.0.1', 9)); c.send(b'z')\n")
    evs = _sensor_events(script, tmp_path)
    assert _one(evs, ("sendto",), "inet:127.0.0.1:9")["result"] == "ok"
    assert _one(evs, ("sendmsg",), "inet:127.0.0.1:9")["result"] == "ok"
    # send() on a connected socket has no destination address and is not emitted as sendto
    assert sum(1 for e in evs if e["syscall"] == "sendto") == 1


def _bind_traceable() -> bool:
    """WSL2's init installs a seccomp filter whose action for bind() outranks SECCOMP_RET_TRACE."""
    probe = ("import ctypes, socket\nlib=ctypes.CDLL('libseccomp.so.2')\nlib.seccomp_init.restype=ctypes.c_void_p\n"
             "ctx=lib.seccomp_init(0x7fff0000)\nlib.seccomp_rule_add(ctypes.c_void_p(ctx), 0x7ff00003, 49, 0)\n"
             "lib.seccomp_load(ctypes.c_void_p(ctx))\ns=socket.socket()\n"
             "try:\n s.bind(('127.0.0.1', 0)); print('BIND_OK')\nexcept OSError as e: print('ERR', e.errno)\n")
    r = subprocess.run(["/usr/bin/python3", "-c", probe], capture_output=True, text=True)
    return "ERR 38" in r.stdout  # ENOSYS: our TRACE action took effect with no tracer attached


@linux_only
def test_sensor_bind(tmp_path: Path) -> None:
    if not _bind_traceable():
        pytest.skip("bind() not observable: a pre-existing seccomp filter (WSL2 init) outranks SECCOMP_RET_TRACE for bind")
    ev = _one(_sensor_events("import socket; socket.socket().bind(('127.0.0.1', 0))", tmp_path), ("bind",), "inet:127.0.0.1:")
    assert ev["result"] == "ok"


@linux_only
def test_landlock_denies_tcp_bind_even_if_unobserved(tmp_path: Path) -> None:
    from demo.security_monitor.app.governance.os_layer.sandbox_spec import compile_landlock_rules, write_rules_file

    ws = Path(os.environ["HOME"]) / "agent_workspaces" / f"pytest_bind_{os.getpid()}_{time.time_ns()}"
    ws.mkdir(parents=True)
    try:
        b = TaskBoundary(task_id="t_bind", workspace_root=str(ws), tools=["run_command"])
        rules = write_rules_file(compile_landlock_rules(b, ws, proxy_port=None), tmp_path / "r.json")
        r = subprocess.run([str(OS_LAYER / "landlock_enforcer"), "--rules", str(rules), "--", "/usr/bin/python3", "-c",
                            "import socket\ntry: socket.socket().bind(('127.0.0.1', 0)); print('BOUND')\nexcept PermissionError: print('DENIED')"],
                           cwd=ws, capture_output=True, text=True, timeout=30)
        assert "DENIED" in r.stdout, r.stdout + r.stderr
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# ---------------------------------------------------------------------------
# M6.1b: task-owned output/ is directory-level read-write
# ---------------------------------------------------------------------------

@linux_only
def test_output_dir_sed_inplace_and_rename_work_but_not_into_input(tmp_path: Path) -> None:
    from demo.security_monitor.app.governance.os_layer.sandbox_spec import compile_landlock_rules, write_rules_file

    ws = Path(os.environ["HOME"]) / "agent_workspaces" / f"pytest_out_{os.getpid()}_{time.time_ns()}"
    (ws / "input").mkdir(parents=True)
    try:
        (ws / "input" / "sales.csv").write_text("a\n")
        b = TaskBoundary(task_id="t_out", workspace_root=str(ws), files_read=["input/sales.csv"],
                         files_write=["output/summary.txt", "summary.txt"], tools=["run_command"])
        spec = compile_landlock_rules(b, ws, proxy_port=None)
        assert not (ws / "summary.txt").exists(), "bare alias of output target must not be pre-created"
        assert not (ws / "output" / "summary.txt").exists(), "output/ targets are covered by the dir rule"
        rules = write_rules_file(spec, tmp_path / "r.json")
        script = (
            "echo one > output/summary.txt && sed -i 's/one/two/' output/summary.txt && echo sed_ok; "
            "echo tmp > output/.tmp_x && mv output/.tmp_x output/summary2.txt && echo rename_ok; "
            "mkdir -p scratch/work && echo s > scratch/work/f && echo scratch_ok; "
            "mv output/summary2.txt input/summary2.txt 2>/dev/null || echo into_input_denied; "
            f"mv output/summary2.txt {os.environ['HOME']}/m6_should_not_exist.txt 2>/dev/null || echo outside_denied; "
            "cp input/sales.csv input/copy.csv 2>/dev/null || echo input_write_denied"
        )
        r = subprocess.run([str(OS_LAYER / "landlock_enforcer"), "--rules", str(rules), "--", "/bin/sh", "-c", script],
                           cwd=ws, capture_output=True, text=True, timeout=30)
        for marker in ("sed_ok", "rename_ok", "scratch_ok", "into_input_denied", "outside_denied", "input_write_denied"):
            assert marker in r.stdout, (marker, r.stdout, r.stderr)
        assert (ws / "output" / "summary.txt").read_text() == "two\n"
        assert (ws / "output" / "summary2.txt").exists()
        assert not (Path(os.environ["HOME"]) / "m6_should_not_exist.txt").exists()
    finally:
        shutil.rmtree(ws, ignore_errors=True)


@linux_only
@needs_scope
def test_unlisted_output_write_recorded_inside_with_note(tmp_path: Path) -> None:
    steps = [
        {"tool": "run_command", "args": {"command": "echo x > output/extra_notes.txt; sed -i 's/x/y/' output/extra_notes.txt; mv output/extra_notes.txt output/final.txt"}},
        {"final": "done"},
    ]
    res, _, _ = _launch(tmp_path, steps)
    try:
        assert res.receipt["freeze_events"] == []
        evs = [e for e in res.receipt["events"] if e.get("source") == "OS_SENSOR" and "output/" in str(e.get("target"))
               and e["kind"] in ("file_write", "file_rename")]
        assert evs and all(e["verdict"] == "INSIDE" for e in evs)
        assert any("not in files_write" in e["rule_matched"] for e in evs)
        assert any(e["kind"] == "file_rename" for e in evs)
        assert (res.workspace / "output" / "final.txt").read_text() == "y\n"
    finally:
        _cleanup(res)


# ---------------------------------------------------------------------------
# M6.1b: broker.run_command uses --rules; legacy mode is labelled
# ---------------------------------------------------------------------------

@linux_only
@needs_scope
def test_broker_run_command_uses_boundary_rules(tmp_path: Path) -> None:
    from demo.security_monitor.app.governance.broker import ToolBroker
    from demo.security_monitor.app.governance.intake import TaskIntakeService

    ws = Path(os.environ["HOME"]) / "agent_workspaces" / f"pytest_brk_{os.getpid()}_{time.time_ns()}"
    (ws / "input").mkdir(parents=True)
    try:
        (ws / "input" / "report.txt").write_text("REPORT_OK\n")
        (ws / "input" / "private.txt").write_text("PRIVATE_7788\n")
        storage = GovernanceStorage(tmp_path / "g.db")
        task, b = TaskIntakeService(storage).submit_task("Read input/report.txt", "agent_b", str(ws))
        b.tools.append("run_command")
        storage.save_boundary(b)
        storage.save_token("gov_tok_brk", task.task_id, task.agent_id)
        res = ToolBroker(storage).run_command("gov_tok_brk", "cat input/report.txt; cat input/private.txt")
        assert res["isolation_level"] == "landlock_rules"
        assert "REPORT_OK" in res["stdout"] and "PRIVATE_7788" not in res["stdout"]
    finally:
        shutil.rmtree(ws, ignore_errors=True)
        shutil.rmtree(ws.parent / ".control" / task.task_id, ignore_errors=True)


@linux_only
@needs_scope
def test_legacy_workspace_mode_is_labelled(tmp_path: Path) -> None:
    from demo.security_monitor.app.governance.os_layer.runner import CgroupTaskRunner, TaskWorkspace

    ws = TaskWorkspace(task_id=f"pytest_legacy_{os.getpid()}_{time.time_ns()}")
    try:
        res = CgroupTaskRunner().run_task_command(ws.task_id, ["/bin/true"], ws)
        assert res.isolation_level == "legacy_workspace"
    finally:
        ws.cleanup()


@linux_only
def test_sensor_resolves_relative_unix_socket_path(tmp_path: Path) -> None:
    """Regression (M6.1b): connect('broker.sock') must be reported with its absolute path,
    otherwise the correlator cannot recognise the broker socket and would freeze the task."""
    script = "import socket; s=socket.socket(socket.AF_UNIX); s.connect_ex('rel.sock')"
    ev = _one(_sensor_events(script, tmp_path), ("connect",), "rel.sock")
    assert ev["abs_target"] == f"unix:{os.path.realpath(tmp_path)}/rel.sock"
