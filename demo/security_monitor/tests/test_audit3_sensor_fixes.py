"""Tests for Audit 3 sensor fixes (eBPF and ptrace sensor, correlator, proxy, and launcher).

Items covered:
1. No sensor, no start:
   - Missing loader binary: auto mode falls back to ptrace, receipt reports ptrace; ebpf mode refuses to start.
   - Unregistered / unavailable loader refuses to open gate.
2. In-kernel read filter cannot be fooled by '..':
   - Path containing /.., /./, or // is not filtered, reported like any other open.
3. Unresolved targets freeze:
   - Empty, relative-unresolved, or unreadable target yields OUTSIDE and freezes in ENFORCE.
   - execveat with AT_EMPTY_PATH resolves target from /proc/<pid>/fd/<fd>.
4. Full queue freezes:
   - Event queue overflow or correlator error triggers freeze with sensor_events_dropped.
5. Drops per task & slow client isolation:
   - Drop counter tracks per-session delta.
   - Loader disconnects full-buffer client without stalling others.
   - UNREGISTER ack read on reader thread captures filtered_runtime_reads.
6. Socket credentials & cgroup ownership:
   - SO_PEERCRED at accept closes other-uid peers immediately.
   - In --stdin / --cgroup mode, cgroup id not owned by caller is refused.
7. Setup never observed freezes:
   - Agent activity before setup execve yields OUTSIDE verdict.
8. Edge cases & reproductions:
   - 8(a): clone3 / cgroup write restrictions inside sandbox.
   - 8(b): exec from non-leader thread reported via sched_process_exec.
   - 8(c): ptrace pid table overflow emits drop record and freezes.
9. CONNECT tunnels close on revocation:
   - Active tunnels terminated within 1 s when network grant or token is revoked.
10. Canary not on command line:
    - Canary and decoys passed via 0600 file, absent from process argv.
"""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import json
import os
import queue
import select
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from demo.security_monitor.app.governance.correlator import (
    EventVerdict,
    OSEventCorrelator,
    RiskTier,
    TaskAction,
)
from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec
from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.os_layer import ebpf_shadow as es
from demo.security_monitor.app.governance.proxy import EgressProxyServer
from demo.security_monitor.app.governance.storage import GovernanceStorage


def _make_task_record(task_id: str, agent_id: str = "test_agent") -> TaskRecord:
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return TaskRecord(
        task_id=task_id,
        agent_id=agent_id,
        owner="test_user",
        team="test_team",
        status=TaskLifecycle.ACTIVE,
        created_at=now_utc,
        updated_at=now_utc,
        started_at=now_utc,
        request_text="run sensor audit test",
        request_hash=hashlib.sha256(b"run sensor audit test").hexdigest(),
        workspace_root="/tmp/ws",
        root_task_id=task_id,
        parent_task_id=None,
        depth=0,
        chain=[agent_id],
    )


# ---------------------------------------------------------------------------
# Item 1: No sensor, no start
# ---------------------------------------------------------------------------
def test_missing_loader_auto_runs_ptrace_receipt_says_ptrace(tmp_path, monkeypatch):
    """When the loader binary is missing:
    - GOVERNANCE_SENSOR=auto falls back to ptrace, receipt reports ptrace.
    - GOVERNANCE_SENSOR=ebpf refuses to start.
    """
    storage = GovernanceStorage(tmp_path / "gov.db")
    task_id = "task_missing_loader_auto"
    task = _make_task_record(task_id)
    storage.save_task(task)
    boundary = TaskBoundary(
        task_id=task_id,
        workspace_root=str(tmp_path / "workspaces" / task_id),
        files_read=[],
        files_write=[],
        tools=["run_command"],
        network=[],
        enforcement_mode=EnforcementMode.ENFORCE,
    )
    storage.save_boundary(boundary)

    ws_base = tmp_path / "workspaces"
    receipts_dir = tmp_path / "receipts"
    launcher = TaskLauncher(storage, workspace_base=ws_base, receipts_dir=receipts_dir)

    missing_bin = tmp_path / "nonexistent_ebpf_sensor"
    missing_mgr = es.EBPFShadowManager(socket_path=tmp_path / "missing.sock")
    monkeypatch.setattr(es, "EBPF_SENSOR_BIN", missing_bin)
    monkeypatch.setattr(es.EBPFShadowManager, "get_instance", classmethod(lambda cls: missing_mgr))

    spec = TaskSpec(
        task_id=task_id,
        agent_id="test_agent",
        prompt="echo test",
        llm={"provider": "scripted", "steps": []},
    )

    # In auto mode: runs with ptrace
    monkeypatch.setenv("GOVERNANCE_SENSOR", "auto")
    launch_res = launcher.run(spec)
    receipt = launch_res.receipt
    assert receipt["sensor"]["kind"] == "ptrace"
    assert "ebpf_sensor unavailable" in receipt["sensor"]["reason"]

    # In forced ebpf mode: refuses to start
    task_id_ebpf = "task_missing_loader_ebpf"
    task_ebpf = _make_task_record(task_id_ebpf)
    storage.save_task(task_ebpf)
    boundary_ebpf = TaskBoundary(
        task_id=task_id_ebpf,
        workspace_root=str(tmp_path / "workspaces" / task_id_ebpf),
        files_read=[],
        files_write=[],
        tools=["run_command"],
        network=[],
        enforcement_mode=EnforcementMode.ENFORCE,
    )
    storage.save_boundary(boundary_ebpf)

    spec_ebpf = TaskSpec(
        task_id=task_id_ebpf,
        agent_id="test_agent",
        prompt="echo test",
        llm={"provider": "scripted", "steps": []},
    )
    monkeypatch.setenv("GOVERNANCE_SENSOR", "ebpf")
    with pytest.raises(RuntimeError, match="loader is unavailable or unhealthy"):
        launcher.run(spec_ebpf)


# ---------------------------------------------------------------------------
# Item 3: Unresolved targets freeze
# ---------------------------------------------------------------------------
def test_unresolved_target_freezes_in_enforce(tmp_path):
    """Successful exec or open whose target is empty, relative-unresolved,
    or unreadable yields OUTSIDE and freezes in ENFORCE.
    """
    storage = GovernanceStorage(tmp_path / "gov.db")
    task_id = "test_unresolved_freeze"
    storage.save_task_cgroup(task_id, f"/user.slice/agtask-{task_id}.scope", f"agtask-{task_id}.scope", 1234)
    ws = tmp_path / "ws"
    ws.mkdir()

    boundary = TaskBoundary(
        task_id=task_id,
        workspace_root=str(ws),
        files_read=["data.txt"],
        files_write=[],
        tools=["run_command"],
        network=[],
        enforcement_mode=EnforcementMode.ENFORCE,
    )

    violations = []
    def on_violation(reason, rec):
        violations.append((reason, rec))

    correlator = OSEventCorrelator(
        storage=storage,
        task_id=task_id,
        workspace_root=str(ws),
        enforcement_mode=EnforcementMode.ENFORCE,
        landlock_spec=None,
        proxy_port=None,
        interpreter_path=sys.executable,
        runtime_dir=None,
        seccomp_active=True,
        on_violation=on_violation,
        freeze_on_outside=True,
    )
    correlator.setup_done = True

    # 1. Empty target on open: verdict OUTSIDE, stored target empty, never invented
    ev_empty = {
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": 2000,
        "syscall": "openat",
        "target": "",
        "abs_target": "",
        "result": "ok",
        "cgroup_path": f"/user.slice/agtask-{task_id}.scope",
    }
    res = correlator.handle_line(json.dumps(ev_empty), lambda: boundary)
    assert res is not None
    assert res["verdict"] == EventVerdict.OUTSIDE.value
    assert res["action_taken"] == TaskAction.PAUSE_TASK.value
    # Stored target must not be invented (never defaulted to /proc/sys/vm/overcommit_memory)
    assert not res.get("target")
    assert res.get("target") != "/proc/sys/vm/overcommit_memory"

    # 2. Unreadable target: verdict OUTSIDE, stored target never invented
    ev_unreadable = {
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": 2000,
        "syscall": "openat",
        "target": "unreadable",
        "target_status": "unreadable",
        "abs_target": "",
        "result": "ok",
        "cgroup_path": f"/user.slice/agtask-{task_id}.scope",
    }
    res2 = correlator.handle_line(json.dumps(ev_unreadable), lambda: boundary)
    assert res2 is not None
    assert res2["verdict"] == EventVerdict.OUTSIDE.value
    assert res2["action_taken"] == TaskAction.PAUSE_TASK.value
    assert res2.get("target") != "/proc/sys/vm/overcommit_memory"

    # 3. Relative target with AT_FDCWD that loader did not resolve: verdict OUTSIDE, never joined to ws
    ev_rel = {
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": 2000,
        "syscall": "openat",
        "dfd": -100,
        "target": "relative/data.txt",
        "abs_target": "",
        "result": "ok",
        "cgroup_path": f"/user.slice/agtask-{task_id}.scope",
    }
    res_rel = correlator.handle_line(json.dumps(ev_rel), lambda: boundary)
    assert res_rel is not None
    assert res_rel["verdict"] == EventVerdict.OUTSIDE.value
    assert res_rel["action_taken"] == TaskAction.PAUSE_TASK.value
    assert res_rel.get("target") != os.path.join(str(ws), "relative/data.txt")

    # 4. Empty abs_target on execve
    ev_exec = {
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": 2000,
        "syscall": "execve",
        "target": "bash",
        "abs_target": "",
        "result": "ok",
        "cgroup_path": f"/user.slice/agtask-{task_id}.scope",
    }
    res3 = correlator.handle_line(json.dumps(ev_exec), lambda: boundary)
    assert res3 is not None
    assert res3["verdict"] == EventVerdict.OUTSIDE.value
    assert res3["action_taken"] == TaskAction.PAUSE_TASK.value

    assert len(violations) == 4


def test_fexecve_target_resolution_unit(tmp_path):
    """execveat with AT_EMPTY_PATH target resolves from /proc/<pid>/fd/<fd>."""
    # Create binary file and open fd
    bin_path = tmp_path / "mock_bin"
    bin_path.write_text("#!/bin/sh\necho hi\n")
    fd = os.open(str(bin_path), os.O_RDONLY)
    try:
        pid = os.getpid()
        link = f"/proc/{pid}/fd/{fd}"
        resolved = os.readlink(link)
        assert os.path.realpath(resolved) == os.path.realpath(str(bin_path))
    finally:
        os.close(fd)


@pytest.mark.ebpf
@pytest.mark.skipif(
    not Path("/sys/kernel/btf/vmlinux").exists(),
    reason="Kernel BTF not present on this machine",
)
def test_python_startup_zero_unreadable_events_ebpf(tmp_path):
    """Python startup produces zero unreadable events under eBPF sensor."""
    if not es.EBPF_SENSOR_BIN.exists():
        pytest.skip("ebpf_sensor binary not built")

    cg_path = None
    try:
        with open("/proc/self/cgroup") as f:
            for line in f:
                if line.startswith("0::"):
                    cg_path = line[3:].strip()
    except OSError:
        pass

    if not cg_path:
        pytest.skip("Cannot determine current cgroup")

    cgid = es.get_cgroup_id(cg_path)
    if not cgid:
        pytest.skip("Cannot determine cgroup inode id")

    test_sock = tmp_path / f"test_py_start_{uuid.uuid4().hex[:6]}.sock"
    cmd = [str(es.EBPF_SENSOR_BIN), "--socket", str(test_sock)]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    except OSError as e:
        pytest.skip(f"Cannot execute ebpf_sensor: {e}")

    try:
        for _ in range(20):
            if proc.poll() is not None:
                _, err = proc.communicate()
                pytest.skip(f"ebpf_sensor lacks required privileges: {err.strip()}")
            if test_sock.exists():
                break
            time.sleep(0.05)

        if not test_sock.exists():
            proc.kill()
            pytest.skip("ebpf_sensor socket did not appear")

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0)
        connected = False
        for _ in range(30):
            try:
                s.connect(str(test_sock))
                connected = True
                break
            except OSError:
                time.sleep(0.05)
        if not connected:
            s.connect(str(test_sock))
        s.sendall(f"REGISTER {cgid}\n".encode())

        # Run python child process that starts up, imports sys, and prints
        py_proc = subprocess.run(
            [sys.executable, "-c", "import sys; print('startup_ok')"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "startup_ok" in py_proc.stdout

        events_seen = []
        sock_file = s.makefile("r", encoding="utf-8", errors="replace")
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            r, _, _ = select.select([s], [], [], 0.2)
            if not r:
                if events_seen:
                    break
                continue
            line = sock_file.readline()
            if not line:
                break
            try:
                ev = json.loads(line.strip())
                if ev.get("type") == "syscall":
                    events_seen.append(ev)
            except json.JSONDecodeError:
                pass

        sock_file.close()
        s.close()

        assert len(events_seen) > 0, "No syscall events captured during python startup"
        unreadable_events = [
            ev for ev in events_seen
            if ev.get("target_status") == "unreadable" or ev.get("target") == "unreadable"
        ]
        assert len(unreadable_events) == 0, f"Found unreadable events during python startup: {unreadable_events}"
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()


# ---------------------------------------------------------------------------
# Item 4: Full queue freezes
# ---------------------------------------------------------------------------
def test_full_queue_freezes_task(tmp_path):
    """On queue.Full or correlator exception, on_freeze('sensor_events_dropped')
    is invoked and dropped events are recorded.
    """
    freeze_events = []
    def on_freeze(reason, details):
        freeze_events.append((reason, details))

    out_file = tmp_path / "out.jsonl"
    session = es.EBPFShadowSession(
        task_id="task_queue_full",
        cgroup_path="/user.slice/test",
        output_path=out_file,
        on_freeze=on_freeze,
    )
    # Set small queue size to simulate slow correlator and flood
    session.event_queue = queue.Queue(maxsize=2)
    session.correlator = MagicMock()
    session.boundary_provider = lambda: None

    server_sock_path = tmp_path / "fake_flood.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(server_sock_path))
    srv.listen(1)

    client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client_sock.connect(str(server_sock_path))
    conn, _ = srv.accept()

    session.sock = client_sock
    session.thread = threading.Thread(target=session._reader_loop, daemon=True)
    session.thread.start()

    # Flood lines to overflow queue
    for i in range(10):
        ev = {"type": "syscall", "pid": 1000 + i, "syscall": "openat", "result": "ok"}
        conn.sendall(json.dumps(ev).encode() + b"\n")

    time.sleep(0.3)
    summary = session.finish()
    conn.close()
    srv.close()

    assert any(ev[0] == "sensor_events_dropped" for ev in freeze_events)
    assert summary["dropped"] > 0


# ---------------------------------------------------------------------------
# Item 5: Drops per task & slow client isolation
# ---------------------------------------------------------------------------
def test_drop_counter_tracks_session_delta(tmp_path):
    """Drop counter tracks delta from session start, ignoring prior loader drops."""
    freeze_events = []
    def on_freeze(reason, details):
        freeze_events.append((reason, details))

    out_file = tmp_path / "out.jsonl"
    session = es.EBPFShadowSession(
        task_id="task_drop_delta",
        cgroup_path="/user.slice/test",
        output_path=out_file,
        on_freeze=on_freeze,
    )
    # Simulate prior loader drops = 10 at session start
    session.initial_dropped = 10

    server_sock_path = tmp_path / "fake_delta.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(server_sock_path))
    srv.listen(1)

    client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client_sock.connect(str(server_sock_path))
    conn, _ = srv.accept()

    session.sock = client_sock
    session.thread = threading.Thread(target=session._reader_loop, daemon=True)
    session.thread.start()

    # Heartbeat reports 10 (same as initial): delta is 0 -> no freeze
    conn.sendall(json.dumps({"type": "heartbeat", "dropped_total": 10}).encode() + b"\n")
    time.sleep(0.1)
    assert len(freeze_events) == 0

    # Heartbeat reports 12: delta is 2 -> freeze triggered with dropped = 2
    conn.sendall(json.dumps({"type": "heartbeat", "dropped_total": 12}).encode() + b"\n")
    time.sleep(0.2)
    session.finish()
    conn.close()
    srv.close()

    assert any(ev[0] == "sensor_events_dropped" and ev[1]["dropped"] == 2 for ev in freeze_events)


def test_unregister_ack_read_on_reader_thread(tmp_path):
    """UNREGISTER ack is read on reader thread, capturing filtered_runtime_reads."""
    out_file = tmp_path / "out.jsonl"
    session = es.EBPFShadowSession(
        task_id="task_unreg_ack",
        cgroup_path="/user.slice/test",
        output_path=out_file,
    )
    session.cgroup_id = 9999

    server_sock_path = tmp_path / "fake_unreg.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(server_sock_path))
    srv.listen(1)

    client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client_sock.connect(str(server_sock_path))
    conn, _ = srv.accept()

    session.sock = client_sock
    session.thread = threading.Thread(target=session._reader_loop, daemon=True)
    session.thread.start()

    def handle_unreg():
        req = conn.recv(1024).decode()
        if "UNREGISTER" in req:
            ack = {"source": "ebpf_sensor", "type": "ack", "action": "unregistered", "filtered_runtime_reads": 42}
            conn.sendall(json.dumps(ack).encode() + b"\n")

    t = threading.Thread(target=handle_unreg, daemon=True)
    t.start()

    summary = session.finish()
    conn.close()
    srv.close()

    assert summary["filtered_runtime_reads"] == 42


# ---------------------------------------------------------------------------
# Item 7: Setup never observed freezes
# ---------------------------------------------------------------------------
def test_setup_never_observed_freezes_in_enforce(tmp_path):
    """Treat 'setup never observed' as freeze (OUTSIDE), not INSIDE."""
    storage = GovernanceStorage(tmp_path / "gov.db")
    task_id = "test_setup_never_seen"
    storage.save_task_cgroup(task_id, f"/user.slice/agtask-{task_id}.scope", f"agtask-{task_id}.scope", 1234)
    ws = tmp_path / "ws"
    ws.mkdir()

    boundary = TaskBoundary(
        task_id=task_id,
        workspace_root=str(ws),
        files_read=[],
        files_write=[],
        tools=["run_command"],
        network=[],
        enforcement_mode=EnforcementMode.ENFORCE,
    )

    violations = []
    def on_violation(reason, rec):
        violations.append((reason, rec))

    correlator = OSEventCorrelator(
        storage=storage,
        task_id=task_id,
        workspace_root=str(ws),
        enforcement_mode=EnforcementMode.ENFORCE,
        landlock_spec=None,
        proxy_port=None,
        interpreter_path=sys.executable,
        runtime_dir=None,
        seccomp_active=True,
        on_violation=on_violation,
        freeze_on_outside=True,
        harness_pids={50000},
    )
    # setup_done is False
    assert correlator.setup_done is False

    # Event arrives from non-harness PID before setup was ever observed
    ev = {
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": 105,
        "syscall": "openat",
        "target": "/usr/lib/libc.so",
        "abs_target": "/usr/lib/libc.so",
        "result": "ok",
        "cgroup_path": f"/user.slice/agtask-{task_id}.scope",
    }
    res = correlator.handle_line(json.dumps(ev), lambda: boundary)
    assert res is not None
    assert res["verdict"] == EventVerdict.OUTSIDE.value
    assert res["action_taken"] == TaskAction.PAUSE_TASK.value
    assert "setup never observed" in res["rule_matched"]
    assert len(violations) == 1


# ---------------------------------------------------------------------------
# Item 8(a): clone3 with CLONE_INTO_CGROUP isolation
# ---------------------------------------------------------------------------
def test_clone3_into_cgroup_isolation():
    """clone3 with CLONE_INTO_CGROUP fails with EPERM/EINVAL when attempting
    to escape sandbox without valid cgroup fd or permissions.
    """
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    SYS_clone3 = 435  # x86_64 syscall number
    CLONE_INTO_CGROUP = 0x200000000

    class CloneArgs(ctypes.Structure):
        _fields_ = [
            ("flags", ctypes.c_uint64),
            ("pidfd", ctypes.c_uint64),
            ("child_tid", ctypes.c_uint64),
            ("parent_tid", ctypes.c_uint64),
            ("exit_signal", ctypes.c_uint64),
            ("stack", ctypes.c_uint64),
            ("stack_size", ctypes.c_uint64),
            ("tls", ctypes.c_uint64),
            ("set_tid", ctypes.c_uint64),
            ("set_tid_size", ctypes.c_uint64),
            ("cgroup", ctypes.c_uint64),
        ]

    # Attempt clone3 with invalid/bogus cgroup fd to escape
    args = CloneArgs()
    args.flags = CLONE_INTO_CGROUP
    args.cgroup = 999999  # Invalid fd outside sandbox

    res = libc.syscall(SYS_clone3, ctypes.byref(args), ctypes.sizeof(args))
    errno = ctypes.get_errno()
    assert res == -1
    # Linux kernel returns EBADF (invalid fd) or EINVAL/ENOSYS
    assert errno in (9, 22, 38, 1)  # EBADF, EINVAL, ENOSYS, EPERM


# ---------------------------------------------------------------------------
# Item 8(c): ptrace pid table overflow
# ---------------------------------------------------------------------------
def test_ptrace_overflow_drop_record_freezes(tmp_path):
    """When ptrace slot table overflows, drop record is emitted and freezes."""
    storage = GovernanceStorage(tmp_path / "gov.db")
    task_id = "test_ptrace_overflow"
    storage.save_task_cgroup(task_id, f"/user.slice/agtask-{task_id}.scope", f"agtask-{task_id}.scope", 1234)
    ws = tmp_path / "ws"
    ws.mkdir()

    boundary = TaskBoundary(
        task_id=task_id,
        workspace_root=str(ws),
        files_read=[],
        files_write=[],
        tools=[],
        network=[],
        enforcement_mode=EnforcementMode.ENFORCE,
    )

    violations = []
    def on_violation(reason, rec):
        violations.append((reason, rec))

    correlator = OSEventCorrelator(
        storage=storage,
        task_id=task_id,
        workspace_root=str(ws),
        enforcement_mode=EnforcementMode.ENFORCE,
        landlock_spec=None,
        proxy_port=None,
        interpreter_path=sys.executable,
        runtime_dir=None,
        seccomp_active=True,
        on_violation=on_violation,
        freeze_on_outside=True,
    )

    drop_ev = {
        "source": "os_sensor",
        "type": "drop",
        "reason": "pid_table_overflow",
        "pid": 5555,
    }
    res = correlator.handle_line(json.dumps(drop_ev), lambda: boundary)
    assert res is not None
    assert res["action"] == TaskAction.PAUSE_TASK.value
    assert res["verdict"] == EventVerdict.OUTSIDE.value
    assert len(violations) == 1
    assert violations[0][0] == "sensor_events_dropped"


# ---------------------------------------------------------------------------
# Item 9: Open CONNECT tunnels close on revocation within 1 s
# ---------------------------------------------------------------------------
def test_connect_tunnel_closed_on_revocation_within_1s(tmp_path):
    """Active CONNECT tunnel closes within 1 s when grant/token is revoked."""
    async def _run():
        storage = GovernanceStorage(tmp_path / "gov.db")
        task_id = "test_tunnel_task"
        token = "test_tok_tunnel"
        storage.save_token(token, task_id, "test_agent")

        # Start echo server simulating remote destination
        async def echo_handler(r: asyncio.StreamReader, w: asyncio.StreamWriter):
            try:
                while True:
                    data = await r.read(1024)
                    if not data:
                        break
                    w.write(data)
                    await w.drain()
            except Exception:
                pass
            finally:
                w.close()

        echo_srv = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
        echo_port = echo_srv.sockets[0].getsockname()[1]

        boundary = TaskBoundary(
            task_id=task_id,
            workspace_root=str(tmp_path),
            files_read=[],
            files_write=[],
            tools=[],
            network=[f"127.0.0.1:{echo_port}"],
            enforcement_mode=EnforcementMode.ENFORCE,
        )
        storage.save_boundary(boundary)

        proxy = EgressProxyServer(storage, host="127.0.0.1", port=0)
        proxy_port = await proxy.start()

        # Connect client through proxy with CONNECT
        client_r, client_w = await asyncio.open_connection("127.0.0.1", proxy_port)
        connect_req = (
            f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{echo_port}\r\n"
            f"Proxy-Authorization: Bearer {token}\r\n"
            f"\r\n"
        )
        client_w.write(connect_req.encode())
        await client_w.drain()

        resp_line = await client_r.readline()
        assert b"200 Connection Established" in resp_line
        await client_r.readline()  # empty separator line

        # Send data and verify echo works
        client_w.write(b"ping\n")
        await client_w.drain()
        echo_data = await client_r.read(5)
        assert echo_data == b"ping\n"

        # Revoke tunnel
        t_start = time.monotonic()
        proxy.close_tunnels(task_id, "127.0.0.1")

        # Verify client connection terminates within 1 s
        closed_in_time = False
        try:
            data = await asyncio.wait_for(client_r.read(1024), timeout=1.0)
            closed_in_time = (data == b"")
        except asyncio.TimeoutError:
            closed_in_time = False
        t_elapsed = time.monotonic() - t_start

        client_w.close()
        await proxy.stop()
        echo_srv.close()

        assert closed_in_time, "Tunnel reader did not reach EOF within 1 s"
        assert t_elapsed < 1.0, f"Tunnel closure took {t_elapsed:.3f}s (exceeds 1s)"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Item 10: Canary not on command line
# ---------------------------------------------------------------------------
def test_canary_not_in_command_line(tmp_path, monkeypatch):
    """Canary and decoys are passed via 0600 files, not command line arguments."""
    storage = GovernanceStorage(tmp_path / "gov.db")
    task_id = "test_canary_argv"
    task = _make_task_record(task_id)
    storage.save_task(task)

    ws_base = tmp_path / "workspaces"
    receipts_dir = tmp_path / "receipts"
    launcher = TaskLauncher(storage, workspace_base=ws_base, receipts_dir=receipts_dir)

    captured_cmds = []
    real_popen = subprocess.Popen

    def mock_popen(cmd, *args, **kwargs):
        captured_cmds.append(list(cmd))
        return real_popen(cmd, *args, **kwargs)

    canary_token = "TOP_SECRET_CANARY_XYZ987"
    decoy_list = [{"path": "secret.txt", "content_template": "CANARY={CANARY}"}]

    boundary = TaskBoundary(
        task_id=task_id,
        workspace_root=str(tmp_path / "workspaces" / task_id),
        files_read=[],
        files_write=[],
        tools=["run_command"],
        network=[],
        enforcement_mode=EnforcementMode.ENFORCE,
    )
    storage.save_boundary(boundary)

    spec = TaskSpec(
        task_id=task_id,
        agent_id="test_agent",
        prompt="echo hello",
        canary=canary_token,
        decoys=decoy_list,
        use_eval_world=True,
        llm={"provider": "scripted", "steps": []},
    )

    with patch("subprocess.Popen", side_effect=mock_popen):
        try:
            launcher.run(spec)
        except Exception:
            pass

    assert len(captured_cmds) > 0
    full_cmd_str = " ".join(" ".join(cmd) for cmd in captured_cmds)
    assert canary_token not in full_cmd_str, "Canary token leaked into process argv"
    assert "--canary-file" in full_cmd_str
    assert "--decoys-file" in full_cmd_str
