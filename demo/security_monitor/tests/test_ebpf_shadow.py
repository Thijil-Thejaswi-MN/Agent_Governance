"""Unit and integration tests for eBPF shadow sensor."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec
from demo.security_monitor.app.governance.os_layer.ebpf_shadow import (
    EBPFShadowSession,
    EBPF_SENSOR_BIN,
    get_cgroup_id,
    is_ebpf_shadow_enabled,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.measure_ebpf_shadow import (
    classify_ebpf_only,
    match_task_events,
    normalise_op,
    normalise_result_class,
    normalise_target,
    ptrace_only_reason,
)


def test_normalise_helpers():
    assert normalise_op("openat", "file_open") == "open"
    assert normalise_op("execve", "process_exec") == "exec"
    assert normalise_op("sendto", "network_send") == "send"
    assert normalise_op("bind", "network_bind") == "bind"
    assert normalise_op("listen", "network_listen") == "listen"
    assert normalise_op("accept4", "network_accept") == "accept"
    assert normalise_op("unlinkat", "file_unlink") == "unlink"
    assert normalise_op("renameat2", "file_rename") == "rename"
    assert normalise_op("mkdirat", "dir_create") == "mkdir"
    assert normalise_op("clone3") == "clone"
    assert normalise_op("exit_group") == "exit"

    assert normalise_target("/tmp/foo/../bar") == "/tmp/bar"
    assert normalise_target("inet:127.0.0.1:8080") == "inet:127.0.0.1:8080"
    assert normalise_target("unix:/tmp/test.sock") == "unix:/tmp/test.sock"

    assert normalise_result_class("ok") == "ok"
    assert normalise_result_class(0) == "ok"
    assert normalise_result_class(3) == "ok"
    assert normalise_result_class("ENOENT", -2) == "ENOENT"
    assert normalise_result_class("EACCES", -13) == "EACCES"


def test_event_matching_and_diff_logic():
    ptrace_events = [
        {
            "type": "syscall",
            "pid": 1001,
            "syscall": "openat",
            "op": "open",
            "target": "input/data.csv",
            "abs_target": "/workspace/input/data.csv",
            "result": "ok",
            "ret": 3,
        },
        {
            "type": "syscall",
            "pid": 1001,
            "syscall": "execve",
            "op": "exec",
            "target": "/bin/cat",
            "abs_target": "/bin/cat",
            "result": "ok",
            "ret": 0,
        },
        {
            "type": "syscall",
            "pid": 1001,
            "syscall": "truncate",
            "op": "file_truncate",
            "target": "/workspace/data.bin",
            "abs_target": "/workspace/data.bin",
            "result": "ok",
            "ret": 0,
        },
    ]

    ebpf_events = [
        {
            "type": "syscall",
            "pid": 1001,
            "syscall": "openat",
            "op": "open",
            "target": "/workspace/input/data.csv",
            "abs_target": "/workspace/input/data.csv",
            "result": "ok",
            "ret": 3,
            "dropped": 0,
        },
        {
            "type": "syscall",
            "pid": 1001,
            "syscall": "execve",
            "op": "exec",
            "target": "/bin/cat",
            "abs_target": "/bin/cat",
            "result": "ok",
            "ret": 0,
            "dropped": 0,
        },
        {
            "type": "syscall",
            "pid": 1001,
            "syscall": "sendto",
            "op": "send",
            "target": "inet:127.0.0.1:9000",
            "abs_target": "inet:127.0.0.1:9000",
            "result": "ok",
            "ret": 4,
            "dropped": 0,
        },
        {
            "type": "syscall",
            "pid": 1001,
            "syscall": "bind",
            "op": "bind",
            "target": "inet:0.0.0.0:8080",
            "abs_target": "inet:0.0.0.0:8080",
            "result": "ok",
            "ret": 0,
            "dropped": 0,
        },
    ]

    diff = match_task_events(ptrace_events, ebpf_events)
    assert diff["matched"] == 2
    assert diff["ptrace_only_count"] == 1
    assert diff["ptrace_only"][0]["syscall"] == "truncate"
    assert "truncate" in diff["ptrace_only"][0]["reason"]

    assert diff["ebpf_only_count"] == 2
    assert diff["ebpf_by_category"]["UDP"] == 1
    assert diff["ebpf_by_category"]["bind-listen-accept"] == 1


def test_basename_match_not_counted_as_matched():
    ptrace_events = [{
        "type": "syscall",
        "pid": 2001,
        "syscall": "openat",
        "op": "open",
        "target": "notes.txt",
        "abs_target": "/workspace/notes.txt",
        "result": "ok",
        "ret": 3,
    }]
    ebpf_events = [{
        "type": "syscall",
        "pid": 2001,
        "syscall": "openat",
        "op": "open",
        "target": "/etc/notes.txt",
        "abs_target": "/etc/notes.txt",
        "result": "ok",
        "ret": 3,
        "dropped": 0,
    }]
    res = match_task_events(ptrace_events, ebpf_events)
    # Basename-only match must NOT count as matched
    assert res["exact"] == 0
    assert res["matched"] == 0
    assert len(res["basename_matches"]) == 1
    assert res["basename_matches"][0]["ptrace_target"] == "/workspace/notes.txt"
    assert res["basename_matches"][0]["ebpf_target"] == "/etc/notes.txt"
    assert res["ptrace_only_count"] == 1
    assert res["ebpf_only_count"] == 1


def test_udp_send_classified_as_udp():
    cat, pfx, reason = classify_ebpf_only("send", "inet:127.0.0.1:8999", "sendto")
    assert cat == "UDP"
    assert pfx == "network_udp"
    assert "UDP" in reason


def test_ebpf_shadow_unavailable_path(monkeypatch, tmp_path):
    monkeypatch.setenv("GOVERNANCE_EBPF_SHADOW", "1")
    dummy_out = tmp_path / "dummy.ebpf.jsonl"
    session = EBPFShadowSession(
        task_id="task_unavail",
        cgroup_path="/nonexistent_cgroup_slice",
        output_path=dummy_out,
        socket_path=tmp_path / "nonexistent.sock",
    )
    session.start()
    summary = session.finish()

    assert summary["status"] == "unavailable"
    assert "reason" in summary


def test_launcher_unavailable_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("GOVERNANCE_SENSOR", "auto")
    monkeypatch.setenv("GOVERNANCE_EBPF_SHADOW", "1")
    # Point socket to nonexistent path
    monkeypatch.setattr(
        "demo.security_monitor.app.governance.os_layer.ebpf_shadow.DEFAULT_SOCKET_PATH",
        tmp_path / "absent_loader.sock",
    )
    # Point loader binary to nonexistent file
    monkeypatch.setattr(
        "demo.security_monitor.app.governance.os_layer.ebpf_shadow.EBPF_SENSOR_BIN",
        tmp_path / "absent_binary",
    )

    storage = GovernanceStorage(tmp_path / "gov.db")
    launcher = TaskLauncher(storage=storage, workspace_base=tmp_path / "ws", receipts_dir=tmp_path / "receipts")

    spec = TaskSpec(
        prompt="Summarise test file",
        task_id="task_shadow_fallback",
        agent_id="finance_bot",
        condition="C",
        enforcement_mode="ENFORCE",
        declared_tools=["write_file"],
        llm={"provider": "scripted", "steps": [
            {"tool": "write_file", "args": {"path": "output/res.txt", "content": "Done"}},
            {"final": "Finished"},
        ]},
        max_iterations=3,
    )

    result = launcher.run(spec)
    assert result.receipt is not None
    extra = result.receipt.get("extra", {})
    assert "ebpf_shadow" in extra
    assert extra["ebpf_shadow"]["status"] == "unavailable"


@pytest.mark.skipif(
    not os.path.exists("/sys/kernel/btf/vmlinux"),
    reason="Kernel BTF not present on this machine",
)
def test_os_layer_ebpf_sensor_live(tmp_path):
    if not EBPF_SENSOR_BIN.exists():
        pytest.skip("ebpf_sensor binary not built yet")

    # Test checking if ebpf_sensor can run with current capabilities
    test_sock = tmp_path / f"test_live_{uuid.uuid4().hex[:6]}.sock"
    cmd = [str(EBPF_SENSOR_BIN), "--socket", str(test_sock)]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    except OSError as e:
        pytest.skip(f"Cannot execute ebpf_sensor: {e}")

    try:
        # Check if process died from permission error
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

        # Live probe test in self cgroup
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

        cgid = get_cgroup_id(cg_path)
        if not cgid:
            pytest.skip("Cannot determine cgroup inode id")

        # Connect to socket and register cgid
        import socket as py_socket
        s = py_socket.socket(py_socket.AF_UNIX, py_socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(str(test_sock))
        s.sendall(f"REGISTER {cgid}\n".encode())

        # Perform cat and udp send
        subprocess.run(["cat", "/dev/null"], check=True)
        probe_py = (
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
            "s.sendto(b'live_probe', ('127.0.0.1', 8999))"
        )
        subprocess.run(["python3", "-c", probe_py], check=True)

        events_seen = []
        sock_file = s.makefile("r", encoding="utf-8", errors="replace")
        deadline = time.monotonic() + 4.0
        cat_seen = False
        udp_seen = False
        while time.monotonic() < deadline and not (cat_seen and udp_seen):
            line = sock_file.readline()
            if not line:
                break
            try:
                ev = json.loads(line.strip())
                if ev.get("type") == "syscall":
                    events_seen.append(ev)
                    tgt = ev.get("target", "") + " " + ev.get("abs_target", "")
                    if "cat" in tgt or ev.get("syscall") == "execve":
                        cat_seen = True
                    if ev.get("syscall") == "sendto" and "8999" in tgt:
                        udp_seen = True
            except json.JSONDecodeError:
                pass

        sock_file.close()
        s.close()

        assert cat_seen, f"Expected cat event among: {events_seen}"
        assert udp_seen, f"Expected UDP event among: {events_seen}"
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()


@pytest.mark.skipif(
    not os.path.exists("/sys/kernel/btf/vmlinux"),
    reason="Kernel BTF not present on this machine",
)
def test_control_socket_rejection_from_registered_cgroup(tmp_path):
    if not EBPF_SENSOR_BIN.exists():
        pytest.skip("ebpf_sensor binary not built yet")

    sock_dir = tmp_path / "sock_dir"
    sock_dir.mkdir(mode=0o700)
    test_sock = sock_dir / "test_reject.sock"

    cmd = [str(EBPF_SENSOR_BIN), "--socket", str(test_sock)]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

    try:
        for _ in range(20):
            if proc.poll() is not None:
                _, err = proc.communicate()
                pytest.skip(f"ebpf_sensor lacking privileges: {err.strip()}")
            if test_sock.exists():
                break
            time.sleep(0.05)

        if not test_sock.exists():
            proc.kill()
            pytest.skip("ebpf_sensor socket did not appear")

        mode = test_sock.stat().st_mode & 0o777
        assert mode == 0o600, f"Expected socket mode 0600, got {oct(mode)}"

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

        cgid = get_cgroup_id(cg_path)
        if not cgid:
            pytest.skip("Cannot determine cgroup inode id")

        import socket as py_socket
        s = py_socket.socket(py_socket.AF_UNIX, py_socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(str(test_sock))
        s.sendall(f"REGISTER {cgid}\n".encode())

        sock_file = s.makefile("r", encoding="utf-8", errors="replace")
        reg_ack = False
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            line = sock_file.readline()
            if not line:
                break
            try:
                data = json.loads(line.strip())
                if data.get("type") == "ack" and data.get("action") == "registered":
                    reg_ack = True
                    break
            except json.JSONDecodeError:
                pass
        assert reg_ack, "Expected registration ack"

        # Current process is inside registered cgroup: UNREGISTER must be rejected
        s.sendall(f"UNREGISTER {cgid}\n".encode())
        unreg_err = None
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            line = sock_file.readline()
            if not line:
                break
            try:
                data = json.loads(line.strip())
                if data.get("type") == "error":
                    unreg_err = data
                    break
            except json.JSONDecodeError:
                pass
        assert unreg_err is not None, "Expected error response for UNREGISTER"
        assert unreg_err.get("error") == "permission_denied"

        # QUIT must also be rejected
        s.sendall(b"QUIT\n")
        quit_err = None
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            line = sock_file.readline()
            if not line:
                break
            try:
                data = json.loads(line.strip())
                if data.get("type") == "error":
                    quit_err = data
                    break
            except json.JSONDecodeError:
                pass
        assert quit_err is not None, "Expected error response for QUIT"
        assert quit_err.get("error") == "permission_denied"

        # Sensor process must still be running and reporting
        time.sleep(0.2)
        assert proc.poll() is None, "ebpf_sensor must remain running after rejected QUIT command"

        sock_file.close()
        s.close()
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()


def test_ebpf_fail_closed_lost_heartbeat(tmp_path):
    import threading
    import socket as py_socket

    freeze_calls = []
    def on_freeze(reason, details):
        freeze_calls.append((reason, details))

    out_file = tmp_path / "out.jsonl"
    session = EBPFShadowSession(
        task_id="test_task_hb",
        cgroup_path="/user.slice/test",
        output_path=out_file,
        on_freeze=on_freeze,
    )
    server_sock_path = tmp_path / "fake_hb.sock"
    srv = py_socket.socket(py_socket.AF_UNIX, py_socket.SOCK_STREAM)
    srv.bind(str(server_sock_path))
    srv.listen(1)

    client_sock = py_socket.socket(py_socket.AF_UNIX, py_socket.SOCK_STREAM)
    client_sock.connect(str(server_sock_path))
    conn, _ = srv.accept()

    session.sock = client_sock
    session.last_heartbeat_time = time.monotonic() - 3.0  # Expired > 2.0s
    session.thread = threading.Thread(target=session._reader_loop, daemon=True)
    session.thread.start()

    time.sleep(0.6)
    session.finish()
    conn.close()
    srv.close()

    assert any(call[0] == "sensor_unhealthy" for call in freeze_calls)


def test_ebpf_fail_closed_dropped_events(tmp_path):
    import threading
    import socket as py_socket

    freeze_calls = []
    def on_freeze(reason, details):
        freeze_calls.append((reason, details))

    out_file = tmp_path / "out.jsonl"
    session = EBPFShadowSession(
        task_id="test_task_drop",
        cgroup_path="/user.slice/test",
        output_path=out_file,
        on_freeze=on_freeze,
    )
    server_sock_path = tmp_path / "fake_drop.sock"
    srv = py_socket.socket(py_socket.AF_UNIX, py_socket.SOCK_STREAM)
    srv.bind(str(server_sock_path))
    srv.listen(1)

    client_sock = py_socket.socket(py_socket.AF_UNIX, py_socket.SOCK_STREAM)
    client_sock.connect(str(server_sock_path))
    conn, _ = srv.accept()

    session.sock = client_sock
    session.thread = threading.Thread(target=session._reader_loop, daemon=True)
    session.thread.start()

    # Heartbeat containing dropped count > 0 triggers freeze
    conn.sendall(json.dumps({"type": "heartbeat", "dropped_total": 3}).encode() + b"\n")

    time.sleep(0.3)
    session.finish()
    conn.close()
    srv.close()

    assert any(call[0] == "sensor_events_dropped" for call in freeze_calls)


def test_ebpf_fail_closed_loader_dies(tmp_path):
    import threading
    import socket as py_socket

    freeze_calls = []
    def on_freeze(reason, details):
        freeze_calls.append((reason, details))

    out_file = tmp_path / "out.jsonl"
    session = EBPFShadowSession(
        task_id="test_task_die",
        cgroup_path="/user.slice/test",
        output_path=out_file,
        on_freeze=on_freeze,
    )
    server_sock_path = tmp_path / "fake_die.sock"
    srv = py_socket.socket(py_socket.AF_UNIX, py_socket.SOCK_STREAM)
    srv.bind(str(server_sock_path))
    srv.listen(1)

    client_sock = py_socket.socket(py_socket.AF_UNIX, py_socket.SOCK_STREAM)
    client_sock.connect(str(server_sock_path))
    conn, _ = srv.accept()

    session.sock = client_sock
    session.thread = threading.Thread(target=session._reader_loop, daemon=True)
    session.thread.start()

    time.sleep(0.1)
    # Loader terminates connection abruptly
    conn.close()

    time.sleep(0.3)
    session.finish()
    srv.close()

    assert any(call[0] == "sensor_unhealthy" for call in freeze_calls)


def test_in_kernel_filtering_rules():
    RUNTIME_PREFIXES = [
        "/usr/lib",
        "/lib",
        "/usr/share/zoneinfo",
        "/etc/ld.so.cache",
        "/lib64",
        "/usr/lib64",
        "/usr/share/locale",
    ]
    O_WRONLY = 0o1
    O_RDWR = 0o2
    O_CREAT = 0o100
    O_TRUNC = 0o1000

    def should_in_kernel_filter(path: str, flags: int, ret: int) -> bool:
        # Replicates BPF kernel logic:
        # ret >= 0 && (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) == 0 && prefix_matches
        is_write = (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) != 0
        matches_prefix = any(path == p or path.startswith(p + "/") for p in RUNTIME_PREFIXES)
        return ret >= 0 and (not is_write) and matches_prefix

    # Read-only open of /usr/lib/libc.so succeeding: filtered (dropped in kernel)
    assert should_in_kernel_filter("/usr/lib/libc.so", 0, 3) is True
    # Write open of /usr/lib/libc.so: NEVER dropped
    assert should_in_kernel_filter("/usr/lib/libc.so", O_WRONLY, 3) is False
    assert should_in_kernel_filter("/usr/lib/libc.so", O_RDWR, 3) is False
    assert should_in_kernel_filter("/usr/lib/libc.so", O_CREAT, 3) is False
    # Failed open (e.g. permission denied -13 or ENOENT -2): NEVER dropped
    assert should_in_kernel_filter("/usr/lib/libc.so", 0, -13) is False
    assert should_in_kernel_filter("/usr/lib/libc.so", 0, -2) is False
    # Path outside prefixes: NEVER dropped
    assert should_in_kernel_filter("/home/thiji/test.txt", 0, 3) is False
    assert should_in_kernel_filter("/etc/shadow", 0, 3) is False


def test_fd_gap_closure_by_construction(tmp_path):
    # Tests that the FD layout ensures only standard descriptors and broker socket remain
    test_code = """
import os, sys, json, socket

# Simulate pipeline receiving token fd, task fd, and broker socket
token_r, token_w = os.pipe()
task_r, task_w = os.pipe()

os.write(token_w, b"tok_123")
os.close(token_w)
os.write(task_w, json.dumps({"prompt": "hi"}).encode())
os.close(task_w)

os.environ["GOVERNANCE_TOKEN_FD"] = str(token_r)
os.environ["GOVERNANCE_TASK_FD"] = str(task_r)

# Consume token and task
t_fd = int(os.environ.pop("GOVERNANCE_TOKEN_FD"))
os.read(t_fd, 1024)
os.close(t_fd)

task_fd = int(os.environ.pop("GOVERNANCE_TASK_FD"))
os.read(task_fd, 1024)
os.close(task_fd)

# Create broker socket pair and dup to fd 3
s_p, s_c = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
os.dup2(s_c.fileno(), 3)
s_c.close()
s_p.close()

# Close all descriptors from 4 up
os.closerange(4, 65536)

# Inspect /proc/self/fd
entries = os.listdir("/proc/self/fd")
numeric_fds = {int(x) for x in entries if x.isdigit()}
# The only persistent descriptors must be 0, 1, 2, 3 (plus listdir dirfd which is closed upon exit)
persistent = numeric_fds - {0, 1, 2, 3}
assert len(persistent) <= 1, f"Unexpected extra persistent FDs: {persistent}"
print("FD_GAP_CLOSED_OK")
"""
    res = subprocess.run([sys.executable, "-c", test_code], capture_output=True, text=True)
    assert res.returncode == 0
    assert "FD_GAP_CLOSED_OK" in res.stdout


def test_shim_refuses_extra_fds(tmp_path):
    # Test that passing a dummy extra FD causes agent_shim to refuse to run with open_fds_at_start
    test_code = """
import os, sys, json, socket, subprocess

tok_r, tok_w = os.pipe()
os.write(tok_w, b"tok_test")
os.close(tok_w)

task_r, task_w = os.pipe()
os.write(task_w, json.dumps({"prompt": "test prompt", "condition": "A"}).encode())
os.close(task_w)

extra_r, extra_w = os.pipe()

env = dict(os.environ)
env["GOVERNANCE_TOKEN_FD"] = str(tok_r)
env["GOVERNANCE_TASK_FD"] = str(task_r)

shim_py = os.path.abspath("demo/security_monitor/app/governance/agent_shim.py")
p = subprocess.Popen(
    [sys.executable, shim_py],
    env=env,
    pass_fds=[tok_r, task_r, extra_r],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
out, err = p.communicate(timeout=10)
os.close(tok_r)
os.close(task_r)
os.close(extra_r)
os.close(extra_w)

assert p.returncode != 0, f"Shim should have failed but exited {p.returncode}"
assert "open_fds_at_start" in err, f"Expected open_fds_at_start in stderr, got: {err}"
print("EXTRA_FD_REFUSAL_OK")
"""
    res = subprocess.run([sys.executable, "-c", test_code], capture_output=True, text=True)
    assert res.returncode == 0
    assert "EXTRA_FD_REFUSAL_OK" in res.stdout


def test_harness_detection_does_not_use_pid_comparison(tmp_path):
    from demo.security_monitor.app.governance.correlator import OSEventCorrelator, EventVerdict
    from demo.security_monitor.app.governance.storage import GovernanceStorage
    from demo.security_monitor.app.governance.models import TaskBoundary, EnforcementMode

    storage = GovernanceStorage(tmp_path / "gov.db")
    task_id = "test_pid_wrap"
    storage.save_task_cgroup(task_id, f"/user.slice/agtask-{task_id}.scope", f"agtask-{task_id}.scope", 1234)
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "output").mkdir()
    (ws / "scratch").mkdir()
    (ws / "runtime").mkdir()

    boundary = TaskBoundary(
        task_id=task_id,
        workspace_root=str(ws),
        files_read=[],
        files_write=["output/out.txt"],
        tools=["run_command"],
        network=[],
        enforcement_mode=EnforcementMode.ENFORCE,
    )

    violations = []
    def on_violation(reason, rec):
        violations.append((reason, rec))

    sensor_pid = 50000
    root_pid = 100
    interp = sys.executable

    correlator = OSEventCorrelator(
        storage=storage,
        task_id=task_id,
        workspace_root=str(ws),
        enforcement_mode=EnforcementMode.ENFORCE,
        landlock_spec=None,
        proxy_port=None,
        interpreter_path=interp,
        runtime_dir=str(ws / "runtime"),
        seccomp_active=True,
        on_violation=on_violation,
        freeze_on_outside=True,
        harness_pids={49999},
    )

    # 1. Start event arrives with sensor_pid = 50000, root_pid = 100
    correlator.handle_line(json.dumps({
        "source": "ebpf_sensor",
        "type": "start",
        "sensor_pid": sensor_pid,
        "child_pid": root_pid,
    }), lambda: boundary)

    assert correlator.setup_done is False
    assert sensor_pid in correlator.harness_pids

    # 2. Setup execve of agent interpreter by root_pid
    correlator.handle_line(json.dumps({
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": root_pid,
        "syscall": "execve",
        "abs_target": interp,
        "result": "ok",
        "cgroup_path": f"/user.slice/agtask-{task_id}.scope",
    }), lambda: boundary)

    assert correlator.setup_done is True

    # 3. Agent child process (pid 105 < sensor_pid 50000) accesses /home/other/secret.txt
    agent_child_pid = 105
    res = correlator.handle_line(json.dumps({
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": agent_child_pid,
        "syscall": "openat",
        "abs_target": "/home/other/secret.txt",
        "result": "ok",
        "cgroup_path": f"/user.slice/agtask-{task_id}.scope",
    }), lambda: boundary)

    assert res is not None
    assert res["verdict"] == EventVerdict.OUTSIDE.value
    assert len(violations) == 1
    assert violations[0][0] == "unprevented_outside_os_event"
    assert violations[0][1]["pid"] == agent_child_pid


def test_relative_path_classification_and_dirfd_resolution(tmp_path):
    from demo.security_monitor.app.governance.correlator import OSEventCorrelator, EventVerdict
    from demo.security_monitor.app.governance.storage import GovernanceStorage
    from demo.security_monitor.app.governance.models import TaskBoundary, EnforcementMode

    storage = GovernanceStorage(tmp_path / "gov.db")
    task_id = "test_rel_path"
    storage.save_task_cgroup(task_id, f"/user.slice/agtask-{task_id}.scope", f"agtask-{task_id}.scope", 1234)
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "scratch").mkdir()
    (ws / "output").mkdir()

    boundary = TaskBoundary(
        task_id=task_id,
        workspace_root=str(ws),
        files_read=["notes.txt"],
        files_write=[],
        tools=[],
        network=[],
        enforcement_mode=EnforcementMode.ENFORCE,
    )

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
    )
    correlator.setup_done = True

    # Case A: A relative "notes.txt" without abs_target (could not be resolved against cwd)
    # Even though boundary allows "notes.txt", relative path MUST be AMBIGUOUS with "unresolved relative path", NEVER INSIDE
    ev_rel = {
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": 1234,
        "syscall": "openat",
        "target": "notes.txt",
        "abs_target": "",
        "result": "ok",
        "cgroup_path": f"/user.slice/agtask-{task_id}.scope",
    }
    res_rel = correlator.handle_line(json.dumps(ev_rel), lambda: boundary)
    assert res_rel is not None
    assert res_rel["verdict"] == EventVerdict.AMBIGUOUS.value
    assert "unresolved relative path" in res_rel["rule_matched"]
    assert correlator.unresolved_relative_paths == 1

    # Case B: notes.txt opened with cwd outside workspace (e.g. /tmp/other_dir/notes.txt)
    # The loader resolved it against cwd to /tmp/other_dir/notes.txt
    ev_outside = {
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": 1234,
        "syscall": "openat",
        "target": "notes.txt",
        "abs_target": "/tmp/other_dir/notes.txt",
        "result": "ok",
        "cgroup_path": f"/user.slice/agtask-{task_id}.scope",
    }
    res_outside = correlator.handle_line(json.dumps(ev_outside), lambda: boundary)
    assert res_outside is not None
    assert res_outside["verdict"] == EventVerdict.OUTSIDE.value

    # Case C: openat with dirfd pointing to scratch inside workspace
    (ws / "scratch" / "data.txt").write_text("hello")
    ev_dirfd = {
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": 1234,
        "syscall": "openat",
        "target": "data.txt",
        "abs_target": str(ws / "scratch" / "data.txt"),
        "result": "ok",
        "cgroup_path": f"/user.slice/agtask-{task_id}.scope",
    }
    res_dirfd = correlator.handle_line(json.dumps(ev_dirfd), lambda: boundary)
    assert res_dirfd is not None
    assert res_dirfd["verdict"] == EventVerdict.INSIDE.value

