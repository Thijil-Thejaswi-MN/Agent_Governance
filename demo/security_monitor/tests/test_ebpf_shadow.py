"""Unit and integration tests for eBPF shadow sensor."""
from __future__ import annotations

import json
import os
import subprocess
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
    assert diff["ebpf_by_category"]["bind/listen/accept"] == 1


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
