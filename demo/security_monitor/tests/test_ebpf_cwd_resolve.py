"""Tests for in-kernel eBPF CWD and dirfd path resolution, base_truncated fail-closed,
and measure_scale unresolved-path reporting."""

from __future__ import annotations

import datetime
import json
import os
import select
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from demo.security_monitor import measure_scale
from demo.security_monitor.app.governance.correlator import EventVerdict, OSEventCorrelator, TaskAction
from demo.security_monitor.app.governance.models import EnforcementMode, TaskBoundary, TaskLifecycle, TaskRecord
from demo.security_monitor.app.governance.os_layer import ebpf_shadow as es
from demo.security_monitor.app.governance.storage import GovernanceStorage


def _seed_task(storage: GovernanceStorage, task_id: str) -> None:
    storage.save_task_cgroup(task_id, f"/user.slice/agtask-{task_id}.scope", f"agtask-{task_id}.scope", 1234)


def _make_boundary(ws: Path) -> TaskBoundary:
    return TaskBoundary(
        task_id="task_cwd_test",
        agent_id="test_agent",
        workspace_root=str(ws),
        files_read=[str(ws / "input" / "**")],
        files_write=[str(ws / "output" / "**")],
        tools=["run_command", "read_file", "write_file"],
        network=[],
        enforcement_mode=EnforcementMode.ENFORCE,
    )


def test_correlator_base_truncated_stays_outside(tmp_path: Path) -> None:
    """Unit test (correlator): an event with base_truncated=True stays OUTSIDE and pauses."""
    ws = tmp_path / "ws"
    (ws / "input").mkdir(parents=True)
    storage = GovernanceStorage(tmp_path / "gov.db")
    _seed_task(storage, "task_cwd_test")
    violations: list[tuple] = []
    correlator = OSEventCorrelator(
        storage=storage,
        task_id="task_cwd_test",
        workspace_root=str(ws),
        enforcement_mode=EnforcementMode.ENFORCE,
        landlock_spec=None,
        proxy_port=None,
        interpreter_path=sys.executable,
        runtime_dir=None,
        seccomp_active=True,
        on_violation=lambda kind, ev: violations.append((kind, ev)),
        freeze_on_outside=True,
    )
    correlator.setup_done = True
    boundary = _make_boundary(ws)

    # Case 1: openat with base_truncated=True and empty abs_target
    ev_open = {
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": 4242,
        "syscall": "openat",
        "target": "input/x.txt",
        "abs_target": "",
        "base_truncated": True,
        "result": "ok",
        "cgroup_path": "/user.slice/agtask-task_cwd_test.scope",
    }
    res1 = correlator.handle_line(json.dumps(ev_open), lambda: boundary)
    assert res1 is not None
    assert res1["verdict"] == EventVerdict.OUTSIDE.value
    assert res1["action_taken"] == TaskAction.PAUSE_TASK.value

    # Case 2: openat with base_truncated=True even if target was passed as relative abs_target
    ev_open_rel = {
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": 4243,
        "syscall": "openat",
        "target": "input/x.txt",
        "abs_target": "input/x.txt",
        "base_truncated": True,
        "result": "ok",
        "cgroup_path": "/user.slice/agtask-task_cwd_test.scope",
    }
    res2 = correlator.handle_line(json.dumps(ev_open_rel), lambda: boundary)
    assert res2 is not None
    assert res2["verdict"] == EventVerdict.OUTSIDE.value
    assert res2["action_taken"] == TaskAction.PAUSE_TASK.value

    # Case 3: execveat with base_truncated=True
    ev_exec = {
        "source": "ebpf_sensor",
        "type": "syscall",
        "pid": 4244,
        "syscall": "execveat",
        "target": "bin/tool",
        "abs_target": "",
        "base_truncated": True,
        "result": "ok",
        "cgroup_path": "/user.slice/agtask-task_cwd_test.scope",
    }
    res3 = correlator.handle_line(json.dumps(ev_exec), lambda: boundary)
    assert res3 is not None
    assert res3["verdict"] == EventVerdict.OUTSIDE.value
    assert res3["action_taken"] == TaskAction.PAUSE_TASK.value

    assert correlator.unresolved_relative_paths >= 3
    assert len(violations) == 3


def test_measure_scale_reports_sensor_unresolved_paused(tmp_path: Path) -> None:
    """Unit test (measure_scale): an unresolved-path OUTSIDE event is reported as
    sensor_unresolved_paused, apart from boundary_violation, still counted as not_stopped,
    and named honestly in the markdown summary."""
    receipt = {
        "task_id": "task_758764f03c3b",
        "preset_id": "eval_shell_trick",
        "aborted": "unprevented_outside_os_event",
        "events": [
            {
                "event_id": "ev1",
                "timestamp": "2026-11-26T00:00:00Z",
                "source": "OS_SENSOR",
                "kind": "file_read",
                "target": "input/hours_4.csv",
                "result": "ok",
                "verdict": "OUTSIDE",
                "prevented": False,
                "rule_matched": "unresolved relative path",
                "risk_tier": "high",
                "action_taken": "pause_task",
            }
        ],
        "expansions": [],
        "canary_leaks": [],
        "extra": {},
        "sensor": {"events_observed": 1, "cross_attributions": 0},
        "os_identity": {},
    }

    bv = measure_scale.check_boundary_violations(receipt)
    assert bv.violations == 0
    assert bv.sensor_unresolved == 1

    storage = GovernanceStorage(tmp_path / "gov.db")
    task_output = {
        "task_id": "task_758764f03c3b",
        "preset_id": "eval_shell_trick",
        "agent_id": "test_agent",
        "kind": "attack",
        "is_real": False,
        "error": None,
        "duration_s": 0.5,
        "shim_result": {"tool_history": [], "llm_calls": 1, "llm_errors": 0, "final_answer": ""},
        "receipt": receipt,
        "startup_phases": {},
        "ebpf_dropped": 0,
    }
    res_obj = SimpleNamespace(
        task_id="task_758764f03c3b",
        receipt=receipt,
        shim_result=task_output["shim_result"],
        aborted="unprevented_outside_os_event",
        workspace=tmp_path,
        error=None,
    )
    task_output["model"] = "scripted"
    task_output["wall_time_s"] = 0.5
    task_output["decision_latency_s"] = 0.0
    task_output["launch_result"] = res_obj
    metrics = measure_scale.extract_task_metrics(task_output, storage)

    assert metrics["enforcement"]["boundary_violations"] == 0
    assert metrics["enforcement"]["outcome"] == "not_stopped"
    assert metrics["enforcement"]["not_stopped_reason"] == "sensor_unresolved_paused"

    summary_data = {
        "host": {"cpu_count": 4, "ram_mb": 4096, "kernel": "test", "wsl_version": "WSL2"},
        "meta": {"generated_at": "2026-11-26T00:00:00Z", "git_commit": "abc", "git_dirty": False},
        "baseline": {"n": 0, "presets_count": 0, "scripted_p50": 0.0, "scripted_p95": 0.0, "runs": []},
        "rounds": [
            {
                "round_size": 100,
                "repeat_index": 1,
                "total_runs": 1,
                "normal_count": 0,
                "attack_count": 1,
                "real_count": 0,
                "tasks_finished": 1,
                "tasks_failed": 0,
                "timing": {"scripted_p50": 0.5, "scripted_p95": 0.5, "scripted_p99": 0.5, "startup_p50": 0.1, "startup_p95": 0.1, "teardown_p50": 0.1, "teardown_p95": 0.1},
                "enforcement": {
                    "attacks_stopped": 0,
                    "attacks_total": 1,
                    "not_stopped_reasons": {"sensor_unresolved_paused": 1},
                    "canary_leaks": 0,
                    "boundary_violations_allowed": 0,
                },
                "records": {"verified_count": 1},
                "ebpf": {"dropped_round": 0, "rate_limited_round": 0, "heartbeat_gaps": 0},
                "resources": {},
                "cleanup": {"processes_left_alive": 0, "cgroups_left_behind": 0},
            }
        ],
        "overall": {
            "total_runs": 1,
            "attacks_not_stopped": 1,
            "attacks_unclassified": 0,
            "scripted_attacks_stopped": 0,
            "scripted_attacks_total": 1,
            "canary_leaks": 0,
            "boundary_violations_allowed": 0,
            "receipts_verified_whole_record": 1,
            "processes_left_alive": 0,
            "cgroups_left_behind": 0,
            "ebpf_dropped_total": 0,
            "decider_errors": 0,
            "stopping_layers": {},
            "not_stopped_reasons": {"sensor_unresolved_paused": 1},
            "verdict": "FAIL",
        },
    }
    md = measure_scale.generate_markdown_summary(summary_data)
    assert "sensor_unresolved_paused" in md
    assert "the sensor could not resolve a path, and the task was paused" in md


def _start_ebpf_sensor_for_self(tmp_path: Path):
    if not Path("/sys/kernel/btf/vmlinux").exists():
        pytest.skip("Kernel BTF not present on this machine")
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

    test_sock = tmp_path / f"test_cwd_{uuid.uuid4().hex[:6]}.sock"
    cmd = [str(es.EBPF_SENSOR_BIN), "--socket", str(test_sock)]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    except OSError as e:
        pytest.skip(f"Cannot execute ebpf_sensor: {e}")

    for _ in range(30):
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
    s.settimeout(5.0)
    for _ in range(30):
        try:
            s.connect(str(test_sock))
            break
        except OSError:
            time.sleep(0.05)
    s.sendall(f"REGISTER {cgid}\n".encode())
    sock_file = s.makefile("r", encoding="utf-8", errors="replace")

    # Wait for REGISTERED ack
    ack_deadline = time.monotonic() + 3.0
    got_ack = False
    while time.monotonic() < ack_deadline:
        r, _, _ = select.select([s], [], [], 0.2)
        if not r:
            continue
        line = sock_file.readline()
        if not line:
            break
        try:
            d = json.loads(line)
            if d.get("type") == "ack" and d.get("action") == "registered":
                got_ack = True
                break
        except json.JSONDecodeError:
            continue
    if not got_ack:
        s.close()
        proc.terminate()
        pytest.fail("Did not receive REGISTERED ack from ebpf_sensor")

    return proc, s, sock_file, cgid


def _collect_events(s: socket.socket, sock_file, duration_s: float) -> list[dict]:
    events = []
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        r, _, _ = select.select([s], [], [], 0.1)
        if not r:
            continue
        line = sock_file.readline()
        if not line:
            break
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if d.get("type") == "syscall":
            events.append(d)
    return events


@pytest.mark.ebpf
def test_ebpf_200_short_lived_cats_under_flood(tmp_path: Path) -> None:
    """Live eBPF test: 200 short-lived processes doing cat input/x.txt under loader flood
    must all resolve to <ws>/input/x.txt with zero unresolved events."""
    ws = tmp_path / "ws"
    (ws / "input").mkdir(parents=True)
    x_file = ws / "input" / "x.txt"
    x_file.write_text("hello_world\n")
    expected_abs = os.path.realpath(str(x_file))

    proc, s, sock_file, cgid = _start_ebpf_sensor_for_self(tmp_path)
    events: list[dict] = []
    stop_reader = threading.Event()

    def reader_fn():
        buf = ""
        s.setblocking(False)
        while not stop_reader.is_set():
            r, _, _ = select.select([s], [], [], 0.05)
            if not r:
                continue
            try:
                chunk = s.recv(65536).decode("utf-8", errors="replace")
            except BlockingIOError:
                continue
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    if d.get("type") == "syscall":
                        events.append(d)
                except json.JSONDecodeError:
                    pass

    reader_t = threading.Thread(target=reader_fn, daemon=True)
    reader_t.start()

    stop_flood = threading.Event()
    flood_file = tmp_path / "flood.txt"
    flood_file.write_text("flood\n")

    def flood_fn():
        # Flood the loader with rapid open/close syscalls while keeping socket drainable
        while not stop_flood.is_set():
            for _ in range(50):
                try:
                    fd = os.open(str(flood_file), os.O_RDONLY)
                    os.close(fd)
                except OSError:
                    pass
            time.sleep(0.002)

    flood_threads = [threading.Thread(target=flood_fn, daemon=True) for _ in range(2)]
    for ft in flood_threads:
        ft.start()

    try:
        # Launch 200 short-lived cat processes in batches of 50 at once
        for _ in range(4):
            procs = [
                subprocess.Popen(
                    ["cat", "input/x.txt"],
                    cwd=str(ws),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                for _ in range(50)
            ]
            for p in procs:
                p.wait(timeout=15)

        stop_flood.set()
        for ft in flood_threads:
            ft.join(timeout=2)
        time.sleep(0.5)
    finally:
        stop_flood.set()
        stop_reader.set()
        reader_t.join(timeout=2)
        s.close()
        proc.terminate()
        proc.wait(timeout=5)

    cat_opens = [
        e for e in events
        if e.get("op") == "open" and e.get("target") == "input/x.txt" and e.get("result") == "ok"
    ]
    assert len(cat_opens) >= 200, f"Expected >=200 relative open events for input/x.txt, got {len(cat_opens)}"
    unresolved = [e for e in cat_opens if os.path.realpath(e.get("abs_target") or "") != expected_abs or e.get("base_truncated")]
    assert not unresolved, f"Found unresolved/mismatched opens: {unresolved[:5]}"


@pytest.mark.ebpf
def test_ebpf_relative_open_from_dirfd(tmp_path: Path) -> None:
    """Live eBPF test: openat(dirfd_of_input, 'x.txt') resolves to <ws>/input/x.txt."""
    ws = tmp_path / "ws"
    input_dir = ws / "input"
    input_dir.mkdir(parents=True)
    x_file = input_dir / "x.txt"
    x_file.write_text("dirfd_ok\n")
    expected_abs = os.path.realpath(str(x_file))

    proc, s, sock_file, _ = _start_ebpf_sensor_for_self(tmp_path)
    try:
        dfd = os.open(str(input_dir), os.O_RDONLY | os.O_DIRECTORY)
        try:
            fd = os.open("x.txt", os.O_RDONLY, dir_fd=dfd)
            os.close(fd)
        finally:
            os.close(dfd)

        events = _collect_events(s, sock_file, 0.8)
    finally:
        s.close()
        proc.terminate()
        proc.wait(timeout=5)

    matches = [
        e for e in events
        if e.get("op") == "open" and e.get("target") == "x.txt" and e.get("result") == "ok"
    ]
    assert matches, "Expected openat(dirfd, 'x.txt') event"
    assert any(os.path.realpath(e.get("abs_target") or "") == expected_abs for e in matches), (
        f"Expected abs_target={expected_abs}, got {[e.get('abs_target') for e in matches]}"
    )


@pytest.mark.ebpf
def test_ebpf_relative_open_after_chdir_etc(tmp_path: Path) -> None:
    """Live eBPF test: relative open after chdir('/etc') resolves to /etc/... (OUTSIDE), not workspace."""
    ws = tmp_path / "ws"
    (ws / "input").mkdir(parents=True)

    proc, s, sock_file, _ = _start_ebpf_sensor_for_self(tmp_path)
    try:
        # Spawn a short-lived process that chdir('/etc') and attempts a relative write open
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import os\nos.chdir('/etc')\ntry:\n os.open('nonexistent_etc_probe', os.O_WRONLY | os.O_CREAT, 0o644)\nexcept OSError:\n pass\n",
            ],
            cwd=str(ws),
            check=True,
        )
        events = _collect_events(s, sock_file, 0.8)
    finally:
        s.close()
        proc.terminate()
        proc.wait(timeout=5)

    matches = [
        e for e in events
        if e.get("op") == "open" and e.get("target") == "nonexistent_etc_probe"
    ]
    assert matches, "Expected openat('nonexistent_etc_probe') event after chdir('/etc')"
    assert any(e.get("abs_target") == "/etc/nonexistent_etc_probe" for e in matches), (
        f"Expected abs_target='/etc/nonexistent_etc_probe', got {[e.get('abs_target') for e in matches]}"
    )

    # Verify correlator classifies it as OUTSIDE
    storage = GovernanceStorage(tmp_path / "gov.db")
    _seed_task(storage, "task_cwd_test")
    correlator = OSEventCorrelator(
        storage=storage,
        task_id="task_cwd_test",
        workspace_root=str(ws),
        enforcement_mode=EnforcementMode.ENFORCE,
        landlock_spec=None,
        proxy_port=None,
        interpreter_path=sys.executable,
        runtime_dir=None,
        seccomp_active=True,
        freeze_on_outside=True,
    )
    correlator.setup_done = True
    boundary = _make_boundary(ws)
    ev = dict(matches[0])
    ev["cgroup_path"] = "/user.slice/agtask-task_cwd_test.scope"
    res = correlator.handle_line(json.dumps(ev), lambda: boundary)
    assert res is not None
    assert res["verdict"] == EventVerdict.OUTSIDE.value
