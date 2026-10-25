"""cgroup v2 helpers for per-task scopes (M6.1).

All task identity comes from /proc/<pid>/cgroup of the launched process; the
unit name is only used to confirm the move into the scope has completed.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

CGROUP_ROOT = Path("/sys/fs/cgroup")


def read_proc_cgroup(pid: int) -> str | None:
    """Returns the cgroup v2 path ("0::<path>") of a pid, or None if unreadable."""
    try:
        content = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in content.splitlines():
        if line.startswith("0::"):
            return line[3:].strip()
    return None


def wait_for_scope(pid: int, unit_name: str, previous: str | None, timeout: float = 10.0) -> str:
    """Polls /proc/<pid>/cgroup until the process sits in its new scope.

    Raises RuntimeError (fail closed) if the process never leaves `previous`
    or lands somewhere other than `<unit_name>.scope`.
    """
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = read_proc_cgroup(pid)
        if last and last != previous and last.endswith(f"/{unit_name}.scope"):
            return last
        time.sleep(0.01)
    raise RuntimeError(f"process {pid} did not enter scope {unit_name} (last cgroup: {last!r})")


def cgroup_dir(cgroup_path: str) -> Path:
    return CGROUP_ROOT / cgroup_path.lstrip("/")


def cgroup_pids(cgroup_path: str) -> list[int]:
    try:
        txt = (cgroup_dir(cgroup_path) / "cgroup.procs").read_text()
    except OSError:
        return []
    return [int(x) for x in txt.split() if x.strip()]


def is_frozen(cgroup_path: str) -> bool:
    try:
        for line in (cgroup_dir(cgroup_path) / "cgroup.events").read_text().splitlines():
            if line.startswith("frozen "):
                return line.split()[1] == "1"
    except OSError:
        pass
    return False


def freeze(cgroup_path: str, unit_name: str | None = None, timeout: float = 5.0) -> str:
    """Freezes the task cgroup. Returns the method that worked, or raises."""
    errors = []
    try:
        (cgroup_dir(cgroup_path) / "cgroup.freeze").write_text("1")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if is_frozen(cgroup_path) or not cgroup_pids(cgroup_path):
                return "cgroup.freeze"
            time.sleep(0.02)
        errors.append("cgroup.freeze written but cgroup.events never reported frozen")
    except OSError as e:
        errors.append(f"cgroup.freeze: {e}")
    if unit_name:
        r = subprocess.run(["systemctl", "--user", "freeze", f"{unit_name}.scope"], capture_output=True, text=True)
        if r.returncode == 0:
            return "systemctl --user freeze"
        errors.append(f"systemctl freeze: {r.stderr.strip()}")
    raise RuntimeError("; ".join(errors))


def kill_all(cgroup_path: str, unit_name: str | None = None, timeout: float = 5.0) -> str:
    """SIGKILLs every process in the task cgroup (works on frozen cgroups)."""
    method = "cgroup.kill"
    try:
        (cgroup_dir(cgroup_path) / "cgroup.kill").write_text("1")
    except OSError:
        method = "signal_each_pid"
        for pid in cgroup_pids(cgroup_path):
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        if unit_name:
            subprocess.run(["systemctl", "--user", "kill", "-s", "KILL", f"{unit_name}.scope"], capture_output=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and cgroup_pids(cgroup_path):
        time.sleep(0.02)
    return method


def own_seccomp_filter_count() -> int:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("Seccomp_filters:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0
