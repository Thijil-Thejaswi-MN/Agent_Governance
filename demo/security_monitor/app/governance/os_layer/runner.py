"""WSL ext4 Task Workspace Manager and Cgroup Runner.

Executes AI agent tasks under:
1. ext4 isolated task workspaces (~/agent_workspaces/<task_id>/)
2. cgroup v2 task scoping via systemd-run --user --scope
3. Landlock ABI v7 filesystem and network floor
4. Seccomp io_uring and ABI denial filter
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.models import TaskBoundary


def get_default_workspace_base() -> Path:
    """Returns the ext4 workspace base directory in Linux ($HOME/agent_workspaces)."""
    home = os.environ.get("HOME", "/tmp")
    return Path(home) / "agent_workspaces"


class TaskWorkspace:
    """Manages isolated filesystem workspace layout on ext4."""

    def __init__(self, task_id: str, base_dir: Path | None = None) -> None:
        self.task_id = task_id
        self.base_dir = base_dir or get_default_workspace_base()
        self.root = self.base_dir / task_id
        self.input_dir = self.root / "input"
        self.output_dir = self.root / "output"
        self.scratch_dir = self.root / "scratch"

    def setup(self) -> None:
        """Creates the directory structure on ext4."""
        self.root.mkdir(parents=True, exist_ok=True)
        self.input_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scratch_dir.mkdir(parents=True, exist_ok=True)

    def cleanup(self) -> None:
        """Removes the task workspace."""
        import shutil
        if self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)


class CgroupTaskRunner:
    """
    Executes commands in an isolated cgroup v2 using systemd-run --user --scope.
    Records mapping of cgroup_id <-> task_id in governance storage.
    """

    def __init__(self, storage: GovernanceStorage | None = None) -> None:
        self.storage = storage

    @staticmethod
    def get_process_cgroup(pid: int | None = None) -> str:
        """Extracts the cgroup v2 path for a process from /proc/<pid>/cgroup."""
        if sys.platform != "linux":
            return "windows_fallback"
        target_pid = pid or os.getpid()
        cgroup_file = Path(f"/proc/{target_pid}/cgroup")
        if not cgroup_file.exists():
            return "unknown"
        try:
            content = cgroup_file.read_text(encoding="utf-8").strip()
            # In cgroup2, format is 0::<path>
            for line in content.splitlines():
                parts = line.split(":")
                if len(parts) >= 3:
                    return parts[2]
            return content
        except Exception:
            return "unknown"

    def run_task_command(
        self,
        task_id: str,
        cmd: list[str],
        workspace: TaskWorkspace,
        proxy_port: int | None = None,
        timeout: float = 30.0,
        enable_landlock: bool = True,
        enable_seccomp: bool = True,
    ) -> subprocess.CompletedProcess:
        """
        Runs a command under systemd-run --user --scope with Landlock and Seccomp enforcement.
        """
        workspace.setup()
        unit_name = f"agent-task-{task_id[:16]}-{int(time.time()*1000)%100000}"

        # Build execution wrapper
        # Binary wrappers:
        here = Path(__file__).resolve().parent
        landlock_bin = here / "landlock_enforcer"
        seccomp_bin = here / "seccomp_filter"

        wrapped_cmd = list(cmd)

        # Landlock wrapping
        if enable_landlock and landlock_bin.exists():
            ll_args = [str(landlock_bin), "--workspace", str(workspace.root)]
            if proxy_port:
                ll_args.extend(["--proxy-port", str(proxy_port)])
            ll_args.append("--")
            wrapped_cmd = ll_args + wrapped_cmd

        # Seccomp wrapping
        if enable_seccomp and seccomp_bin.exists():
            wrapped_cmd = [str(seccomp_bin)] + wrapped_cmd

        # Wrap in systemd-run scope
        systemd_cmd = [
            "systemd-run",
            "--user",
            "--scope",
            "-p", "Delegate=yes",
            f"--unit={unit_name}",
            "--",
        ] + wrapped_cmd

        # Record task cgroup in storage if available
        # Unit scope maps to /user.slice/user-<uid>.slice/user@<uid>.service/app.slice/<unit_name>.scope
        cgroup_id = f"/user.slice/{unit_name}.scope"
        if self.storage:
            try:
                # Save cgroup mapping in storage
                with self.storage._get_conn() as conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS task_cgroups (
                            task_id TEXT PRIMARY KEY,
                            cgroup_id TEXT NOT NULL,
                            unit_name TEXT NOT NULL,
                            created_at TEXT NOT NULL
                        )
                        """
                    )
                    import datetime
                    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    conn.execute(
                        "INSERT OR REPLACE INTO task_cgroups VALUES (?, ?, ?, ?)",
                        (task_id, cgroup_id, unit_name, now_utc),
                    )
            except Exception:
                pass

        return subprocess.run(
            systemd_cmd,
            cwd=str(workspace.root),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
