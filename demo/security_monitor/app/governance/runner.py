"""Agent Runner (F4).

Launches agent processes with scoped per-task tokens, tracks PID lineage,
and provides a pluggable interface for Linux cgroups/Landlock (M4).
"""
from __future__ import annotations

import abc
import datetime
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

from .models import TaskRecord, TaskLifecycle
from .storage import GovernanceStorage


class BaseAgentRunner(abc.ABC):
    """Abstract interface for task-isolated agent execution."""

    @abc.abstractmethod
    def start_agent(self, task: TaskRecord, agent_command: list[str]) -> tuple[str, int]:
        """Starts the agent process, returning (task_token, pid)."""
        pass

    @abc.abstractmethod
    def terminate_agent(self, task_id: str) -> bool:
        """Terminates the running agent process."""
        pass


class ProcessAgentRunner(BaseAgentRunner):
    """Process-per-task agent launcher (Windows & Linux non-cgroup)."""

    def __init__(self, storage: GovernanceStorage) -> None:
        self.storage = storage
        self._active_processes: dict[str, subprocess.Popen[str]] = {}

    def start_agent(self, task: TaskRecord, agent_command: list[str]) -> tuple[str, int]:
        # 1. Generate cryptographically strong, scoped task credential
        task_token = f"gov_tok_{secrets.token_urlsafe(32)}"
        self.storage.save_token(task_token, task.task_id, task.agent_id)

        # 2. Inject token via environment variables (never command-line args or logs)
        env = os.environ.copy()
        env["GOVERNANCE_TASK_TOKEN"] = task_token
        env["GOVERNANCE_TASK_ID"] = task.task_id
        env["GOVERNANCE_AGENT_ID"] = task.agent_id
        env["GOVERNANCE_WORKSPACE_ROOT"] = task.workspace_root
        if self.storage.db_path and self.storage.db_path != ":memory:":
            env["GOVERNANCE_DB_PATH"] = str(self.storage.db_path)

        # Ensure child process can import project packages
        repo_root = str(Path(__file__).resolve().parent.parent.parent.parent.parent)
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{repo_root}{os.pathsep}{existing_pp}" if existing_pp else repo_root

        # 3. Spawn child process
        proc = subprocess.Popen(
            agent_command,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=task.workspace_root,
        )
        pid = proc.pid
        self._active_processes[task.task_id] = proc

        # 4. Record task start and PID
        task.status = TaskLifecycle.ACTIVE
        task.started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        task.pid = pid
        self.storage.save_task(task)

        return task_token, pid

    def terminate_agent(self, task_id: str) -> bool:
        proc = self._active_processes.get(task_id)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
            task = self.storage.get_task(task_id)
            if task:
                task.status = TaskLifecycle.TERMINATED
                task.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                self.storage.save_task(task)
            return True
        return False

    def wait_for_completion(self, task_id: str, timeout: float | None = 15.0) -> tuple[int, str, str]:
        """Waits for process and returns (exit_code, stdout, stderr)."""
        proc = self._active_processes.get(task_id)
        if not proc:
            raise KeyError(f"No running process for task {task_id}")
        stdout, stderr = proc.communicate(timeout=timeout)
        code = proc.returncode

        task = self.storage.get_task(task_id)
        if task:
            task.status = TaskLifecycle.COMPLETED if code == 0 else TaskLifecycle.FAILED
            task.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.storage.save_task(task)

        return code, stdout, stderr
