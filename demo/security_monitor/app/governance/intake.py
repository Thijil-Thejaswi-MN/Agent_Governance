"""Task Intake Layer (F1).

Front door for registering tasks, generating immutable request digests,
deriving boundaries (F2), and initiating agent execution (F4).
"""
from __future__ import annotations

import datetime
import hashlib
import uuid
from pathlib import Path

from .models import TaskRecord, TaskBoundary, TaskLifecycle, EnforcementMode
from .storage import GovernanceStorage
from .catalog import BoundaryDerivationV1
from .runner import BaseAgentRunner, ProcessAgentRunner


class TaskIntakeService:
    """Orchestrates task intake, boundary derivation, and agent launch."""

    def __init__(
        self,
        storage: GovernanceStorage,
        derivation: BoundaryDerivationV1 | None = None,
        runner: BaseAgentRunner | None = None,
    ) -> None:
        self.storage = storage
        self.derivation = derivation or BoundaryDerivationV1()
        self.runner = runner or ProcessAgentRunner(storage)

    def submit_task(
        self,
        request_text: str,
        agent_id: str,
        workspace_root: str,
        enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE,
        output_targets: list[str] | None = None,
        files_read: list[str] | None = None,
        task_id: str | None = None,
    ) -> tuple[TaskRecord, TaskBoundary]:
        """
        Creates a new task record, derives its initial execution boundary contract,
        and persists them.
        """
        if not task_id:
            task_id = f"task_{uuid.uuid4().hex[:12]}"
        req_hash = hashlib.sha256(request_text.encode("utf-8")).hexdigest()
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Normalize workspace root
        w_root = str(Path(workspace_root).resolve())

        # 1. Create task record (PENDING)
        task = TaskRecord(
            task_id=task_id,
            request_text=request_text,
            request_hash=req_hash,
            agent_id=agent_id,
            workspace_root=w_root,
            status=TaskLifecycle.PENDING,
            created_at=now_utc,
            current_boundary_version=1,
        )
        self.storage.save_task(task)

        # 2. Derive Task Boundary before execution begins
        boundary = self.derivation.derive(
            task_id=task_id,
            request_text=request_text,
            workspace_root=w_root,
            enforcement_mode=enforcement_mode,
            output_targets=output_targets,
            explicit_files_read=files_read,
        )
        self.storage.save_boundary(boundary)

        return task, boundary

    def launch_task(self, task_id: str, agent_command: list[str]) -> tuple[str, int]:
        """
        Starts the agent process for a pending task.
        Returns (task_token, pid).
        """
        task = self.storage.get_task(task_id)
        if not task:
            raise KeyError(f"Task {task_id} not found")
        return self.runner.start_agent(task, agent_command)
