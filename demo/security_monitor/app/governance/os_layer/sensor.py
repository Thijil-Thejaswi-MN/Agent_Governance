"""Python bridge for OS Sensor syscall events.

Reads events emitted by the native ptrace sensor and records them
into GovernanceStorage as GovernanceEvent records.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Callable

from demo.security_monitor.app.governance.models import GovernanceEvent
from demo.security_monitor.app.governance.storage import GovernanceStorage


class OSSensorBridge:
    """Manages sensor execution and processes stream of syscall events."""

    def __init__(self, storage: GovernanceStorage | None = None) -> None:
        self.storage = storage
        self.events: list[dict] = []
        here = Path(__file__).resolve().parent
        self.sensor_bin = here / "sensor"

    def run_with_sensor(
        self,
        task_id: str,
        cmd: list[str],
        cwd: str | Path | None = None,
        timeout: float = 30.0,
    ) -> tuple[subprocess.CompletedProcess, list[dict]]:
        """
        Runs a command under the ptrace OS sensor.
        Captures emitted JSON lines and attributes them to task_id.
        """
        if not self.sensor_bin.exists():
            raise FileNotFoundError(f"Sensor binary not found at {self.sensor_bin}")

        sensor_cmd = [str(self.sensor_bin)] + cmd
        proc = subprocess.Popen(
            sensor_cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        captured_events = []
        stdout_lines = []

        try:
            raw_stdout, raw_stderr = proc.communicate(timeout=timeout)
            for line in raw_stdout.splitlines():
                line = line.strip()
                if line.startswith('{"source":"os_sensor"'):
                    try:
                        ev = json.loads(line)
                        ev["task_id"] = task_id
                        captured_events.append(ev)

                        if self.storage:
                            # Record in storage as GovernanceEvent
                            gov_ev = GovernanceEvent(
                                task_id=task_id,
                                token="os_syscall_trace",
                                agent_id="os_process",
                                action_type=ev.get("syscall", "syscall"),
                                resource=ev.get("target", "unknown"),
                                verdict="INSIDE" if ev.get("verdict") == "ALLOWED" else "OUTSIDE",
                                prevented=(ev.get("verdict") == "PREVENTED"),
                                violation_type=None if ev.get("verdict") == "ALLOWED" else "OS_LANDLOCK_DENY",
                                rule_matched="os_sensor_cgroup_attribution",
                                timestamp=ev.get("timestamp"),
                            )
                            self.storage.record_event(gov_ev)
                    except Exception:
                        stdout_lines.append(line)
                else:
                    stdout_lines.append(line)

            ret = subprocess.CompletedProcess(
                args=cmd,
                returncode=proc.returncode,
                stdout="\n".join(stdout_lines),
                stderr=raw_stderr,
            )
            return ret, captured_events
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
