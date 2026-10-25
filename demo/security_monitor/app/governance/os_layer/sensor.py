"""Python bridge for OS Sensor syscall events.

Reads events emitted by the native ptrace sensor and records them
into GovernanceStorage as GovernanceEvent records.
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Callable

from demo.security_monitor.app.governance.models import (
    EventSource,
    EventVerdict,
    GovernanceEvent,
    RiskTier,
    TaskAction,
)
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

                        if self.storage and ev.get("type", "syscall") == "syscall":
                            # task_id here comes from the caller, i.e. from which sensor
                            # instance traced the process (tracer lineage), not from the
                            # cgroup path. The verdict is not evaluated here (no boundary):
                            # AMBIGUOUS. Boundary-aware, cgroup-based attribution lives in
                            # app/governance/correlator.py (M6).
                            gov_ev = GovernanceEvent(
                                event_id=f"evt_os_bridge_{uuid.uuid4().hex[:12]}",
                                timestamp=ev.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                source=EventSource.OS_SENSOR,
                                task_id=task_id,
                                agent_id="os_process",
                                pid=ev.get("pid"),
                                kind=ev.get("syscall", "syscall"),
                                target=str(ev.get("abs_target") or ev.get("target", "unknown")),
                                details={
                                    "attribution_method": "tracer_lineage",
                                    "cgroup_path": ev.get("cgroup_id"),
                                    "result": ev.get("result"),
                                },
                                verdict=EventVerdict.AMBIGUOUS,
                                risk_tier=RiskTier.LOW,
                                action_taken=TaskAction.LOG,
                                prevented=False,
                                rule_matched="os_sensor_tracer_lineage_attribution",
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
