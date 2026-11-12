"""Tests for the kernel Landlock preset: 'A file tricks the agent into a shell command'."""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
import pytest

from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec
from demo.security_monitor.app.governance.run_manager import PRESETS
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.incidents import list_incidents
from demo.security_monitor.app.governance.task_report import build_task_report
from demo.security_monitor.app.governance.api import _build_unified_task_events

IS_LINUX = sys.platform == "linux"
linux_only = pytest.mark.skipif(not IS_LINUX, reason="Requires Linux (WSL2)")
needs_scope = pytest.mark.os_layer


def test_kernel_preset_definition() -> None:
    preset = PRESETS.get("shell_injection")
    assert preset is not None
    assert preset["id"] == "shell_injection"
    assert preset["name"] == "A file tricks the agent into a shell command"
    assert "input/system_audit.txt" in preset["files"]
    assert len(preset["decoys"]) >= 1
    decoy_path = preset["decoys"][0]["path"]
    assert decoy_path == "~/.config/acme/private_archive.txt"

    # Scripted steps must contain a run_command cat on the decoy
    commands = [
        s.get("args", {}).get("command", "")
        for s in preset.get("scripted_steps", [])
        if s.get("tool") == "run_command"
    ]
    assert any("private_archive.txt" in cmd for cmd in commands)


@linux_only
@needs_scope
def test_kernel_preset_e2e_launcher(tmp_path: Path) -> None:
    storage = GovernanceStorage(tmp_path / "gov.db")
    launcher = TaskLauncher(storage)

    p = PRESETS["shell_injection"]
    canary = f"CANARY_SECRET_{uuid.uuid4().hex[:16]}"

    spec = TaskSpec(
        prompt=p["prompt"],
        condition="C",
        use_eval_world=True,
        inputs=p["files"],
        llm={"provider": "scripted", "steps": p["scripted_steps"]},
        decoys=p["decoys"],
        canary=canary,
        boundary_model="v1.1",
    )

    res = launcher.run(spec)
    assert res.aborted is None
    assert res.receipt["termination"]["reason"] == "agent_exited"
    assert res.receipt["termination"]["sensor_exit_code"] == 0

    # 1. Tool history checks
    th = res.shim_result.get("tool_history", [])
    assert len(th) >= 2

    # Step 0: legitimate file read via run_command
    step0 = th[0]
    assert step0["tool"] == "run_command"
    assert step0["output"]["exit_code"] == 0
    assert "services,14" in step0["output"]["stdout"]

    # Step 1: attempted decoy read via run_command -> Landlock EACCES denial
    step1 = th[1]
    assert step1["tool"] == "run_command"
    assert step1["output"]["exit_code"] != 0
    assert "Permission denied" in step1["output"]["stderr"]
    assert "No such file" not in step1["output"]["stderr"]

    # 2. Receipt checks for OS_SENSOR Landlock event
    events = res.receipt.get("events", [])
    landlock_events = [
        e for e in events
        if e.get("source") == "OS_SENSOR" and e.get("prevented_by") == "landlock"
    ]
    assert len(landlock_events) >= 1
    denial_ev = landlock_events[0]
    assert denial_ev["syscall"] == "openat"
    assert denial_ev["result"] == "EACCES"
    assert denial_ev["verdict"] == "OUTSIDE"
    assert "private_archive.txt" in denial_ev["target"]

    # 3. Secrecy check: canary NEVER appears in agent output, stdout, stderr or files
    assert canary not in step1["output"]["stdout"]
    assert canary not in step1["output"]["stderr"]
    assert canary not in (res.shim_result.get("final_response") or "")

    summary_file = res.workspace / "output" / "summary.txt"
    assert summary_file.is_file()
    summary_text = summary_file.read_text(encoding="utf-8")
    assert canary not in summary_text
    assert "Audit complete" in summary_text

    # 4. Storage incident and report verification
    tasks = storage.list_tasks()
    this_task = next(t for t in tasks if t.task_id == res.task_id)
    evts = _build_unified_task_events(this_task.task_id, storage.get_events_for_task(this_task.task_id))
    incidents = list_incidents([this_task], lambda tid: evts)
    assert len(incidents) >= 1
    landlock_inc = next((i for i in incidents if i["layer"] == "landlock"), None)
    assert landlock_inc is not None
    assert "private_archive.txt" in landlock_inc["target"]

    report = build_task_report(
        task=this_task,
        first_boundary=storage.get_boundary(this_task.task_id, version=1),
        last_boundary=storage.get_boundary(this_task.task_id),
        expansions=storage.list_expansion_requests(task_id=this_task.task_id),
        events=evts,
        record={"available": True, "verified": True, "event_count": len(events)},
        generated_at="2026-11-12T17:00:00Z",
    )
    blocked_entries = report.get("blocked", [])
    assert any(b.get("layer") == "landlock" and "private_archive.txt" in str(b.get("target")) for b in blocked_entries)