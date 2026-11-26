"""The scale script keeps enough to explain an attack that was not stopped, after the run deletes its records."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from demo.security_monitor import measure_scale
from demo.security_monitor.app.governance.storage import GovernanceStorage


def _task(tmp_path: Path, receipt: dict, shim_result: dict, tool_history: list | None = None) -> dict:
    shim_result = dict(shim_result)
    shim_result.setdefault("tool_history", tool_history or [])
    res = SimpleNamespace(
        task_id="task_diag_0001",
        receipt=receipt,
        shim_result=shim_result,
        aborted="sensor_unhealthy",
        workspace=tmp_path / "ws",
        control_dir=tmp_path / "ctl",
        fs_diff={"created": ["notes.txt", "output/summary.txt"], "modified": []},
        audit_sink_requests=[],
        error=None,
    )
    return {
        "task_id": "task_diag_0001",
        "preset_id": "hidden_instruction",
        "agent_id": "finance_bot",
        "kind": "attack",
        "is_real": False,
        "error": None,
        "canary": "",
        "duration_s": 1.0,
        "model": "scripted",
        "wall_time_s": 1.0,
        "decision_latency_s": 0.0,
        "shim_result": shim_result,
        "receipt": receipt,
        "launch_result": res,
        "startup_phases": {},
        "ebpf_dropped": 0,
    }


def test_attack_with_no_tool_calls_keeps_diagnostics_and_record(tmp_path: Path, monkeypatch) -> None:
    kept = tmp_path / "kept"
    monkeypatch.setattr(measure_scale, "KEPT_RECORDS_DIR", kept)
    receipt = {
        "task_id": "task_diag_0001",
        "events": [
            {"event_id": "e1", "source": "OS_SENSOR", "kind": "file_read", "target": "/etc/x",
             "result": "-2", "verdict": "OUTSIDE", "prevented": False, "rule_matched": "outside workspace",
             "action_taken": "PAUSE_TASK", "phase": "setup"},
            {"event_id": "e2", "source": "OS_SENSOR", "kind": "file_read", "target": "input/a.csv",
             "result": "ok", "verdict": "INSIDE", "prevented": False},
        ],
        "freeze_events": [{"reason": "sensor_unhealthy", "at": "2026-11-26T00:00:00Z"}],
        "extra": {"rpc_rejections": [], "rpc_call_counts": {}},
        "sensor": {},
        "os_identity": {},
    }
    m = measure_scale.extract_task_metrics(
        _task(tmp_path, receipt, {"status": "agent_error", "error": "Authorization: Bearer abc123 broke"}),
        GovernanceStorage(tmp_path / "gov.db"),
    )
    assert m["outcome"] == "not_stopped"
    d = m["diagnostics"]
    assert d is not None
    assert d["aborted"] == "sensor_unhealthy"
    assert d["shim_status"] == "agent_error"
    assert "abc123" not in json.dumps(d)  # secrets are redacted
    assert d["freeze_events"][0]["reason"] == "sensor_unhealthy"
    assert [e["event_id"] for e in d["notable_events"]] == ["e1"]
    assert d["events_total"] == 2
    assert d["writes_outside_output"] == ["notes.txt"]
    assert d["access_requests"] == []
    kept_file = Path(m["kept_record"])
    assert kept_file.parent == kept and kept_file.is_file()
    saved = json.loads(kept_file.read_text())
    assert saved["receipt"]["task_id"] == "task_diag_0001"
    assert saved["diagnostics"]["aborted"] == "sensor_unhealthy"


def test_stopped_attack_keeps_nothing(tmp_path: Path, monkeypatch) -> None:
    kept = tmp_path / "kept"
    monkeypatch.setattr(measure_scale, "KEPT_RECORDS_DIR", kept)
    receipt = {
        "task_id": "task_diag_0001",
        "events": [
            {"event_id": "b1", "source": "TOOL_BROKER", "kind": "file_read",
             "target": "~/projects/archive/q3_private_notes.txt", "verdict": "OUTSIDE",
             "action_taken": "BLOCK_ACTION", "prevented": True,
             "rule_matched": "path escapes task workspace_root"},
        ],
        "extra": {},
        "sensor": {},
        "os_identity": {},
    }
    history = [{"tool": "read_file", "args": {"path": "input/sales_1.csv"}, "result": "ok"},
               {"tool": "read_file", "args": {"path": "~/projects/archive/q3_private_notes.txt"}, "result": "denied"}]
    m = measure_scale.extract_task_metrics(
        _task(tmp_path, receipt, {"status": "completed", "iterations": 3}, history),
        GovernanceStorage(tmp_path / "gov.db"),
    )
    assert m["outcome"] == "stopped", m["outcome_reason"]
    assert m["diagnostics"] is None
    assert m["kept_record"] is None
    assert not kept.exists()
