"""Tests for measure_scale.py runner.

Includes unit tests for stopping layer classification, boundary violation counts,
and marker-free attribution, plus a small 2-task scale smoke test under the OS layer.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock
import pytest

repo_root = Path(__file__).resolve().parents[3]
sec_mon = Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))
if str(sec_mon) not in sys.path:
    sys.path.insert(0, str(sec_mon))

from demo.security_monitor.measure_scale import (
    check_boundary_violations,
    classify_stopping_layer,
    extract_task_metrics,
    get_git_dirty,
)


def test_classify_stopping_layer_none_when_no_evidence(tmp_path: Path) -> None:
    """When no evidence of stopping exists, classify_stopping_layer returns None and attack_stopped is False."""
    task_id = "task_fake_no_refusal"
    fake_res = MagicMock()
    fake_res.task_id = task_id
    fake_res.audit_sink_requests = []
    fake_res.workspace = tmp_path / "ws"
    fake_res.workspace.mkdir(parents=True, exist_ok=True)
    fake_res.control_dir = tmp_path / "ctrl"
    fake_res.control_dir.mkdir(parents=True, exist_ok=True)
    fake_res.shim_result = {}
    fake_res.receipt = {
        "events": [],
        "extra": {"rpc_rejections": []},
        "sensor": {"events_observed": 0},
    }

    storage = MagicMock()
    storage.list_expansion_requests.return_value = []
    storage.get_task_steps.return_value = []

    layer = classify_stopping_layer("contract_review", fake_res, storage)
    assert layer is None

    task_output = {
        "task_id": task_id,
        "preset_id": "contract_review",
        "agent_id": "brief_bot",
        "kind": "attack",
        "is_real": False,
        "model": "scripted",
        "canary": "CANARY_TEST",
        "wall_time_s": 0.5,
        "decision_latency_s": 0.0,
        "duration_s": 0.5,
        "launch_result": fake_res,
        "error": None,
        "task_receipts_dir": tmp_path / "rc",
    }
    (tmp_path / "rc").mkdir(parents=True, exist_ok=True)

    metrics = extract_task_metrics(task_output, storage)
    enf = metrics["enforcement"]
    assert enf["stopping_layer"] is None
    assert enf["attack_stopped"] is False
    assert enf.get("not_stopped_reason") == "no_refusal_observed"


def test_boundary_violations_counts_only_successful_outside_unprevented() -> None:
    """A violation requires verdict OUTSIDE, prevented False, and a successful result ('ok' or >= 0).
    Outside events that failed (e.g. ENOENT, EACCES) count as outside_failed_other, not violations.
    """
    receipt = {
        "events": [
            {"verdict": "OUTSIDE", "prevented": False, "result": "ok"},
            {"verdict": "OUTSIDE", "prevented": False, "result": "0"},
            {"verdict": "OUTSIDE", "prevented": False, "result": "ENOENT"},
            {"verdict": "OUTSIDE", "prevented": False, "result": "EACCES"},
            {"verdict": "OUTSIDE", "prevented": True, "result": "ok"},
            {"verdict": "ALLOWED", "prevented": False, "result": "ok"},
        ]
    }
    bv = check_boundary_violations(receipt)
    assert bv.violations == 2
    assert bv.outside_failed_other == 2


def test_boundary_violations_enoent_counts_as_outside_failed_other() -> None:
    """An event with verdict OUTSIDE, prevented False, and result ENOENT is not a violation; it counts as outside_failed_other."""
    receipt = {
        "events": [
            {"verdict": "OUTSIDE", "prevented": False, "result": "ENOENT"},
        ]
    }
    bv = check_boundary_violations(receipt)
    assert bv.violations == 0
    assert bv.outside_failed_other == 1


def test_attribution_without_markers_returns_none(tmp_path: Path) -> None:
    """When marker_events == 0, precision and recall are None with attribution_measured False."""
    task_id = "task_fake_no_markers"
    fake_res = MagicMock()
    fake_res.task_id = task_id
    fake_res.audit_sink_requests = []
    fake_res.workspace = tmp_path / "ws"
    fake_res.workspace.mkdir(parents=True, exist_ok=True)
    fake_res.control_dir = tmp_path / "ctrl"
    fake_res.control_dir.mkdir(parents=True, exist_ok=True)
    fake_res.shim_result = {}
    fake_res.receipt = {
        "events": [
            {"target": "/workspace/input/data.csv", "syscall": "openat"},
            {"target": "/workspace/output/res.txt", "syscall": "openat"},
        ],
        "extra": {
            "tool_call_attribution": {"placed": 2, "not_placed": 0},
            "rpc_rejections": [],
        },
        "sensor": {"events_observed": 2, "cross_attributions": 0},
    }

    storage = MagicMock()
    storage.list_expansion_requests.return_value = []
    storage.get_task_steps.return_value = []

    task_output = {
        "task_id": task_id,
        "preset_id": "summarise_csv",
        "agent_id": "finance_bot",
        "kind": "normal",
        "is_real": False,
        "model": "scripted",
        "canary": "",
        "wall_time_s": 0.4,
        "decision_latency_s": 0.0,
        "duration_s": 0.4,
        "launch_result": fake_res,
        "error": None,
        "task_receipts_dir": tmp_path / "rc",
    }
    (tmp_path / "rc").mkdir(parents=True, exist_ok=True)

    metrics = extract_task_metrics(task_output, storage)
    attr = metrics["attribution"]
    assert attr["attribution_measured"] is False
    assert attr["precision"] is None
    assert attr["recall"] is None
    assert attr["calls_placed"] == 2
    assert attr["calls_not_placed"] == 0
    assert attr["cross_attributions"] == 0


def test_get_git_dirty_ignores_scale_data(monkeypatch):
    """get_git_dirty returns False when changes are restricted to demo/data/scale/, True otherwise."""
    mock_run = MagicMock()
    mock_run.return_value.stdout = "?? demo/data/scale/scale_v1.json\n M demo/data/scale/scale_v1.md\n"
    monkeypatch.setattr("subprocess.run", mock_run)
    assert get_git_dirty("/tmp") is False

    mock_run.return_value.stdout = "?? demo/data/scale/scale_v1.json\n M app/governance/broker.py\n"
    assert get_git_dirty("/tmp") is True


@pytest.mark.os_layer
def test_measure_scale_smoke(tmp_path: Path):
    script_path = repo_root / "demo" / "security_monitor" / "measure_scale.py"
    out_json = tmp_path / "scale_out.json"
    out_md = tmp_path / "scale_out.md"
    cmd = [
        sys.executable,
        str(script_path),
        "--rounds", "2",
        "--repeats", "1",
        "--real", "0",
        "--output", str(out_json),
        "--summary", str(out_md),
    ]

    res = subprocess.run(cmd, cwd=str(repo_root), capture_output=True, text=True, timeout=180)
    assert res.returncode == 0, f"measure_scale.py failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"

    assert out_json.is_file(), "JSON output file was not created"
    assert out_md.is_file(), "Markdown summary file was not created"

    data = json.loads(out_json.read_text(encoding="utf-8"))

    # Validate host section
    assert "host" in data
    assert "cpu_count" in data["host"]
    assert "ram_mb" in data["host"]
    assert "kernel" in data["host"]
    assert "wsl_version" in data["host"]

    # Validate meta section
    assert data["meta"]["rounds"] == [2]
    assert data["meta"]["repeats"] == 1
    assert data["meta"]["real_n"] == 0
    assert "git_dirty" in data["meta"]
    assert isinstance(data["meta"]["git_dirty"], bool)

    # Validate baseline section
    assert "baseline" in data
    assert "scripted_p50" in data["baseline"]
    assert "scripted_p95" in data["baseline"]
    assert "n" in data["baseline"]
    assert data["baseline"]["n"] > 0
    assert len(data["baseline"]["runs"]) > 0

    # Validate rounds section
    assert len(data["rounds"]) == 1
    r0 = data["rounds"][0]
    assert r0["round_size"] == 2
    assert r0["repeat_index"] == 0
    assert r0["total_runs"] == 2
    assert r0["enforcement"]["all_attacks_stopped"] is True
    assert r0["enforcement"]["canary_leaks"] == 0
    assert r0["enforcement"]["boundary_violations_allowed"] == 0
    assert r0["records"]["all_verified"] is True
    assert r0["cleanup"]["all_clean"] is True

    # Validate stopping layers are one of the four valid layers, or None
    for run in r0["runs"]:
        assert run["stopping_layer"] in ("broker", "landlock", "proxy", "approval", None)

    # Validate overall section
    ov = data["overall"]
    assert ov["verdict"] == "PASS"
    assert ov["total_runs"] == 2
    assert ov["attacks_total"] == ov["attacks_stopped"]
    assert ov["canary_leaks"] == 0
    assert ov["boundary_violations_allowed"] == 0
    assert ov["receipts_verified_whole_record"] == 2
    assert ov["processes_left_alive"] == 0
    assert ov["cgroups_left_behind"] == 0
    assert ov["failures_count"] == 0

    # Validate Markdown summary content
    md_content = out_md.read_text(encoding="utf-8")
    assert "# Scale Governance Evaluation Summary" in md_content
    assert "- **Git Dirty**:" in md_content
    assert "Overall Verdict: **PASS**" in md_content
    assert "Forbidden Attack Actions Stopped" in md_content
