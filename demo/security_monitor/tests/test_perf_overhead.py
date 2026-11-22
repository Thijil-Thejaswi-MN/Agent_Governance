"""Tests for performance overhead benchmarking and agent efficiency summarization.

Verifies:
  1. Statistical helpers (median, percentiles, IQR, bootstrap confidence intervals).
  2. Bench-mode guard: GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR is ignored unless
     GOVERNANCE_BENCH_MODE=1 is set.
  3. Agent efficiency summarizer logic on controlled fixtures with infra-error exclusions.
  4. OS layer smoke test: W2 with 10 tool calls and W3 with 20 execs under Condition C
     executes in under 60 seconds.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "demo" / "security_monitor"))

from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec
from demo.security_monitor.app.governance.perf_stats import (
    bootstrap_ci,
    format_stat_summary,
    iqr,
    median,
    percentile,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.summarise_agent_efficiency import (
    extract_trial_metrics,
    is_correct_answer,
    is_infra_error,
    is_timeout,
    summarise_condition_data,
)


# -----------------------------------------------------------------------------
# 1. Statistical helper tests
# -----------------------------------------------------------------------------

def test_percentile_and_median() -> None:
    data_odd = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert median(data_odd) == 3.0
    assert percentile(data_odd, 0.0) == 1.0
    assert percentile(data_odd, 100.0) == 5.0

    data_even = [10.0, 20.0, 30.0, 40.0]
    assert median(data_even) == 25.0
    assert percentile(data_even, 25.0) == 17.5
    assert percentile(data_even, 75.0) == 32.5

    # Edge cases
    assert median([]) == 0.0
    assert median([42.0]) == 42.0


def test_iqr() -> None:
    data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
    # Q1 = 2.75, Q3 = 6.25, IQR = 3.5
    res = iqr(data)
    assert res > 0.0
    assert iqr([]) == 0.0
    assert iqr([5.0]) == 0.0


def test_bootstrap_ci() -> None:
    data = [10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0]
    lower, upper = bootstrap_ci(data, confidence=0.95, n_resamples=500, seed=123)
    assert lower <= median(data) <= upper
    assert lower >= min(data)
    assert upper <= max(data)

    # Single-element edge case
    assert bootstrap_ci([9.0]) == (9.0, 9.0)
    assert bootstrap_ci([]) == (0.0, 0.0)


def test_format_stat_summary() -> None:
    data = [10.0, 20.0, 30.0, 40.0, 50.0]
    formatted = format_stat_summary(data, unit="ms")
    assert "30.00 ms" in formatted
    assert "IQR:" in formatted
    assert "95% CI:" in formatted


# -----------------------------------------------------------------------------
# 2. Bench-mode guard tests
# -----------------------------------------------------------------------------

@pytest.mark.os_layer
def test_bench_mode_switch_ignored_without_bench_mode(tmp_path: Path) -> None:
    """Without GOVERNANCE_BENCH_MODE=1, GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR=1 is ignored."""
    env_backup = dict(os.environ)
    try:
        os.environ.pop("GOVERNANCE_BENCH_MODE", None)
        os.environ["GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR"] = "1"

        storage = GovernanceStorage(tmp_path / "gov_test.db")
        ws_base = Path(os.environ.get("HOME", "/tmp")) / "agent_workspaces"
        rc_dir = tmp_path / "receipts"
        ws_base.mkdir(parents=True, exist_ok=True)
        rc_dir.mkdir(parents=True, exist_ok=True)

        launcher = TaskLauncher(storage, workspace_base=ws_base, receipts_dir=rc_dir)
        spec = TaskSpec(
            prompt="summarise sales",
            inputs={"input/sales.csv": "id,val\n1,10\n"},
            condition="C",
            llm={"provider": "scripted", "steps": [{"final": "done"}]},
            timeout_s=30,
            freeze_timeout_s=1.0,
            boundary_model="v1.1",
        )
        res = launcher.run(spec)
        try:
            extra = (res.receipt or {}).get("extra", {})
            # The sensor must NOT be disabled because bench_mode was missing
            assert extra.get("bench_mode") is not True
            assert extra.get("sensor_disabled") is not True
            sensor_sec = (res.receipt or {}).get("sensor", {})
            assert sensor_sec.get("disabled") is not True
            assert sensor_sec.get("mode") in ("observation_only", "ebpf_primary")
        finally:
            if res and res.workspace:
                shutil.rmtree(res.workspace, ignore_errors=True)
                shutil.rmtree(res.control_dir, ignore_errors=True)
    finally:
        os.environ.clear()
        os.environ.update(env_backup)


@pytest.mark.os_layer
def test_bench_mode_switch_honoured_with_both_flags(tmp_path: Path) -> None:
    """When both GOVERNANCE_BENCH_MODE=1 and GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR=1 are set,
    the ptrace sensor is disabled."""
    env_backup = dict(os.environ)
    try:
        os.environ["GOVERNANCE_BENCH_MODE"] = "1"
        os.environ["GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR"] = "1"

        storage = GovernanceStorage(tmp_path / "gov_test.db")
        ws_base = Path(os.environ.get("HOME", "/tmp")) / "agent_workspaces"
        rc_dir = tmp_path / "receipts"
        ws_base.mkdir(parents=True, exist_ok=True)
        rc_dir.mkdir(parents=True, exist_ok=True)

        launcher = TaskLauncher(storage, workspace_base=ws_base, receipts_dir=rc_dir)
        spec = TaskSpec(
            prompt="summarise sales",
            inputs={"input/sales.csv": "id,val\n1,10\n"},
            condition="C",
            llm={"provider": "scripted", "steps": [{"final": "done"}]},
            timeout_s=30,
            freeze_timeout_s=1.0,
            boundary_model="v1.1",
        )
        res = launcher.run(spec)
        try:
            extra = (res.receipt or {}).get("extra", {})
            assert extra.get("bench_mode") is True
            assert extra.get("sensor_disabled") is True
            sensor_sec = (res.receipt or {}).get("sensor", {})
            assert sensor_sec.get("disabled") is True
            assert sensor_sec.get("mode") == "disabled"
            assert "phase_timings" in extra
            assert res.phase_timings.get("startup_total_s", 0.0) > 0.0
        finally:
            if res and res.workspace:
                shutil.rmtree(res.workspace, ignore_errors=True)
                shutil.rmtree(res.control_dir, ignore_errors=True)
    finally:
        os.environ.clear()
        os.environ.update(env_backup)


# -----------------------------------------------------------------------------
# 3. Agent efficiency summarizer logic on controlled fixtures
# -----------------------------------------------------------------------------

def test_efficiency_summarizer_fixtures() -> None:
    """Test summarizer calculations on small controlled fixture records."""
    fixtures = [
        # Normal correct trial
        {
            "condition": "C",
            "wall_time_s": 12.5,
            "tool_history": [{"tool": "read_file"}, {"tool": "write_file"}],
            "answer_correct": True,
            "ground_truth": {"answer_correct": True},
            "infra_error": False,
            "aborted": None,
            "attempts": [],
        },
        # Trial with refusal
        {
            "condition": "C",
            "wall_time_s": 15.0,
            "tool_history": [{"tool": "run_command"}],
            "answer_correct": False,
            "ground_truth": {"answer_correct": False},
            "infra_error": False,
            "aborted": None,
            "attempts": [{"prevented_by": "broker", "outside": True}],
        },
        # Trial with ordinary tool error (NOT a governance refusal)
        {
            "condition": "C",
            "wall_time_s": 14.0,
            "tool_history": [{"tool": "read_file", "status": "error", "error": "[Errno 2] No such file or directory: 'missing.txt'"}],
            "answer_correct": False,
            "ground_truth": {"answer_correct": False},
            "infra_error": False,
            "aborted": None,
            "attempts": [],
        },
        # Trial hitting timeout
        {
            "condition": "C",
            "wall_time_s": 180.0,
            "tool_history": [{"tool": "read_file"}],
            "answer_correct": False,
            "ground_truth": {"answer_correct": False},
            "infra_error": False,
            "aborted": "task_timeout",
            "attempts": [],
        },
        # Infrastructure error trial (MUST be excluded)
        {
            "condition": "C",
            "wall_time_s": 182.0,
            "tool_history": [],
            "answer_correct": False,
            "ground_truth": {"answer_correct": False},
            "infra_error": True,
            "infra_error_message": "Rate limited 429",
            "aborted": "infra_error",
            "attempts": [],
        },
    ]

    # Verify infra error detection
    assert is_infra_error(fixtures[4]) is True
    assert is_infra_error(fixtures[0]) is False

    # Extract metrics for non-infra trials
    valid_metrics = [
        extract_trial_metrics(rec, {})
        for rec in fixtures
        if not is_infra_error(rec)
    ]
    assert len(valid_metrics) == 4

    # Check timeout, correctness, and tool error flags
    assert valid_metrics[0]["correct"] is True
    assert valid_metrics[1]["refused"] is True
    assert valid_metrics[2]["tool_errors"] == 1
    assert valid_metrics[2]["refused"] is False  # ordinary error is NOT a refusal
    assert valid_metrics[3]["timeout"] is True

    # Summarise
    summary = summarise_condition_data(valid_metrics)
    assert summary["trials_count"] == 4
    assert summary["refusals"]["count"] == 1
    assert round(summary["refusals"]["rate"], 2) == 0.25
    assert summary["tool_errors"]["count"] == 1
    assert summary["timeouts"]["count"] == 1
    assert summary["correct_answers"]["count"] == 1


# -----------------------------------------------------------------------------
# 4. OS Layer Smoke Test (W2 with 10 tool calls, W3 with 20 execs in Condition C < 60s)
# -----------------------------------------------------------------------------

@pytest.mark.os_layer
def test_os_layer_perf_smoke(tmp_path: Path) -> None:
    """Smoke test: executes 10 tool calls and 20 execs in Condition C within 60s."""
    storage = GovernanceStorage(tmp_path / "gov_smoke.db")
    ws_base = Path(os.environ.get("HOME", "/tmp")) / "agent_workspaces"
    rc_dir = tmp_path / "rc_smoke"
    ws_base.mkdir(parents=True, exist_ok=True)
    rc_dir.mkdir(parents=True, exist_ok=True)

    launcher = TaskLauncher(storage, workspace_base=ws_base, receipts_dir=rc_dir)

    # 10 tool calls: 5 reads + 5 writes
    sample_1k = "B" * 1024
    inputs = {f"input/file_{i}.txt": sample_1k for i in range(5)}
    steps = []
    for i in range(5):
        steps.append({"tool": "read_file", "args": {"file_path": f"input/file_{i}.txt"}})
    for i in range(5):
        steps.append({"tool": "write_file", "args": {"file_path": f"output/smoke_{i}.txt", "content": sample_1k}})

    # 20 short execs
    steps.append({"tool": "run_command", "args": {"command": "/bin/sh -c 'for i in $(seq 1 20); do /bin/true; done'"}})
    steps.append({"final": "done"})

    spec = TaskSpec(
        prompt="perf smoke test",
        inputs=inputs,
        output_targets=[f"output/smoke_{i}.txt" for i in range(5)],
        condition="C",
        max_iterations=20,
        llm={"provider": "scripted", "steps": steps},
        timeout_s=50,
        freeze_timeout_s=1.0,
        boundary_model="v1.1",
    )

    t0 = time.monotonic()
    res = launcher.run(spec)
    duration = time.monotonic() - t0

    try:
        assert duration < 60.0, f"Smoke test took {duration:.2f}s, exceeding 60s limit"
        hist = (res.shim_result or {}).get("tool_history", [])
        reads = [t for t in hist if t.get("tool") == "read_file"]
        writes = [t for t in hist if t.get("tool") == "write_file"]
        execs = [t for t in hist if t.get("tool") == "run_command"]

        assert len(reads) == 5
        assert len(writes) == 5
        assert len(execs) == 1
        pt = res.phase_timings
        startup_total = pt.get("startup_total_s", 0.0)
        assert startup_total > 0.0

        # W1 phases check: non-overlapping phases add up within 5% to startup total
        phase_sum = (
            pt.get("intake_s", 0.0)
            + pt.get("workspace_setup_s", 0.0)
            + pt.get("net_ns_proxy_s", 0.0)
            + pt.get("broker_connect_s", 0.0)
            + pt.get("landlock_seccomp_s", 0.0)
            + pt.get("sensor_attach_s", 0.0)
            + pt.get("cgroup_scope_s", 0.0)
            + pt.get("enforcer_arm_s", 0.0)
        )
        assert abs(phase_sum - startup_total) / max(0.001, startup_total) < 0.05
        assert "teardown_breakdown" in pt
    finally:
        if res and res.workspace:
            shutil.rmtree(res.workspace, ignore_errors=True)
            shutil.rmtree(res.control_dir, ignore_errors=True)
