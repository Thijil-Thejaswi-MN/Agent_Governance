from __future__ import annotations

import json
from pathlib import Path
import pytest

from evaluation.stats import compute_series_stats, compute_wilson_ci, compute_proportion_metrics
from evaluation.scenarios import (
    generate_benign_scenarios,
    generate_as_scenarios,
    generate_cc_scenarios,
    generate_co_scenarios,
)
from evaluation.runner import EvaluationRunner


def test_wilson_ci_bounds_and_coverage():
    """Verify Wilson score confidence interval calculations."""
    # 0/100 case
    low_0, high_0 = compute_wilson_ci(0, 100)
    assert low_0 == 0.0
    assert 0.03 < high_0 < 0.04  # ~3.68%

    # 100/100 case
    low_100, high_100 = compute_wilson_ci(100, 100)
    assert 0.96 < low_100 < 0.97  # ~96.32%
    assert high_100 == 1.0

    # 50/100 case
    low_50, high_50 = compute_wilson_ci(50, 100)
    assert 0.40 < low_50 < 0.41
    assert 0.59 < high_50 < 0.60


def test_series_stats_calculation():
    series = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    stats = compute_series_stats(series)
    assert stats["count"] == 10
    assert stats["mean_ms"] == 5.5
    assert stats["median_ms"] == 5.5
    assert stats["min_ms"] == 1.0
    assert stats["max_ms"] == 10.0
    assert stats["p95_ms"] == 10.0


def test_scenarios_deterministic_reproducibility():
    """Verify that scenarios generated with the same seed produce identical outputs."""
    sc_a1 = generate_as_scenarios(count=10, seed=42)
    sc_a2 = generate_as_scenarios(count=10, seed=42)
    assert sc_a1 == sc_a2

    sc_b1 = generate_benign_scenarios(count=10, seed=42)
    sc_b2 = generate_benign_scenarios(count=10, seed=42)
    assert sc_b1 == sc_b2

    sc_cc1 = generate_cc_scenarios(count=10, seed=42)
    sc_cc2 = generate_cc_scenarios(count=10, seed=42)
    assert sc_cc1 == sc_cc2

    sc_co1 = generate_co_scenarios(count=10, seed=42)
    sc_co2 = generate_co_scenarios(count=10, seed=42)
    assert sc_co1 == sc_co2


def test_evaluation_state_isolation_and_no_dev_db_pollution(tmp_path):
    """
    Verify that running EvaluationRunner:
    1. Writes to an isolated database in tmp_path.
    2. Does NOT modify or use demo/data/security_monitor.db.
    3. Produces valid JSON/JSONL artifacts.
    """
    eval_id = "test_eval_isolation_01"
    runner = EvaluationRunner(
        trials_per_scenario=5,
        random_seed=123,
        output_dir=tmp_path,
        evaluation_id=eval_id,
    )

    # Database must be within the dedicated evaluation directory
    assert runner.db_path.parent == tmp_path
    assert eval_id in runner.db_path.name

    summary = runner.run_all()
    assert summary["evaluation_id"] == eval_id
    assert summary["trials_per_condition"] == 5

    # Check generated files in tmp_path
    expected_files = [
        "evaluation_manifest.json",
        "evaluation_summary.json",
        "benign_trials.jsonl",
        "as_trials.jsonl",
        "cc_trials.jsonl",
        "co_trials.jsonl",
        "latency_trials.jsonl",
        "README.md",
        f"{eval_id}.db",
    ]
    for ef in expected_files:
        assert (tmp_path / ef).exists(), f"Missing expected artifact {ef}"

    # Verify manifest and summary can be loaded cleanly as JSON
    with open(tmp_path / "evaluation_manifest.json", "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["evaluation_id"] == eval_id

    with open(tmp_path / "as_trials.jsonl", "r", encoding="utf-8") as f:
        lines = f.readlines()
    assert len(lines) == 5
    first_trial = json.loads(lines[0])
    assert first_trial["category"] == "AS"
    assert "trial_id" in first_trial
    assert "actual_detected" in first_trial
