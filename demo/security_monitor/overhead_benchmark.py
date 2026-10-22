"""Overhead benchmark for OS-level enforcement on ext4 (WSL2 / Linux).

Measures runtime latency of agent workload:
- Baseline (Unconfined on ext4)
- Sandboxed (Cgroups v2 + Seccomp filter + Landlock ABI 7 sandbox)

Methodology:
- Interleaved execution order (Baseline, Sandboxed, Baseline, Sandboxed...)
- Warm-up iterations (5 per condition)
- N = 50 runs per condition (N >= 30)
- High-precision timing via time.perf_counter_ns
- Computes: median, mean, p95, stdev, 95% Confidence Intervals
"""
from __future__ import annotations

import json
import math
import os
import random
import statistics
import sys
import time
from pathlib import Path

# Ensure repo root is on sys.path
repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from demo.security_monitor.app.governance.os_layer.runner import (
    CgroupTaskRunner,
    TaskWorkspace,
)

PYTHON_BIN = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable


def compute_ci95(data: list[float]) -> tuple[float, float]:
    """Computes the 95% confidence interval of the mean using Student-t distribution."""
    n = len(data)
    if n < 2:
        return (data[0], data[0]) if data else (0.0, 0.0)
    mean = statistics.mean(data)
    stderr = statistics.stdev(data) / math.sqrt(n)
    # Critical t for n=50 (df=49) at alpha=0.05 is ~2.0096
    # Exact approximation for df >= 30: 1.960 + 2.37/(n-1)
    t_crit = 1.960 + (2.37 / (n - 1))
    margin = t_crit * stderr
    return (round(mean - margin, 3), round(mean + margin, 3))


def run_benchmark(n_trials: int = 50, n_warmup: int = 5) -> dict:
    print(f"=== Milestone 4 Ext4 Enforcement Overhead Benchmark ===")
    print(f"Kernel: {os.uname().release}")
    print(f"Interleaved trials: {n_trials} per condition (Warm-up: {n_warmup})")

    # Setup ext4 workspaces
    ws_base = TaskWorkspace(task_id="bench_baseline")
    ws_base.setup()
    ws_sand = TaskWorkspace(task_id="bench_sandboxed")
    ws_sand.setup()

    # Create dummy workload input
    workload_input = ws_base.input_dir / "data.csv"
    workload_input.write_text("id,val\n" + "\n".join(f"{i},{i*2}" for i in range(1000)), encoding="utf-8")
    (ws_sand.input_dir / "data.csv").write_text(workload_input.read_text(encoding="utf-8"), encoding="utf-8")

    # Workload: read 1000-line input, compute hash, write output
    workload_code = (
        "import hashlib, os, sys\n"
        "ws = sys.argv[1]\n"
        "inp = os.path.join(ws, 'input', 'data.csv')\n"
        "with open(inp, 'r') as f:\n"
        "    data = f.read()\n"
        "h = hashlib.sha256(data.encode('utf-8')).hexdigest()\n"
        "out = os.path.join(ws, 'output', 'hash.txt')\n"
        "with open(out, 'w') as f:\n"
        "    f.write(h)\n"
    )

    script_base = ws_base.root / "workload.py"
    script_base.write_text(workload_code, encoding="utf-8")
    script_sand = ws_sand.root / "workload.py"
    script_sand.write_text(workload_code, encoding="utf-8")

    runner = CgroupTaskRunner()

    def run_one_baseline() -> float:
        t0 = time.perf_counter_ns()
        # Direct execution in ext4 workspace without confinement
        import subprocess
        res = subprocess.run(
            [PYTHON_BIN, str(script_base), str(ws_base.root)],
            cwd=str(ws_base.root),
            capture_output=True,
            text=True,
        )
        t1 = time.perf_counter_ns()
        assert res.returncode == 0, f"Baseline failed: {res.stderr}"
        return (t1 - t0) / 1_000_000.0  # ms

    def run_one_sandboxed() -> float:
        t0 = time.perf_counter_ns()
        res = runner.run_task_command(
            task_id=ws_sand.task_id,
            cmd=[PYTHON_BIN, str(script_sand), str(ws_sand.root)],
            workspace=ws_sand,
            enable_landlock=True,
            enable_seccomp=True,
        )
        t1 = time.perf_counter_ns()
        assert res.returncode == 0, f"Sandboxed failed: {res.stderr}"
        return (t1 - t0) / 1_000_000.0  # ms

    # Warm-up
    print("Running warm-up iterations...")
    for _ in range(n_warmup):
        run_one_baseline()
        run_one_sandboxed()

    # Interleaved measurement
    print(f"Collecting {n_trials} interleaved measurements...")
    baseline_times: list[float] = []
    sandboxed_times: list[float] = []

    for i in range(n_trials):
        # Alternate order to avoid bias
        if i % 2 == 0:
            b_t = run_one_baseline()
            s_t = run_one_sandboxed()
        else:
            s_t = run_one_sandboxed()
            b_t = run_one_baseline()
        baseline_times.append(b_t)
        sandboxed_times.append(s_t)

    # Cleanup
    ws_base.cleanup()
    ws_sand.cleanup()

    # Statistics
    base_sorted = sorted(baseline_times)
    sand_sorted = sorted(sandboxed_times)

    def p95(data_sorted: list[float]) -> float:
        idx = int(0.95 * len(data_sorted))
        return data_sorted[min(idx, len(data_sorted) - 1)]

    base_median = statistics.median(baseline_times)
    base_mean = statistics.mean(baseline_times)
    base_p95 = p95(base_sorted)
    base_ci95 = compute_ci95(baseline_times)

    sand_median = statistics.median(sandboxed_times)
    sand_mean = statistics.mean(sandboxed_times)
    sand_p95 = p95(sand_sorted)
    sand_ci95 = compute_ci95(sandboxed_times)

    overhead_median_ms = sand_median - base_median
    overhead_p95_ms = sand_p95 - base_p95
    overhead_mean_ms = sand_mean - base_mean

    results = {
        "metadata": {
            "kernel": os.uname().release,
            "filesystem": "ext4",
            "trials": n_trials,
            "warmup": n_warmup,
            "unit": "milliseconds",
        },
        "baseline": {
            "median_ms": round(base_median, 3),
            "mean_ms": round(base_mean, 3),
            "p95_ms": round(base_p95, 3),
            "stdev_ms": round(statistics.stdev(baseline_times), 3),
            "ci95_ms": base_ci95,
            "raw_samples": [round(x, 3) for x in baseline_times],
        },
        "sandboxed": {
            "median_ms": round(sand_median, 3),
            "mean_ms": round(sand_mean, 3),
            "p95_ms": round(sand_p95, 3),
            "stdev_ms": round(statistics.stdev(sandboxed_times), 3),
            "ci95_ms": sand_ci95,
            "raw_samples": [round(x, 3) for x in sandboxed_times],
        },
        "overhead": {
            "median_overhead_ms": round(overhead_median_ms, 3),
            "mean_overhead_ms": round(overhead_mean_ms, 3),
            "p95_overhead_ms": round(overhead_p95_ms, 3),
        },
    }

    # Print Table
    print("\n" + "=" * 65)
    print(f"{'Metric':<20} | {'Baseline (Unconfined)':<18} | {'Sandboxed (M4 Full)':<18}")
    print("-" * 65)
    print(f"{'Median':<20} | {base_median:>14.3f} ms | {sand_median:>14.3f} ms")
    print(f"{'Mean':<20} | {base_mean:>14.3f} ms | {sand_mean:>14.3f} ms")
    print(f"{'p95':<20} | {base_p95:>14.3f} ms | {sand_p95:>14.3f} ms")
    print(f"{'95% CI':<20} | [{base_ci95[0]:.2f}, {base_ci95[1]:.2f}] ms | [{sand_ci95[0]:.2f}, {sand_ci95[1]:.2f}] ms")
    print("=" * 65)
    print(f"Median Enforcement Overhead: +{overhead_median_ms:.3f} ms")
    print(f"p95 Enforcement Overhead:    +{overhead_p95_ms:.3f} ms")
    print("=" * 65 + "\n")

    out_path = repo_root / "demo" / "data" / "overhead_benchmark_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Saved benchmark results to {out_path}")

    return results


if __name__ == "__main__":
    run_benchmark(n_trials=50, n_warmup=5)
