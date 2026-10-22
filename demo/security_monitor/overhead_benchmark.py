"""Milestone 4 5-Arm Enforcement Overhead Benchmark on ext4 (WSL2 / Linux).

Arms measured:
1. Baseline: Unconfined execution on ext4
2. Cgroup Scope Only: systemd-run --user --scope (no Landlock, no seccomp, no sensor)
3. Landlock + Seccomp Only: seccomp_filter + landlock_enforcer (no systemd-run)
4. Landlock + Seccomp + Sensor: sensor (ptrace) + seccomp_filter + landlock_enforcer (no systemd-run)
5. Full: systemd-run + sensor + seccomp_filter + landlock_enforcer

Methodology:
- Rotated interleaved execution order across all 5 arms
- Warm-up iterations (5 per arm)
- N = 35 trials per arm (N >= 30)
- High-precision timing via time.perf_counter_ns
- Computes: median, mean, p95, stdev, 95% Confidence Intervals
"""
from __future__ import annotations

import json
import math
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

# Ensure repo root is on sys.path
repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from demo.security_monitor.app.governance.os_layer.runner import TaskWorkspace

PYTHON_BIN = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable


def compute_ci95(data: list[float]) -> tuple[float, float]:
    """Computes the 95% confidence interval of the mean using Student-t distribution."""
    n = len(data)
    if n < 2:
        return (data[0], data[0]) if data else (0.0, 0.0)
    mean = statistics.mean(data)
    stderr = statistics.stdev(data) / math.sqrt(n)
    t_crit = 1.960 + (2.37 / (n - 1))
    margin = t_crit * stderr
    return (round(mean - margin, 3), round(mean + margin, 3))


def p95(data: list[float]) -> float:
    s = sorted(data)
    idx = int(0.95 * len(s))
    return s[min(idx, len(s) - 1)]


def run_benchmark(n_trials: int = 35, n_warmup: int = 5) -> dict:
    print("=== Milestone 4 5-Arm Ext4 Enforcement Overhead Benchmark ===")
    print(f"Kernel: {os.uname().release}")
    print(f"Trials per arm: {n_trials} (Warm-up: {n_warmup} per arm)")

    os_layer_dir = repo_root / "demo" / "security_monitor" / "app" / "governance" / "os_layer"
    landlock_bin = os_layer_dir / "landlock_enforcer"
    seccomp_bin = os_layer_dir / "seccomp_filter"
    sensor_bin = os_layer_dir / "sensor"

    assert landlock_bin.exists(), f"Missing {landlock_bin}"
    assert seccomp_bin.exists(), f"Missing {seccomp_bin}"
    assert sensor_bin.exists(), f"Missing {sensor_bin}"

    # Setup ext4 workspaces for each arm
    workspaces: dict[str, TaskWorkspace] = {}
    arms = [
        "1_baseline",
        "2_cgroup_only",
        "3_landlock_seccomp",
        "4_landlock_seccomp_sensor",
        "5_full",
    ]
    for arm in arms:
        ws = TaskWorkspace(task_id=f"bench_{arm}")
        ws.setup()
        workspaces[arm] = ws
        # Prepare workload input: 1000 records CSV
        inp = ws.input_dir / "data.csv"
        inp.write_text("id,val\n" + "\n".join(f"{i},{i*2}" for i in range(1000)), encoding="utf-8")
        # Prepare workload code: read CSV, compute SHA-256, write output
        code = (
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
        (ws.root / "workload.py").write_text(code, encoding="utf-8")

    # Define execution functions for each arm
    def run_arm(arm_name: str) -> float:
        ws = workspaces[arm_name]
        script = str(ws.root / "workload.py")
        unit_name = f"bench-{arm_name[:8]}-{int(time.time()*10000)%100000}"

        if arm_name == "1_baseline":
            cmd = [PYTHON_BIN, script, str(ws.root)]
        elif arm_name == "2_cgroup_only":
            cmd = ["systemd-run", "--user", "--scope", f"--unit={unit_name}", "--", PYTHON_BIN, script, str(ws.root)]
        elif arm_name == "3_landlock_seccomp":
            cmd = [str(seccomp_bin), str(landlock_bin), "--workspace", str(ws.root), "--", PYTHON_BIN, script, str(ws.root)]
        elif arm_name == "4_landlock_seccomp_sensor":
            cmd = [str(sensor_bin), str(seccomp_bin), str(landlock_bin), "--workspace", str(ws.root), "--", PYTHON_BIN, script, str(ws.root)]
        elif arm_name == "5_full":
            cmd = ["systemd-run", "--user", "--scope", f"--unit={unit_name}", "--",
                   str(sensor_bin), str(seccomp_bin), str(landlock_bin), "--workspace", str(ws.root), "--",
                   PYTHON_BIN, script, str(ws.root)]
        else:
            raise ValueError(f"Unknown arm {arm_name}")

        t0 = time.perf_counter_ns()
        res = subprocess.run(cmd, cwd=str(ws.root), capture_output=True, text=True)
        t1 = time.perf_counter_ns()
        assert res.returncode == 0, f"Arm {arm_name} failed: {res.stderr}"
        return (t1 - t0) / 1_000_000.0  # ms

    # Warm-up
    print("Running warm-up iterations...")
    for _ in range(n_warmup):
        for arm in arms:
            run_arm(arm)

    # Interleaved execution across 5 arms
    print(f"Collecting {n_trials} trials across {len(arms)} arms (rotated interleaved)...")
    results_raw: dict[str, list[float]] = {arm: [] for arm in arms}

    for i in range(n_trials):
        # Rotate order each trial: e.g. [0,1,2,3,4], [1,2,3,4,0], etc.
        rotated_arms = arms[i % len(arms):] + arms[:i % len(arms)]
        for arm in rotated_arms:
            dur = run_arm(arm)
            results_raw[arm].append(dur)

    # Cleanup workspaces
    for ws in workspaces.values():
        ws.cleanup()

    # Compile statistics
    stats: dict[str, dict] = {}
    for arm in arms:
        data = results_raw[arm]
        stats[arm] = {
            "median_ms": round(statistics.median(data), 3),
            "mean_ms": round(statistics.mean(data), 3),
            "p95_ms": round(p95(data), 3),
            "stdev_ms": round(statistics.stdev(data), 3),
            "ci95_ms": compute_ci95(data),
            "samples": [round(x, 3) for x in data],
        }

    # Print summary table
    print("\n" + "=" * 90)
    print(f"{'Arm':<30} | {'Median':<11} | {'Mean':<11} | {'p95':<11} | {'95% CI':<20}")
    print("-" * 90)
    arm_labels = {
        "1_baseline": "1. Baseline (Unconfined)",
        "2_cgroup_only": "2. Cgroup Scope Only",
        "3_landlock_seccomp": "3. Landlock + Seccomp Only",
        "4_landlock_seccomp_sensor": "4. Landlock + Seccomp + Sensor",
        "5_full": "5. Full (Cgroup+LL+Sec+Sens)",
    }
    for arm in arms:
        s = stats[arm]
        label = arm_labels[arm]
        ci_str = f"[{s['ci95_ms'][0]:.2f}, {s['ci95_ms'][1]:.2f}]"
        print(f"{label:<30} | {s['median_ms']:>8.3f} ms | {s['mean_ms']:>8.3f} ms | {s['p95_ms']:>8.3f} ms | {ci_str:<20}")
    print("=" * 90)

    # Isolated Deltas
    base_med = stats["1_baseline"]["median_ms"]
    cg_delta = round(stats["2_cgroup_only"]["median_ms"] - base_med, 3)
    ll_sec_delta = round(stats["3_landlock_seccomp"]["median_ms"] - base_med, 3)
    sensor_delta = round(stats["4_landlock_seccomp_sensor"]["median_ms"] - stats["3_landlock_seccomp"]["median_ms"], 3)
    full_delta = round(stats["5_full"]["median_ms"] - base_med, 3)

    print("\nIsolated Overhead Contributions (Median Deltas):")
    print(f"  - Cgroup unit scope (systemd-run):       +{cg_delta:+.3f} ms")
    print(f"  - Landlock + Seccomp syscall filter:     +{ll_sec_delta:+.3f} ms")
    print(f"  - Sensor ptrace tracing overhead:        +{sensor_delta:+.3f} ms")
    print(f"  - Total Full Stack Overhead:             +{full_delta:+.3f} ms")
    print("=" * 90 + "\n")

    report = {
        "metadata": {
            "kernel": os.uname().release,
            "filesystem": "ext4",
            "trials_per_arm": n_trials,
            "warmup_per_arm": n_warmup,
            "arms": arm_labels,
        },
        "stats": stats,
        "deltas": {
            "cgroup_scope_overhead_ms": cg_delta,
            "landlock_seccomp_overhead_ms": ll_sec_delta,
            "sensor_ptrace_overhead_ms": sensor_delta,
            "total_full_stack_overhead_ms": full_delta,
        },
    }

    out_file = repo_root / "demo" / "data" / "overhead_benchmark_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Saved results to {out_file}")

    return report


if __name__ == "__main__":
    run_benchmark(n_trials=35, n_warmup=5)
