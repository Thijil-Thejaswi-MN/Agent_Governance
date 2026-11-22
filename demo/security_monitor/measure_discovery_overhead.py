#!/usr/bin/env python3
"""Measures discovery-mode CPU overhead on the W3 workload (GOVERNANCE_DISCOVERY_EBPF on vs off)."""
from __future__ import annotations

import json
import os
import statistics
import time
from pathlib import Path

from demo.security_monitor.measure_overhead import GovernanceBenchmarkRunner


def measure_w3_discovery(repeats: int = 5) -> dict[str, dict[str, float]]:
    print(f"Measuring W3 workload across {repeats} repetitions: discovery OFF vs ON...")

    results: dict[str, list[dict[str, float]]] = {
        "discovery_off": [],
        "discovery_on": [],
    }

    # 1. Discovery OFF
    os.environ["GOVERNANCE_DISCOVERY_EBPF"] = "0"
    runner_off = GovernanceBenchmarkRunner(configs=["C-ebpf"], repeats_w2_w4=2)
    for i in range(repeats):
        res = runner_off.run_w3_single("C-ebpf")
        assert not res.get("failures"), f"Failures in discovery_off run {i}: {res.get('failures')}"
        tot = sum(res[k] for k in ["find_ms", "grep_ms", "py_read_ms", "tar_ms", "execs_ms"] if isinstance(res[k], (int, float)))
        res["total_ms"] = tot
        results["discovery_off"].append(res)
        print(f"  [Discovery OFF] run {i+1}/{repeats}: total={res['total_ms']:.1f}ms (500_execs={res['execs_ms']:.1f}ms, find={res['find_ms']:.1f}ms, grep={res['grep_ms']:.1f}ms)")

    # 2. Discovery ON
    os.environ["GOVERNANCE_DISCOVERY_EBPF"] = "1"
    runner_on = GovernanceBenchmarkRunner(configs=["C-ebpf"], repeats_w2_w4=2)
    for i in range(repeats):
        res = runner_on.run_w3_single("C-ebpf")
        assert not res.get("failures"), f"Failures in discovery_on run {i}: {res.get('failures')}"
        tot = sum(res[k] for k in ["find_ms", "grep_ms", "py_read_ms", "tar_ms", "execs_ms"] if isinstance(res[k], (int, float)))
        res["total_ms"] = tot
        results["discovery_on"].append(res)
        print(f"  [Discovery ON ] run {i+1}/{repeats}: total={res['total_ms']:.1f}ms (500_execs={res['execs_ms']:.1f}ms, find={res['find_ms']:.1f}ms, grep={res['grep_ms']:.1f}ms)")

    summary = {}
    for mode in ["discovery_off", "discovery_on"]:
        items = results[mode]
        summary[mode] = {
            "total_ms_mean": statistics.mean(x["total_ms"] for x in items),
            "total_ms_median": statistics.median(x["total_ms"] for x in items),
            "execs_ms_mean": statistics.mean(x["execs_ms"] for x in items),
            "find_ms_mean": statistics.mean(x["find_ms"] for x in items),
            "grep_ms_mean": statistics.mean(x["grep_ms"] for x in items),
            "py_ms_mean": statistics.mean(x["py_read_ms"] for x in items),
            "tar_ms_mean": statistics.mean(x["tar_ms"] for x in items),
        }

    off_tot = summary["discovery_off"]["total_ms_mean"]
    on_tot = summary["discovery_on"]["total_ms_mean"]
    delta_ms = on_tot - off_tot
    pct = (delta_ms / off_tot) * 100.0 if off_tot > 0 else 0.0

    print("\n=== W3 Discovery Mode Overhead Summary ===")
    print(f"Discovery OFF: {off_tot:.2f} ms")
    print(f"Discovery ON : {on_tot:.2f} ms")
    print(f"Delta        : {delta_ms:+.2f} ms ({pct:+.2f}%)")
    print("\nOperation Breakdown (mean ms):")
    print(f"  500 execs: OFF={summary['discovery_off']['execs_ms_mean']:.2f} ms, ON={summary['discovery_on']['execs_ms_mean']:.2f} ms")
    print(f"  find 5k  : OFF={summary['discovery_off']['find_ms_mean']:.2f} ms, ON={summary['discovery_on']['find_ms_mean']:.2f} ms")
    print(f"  grep     : OFF={summary['discovery_off']['grep_ms_mean']:.2f} ms, ON={summary['discovery_on']['grep_ms_mean']:.2f} ms")
    print(f"  python 2k: OFF={summary['discovery_off']['py_ms_mean']:.2f} ms, ON={summary['discovery_on']['py_ms_mean']:.2f} ms")
    print(f"  tar 50MB : OFF={summary['discovery_off']['tar_ms_mean']:.2f} ms, ON={summary['discovery_on']['tar_ms_mean']:.2f} ms")

    return summary


if __name__ == "__main__":
    measure_w3_discovery(repeats=3)
