"""Statistical and system information utilities for governance benchmarks.

Provides statistical summaries (median, percentiles, IQR, bootstrap confidence intervals)
and system telemetry (CPU model, core count, kernel release, load averages).
"""
from __future__ import annotations

import math
import os
import platform
import random
from typing import Any, Sequence


def percentile(data: Sequence[float], p: float) -> float:
    """Calculate the p-th percentile of data (p in [0, 100])."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    n = len(sorted_data)
    if n == 1:
        return float(sorted_data[0])
    
    # Linear interpolation between nearest ranks
    k = (n - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_data[int(k)])
    d0 = sorted_data[int(f)] * (c - k)
    d1 = sorted_data[int(c)] * (k - f)
    return float(d0 + d1)


def median(data: Sequence[float]) -> float:
    """Calculate the median of data."""
    return percentile(data, 50.0)


def iqr(data: Sequence[float]) -> float:
    """Calculate the Interquartile Range (IQR = Q3 - Q1)."""
    if len(data) < 2:
        return 0.0
    q75 = percentile(data, 75.0)
    q25 = percentile(data, 25.0)
    return round(q75 - q25, 6)


def bootstrap_ci(
    data: Sequence[float],
    confidence: float = 0.95,
    n_resamples: int = 1000,
    seed: int | None = 42,
) -> tuple[float, float]:
    """Calculate a bootstrap confidence interval for the median of data.
    
    Returns (ci_lower, ci_upper).
    """
    if not data:
        return (0.0, 0.0)
    if len(data) == 1:
        val = float(data[0])
        return (val, val)
    
    rng = random.Random(seed)
    n = len(data)
    medians: list[float] = []
    for _ in range(n_resamples):
        sample = [rng.choice(data) for _ in range(n)]
        medians.append(median(sample))
    
    alpha = (1.0 - confidence) / 2.0
    lower = percentile(medians, alpha * 100.0)
    upper = percentile(medians, (1.0 - alpha) * 100.0)
    return (round(lower, 6), round(upper, 6))


def get_cpu_model() -> str:
    """Read the CPU model from /proc/cpuinfo."""
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            for line in f:
                if "model name" in line:
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "Unknown CPU"


def get_system_info() -> dict[str, Any]:
    """Gather host system metadata and load averages."""
    load_1, load_5, load_15 = (0.0, 0.0, 0.0)
    try:
        load_1, load_5, load_15 = os.getloadavg()
    except (OSError, AttributeError):
        pass
    
    cores = os.cpu_count() or 1
    cpu_model = get_cpu_model()
    kernel = platform.release()
    
    load_high = load_1 > 1.0
    warning = f"System 1-min load average is high ({load_1:.2f} > 1.00)" if load_high else None
    
    return {
        "cpu_model": cpu_model,
        "cpu_cores": cores,
        "kernel": kernel,
        "load_avg_1m": round(load_1, 2),
        "load_avg_5m": round(load_5, 2),
        "load_avg_15m": round(load_15, 2),
        "load_warning": warning,
    }


def format_stat_summary(data: Sequence[float], unit: str = "ms") -> str:
    """Format median [IQR] (95% CI) into a concise string."""
    if not data:
        return "N/A"
    med = median(data)
    rng = iqr(data)
    ci_l, ci_u = bootstrap_ci(data)
    return f"{med:.2f} {unit} [IQR: {rng:.2f}] (95% CI: {ci_l:.2f}–{ci_u:.2f})"
