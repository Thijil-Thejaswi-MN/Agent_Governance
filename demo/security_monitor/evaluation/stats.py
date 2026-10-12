from __future__ import annotations

import math
import statistics
from typing import Any


def compute_series_stats(series: list[float]) -> dict[str, float]:
    """Compute standard descriptive statistics for a latency series in milliseconds."""
    if not series:
        return {
            "count": 0,
            "mean_ms": 0.0,
            "median_ms": 0.0,
            "stdev_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "ci95_lower_ms": 0.0,
            "ci95_upper_ms": 0.0,
        }

    s_sorted = sorted(series)
    n = len(s_sorted)
    mean_val = statistics.mean(series)
    stdev_val = statistics.stdev(series) if n > 1 else 0.0

    p95_idx = min(int(n * 0.95), n - 1)
    p99_idx = min(int(n * 0.99), n - 1)

    # 95% Confidence Interval for normal distribution / large N (z=1.96)
    sem = (stdev_val / math.sqrt(n)) if n > 1 else 0.0
    ci_margin = 1.96 * sem

    return {
        "count": n,
        "mean_ms": round(mean_val, 4),
        "median_ms": round(statistics.median(series), 4),
        "stdev_ms": round(stdev_val, 4),
        "min_ms": round(s_sorted[0], 4),
        "max_ms": round(s_sorted[-1], 4),
        "p95_ms": round(s_sorted[p95_idx], 4),
        "p99_ms": round(s_sorted[p99_idx], 4),
        "ci95_lower_ms": round(max(0.0, mean_val - ci_margin), 4),
        "ci95_upper_ms": round(mean_val + ci_margin, 4),
    }


def compute_wilson_ci(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """
    Compute Wilson score interval for binomial proportion.
    Robust for extreme proportions (0% or 100%) and small-to-moderate sample sizes.
    """
    if n <= 0:
        return 0.0, 0.0

    z = 1.95996  # for 95% confidence
    p_hat = k / n
    denominator = 1.0 + (z**2) / n
    center = (p_hat + (z**2) / (2.0 * n)) / denominator
    spread = (z / denominator) * math.sqrt((p_hat * (1.0 - p_hat) / n) + ((z**2) / (4.0 * (n**2))))

    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return round(lower, 4), round(upper, 4)


def compute_proportion_metrics(success_count: int, total_count: int) -> dict[str, Any]:
    """Return count, percentage, and 95% Wilson confidence interval."""
    if total_count == 0:
        return {"count": 0, "total": 0, "rate": 0.0, "ci95_lower": 0.0, "ci95_upper": 0.0}

    rate = success_count / total_count
    ci_lower, ci_upper = compute_wilson_ci(success_count, total_count)
    return {
        "count": success_count,
        "total": total_count,
        "rate": round(rate, 4),
        "percentage": round(rate * 100.0, 2),
        "ci95_lower": ci_lower,
        "ci95_upper": ci_upper,
        "ci95_percentage": [round(ci_lower * 100.0, 2), round(ci_upper * 100.0, 2)],
    }
