# Comparative Security Policy Evaluation Data

## Overview
This directory contains empirical data evaluating the research question:
> **Does graduated response provide a better security/availability trade-off than binary blocking for A2A protocol-level threats?**

## Datasets
- `comparative_manifest.json`: Metadata, hypothesis, and variable definitions.
- `comparative_trials.jsonl`: Complete 1800 trial records across the three policy regimes.
- `comparative_summary.json`: Detailed per-policy containment, availability, and latency metrics.
- `comparative_statistics.json`: Comparative delta analysis and hypothesis test statistics.

## Policies Evaluated
1. **Policy A (PERMISSIVE)**: Threat detection occurs for audit telemetry, but traffic is unconditionally allowed.
2. **Policy B (BINARY_QUARANTINE)**: Any detected violation (low, medium, high) immediately triggers quarantine and blocks subsequent communication.
3. **Policy C (GRADUATED)**: Tiered response based on severity (LOW -> RATE_LIMIT, MEDIUM -> RESTRICT, HIGH -> QUARANTINE).
