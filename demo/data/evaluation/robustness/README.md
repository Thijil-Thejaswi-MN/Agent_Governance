# Robustness Evaluation Datasets (CC & CO)

## Overview
Empirical evaluation measuring the robustness, boundaries, and envelope invariants of:
1. **Capability Cloaking (CC)**: Evaluates declared vs undeclared methods, case normalization, boundary strings, parameter structures, and payload prompt injections.
2. **Cycle Overflow (CO)**: Evaluates delegation chains from 0 to 12 hops, budget boundaries, cyclic loop paths, and missing header observability.

## Key Datasets
- `cc_robustness_summary.json`: Category breakdown and envelope-level conformance rates.
- `cc_robustness_trials.jsonl`: Complete CC robustness trial records.
- `co_robustness_summary.json`: Depth progression, cycle detection, and header dependency results.
- `co_robustness_trials.jsonl`: Complete CO robustness trial records.
