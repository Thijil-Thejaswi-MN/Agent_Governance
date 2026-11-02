# INFUSE Benchmark Evaluation Runs

This directory contains execution summaries from running the INFUSE benchmark suite under governed runtime execution.

## Policy & Hygiene Constraints
- **Zero Raw Payloads in Git**: Full trajectories, environment execution transcripts, and raw container outputs are stored locally in the git-ignored `raw/` directory. No attack payload strings or prompt text may be committed to git.
- **Summary Format**: Aggregate metrics, pass/fail verifier outcomes, format errors, network mode, and exit statuses are recorded in `summary.jsonl`.
