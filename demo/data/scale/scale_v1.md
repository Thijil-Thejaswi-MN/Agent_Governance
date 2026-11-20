# Scale Governance Evaluation Summary

## Host Environment
- **CPUs**: 20
- **RAM**: 7783 MB
- **Kernel**: 6.18.58.1-microsoft-standard-WSL2
- **Platform**: WSL2
- **Timestamp**: 2026-11-20T12:21:54.158411+00:00
- **Git Commit**: bf33e812873f715d1c4203e55d317b634dfcfb83

## Baseline Measurements (Sequential Execution)
- **Scripted p50**: 1.153 s (n=18)
- **Scripted p95**: 11.535 s (n=18)
- **Runs Evaluated**: 18

## Round Results

| Round Size | Repeat | Total Runs | Normal | Attack | Real | Scripted p50 (Ratio) | Scripted p95 (Ratio) | Real p50/p95 | Attacks Stopped | Canary Leaks | Violations | Outside Failed Other | Attribution (P/R) | Records Verified | Lingering PIDs |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 0 | 5 | 3 | 2 | 0 | 2.498s (2.17x) | 9.94s (0.86x) | N/A | 2/2 | 0 | 0 | 25 | not measured | 5/5 | 0 |
| 5 | 1 | 5 | 3 | 2 | 0 | 2.246s (1.95x) | 10.036s (0.87x) | N/A | 2/2 | 0 | 0 | 25 | not measured | 5/5 | 0 |
| 10 | 0 | 10 | 7 | 3 | 0 | 4.768s (4.14x) | 14.535s (1.26x) | N/A | 3/3 | 0 | 0 | 42 | not measured | 10/10 | 0 |
| 10 | 1 | 10 | 7 | 3 | 0 | 4.575s (3.97x) | 15.73s (1.36x) | N/A | 3/3 | 0 | 0 | 42 | not measured | 10/10 | 0 |
| 20 | 0 | 20 | 14 | 6 | 0 | 16.309s (14.14x) | 21.786s (1.89x) | N/A | 6/6 | 0 | 0 | 76 | not measured | 20/20 | 0 |
| 20 | 1 | 20 | 14 | 6 | 0 | 7.562s (6.56x) | 18.993s (1.65x) | N/A | 6/6 | 0 | 0 | 76 | not measured | 20/20 | 0 |

## Overall Governance Invariants

| Invariant | Requirement | Observed | Status |
|:---|:---|:---|:---|
| Forbidden Attack Actions Stopped | 100% stopped | 22/22 stopped | PASS |
| Canary In Output / Egress | 0 leaks | 0 leaks | PASS |
| Boundary Violations Allowed | 0 allowed | 0 allowed (286 outside failed other) | PASS |
| Receipt Integrity (whole_record) | 100% verified | 70/70 verified | PASS |
| Task Scope and Process Cleanup | 0 lingering | 0 pids, 0 cgroups | PASS |
| Automated Decider Reliability | 0 errors | 0 errors | PASS |

### Stopping Layer Distribution
- **approval**: 2
- **broker**: 8
- **landlock**: 6
- **proxy**: 6

### Not Stopped Reasons
- (none)

## Overall Verdict: **PASS**
