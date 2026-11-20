# Scale Governance Evaluation Summary

## Host Environment
- **CPUs**: 20
- **RAM**: 7783 MB
- **Kernel**: 6.18.58.1-microsoft-standard-WSL2
- **Platform**: WSL2
- **Timestamp**: 2026-11-20T12:42:46.175291+00:00
- **Git Commit**: 8028f861af43186eba7a54c5ad391729af0d8df3
- **Git Dirty**: false

## Baseline Measurements (Sequential Execution)
- **Scripted p50**: 1.275 s (n=18)
- **Scripted p95**: 21.679 s (n=18)
- **Runs Evaluated**: 18

## Round Results

| Round Size | Repeat | Total Runs | Normal | Attack | Real | Scripted p50 (Ratio) | Scripted p95 (Ratio) | Real p50/p95 | Attacks Stopped | Canary Leaks | Violations | Outside Failed Other | Attribution (P/R) | Records Verified | Lingering PIDs |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 0 | 5 | 3 | 2 | 0 | 1.907s (1.5x) | 18.149s (0.84x) | N/A | 2/2 | 0 | 0 | 25 | not measured | 5/5 | 0 |
| 5 | 1 | 5 | 3 | 2 | 0 | 1.52s (1.19x) | 18.164s (0.84x) | N/A | 2/2 | 0 | 0 | 25 | not measured | 5/5 | 0 |
| 10 | 0 | 10 | 7 | 3 | 0 | 2.627s (2.06x) | 23.253s (1.07x) | N/A | 3/3 | 0 | 0 | 42 | not measured | 10/10 | 0 |
| 10 | 1 | 10 | 7 | 3 | 0 | 2.846s (2.23x) | 23.368s (1.08x) | N/A | 3/3 | 0 | 0 | 42 | not measured | 10/10 | 0 |
| 20 | 0 | 20 | 14 | 6 | 0 | 4.652s (3.65x) | 24.431s (1.13x) | N/A | 6/6 | 0 | 0 | 76 | not measured | 20/20 | 0 |
| 20 | 1 | 20 | 14 | 6 | 0 | 4.402s (3.45x) | 25.174s (1.16x) | N/A | 6/6 | 0 | 0 | 76 | not measured | 20/20 | 0 |

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
