# A2A Security Monitor Research Evaluation Dataset

**Evaluation ID:** `eval_20261006_031152`  
**Generated:** `2026-10-06T03:11:52.597500+00:00` to `2026-10-06T03:15:37.493475+00:00`  
**Trial Design:** $N = 100$ trials per condition (500 total evaluation trials)  
**State Isolation:** Dedicated clean SQLite database (`eval_20261006_031152.db`) — zero pollution from development/test database.

## Dataset Contents

| File | Records | Description |
| :--- | :--- | :--- |
| `evaluation_manifest.json` | 1 | Metadata, configuration version, testbed nodes, database reference |
| `evaluation_summary.json` | 1 | Statistically aggregated results, Wilson 95% CIs, latency profiles |
| `benign_trials.jsonl` | 100 | Raw benign traffic trials for false positive rate quantification |
| `as_trials.jsonl` | 100 | Raw AgentCard Spoofing trials (homoglyph, typosquat, provenance) |
| `cc_trials.jsonl` | 100 | Raw Capability Cloaking trials (unmanifested RPC invocations) |
| `co_trials.jsonl` | 100 | Raw Cycle Overflow trials (cyclic delegation loops, depth overflow) |
| `latency_trials.jsonl` | 100 | Direct vs Mediated paired latency trials |
| `eval_20261006_031152.db` | SQLite DB | Isolated persistence artifact capturing audit events and states |

## Evaluation Summary Highlights

- **Benign Traffic (False Positive Rate):** 0.0% (0 / 100 trials)
- **AgentCard Spoofing (AS) Detection Rate:** 100.0% (100 / 100 trials, 95% CI: [96.3, 100.0]%)
- **Capability Cloaking (CC) Detection Rate:** 100.0% (100 / 100 trials, 95% CI: [96.3, 100.0]%)
- **Cycle Overflow (CO) Detection Rate:** 100.0% (100 / 100 trials, 95% CI: [96.3, 100.0]%)
- **Containment Rate:** 100% across all detected attack families (0 upstream contacts after detection)
- **Internal Security Pipeline Latency:** Mean 17.1011 ms (p95: 26.6498 ms)
- **Direct Roundtrip Latency:** Mean 1.4044 ms (p95: 2.9207 ms)
- **Mediated Roundtrip Latency:** Mean 318.7985 ms (p95: 618.3050 ms)

## Reproduction Command

```bash
python -m evaluation.run --all --trials 100 --seed 42
```
