# Runtime Governance Performance and Resource Overhead (v1)

## Overview

This document describes the performance benchmarking framework (`demo/security_monitor/measure_overhead.py`) and agent efficiency evaluation (`demo/security_monitor/summarise_agent_efficiency.py`) for the runtime governance architecture.

The evaluation quantifies the time and resource impact introduced across each isolation layer:
- **Baseline execution** without containment;
- **Workspace sandboxing** via Landlock;
- **Full multi-layer governance** comprising broker RPC mediation, Landlock filesystem restriction, seccomp syscall filtering, network namespace proxying, and OS sensors;
- **Ptrace sensor cost decomposition** by contrasting full governance with sensor-free and eBPF shadow sensor alternatives.

Both benchmarking scripts reside in the `demo/security_monitor/` directory:
- `demo/security_monitor/measure_overhead.py`: Executes micro- and macro-benchmarks measuring start-up phases, teardown steps, tool latency, shell command costs, network proxy overhead, and end-to-end presets.
- `demo/security_monitor/summarise_agent_efficiency.py`: Parses committed evaluation run logs, separating governance refusals from ordinary tool operational errors and generating per-dataset summary tables.

---

## Evaluated Configurations

The benchmark evaluates five distinct operational configurations:

| Configuration | Description | Layers Armed |
| :--- | :--- | :--- |
| **A** | Direct execution (Baseline) | None (uncontained host process; Condition A via TaskLauncher) |
| **W** | Workspace sandbox | Landlock workspace boundary |
| **C** | Full governance (Default) | Tool broker + Landlock + seccomp + NetNS proxy + ptrace sensor |
| **C-nosensor** | Full governance without ptrace sensor | Tool broker + Landlock + seccomp + NetNS proxy |
| **C-ebpf** | Full governance with eBPF sensor | Tool broker + Landlock + seccomp + NetNS proxy + eBPF shadow sensor |

### Benchmark-Only Switch (`GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR`)

To isolate the overhead of ptrace tracing from the other governance layers:
- The switch `GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR=1` disables ptrace interception.
- **Guard mechanism**: The switch is ignored unless `GOVERNANCE_BENCH_MODE=1` is also explicitly set in the execution environment. In regular operations or evaluation runs without `GOVERNANCE_BENCH_MODE=1`, full ptrace enforcement remains active.
- When honoured, the sensor process runs with `--no-ptrace`, child gating is coordinated via synchronization pipe, `extra.bench_mode=true` and `extra.sensor_disabled=true` are recorded in the receipt, and the dashboard marks the task with the badge `benchmark: sensor off`.

---

## Workload Suite & Operational Validation

Every measured operation is verified for operational success before reporting duration metrics. If an operation fails or produces unexpected output, the benchmark reports `failed: <reason>` rather than a duration metric:

### W1: Start-up & Teardown Phase Breakdown
Initialization is measured across non-overlapping contiguous intervals that sum to total start-up time:
1. `intake`: Request parsing, boundary derivation, and database record creation.
2. `workspace_setup`: Directory scaffolding, input file copying, and runtime token setup.
3. `netns_proxy`: Spawning the ephemeral loopback egress proxy and establishing ports.
4. `broker_connect`: Starting the broker UNIX domain socket RPC listener.
5. `landlock_seccomp`: Compiling the boundary ruleset and emitting the rules file.
6. `sensor_attach`: Spawning the process chain under systemd-run.
7. `cgroup_scope`: Establishing scope cgroup and detecting tracee root PID.
8. `enforcer_arm`: Unblocking the execution gate and receiving enforcer sandbox status.
9. `startup_total`: Total wall-clock duration from intake to agent execution launch (`sum(phases) == startup_total`).

Teardown is decomposed into individual steps:
- Sensor exit trailer wait (`events_done.wait`);
- Process check and freeze/kill (`spec.freeze_timeout_s` at `demo/security_monitor/app/governance/launcher.py` line 1407);
- Correlator event log flush;
- Broker RPC server termination;
- Task cgroup cleanup and deletion;
- Egress proxy termination;
- Receipt document construction and Ed25519 signing.

### W2: Tool-Call Latency (Content Verified)
Measures high-frequency tool invocation:
- 200 sequential `read_file` calls (1 KB content verified on every read).
- 200 sequential `write_file` calls (1 KB content verified on disk).
- 50 sequential `request_access` calls auto-approved at LOW risk tier.
- Condition A and Condition W do not use dynamic access requests and report `n/a`.
- Metrics reported: p50, p95, p99 latency in milliseconds.

### W3: Shell-Heavy / Sensor Cost (Strict Content Checked)
Stresses the system call interception layer with high-density filesystem operations:
- `find` across 5,000 files in 50 subdirectories (verified entry count: 5,000).
- `grep -r` searching for needle patterns across 5,000 files (verified match count: 1).
- Python process reading 2,000 files sequentially (verified bytes read: 34,000).
- `tar -czf` archiving a 50 MB directory structure (verified archive size > 0 and 51 entries).
- 500 short process executions (`/bin/true`, verified loop count: 500).
- Metrics reported: duration in milliseconds and slowdown factor relative to Configuration A. Any failed check yields `failed: <reason>` in place of duration.

### W4: Network Overhead (Status & Length Verified)
Evaluates HTTP mediation and egress filtering:
- 100 sequential HTTP GET requests against a local test HTTP service.
- Each request verified for HTTP 200 status code and exact 1,024 byte body.
- Condition W has no network namespace or proxy by design and reports `n/a (no network in W)`.
- Contrasts direct HTTP requests in Configuration A against brokered proxy requests in Configuration C.
- Metrics reported: per-request p50 and p95 latency in milliseconds.

### W5: End-to-End Scripted Preset (`summarise_csv`)
Evaluates holistic task execution duration on a standard analytics workflow:
- Reading input CSV data (`input/sales.csv`), invoking `awk` to compute summary metrics, and recording results to `output/summary.txt`.
- Output summary content is verified.
- Configuration A executes through the launcher's Condition-A path (same process start via `systemd-run --user --scope`, no governance runtime), ensuring a direct like-with-like comparison.
- Metrics reported: wall-clock duration with teardown and without teardown, alongside respective slowdown factors relative to Configuration A.

---

## Resource Telemetry

Hardware and cgroup utilization are sampled for each run:
- **CPU Time**: User-space (`user_usec`) and kernel system (`system_usec`) consumption read from `/sys/fs/cgroup/<task_scope>/cpu.stat` prior to teardown cgroup removal.
- **Peak Memory**: Peak physical memory residency read from `/sys/fs/cgroup/<task_scope>/memory.peak` prior to teardown cgroup removal.
- When cgroup metrics are unavailable (e.g. uncontained Baseline A), the benchmark reports `not measured` rather than 0.
- **Process Footprint**: Count of auxiliary governance processes (sensor, broker, proxy threads).
- **Host State**: CPU model, core count, kernel release, and 1-minute / 5-minute system load averages before and after benchmark execution (flagging load > 1.0).

---

## Statistical Methodology

To minimize measurement noise and eliminate systematic bias:
- **Warm-ups**: Warm-up cycles executed prior to data collection.
- **Sample Size**: Repeated trials for macro benchmarks (W1, W5) and micro benchmarks (W2, W3, W4).
- **Randomized Order**: Within each repeat iteration, the execution order of configurations (`A`, `W`, `C`, `C-nosensor`, `C-ebpf`) is randomly permuted.
- **Metrics**: Non-parametric statistics are reported: median, Interquartile Range (IQR = Q3 - Q1), and 95% bootstrap confidence intervals computed over resamples.

---

## Agent Efficiency Analysis

The companion utility `demo/security_monitor/summarise_agent_efficiency.py` analyzes committed evaluation runs:
- `inworkspace_v1_qwen2.5_7b.jsonl`
- `inworkspace_v1_gpt-oss-20b.jsonl`
- `full_v3b_qwen2.5_7b.jsonl`
- `utility_v3d_qwen2.5_7b.jsonl`

### Refusal vs. Tool Error Accounting
- **Governance Refusals**: Strictly counts governance boundary denials: tool broker BLOCK actions, Landlock / seccomp `Permission denied` outside boundary, proxy 403 status, and denied access requests.
- **Condition A Refusals**: Consistently 0 because no governance runtime is active.
- **Condition W Refusals**: Consistently 0 on file tasks because the full workspace is granted; refusals occur only on prohibited network connect attempts blocked by Landlock.
- **Tool Errors**: Ordinary operational errors (missing file paths, directory reads, invalid tool arguments, non-zero command exits) are tallied in a distinct "Tool Errors" column.
- **Infrastructure Errors**: Provider HTTP 429 rate limits and transport timeouts are excluded from all denominators.

### Task Set Reporting
- Cross-dataset aggregation is omitted in favor of clear, per-dataset tables.
- `utility_v3d` is decomposed into anticipated and unanticipated access rows.
- `full_v3b` correctness displays an explanatory note (`—*`) referencing known issues in the `legit_v3b` reference labels (as documented in `FINAL_VERIFIED_RESULTS`), while preserving verified runtime duration and refusal metrics.

Generated outputs:
- `demo/data/perf/perf_v1.json`
- `demo/data/perf/perf_v1.md`
- `demo/data/perf/agent_efficiency_v1.json`
- `demo/data/perf/agent_efficiency_v1.md`
