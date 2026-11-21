# Runtime Governance Performance and Resource Overhead (v1)

## Overview

This document describes the performance benchmarking framework (`measure_overhead.py`) and agent efficiency evaluation (`summarise_agent_efficiency.py`) for the runtime governance architecture.

The evaluation quantifies the time and resource impact introduced across each isolation layer:
- **Baseline execution** without containment;
- **Workspace sandboxing** via Landlock;
- **Full multi-layer governance** comprising broker RPC mediation, Landlock filesystem restriction, seccomp syscall filtering, network namespace proxying, and OS sensors;
- **Ptrace sensor cost decomposition** by contrasting full governance with sensor-free and eBPF shadow sensor alternatives.

---

## Evaluated Configurations

The benchmark evaluates five distinct operational configurations:

| Configuration | Description | Layers Armed |
| :--- | :--- | :--- |
| **A** | Direct execution (Baseline) | None (uncontained host process) |
| **W** | Workspace sandbox | Landlock workspace boundary |
| **C** | Full governance (Production default) | Tool broker + Landlock + seccomp + NetNS proxy + ptrace sensor |
| **C-nosensor** | Full governance without ptrace sensor | Tool broker + Landlock + seccomp + NetNS proxy |
| **C-ebpf** | Full governance with eBPF sensor | Tool broker + Landlock + seccomp + NetNS proxy + eBPF shadow sensor |

### Benchmark-Only Switch (`GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR`)

To isolate the overhead of ptrace tracing from the other governance layers:
- The switch `GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR=1` disables ptrace interception.
- **Guard mechanism**: The switch is ignored unless `GOVERNANCE_BENCH_MODE=1` is also explicitly set in the execution environment. In regular operations or evaluation runs without `GOVERNANCE_BENCH_MODE=1`, full ptrace enforcement remains active.
- When honoured, the sensor process runs with `--no-ptrace`, child gating is coordinated via synchronization pipe, `extra.bench_mode=true` and `extra.sensor_disabled=true` are recorded in the receipt, and the dashboard marks the task with the badge `benchmark: sensor off`.

---

## Workload Suite

The benchmark evaluates five targeted workloads:

### W1: Start-up & Teardown Phase Breakdown
Measures the initialization latency of each governance subsystem:
1. `cgroup_scope`: Allocation and transition into transient `systemd --user` cgroup v2 scope.
2. `netns_proxy`: Spawning the ephemeral loopback egress proxy and allocating dynamic port bindings.
3. `landlock_seccomp`: Compiling the boundary ruleset and passing rules to the Landlock enforcer binary.
4. `sensor_attach`: Initializing sensor process and attaching ptrace or eBPF hooks.
5. `broker_connect`: Starting the broker UNIX domain socket RPC listener and arming communications.
6. `startup_total`: Total wall-clock time from task request intake to agent execution launch.
7. `teardown`: Cgroup subtree cleanup, socket closure, token revocation, and receipt sealing.

### W2: Tool-Call Latency
Measures high-frequency brokered tool execution:
- 200 sequential `read_file` calls (1 KB content).
- 200 sequential `write_file` calls (1 KB content written to `output/`).
- 50 sequential `request_access` calls auto-approved at LOW risk tier.
- Compared against direct Python file read/write operations in Configuration A.
- Metrics reported: p50, p95, p99 latency in milliseconds.

### W3: Shell-Heavy / Sensor Cost
Stresses the system call interception layer with high-density filesystem operations:
- `find` across 5,000 files in 50 subdirectories.
- `grep -r` searching for needle patterns across 5,000 files.
- Python process reading 2,000 files sequentially.
- `tar -czf` archiving a 50 MB directory structure.
- 500 short process executions (`/bin/true`).
- Metrics reported: duration in milliseconds and slowdown factor relative to Configuration A.

### W4: Network Overhead
Evaluates HTTP mediation and egress filtering:
- 100 sequential HTTP GET requests against a local test HTTP service.
- Contrasts direct HTTP requests in Configuration A against brokered proxy requests in Configuration C.
- Metrics reported: per-request p50 and p95 latency in milliseconds.

### W5: End-to-End Scripted Preset (`summarise_csv`)
Evaluates holistic task execution duration on a standard analytics workflow:
- Reading input CSV data (`input/sales.csv`), invoking `awk` to compute summary metrics, and recording results to `output/summary.txt`.
- Metrics reported: overall wall-clock task execution time in seconds.

---

## Resource Telemetry

Hardware and cgroup utilization are sampled for each run:
- **CPU Time**: User-space (`user_usec`) and kernel system (`system_usec`) consumption read from `/sys/fs/cgroup/<task_scope>/cpu.stat`.
- **Peak Memory**: Peak physical memory residency read from `/sys/fs/cgroup/<task_scope>/memory.peak`.
- **Process Footprint**: Count of auxiliary governance processes (sensor, broker, proxy threads).
- **Host State**: CPU model, core count, kernel release, and 1-minute / 5-minute system load averages before and after benchmark execution (flagging load > 1.0).

---

## Statistical Methodology

To minimize measurement noise and eliminate systematic bias:
- **Warm-ups**: 2 warm-up cycles executed prior to data collection.
- **Sample Size**: At least 10 repeats for macro benchmarks (W1, W5) and at least 20 repeats for micro benchmarks (W2, W3, W4).
- **Randomized Order**: Within each repeat iteration, the execution order of configurations (`A`, `W`, `C`, `C-nosensor`, `C-ebpf`) is randomly permuted.
- **Metrics**: Non-parametric statistics are reported: median, Interquartile Range (IQR = Q3 - Q1), and 95% bootstrap confidence intervals computed over 1,000 resamples.

---

## Agent Efficiency Analysis

The companion utility `summarise_agent_efficiency.py` analyzes committed evaluation runs:
- `inworkspace_v1_qwen2.5_7b.jsonl`
- `inworkspace_v1_gpt-oss-20b.jsonl`
- `full_v3b_qwen2.5_7b.jsonl`
- `utility_v3d_qwen2.5_7b.jsonl`

Infrastructure errors (such as provider HTTP 429 throttling or network timeouts) are excluded from all denominators.

Per condition (A, W, C, etc.), the report computes:
- Wall time p50 and p95
- Tool calls p50 and p95
- Model calls p50 and p95
- Refusal rates and counts
- Task timeout rates and counts
- Task correctness rates and counts

Generated outputs:
- `demo/data/perf/perf_v1.json`
- `demo/data/perf/perf_v1.md`
- `demo/data/perf/agent_efficiency_v1.json`
- `demo/data/perf/agent_efficiency_v1.md`
