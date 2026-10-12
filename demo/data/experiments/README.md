# Master Experiment Index — A2A Security Monitor Empirical Benchmarks

This directory contains experimentally observed data, latency measurements, and structured trial records generated during the development and evaluation of the A2A Security Monitor.

---

## Experiment Summary Table

| Phase | Scenario / Attack Family | Target Agent(s) | Trials ($N$) | Detection Rate | Enforcement Action | Internal Pipeline Latency (Mean) | Proxy Roundtrip Latency (Mean) | Primary Result Artifact |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Phase 5A** | **AgentCard Spoofing (AS)** | `HelloWorld` (:9999) | 1 (Vertical Slice) | 100% (1/1) | `QUARANTINE` | **0.348 ms** | 2.631 ms | [`phase5a_first_vertical_slice_experiment.json`](./phase5a_first_vertical_slice_experiment.json) |
| **Phase 5B** | **Capability Cloaking (CC)** | `HelloWorld` (:9999) | 1 (Probe) | 100% (1/1) | `QUARANTINE` | **0.101 ms** | 4.850 ms | [`phase5b_multi_agent_cc_experiment.json`](./phase5b_multi_agent_cc_experiment.json) |
| **Phase 5B** | **Direct vs. Mediated Latency** | `HelloWorld` & `AgentAlice` | 30 per path | N/A (Baseline) | N/A (Allowed) | N/A | Direct: 0.92–1.53 ms<br>Mediated: 5.77–6.90 ms | [`phase5b_multi_agent_cc_experiment.json`](./phase5b_multi_agent_cc_experiment.json) |
| **Phase 5C** | **Cycle Overflow (CO)** | `HelloWorld` & `AgentAlice` | 30 (Automated) | 100% (30/30) | `QUARANTINE` | **0.034 ms** | Direct: 1.545 ms<br>Mediated: 6.598 ms | [`phase5c_cycle_overflow_experiment.json`](./phase5c_cycle_overflow_experiment.json)<br>[`phase5c_cycle_overflow_trials.jsonl`](./phase5c_cycle_overflow_trials.jsonl) |

---

## Detailed Experiment Files

### 1. Phase 5A: AgentCard Spoofing First Vertical Slice
- **File**: `phase5a_first_vertical_slice_experiment.json`
- **Objective**: Evaluates homoglyph detection (Cyrillic `\u043e` impersonation) and unauthorized port provenance conflict during candidate card registration.
- **Key Finding**: Registration blocked with HTTP 403; internal security pipeline latency was measured at 0.348 ms; upstream target remained uncontacted.

### 2. Phase 5B: Multi-Agent Mediation & Capability Cloaking
- **File**: `phase5b_multi_agent_cc_experiment.json`
- **Objective**: Mediates both A2A v1.0 (`HelloWorld` on 9999) and v0.3.0 (`AgentAlice` on 8001); benchmarks direct vs. mediated latency across 30 repetitions; evaluates runtime capability envelope enforcement on unadvertised RPC methods (`system_exec`).
- **Key Finding**: Unadvertised method blocked with HTTP 403; internal security pipeline overhead is ~0.10 ms; total proxy roundtrip overhead is +4.85 ms to +5.37 ms.

### 3. Phase 5C: Cycle Overflow & Repeatable Experiment Harness
- **Files**: `phase5c_cycle_overflow_experiment.json`, `phase5c_cycle_overflow_trials.jsonl`
- **Objective**: Executes 30 automated trials simulating cyclic delegation loops (`['helloworld', 'agentalice', 'helloworld']`); logs raw trial records and high-resolution timing.
- **Key Finding**: 100% detection rate (30/30 blocked); internal security processing executed in an average of **0.034 ms** (34 microseconds); 0 requests reached the upstream server.

---

## Methodological Distinctions
- **Internal Security Algorithm Latency**: High-resolution measurement (`time.perf_counter_ns()`) of the interval $t_{\text{recv}} \to t_{\text{enforce}}$ inside the monitor gateway. Across all evaluations, algorithmic cost remains under **0.35 ms**.
- **End-to-End Proxy Overhead**: Roundtrip latency between client and agent through the Python/FastAPI/httpx loopback proxy (+4.8 to +5.4 ms), representing prototype networking overhead rather than algorithmic complexity.
- **Benchmark Alignment**: All detectors are grounded in the threat families defined by A2ASecBench (AS, CC, CO), while operating as real-time inline gateway defense heuristics rather than offline static benchmarks.
