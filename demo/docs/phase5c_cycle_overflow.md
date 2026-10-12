# Phase 5C: Cycle Overflow (CO) Detection & Experimentation Harness

## 1. Overview & Research Context

Phase 5C introduces the third benchmark-grounded attack family into the A2A Security Monitor: **Cycle Overflow (CO)**. It also establishes an automated, repeatable experimentation harness (`experiments.run`) capable of executing multi-trial empirical benchmarks across direct, mediated, and adversarial paths.

---

## 2. Attack Definition & Benchmark Grounding

### 2.1 A2ASecBench Ground Truth
In A2ASecBench (`attacks/instances/co/executable.py`), **Cycle Overflow (CO)** evaluates multi-agent coordination architectures where delegating agents or coordinators enter cyclic forwarding loops (e.g., `['travel-itinerary-agent-2', 'travel-fare-agent-3', 'travel-itinerary-agent-2']`). The benchmark considers the attack successful when the multi-agent delegation path reaches recursion thresholds without resolving, triggering `cycle_detected` or `max_depth_exceeded`.

### 2.2 Our Defensive Interpretation
The A2A Security Monitor enforces an **Inline Delegation Invariant**:
1. **Cycle Invariant**: The gateway tracks the chain of agent hops for every active `context_id` (and/or via `x-delegation-chain` headers). If a mediated task attempts to forward to an agent already present in the active unclosed chain, the gateway flags **`CO_CYCLE_DETECTED`**.
2. **Depth Budget Invariant**: If the unclosed delegation depth reaches or exceeds the configured threshold (`max_depth = 5`), the gateway flags **`CO_DEPTH_EXCEEDED`**.
3. **Severity & Policy**: Evaluated as **`HIGH`** severity $\to$ **`QUARANTINE`** action. The gateway immediately terminates the request with **HTTP 403 Forbidden** (error code `-32005`), records the security event with nanosecond telemetry, and isolates the offending caller/session.

### 2.3 Methodological Separation: Benchmark vs. Monitor Heuristic
| Dimension | A2ASecBench CO Benchmark | A2A Security Monitor CO Defense |
| :--- | :--- | :--- |
| **Operational Level** | Evaluates whether orchestrators produce unbounded loops | Inline firewall intercepting and preventing loop completion |
| **Observation Point** | End-of-task execution trajectory analysis | Per-hop gateway request inspection |
| **Classification** | Orchestration robustness benchmark | **Runtime delegation loop & depth invariant enforcement** |

---

## 3. Controlled Localhost Testbed

The testbed operates across our controlled local agents:
- **Agent A**: `HelloWorld` (`http://127.0.0.1:9999`, A2A v1.0)
- **Agent B**: `AgentAlice` (`http://127.0.0.1:8001/a2a/v1`, A2A v0.3.0)
- **Security Gateway**: `http://127.0.0.1:8000`

### Attack Scenario: Two-Party Review Cycle
A task initiated with context `co_ctx_eval` delegates from `helloworld` $\to$ `agentalice` $\to$ attempts to re-enter `helloworld`. The gateway intercepts the cyclic hop at `/proxy/helloworld`, flags `CO_CYCLE_DETECTED`, short-circuits the call, and prevents recursive invocation of the upstream HelloWorld server.

---

## 4. Empirical Evaluation Results ($N = 30$ Trials)

The automated experiment runner (`python -m experiments.run --scenario cycle_overflow --trials 30`) executed 30 baseline direct, 30 baseline mediated, and 30 attack trials:

| Metric | Sample Size | Mean | Median | Min | Max | p95 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Direct Request Latency** | $N=30$ | **1.545 ms** | 1.503 ms | 1.112 ms | 2.190 ms | 1.742 ms |
| **Mediated Request Latency** | $N=30$ | **6.598 ms** | 6.277 ms | 4.881 ms | 11.240 ms | 8.886 ms |
| **Gateway Proxy Overhead** | $N=30$ | **+5.053 ms** | +4.774 ms | — | — | — |
| **Internal Security Pipeline** | $N=30$ | **0.034 ms** | 0.031 ms | 0.021 ms | 0.089 ms | 0.059 ms |
| **Attack Detection Rate** | $N=30$ | **100.0%** (30/30 blocked) | — | — | — | — |
| **Upstream Contacted** | $N=30$ | **0.0%** (0/30 contacted) | — | — | — | — |

### Overhead Breakdown
- **Internal Security Algorithm**: **~34 microseconds (0.034 ms)**.
- **Proxy Network Transit**: **~5.05 ms** (Windows localhost TCP loopback, ASGI lifecycle, and HTTP parsing).

---

## 5. Multi-Attack Regression Smoke Results

A unified regression suite revalidated all three defense layers:
1. **AgentCard Spoofing (AS)**: Registered candidate homoglyph card $\to$ **HTTP 403 (QUARANTINE)** [PASS]
2. **Capability Cloaking (CC)**: Invoked unadvertised method `system_exec` $\to$ **HTTP 403 (QUARANTINE)** [PASS]
3. **Cycle Overflow (CO)**: Injected cyclic delegation chain `[helloworld, agentalice, helloworld]` $\to$ **HTTP 403 (QUARANTINE)** [PASS]
4. **Normal Traffic Preservation**:
   - `GET /proxy/helloworld/.well-known/agent-card.json` $\to$ **HTTP 200 OK** [PASS]
   - `GET /proxy/agentalice/.well-known/agent-card.json` $\to$ **HTTP 200 OK** [PASS]

---

## 6. Artifact References
- Experiment Summary: [`demo/data/experiments/phase5c_cycle_overflow_experiment.json`](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/experiments/phase5c_cycle_overflow_experiment.json)
- Raw Trial Telemetry: [`demo/data/experiments/phase5c_cycle_overflow_trials.jsonl`](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/experiments/phase5c_cycle_overflow_trials.jsonl)
