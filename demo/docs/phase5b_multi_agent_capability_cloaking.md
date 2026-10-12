# Phase 5B: Multi-Agent Cross-Traffic Mediation & Capability Cloaking Defense

## 1. Overview & Research Methodology

Phase 5B extends the A2A Security Monitor from a single-agent prototype (Phase 5A) to a **multi-agent mediation gateway** capable of mediating distinct, unmodified A2A agents operating across different protocol versions (v1.0 and v0.3.0). In addition, it integrates a second benchmark-grounded detector: **Capability Cloaking (CC)**, derived from the A2ASecBench methodology.

```
                              CLIENT
                                │
                                ▼
                      A2A SECURITY GATEWAY
                      (http://127.0.0.1:8000)
                     /                       \
                    ▼                         ▼
          HelloWorld (v1.0)           AgentAlice (v0.3.0)
       (http://127.0.0.1:9999)      (http://127.0.0.1:8001/a2a/v1)
```

Both agents remain strictly unmodified, running in their native local virtual environments.

---

## 2. Testbed Configuration

| Component | Role | Local Endpoint | Protocol Version | Binding |
| :--- | :--- | :--- | :--- | :--- |
| **Security Monitor** | Inline Gateway & Defense Gate | `http://127.0.0.1:8000` | Gateway | HTTP / JSON-RPC Proxy |
| **Agent A (HelloWorld)** | Official A2A System Agent | `http://127.0.0.1:9999` | 1.0 | JSONRPC |
| **Agent B (AgentAlice)** | Number Guessing Evaluator | `http://127.0.0.1:8001/a2a/v1` | 0.3.0 | JSONRPC |

---

## 3. Second Attack Family: Capability Cloaking (CC)

### 3.1 Grounding in A2ASecBench
In A2ASecBench (`sut/cc/rules_comparator.py`), **Capability Cloaking** is defined as an intentional discrepancy between the capabilities declared by an agent in its published `AgentCard` and the actual executable capabilities/tools present in the backend runtime.

### 3.2 Attack Mechanism
An adversarial agent or caller leverages cloaked capabilities by declaring a benign, minimal skill profile (e.g. `echo_bot` or `number_guess_evaluator`) during discovery, but at runtime attempts to execute unadvertised or sensitive operations (e.g., `system_exec`, `admin_shell`, `eval_code`, or unauthorized tool triggers).

### 3.3 Defensive Property Provided
The A2A Security Monitor provides **Runtime Capability Envelope Enforcement**:
- The monitor extracts the set of explicitly declared skills and capabilities from the trusted `NormalizedAgentCard`.
- Incoming mediated requests (`/proxy/{agent_id}/...`) are inspected for target JSON-RPC methods or task actions.
- If a method falls outside the standard A2A protocol envelope (`SendMessage`, `message/send`, `tasks/get`, etc.) and is not listed in the agent's declared skill set, the monitor raises **`CC_UNDECLARED_CAPABILITY`**.
- Severity is resolved as **`HIGH`**, resulting in immediate request termination (**HTTP 403 Forbidden**) with security event persistence and offender quarantine.

### 3.4 Crucial Research Distinction: Benchmark Definition vs. Runtime Heuristic
It is essential for future publication and evaluation to separate:
1. **A2ASecBench CC Methodology**: An offline/static ground-truth comparator (`RulesComparator` / `WhiteboxStaticComparator`) that inspects code-level capability manifests (`CAPABILITIES_MANIFEST_JSON`) against declared Agent Card skills to identify hidden tools.
2. **Our Implemented Runtime Heuristic**: An inline capability-envelope validator that dynamically detects when an incoming task request targets an unadvertised or unmanifested method at the mediation gateway.

While our heuristic is *conceptually inspired* by the capability-mismatch problem formalized by A2ASecBench, they are **not identical mechanisms**, and our papers must accurately report our implementation as a *runtime capability envelope enforcement heuristic*, rather than claiming to execute the exact A2ASecBench CC benchmark suite inline.

---

## 4. Empirical Evaluation Results

### 4.1 Internal Security Processing Latency
Internal pipeline latency was measured using high-resolution monotonic timers (`time.perf_counter_ns()`):

| Measurement Stage | Timestamp Delta | Observed Runtime Latency |
| :--- | :--- | :--- |
| **Detection Latency** | $t_{\text{detect}} - t_{\text{recv}}$ | **0.0350 ms** to **0.0458 ms** |
| **Decision Latency** | $t_{\text{decide}} - t_{\text{detect}}$ | **0.0060 ms** to **0.0072 ms** |
| **Enforcement Latency** | $t_{\text{enforce}} - t_{\text{decide}}$ | **0.0513 ms** to **0.0590 ms** |
| **Total Internal Monitor Overhead** | $t_{\text{enforce}} - t_{\text{recv}}$ | **0.1012 ms** to **0.1031 ms** |

### 4.2 End-to-End Direct vs. Mediated Latency ($N = 30$)

| Target Agent | Direct Mean Latency (ms) | Direct p95 (ms) | Mediated Mean Latency (ms) | Mediated p95 (ms) | Absolute Gateway Overhead (ms) | Percentage Overhead (%) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **HelloWorld (9999)** | 1.533 ms | 1.958 ms | 6.899 ms | 10.769 ms | **+5.367 ms** | **+350.18%** |
| **AgentAlice (8001)** | 0.919 ms | 1.200 ms | 5.771 ms | 6.339 ms | **+4.852 ms** | **+527.63%** |

### 4.3 Overhead Decomposition: Proxy Mechanics vs. Algorithmic Cost
The measured end-to-end overhead (+350% to +528%) is an artifact of the prototype network path:
$$\text{Total Overhead} \approx \underbrace{\text{Internal Monitor Pipeline}}_{\approx 0.10\text{ ms}} + \underbrace{\text{FastAPI Dispatch + httpx Loopback TCP Connection + Serialization}}_{\approx 4.8\text{ to }5.3\text{ ms}}$$

The fundamental algorithmic cost of detection, decision, and quarantine is approximately **100 microseconds (0.10 ms)**. The remainder is standard Python HTTP reverse-proxy overhead on localhost, which can be further optimized via HTTP keep-alive pooling, Unix domain sockets, or kernel-level eBPF interception in production architectures.

---

## 5. Security Effectiveness Verification

1. **Trusted HelloWorld Request**:
   - `Client -> Gateway -> HelloWorld`: HTTP 200 OK (`Hello, World! I have received your request...`).
2. **Trusted AgentAlice Request**:
   - `Client -> Gateway -> AgentAlice`: HTTP 200 OK (`Go higher`).
3. **Attack 1 (AgentCard Spoofing)**:
   - Candidate `Hellо World Agent` (homoglyph `\u043e`) $\to$ **HTTP 403 Forbidden**, Violation: `AS_HOMOGLYPH_SPOOF`, Action: `QUARANTINE`.
4. **Attack 2 (Capability Cloaking)**:
   - Runtime probe `method="system_exec"` $\to$ **HTTP 403 Forbidden**, Violation: `CC_UNDECLARED_CAPABILITY`, Action: `QUARANTINE`.
   - Upstream agents were **never contacted**.

---

## 6. Experiment Artifacts

- **Phase 5B Experiment Record**: [`demo/data/experiments/phase5b_multi_agent_cc_experiment.json`](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/experiments/phase5b_multi_agent_cc_experiment.json)
- **Phase 5A Baseline Record**: [`demo/data/experiments/phase5a_first_vertical_slice_experiment.json`](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/experiments/phase5a_first_vertical_slice_experiment.json)

---

## 7. Limitations
- Evaluated on localhost TCP loopback under Windows OS.
- In-memory inventory and quarantine store; not distributed.
- Focus is restricted to AgentCard Spoofing (AS) and Capability Cloaking (CC) attack families.
