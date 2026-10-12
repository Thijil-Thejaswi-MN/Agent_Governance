# Stage 2: Research Evaluation Framework & Empirical Methodology

**Project:** Autonomous Agent-to-Agent (A2A) Security Gateway & Policy Mediation Monitor  
**Evaluation Identifier:** `STAGE-2-EVAL`  
**Execution Date:** 2026-10-06  
**Artifact Directory:** `demo/data/evaluation/`  

---

## 1. Executive Summary

This document presents the formal empirical evaluation methodology, experimental design, and quantitative results for the A2A Security Monitor. The evaluation compares undefended direct agent-to-agent communication against mediated communication passing through the Security Gateway across both benign workloads and adversarial exploit campaigns.

### Key Empirical Findings (Scoped to Evaluated Scenarios)
- **AgentCard Spoofing (AS):** 100.0% observed detection on the evaluated scenarios (100/100 trials, 95% Wilson score CI: [96.3%, 100.0%]), 100.0% enforcement rate, 100.0% containment rate (0% upstream contact).
- **Capability Cloaking (CC):** 100.0% observed detection on the evaluated scenarios (100/100 trials, 95% Wilson score CI: [96.3%, 100.0%]), 100.0% containment rate against unmanifested runtime RPC methods.
- **Cycle Overflow (CO):** 100.0% observed detection on the evaluated scenarios (100/100 trials, 95% Wilson score CI: [96.3%, 100.0%]), 100.0% containment rate against cyclic multi-hop delegation loops and recursive stack exhaustion.
- **Benign Baseline (False Positive Quantification):** Observed FPR = 0.0% (0/100 trials, 95% Wilson score CI: [0.0%, 3.7%]) on the evaluated benign workload.
- **Performance Overhead:**
  - Direct baseline round-trip: Mean **1.0803 ms** (p95: 1.1810 ms).
  - Mediated protected round-trip: Mean **5.9205 ms** (p95: 7.3453 ms).
  - Absolute proxy overhead: **4.8402 ms** (representing normal TCP/HTTP reverse proxy forwarding hop).
  - Intrinsic security detection & policy decision latency: **0.0951 ms** (sub-millisecond inline processing).

> [!NOTE]
> These metrics reflect empirical performance strictly on the evaluated benchmark suite and synthetic testbed scenarios. They do not constitute proof of universal 100% detection against arbitrary zero-day exploits, nor do they guarantee a universal 0% FPR across unvetted third-party agent workloads.

---

## 2. Research Questions and Formal Hypotheses

### Research Questions
- **RQ1 (Detection Effectiveness):** Can an inline mediator reliably detect AgentCard Spoofing (AS), Capability Cloaking (CC), and Cycle Overflow (CO) attacks without relying on out-of-band telemetry or manual operator triage?
- **RQ2 (Containment & Defense Isolation):** Does the graduated response architecture prevent adversaries from causing Denial-of-Service (DoS) on legitimate agents when spoofing their identities, and does it guarantee zero upstream contact after violation detection?
- **RQ3 (False Positive Profile):** Does the inline enforcement pipeline erroneously throttle, restrict, or quarantine benign A2A traffic operating within declared specifications?
- **RQ4 (Latency & Overhead Disaggregation):** What is the exact latency cost of runtime inspection, and how does intrinsic security computation compare with network proxy hop overhead?

### Hypotheses
- **$H_1$ (AS Containment):** Pre-ingestion normalization combining Unicode NFKD decomposition, Cyrillic confusable skeleton mapping, Gestalt sequence matching (`difflib.SequenceMatcher.ratio` $\ge 0.85$), and endpoint provenance verification detects $\ge 95\%$ of identity-spoofing candidates with 0 upstream activations.
- **$H_2$ (CC Containment):** Runtime envelope extraction comparing incoming RPC method names against declared AgentCard skill manifests blocks unmanifested methods prior to dispatch with 100% containment on tested payloads.
- **$H_3$ (CO Loop Interception):** Contextual delegation chain tracking detects cyclic re-entry and maximum depth exceedance ($>5$ hops) in $O(1)$ memory lookup without state leaks.
- **$H_4$ (False Positive Invariance):** Benign traffic adhering to declared capabilities experiences $0\%$ false positive rate under baseline operational thresholds on evaluated standard sample agents.

---

## 3. Experimental State Isolation

To preserve scientific rigor and prevent benchmark pollution:
1. **Isolated SQLite Database:** Every evaluation execution instantiates an isolated evaluation database (`demo/data/evaluation/eval_<timestamp>.db`). The active development database (`demo/data/security_monitor.db`) is neither modified nor queried during benchmark runs.
2. **Deterministic Random Seeds:** All stochastic variations (card order, token generator, payload parameterization) utilize fixed pseudo-random number seeds (`seed=42`).
3. **Artifact Provenance:** Every trial generates a structured, machine-readable JSONL entry recording `evaluation_id`, `trial_id`, `input_payload`, `expected_action`, `actual_action`, `timing`, and containment verification.
4. **Reproducibility Manifest:** An immutable `evaluation_manifest.json` accompanies each dataset, documenting software versions, agent endpoints, configuration parameters, and exact trial counts.

---

## 4. Evaluation Matrix & Trial Design

The evaluation matrix tests 500 total controlled trials ($N=100$ per condition):

| Condition | Category | Scenarios | Trial Count | Target Agents | Primary Metric |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Control** | Benign Traffic | `.well-known` reads, task execution | 100 | HelloWorld, AgentAlice | False Positive Rate ($FP$) |
| **Attack** | AS (Spoofing) | Homoglyphs, typosquats, provenance conflicts | 100 | HelloWorld, AgentAlice | Detection Rate, Containment Rate |
| **Attack** | CC (Cloaking) | Undeclared methods (`system_exec`, `eval_code`, etc.) | 100 | HelloWorld, AgentAlice | Detection Rate, Containment Rate |
| **Attack** | CO (Cycle) | Multi-hop cyclic loop, depth $> 5$ | 100 | HelloWorld, AgentAlice | Detection Rate, Containment Rate |
| **Profiling**| Latency | Paired direct vs mediated HTTP calls | 100 | HelloWorld (live port 9999) | Absolute & % Overhead |

---

## 5. A2ASecBench Alignment Mapping

To ensure academic honesty, we explicitly distinguish between benchmark definitions and runtime gateway heuristics:

| Attack Category | A2ASecBench Benchmark Definition | Our Runtime Detector Implementation | Observable Signal | Response Action | Equivalence Status | Methodological Limitation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AS** (AgentCard Spoofing) | Offline task routing benchmark: Evaluates whether a `SelectorSUT` selects an adversarial card over benign target. | Pre-registration gateway validator: Normalizes card names, extracts unicode confusable skeletons via `HOMOGLYPH_MAP`, calculates Gestalt pattern matching ratio via `difflib.SequenceMatcher.ratio() >= 0.85`, and verifies endpoint authority. | Homoglyph match, SequenceMatcher ratio $\ge 0.85$, duplicate name on untrusted origin. | `HIGH` $\to$ `QUARANTINE` (Candidate identifier and candidate endpoint quarantined; HTTP 403 on candidate URL). | **Functionally Equivalent in Objective; Operationally Different** | A2ASecBench evaluates LLM/heuristic card selection; our monitor enforces active pre-filter admission control. |
| **CC** (Capability Cloaking) | Static/Offline probe benchmark: Compares AgentCard declared capabilities against code analysis of backend module functions. | Runtime proxy envelope heuristic: Intercepts incoming JSON-RPC `method` in POST request body and validates against declared skill identifiers in the trusted AgentCard. | Invocation of undeclared method (e.g. `system_exec`, `priv_escalate`). | `HIGH` $\to$ `QUARANTINE` (Caller quarantined; HTTP 403 `-32004`). | **Runtime Proxy Heuristic (Taxonomy Inspired)** | Does not inspect internal Python bytecode of upstream agents; inspects runtime RPC request envelope. |
| **CO** (Cycle Overflow) | Multi-agent delegation benchmark: Traces cyclic routing loops and recursion in agent-to-agent task delegation. | Contextual delegation tracker: Tracks unique context IDs (`x-context-id`) and explicit delegation chains (`x-delegation-chain`); enforces acyclic directed paths and depth cap $\le 5$. | Re-appearance of target agent in delegation chain or depth $> 5$. | `HIGH` $\to$ `QUARANTINE` (Source quarantined; HTTP 403 `-32005`). | **Runtime Delegation Interceptor (Taxonomy Inspired)** | Assumes cooperative or mediated propagation of delegation context headers across hops. |

---

## 6. Statistical Formulas and Uncertainty Quantification

### 1. Detection Rate ($DR$)
$$DR = \frac{TP}{TP + FN}$$

### 2. False Positive Rate ($FPR$)
$$FPR = \frac{FP}{FP + TN}$$

### 3. Containment Rate ($CR$)
$$CR = \frac{\text{Blocked Trials with Zero Upstream Contact}}{\text{Total Attack Trials}}$$

### 4. Wilson Score 95% Confidence Interval for Proportions
To quantify estimation uncertainty around observed binomial proportions (such as detection and false-positive rates) without relying on unrealistic normal approximations near $0$ and $1$:
$$\text{CI}_{95} = \frac{\hat{p} + \frac{z^2}{2n} \pm z\sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}} \quad (z = 1.95996)$$

> [!NOTE]
> Confidence intervals quantify uncertainty due to finite sample size ($N=100$). They do not imply or constitute a formal statistical power analysis.

### 5. Latency Overhead Metrics
$$\text{Absolute Overhead} = \bar{T}_{\text{mediated}} - \bar{T}_{\text{direct}}$$
$$\text{Percentage Overhead} = \left(\frac{\bar{T}_{\text{mediated}} - \bar{T}_{\text{direct}}}{\bar{T}_{\text{direct}}}\right) \times 100\%$$

---

## 7. Empirical Results Summary

### Effectiveness Matrix ($N=100$ per Condition)

| Traffic Class | Total Trials | Detected | Enforced | Contained | Missed (FN) | False Positives | Observed Detection Rate | 95% Wilson Score CI | Upstream Contact |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Benign Traffic** | 100 | N/A | 100 | N/A | 0 | **0** | **N/A** | $[0.0\%, 3.7\%]$ (FPR CI) | 100% (Expected) |
| **AgentCard Spoofing (AS)** | 100 | 100 | 100 | 100 | 0 | 0 | **100.0%** | $[96.3\%, 100.0\%]$ | **0.0%** (Contained) |
| **Capability Cloaking (CC)** | 100 | 100 | 100 | 100 | 0 | 0 | **100.0%** | $[96.3\%, 100.0\%]$ | **0.0%** (Contained) |
| **Cycle Overflow (CO)** | 100 | 100 | 100 | 100 | 0 | 0 | **100.0%** | $[96.3\%, 100.0\%]$ | **0.0%** (Contained) |

### Latency Profiles (Milliseconds)

| Metric | Mean (ms) | Median (ms) | Std Dev (ms) | Min (ms) | Max (ms) | p95 (ms) | p99 (ms) | 95% CI (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Direct Baseline RTT** | 1.0803 | 1.0520 | 0.1245 | 0.8912 | 1.4820 | 1.1810 | 1.4210 | $[1.0559, 1.1047]$ |
| **Mediated Protected RTT** | 5.9205 | 5.6120 | 1.1420 | 4.1205 | 9.8510 | 7.3453 | 9.1240 | $[5.6967, 6.1443]$ |
| **Absolute Proxy Overhead** | **4.8402** | 4.5600 | 1.0815 | 3.2293 | 8.3690 | 6.1643 | 7.7030 | — |
| **Detection Processing** | 0.0927 | 0.0933 | 0.0224 | 0.0516 | 0.1415 | 0.1355 | 0.1415 | $[0.0883, 0.0971]$ |
| **Decision Processing** | 0.0024 | 0.0023 | 0.0004 | 0.0017 | 0.0042 | 0.0032 | 0.0042 | $[0.0023, 0.0025]$ |
| **Security Pipeline Total** | **0.0951** | 0.0956 | 0.0226 | 0.0533 | 0.1457 | 0.1387 | 0.1457 | $[0.0907, 0.0995]$ |

---

## 8. Explicit Threats to Validity & Methodological Limitations

1. **Scenario-Construction Bias:** Adversarial test cases were generated programmatically according to modeled attack templates. While grounded in the A2ASecBench taxonomy, they may not encompass complex obfuscations or evasion strategies crafted by adaptive adversaries.
2. **Limited Attack Diversity:** The testbed evaluates three primary vulnerability archetypes (AS, CC, CO). It does not test prompt injection, jailbreaking, or multi-modal exfiltration attacks.
3. **Local Loopback Network Testbed:** Latency measurements were captured over localhost (`127.0.0.1`) on Windows. In real-world WAN deployments, network jitter and cross-cloud latency will exceed the ~4.8 ms reverse-proxy overhead, altering relative percentage calculations.
4. **Two-Agent Benign Testbed:** The benign control set utilizes HelloWorld (A2A v1.0) and AgentAlice (A2A v0.3). While representing two key protocol revisions, this small testbed cannot fully model large-scale enterprise deployments with thousands of dynamically registered agents.
5. **Runtime Envelope Boundary (CC Limitation):** The Capability Cloaking detector validates incoming RPC method identifiers against declared manifest skills. If an upstream agent executes malicious code internally inside a validly declared method without altering the RPC method name, manifest-based detection alone will not observe the cloaking.
6. **Delegation Header Compliance (CO Limitation):** Cycle Overflow tracking assumes that mediating proxies or compliant agents forward context identifiers (`x-context-id`, `x-delegation-chain`). Adversaries communicating through unmediated side-channels could bypass header-based tracking unless all hops are routed through the Security Gateway.
7. **Environment-Dependent Timing:** Monotonic timers and network roundtrips depend on hardware specifications, OS scheduler priority, and loopback socket buffering.

---

## 9. Reproducibility & Nondeterminism Notes

To reproduce the research evaluation and regenerate trial records:

```bash
cd demo/security_monitor
.\.venv\Scripts\activate
python -m evaluation.run --all --trials 100 --seed 42
```

### Deterministic vs Nondeterministic Fields
- **Deterministic:** Scenario definitions, input payloads, classification labels, ground truth outcomes, and enforcement policy decisions are strictly deterministic across runs with fixed seed (`seed=42`).
- **Nondeterministic:** Wall-clock timestamps (`start_time_utc`, `end_time_utc`, `timestamp_utc`), monotonic latency readings (`t_recv_ns`, `t_detect_ns`, `roundtrip_latency_ms`), and evaluation identifiers (`eval_<timestamp>`) vary naturally across executions due to operating system scheduling and real-time execution.
