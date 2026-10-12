# A2A Security Research Evaluation — Authoritative Baseline Specification

**Document Version:** `2.0.0-POST-STAGE6-FROZEN`  
**Evaluation Date:** October 6, 2026  
**Status:** FROZEN RESEARCH BASELINE  

---

## 1. Overview & Data Integrity Scope

This document specifies the frozen, verified research evaluation baseline for the A2A Security Monitor. Following empirical data integrity audits, all trial records are verified directly from raw JSONL event ledgers, resolving earlier permissive-policy enforcement gate leakage, formalizing cycle overflow boundary semantics, and establishing real-world generalization across public agent registries.

> **Pre-Audit Artifact Status**: Historical and pre-audit trial records are preserved under clearly named `legacy_pre_audit/` subdirectories for forensic provenance, but are **NOT** authoritative for research claims or publications. The trial ledgers listed in this baseline specification represent the sole authoritative ground truth.

---

## 2. Dataset Inventory & Exact Trial Counts

The authoritative post-audit empirical corpus contains **3,145 total trials** across coordinated experimental modules:

| Evaluation Module | Artifact File | Total Trials | Random Seed / Design | Independent Variable | Output Directory |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **Stage 4 Comparative Evaluation** | `comparative_trials.jsonl` | **1,800** | `42` | Policy Regime (Permissive vs Binary vs Graduated) | `demo/data/evaluation/comparative/` |
| **Stage 5 AS Component Ablation** | `as_ablation_trials.jsonl` | **600** | `42` | Detector Components (Full, No-Homoglyph, No-Sim, No-Prov) | `demo/data/evaluation/ablation/` |
| **Stage 5 CC Robustness & Envelope** | `cc_robustness_trials.jsonl` | **31** | Deterministic | Method Invocation Vector Classes | `demo/data/evaluation/robustness/` |
| **Stage 5 CO Robustness & Limits** | `co_robustness_trials.jsonl` | **14** | Deterministic | Delegation Depth ($1 \dots 12$), Loops, Header Presence | `demo/data/evaluation/robustness/` |
| **Stage 6 Benign Admission Benchmark** | `real_card_detector_results.jsonl` | **100** | Read-Only Snapshot | Real-world legitimate agent admission vs trusted baseline | `demo/data/evaluation/real_world/` |
| **Stage 6 Controlled Mutations** | `real_card_mutations.jsonl` | **400** | Mechanically Controlled | Mutation Type (Homoglyph, Typosquat, Provenance, Combined) | `demo/data/evaluation/real_world/` |
| **Stage 6 Orthogonal AS Ablation** | `orthogonal_homoglyph_trials.jsonl` | **200** | Orthogonal Sets | Component Necessity (Condition A: $\text{sim}<0.85$; Condition B: non-confusable) | `demo/data/evaluation/real_world/` |
| **GRAND EMPIRICAL TOTAL** | — | **3,145** | — | — | — |

### Arithmetic Accounting Breakdown
$$\begin{aligned}
\text{Stage 4 Comparative Evaluation} &= 1,800 \\
\text{Stage 5 Component Ablation \& Invariant Limits} &= 645 \quad (600 + 31 + 14) \\
\text{Stage 6 Real-World Generalization Benchmark} &= 700 \quad (100 + 400 + 200) \\
\hline
\mathbf{Grand\ Empirical\ Total} &= \mathbf{3,145\ trials}
\end{aligned}$$

---

## 3. Policy Regime Operational Definitions

1. **Policy A — PERMISSIVE BASELINE**:
   - Inherent threat detection occurs across all protocol violation types.
   - Violation events and microsecond pipeline latencies are logged to the persistent SQLite event store for audit telemetry.
   - Enforcement action is strictly and unconditionally `ALLOW`.
   - Traffic is never blocked (HTTP 403) or throttled (HTTP 429); requests are forwarded to upstream agent sockets without impedance.
2. **Policy B — BINARY QUARANTINE BASELINE**:
   - Any detected security anomaly (low, medium, or high severity) immediately maps to a `QUARANTINE` enforcement action.
   - Offending identities and endpoints are persisted to the quarantine store.
   - All subsequent traffic to or from the entity is rejected with HTTP 403 Forbidden.
3. **Policy C — PROPOSED GRADUATED RESPONSE**:
   - Deterministic multi-tier enforcement based on threat severity:
     - **LOW Severity** (e.g. rate limit bursts): `RATE_LIMIT` (HTTP 429 with `Retry-After`; entity is not quarantined).
     - **MEDIUM Severity** (e.g. unapproved mutating operation during interface audit): `RESTRICT` (mutating task blocked HTTP 403; safe read-only inspection permitted HTTP 200).
     - **HIGH Severity** (e.g. homoglyph spoofing, undeclared capability cloaking, circular delegation): `QUARANTINE` (HTTP 403, entity isolated).

---

## 4. Canonical Metrics Definitions

### 4.1. Threat Containment Rate ($C_R$)
- **Definition**: Proportion of adversarial attempts terminated inline before reaching the upstream target or registering into inventory.
- **Formula**: $C_R = \frac{N_{\text{contained}}}{N_{\text{adv}}} \quad (N_{\text{adv}} = 350)$

### 4.2. Attacker Upstream Exposure Rate ($E_R$)
- **Definition**: Proportion of adversarial attempts that contact upstream agent sockets or enter inventory.
- **Formula**: $E_R = \frac{N_{\text{exposed}}}{N_{\text{adv}}} = 1 - C_R \quad (N_{\text{adv}} = 350)$

### 4.3. Legitimate Security Availability Rate ($A_R^{\text{sec}}$)
- **Definition**: Proportion of legitimate requests that are **not denied or throttled by security enforcement** (status code $\notin \{403, 429\}$).
- **Formula**: $A_R^{\text{sec}} = \frac{N_{\text{sec\_avail}}}{N_{\text{legit}}} \quad (N_{\text{legit}} = 250)$

### 4.4. Upstream Application Success Rate ($A_R^{\text{app}}$)
- **Definition**: Proportion of legitimate requests receiving successful operational completion responses (HTTP 200 OK) from the target upstream agent.
- **Workload Note**: Because unblocked legitimate requests did not trigger internal agent crashes, $A_R^{\text{app}} = A_R^{\text{sec}}$ on this workload. In contrast, under Permissive mode, 50 CC adversarial requests produced upstream HTTP 500 errors because AgentAlice had no handler for unadvertised RPC methods.

### 4.5. Collateral Security Disruption Rate ($D_R$)
- **Definition**: Proportion of legitimate requests blocked or throttled by security enforcement.
- **Formula**: $D_R = \frac{N_{\text{blocked\_legit}}}{N_{\text{legit}}} = 1 - A_R^{\text{sec}} \quad (N_{\text{legit}} = 250)$

### 4.6. Observed Offline Benign-Card False-Positive Rate ($FPR_{\text{real}}$)
- **Definition**: Proportion of legitimate real-world Agent Card records falsely flagged as security violations during offline admission evaluation against the trusted baseline.
- **Formula**: $FPR_{\text{real}} = \frac{N_{\text{flagged\_benign}}}{N_{\text{evaluated\_benign}}} \quad (N_{\text{evaluated\_benign}} = 100 \text{ live snapshot cards})$

---

## 5. Authoritative Results Summary

### 5.1. Stage 4 Comparative Evaluation ($N=1,800$, Seed = 42)

```text
PERMISSIVE:
- containment: 0% (0/350)
- attacker upstream: 100% (350/350)
- security availability: 100% (250/250)
- security-blocked legitimate: 0 (0/250)

BINARY:
- containment: 100% (350/350)
- attacker upstream: 0% (0/350)
- security availability: 40% (100/250)
- security-blocked legitimate: 150 (150/250)

GRADUATED:
- containment: 100% (350/350)
- attacker upstream: 0% (0/350)
- security availability: 70% (175/250)
- security-blocked legitimate: 75 (75/250)
```

| Policy Regime | Total Trials | Containment ($C_R$) | 95% Wilson CI | Security Availability ($A_R^{\text{sec}}$) | 95% Wilson CI | Blocked Legit | Mean Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Policy A (PERMISSIVE)** | 600 | **0.0%** (0/350) | [0.0%, 1.1%] | **100.0%** (250/250) | [98.5%, 100.0%] | 0 | 127.09 ms |
| **Policy B (BINARY QUARANTINE)** | 600 | **100.0%** (350/350) | [98.9%, 100.0%] | **40.0%** (100/250) | [34.1%, 46.2%] | 150 | 38.08 ms |
| **Policy C (GRADUATED RESPONSE)** | 600 | **100.0%** (350/350) | [98.9%, 100.0%] | **70.0%** (175/250) | [64.1%, 75.3%] | 75 | 57.95 ms |

### 5.2. Stage 5 Component Ablation & Robustness Studies ($N=645$)

#### AS Component Ablation ($N=600$, Seed = 42)
| Configuration | True Positives | False Negatives | False Positives | True Negatives | Recall | Precision | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **FULL_DETECTOR** | 100 | 0 | 0 | 50 | **100.0%** | **100.0%** | **0.0%** |
| **NO_HOMOGLYPH** | 100 | 0 | 0 | 50 | **100.0%** | **100.0%** | **0.0%** |
| **NO_PROVENANCE** | 67 | 33 | 0 | 50 | **67.0%** | **100.0%** | **0.0%** |
| **NO_SIMILARITY** | 67 | 33 | 0 | 50 | **67.0%** | **100.0%** | **0.0%** |

#### CC Envelope Robustness ($N=31$)
- **Conformance Rate:** **100.0%** (31/31). Prompt injections within declared parameters pass envelope checks, confirming structural protocol separation.

#### CO Robustness & Limits ($N=14$)
- Total depth budget configured: $K = 5$.
- Depths $1 \dots 5$: **Allowed**. Depth 6: **Rejected** (`CO_DEPTH_EXCEEDED`). Depths 8, 12: Rejected. Explicit cycles: Rejected (`CO_CYCLE_DETECTED`). Missing headers: Passes through (documenting cooperative tracing limitation).
- **Conformance Rate:** **100.0%** (14/14).

### 5.3. Stage 6 Real-World Generalization Validation ($N=700$)

#### Corpus Partitioning
- **Combined Corpus Size**: 203 cards.
- **100-card Live Registry Snapshot**: Used for benign offline admission FPR evaluation and controlled mutation generation.
- **103-card Static Registry Corpus**: Used for cross-version parser and normalization invariance testing (0 parsing or normalization failures across all 203 cards).

#### Benign Admission Benchmark ($N=100$)
- **Observed offline benign-card false-positive rate**: **0.0%** (0/100, $[0.0\%, 3.7\%]$ 95% Wilson CI).
- Max observed similarity against baseline: **0.6364** (`Agentropolis` vs `AgentAlice`, margin = 0.2136 below 0.85 threshold).
- Max intra-corpus similarity: **0.8475** (`LangChain Login and Token Agent` vs `OpenAI Login and Token Agent`, margin = 0.0025 below 0.85 threshold).

#### Controlled Real-World Mutations ($N=400$)
- Fixed-threshold detector identified **400/400 controlled offline mutations** (100% Homoglyph, 100% Typosquat, 100% Provenance Conflict, 100% Combined Attack).

#### Orthogonal AS Component Ablation ($N=200$)
| Condition | $N$ | FULL_DETECTOR | NO_HOMOGLYPH (Similarity Only) | NO_SIMILARITY (Homoglyph Only) | Empirical Finding |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Condition A ($\text{sim} < 0.85$)** | 100 | 100.0% (100/100) | **0.0% (0/100)** | 100.0% (100/100) | Demonstrates necessity of homoglyph mapper when similarity fails. |
| **Condition B (Non-confusable, $\text{sim} \ge 0.85$)** | 100 | 100.0% (100/100) | 100.0% (100/100) | **0.0% (0/100)** | Demonstrates necessity of similarity matcher when skeleton differs. |

---

## 6. Authoritative Empirical Conclusions

1. **Comparative Policy Trade-off**:
   > "Under the evaluated workload, graduated response achieved the same observed attack containment as binary quarantine while preserving 30 percentage points more legitimate security availability and reducing security-induced collateral blocking from 150 to 75 requests."
2. **Real-World Generalization**:
   > "Under offline generalization evaluation using publicly registered Agent Card data, the fixed-threshold A2A Security Monitor achieved an observed offline benign-card false-positive rate of 0.0% (0/100) and detected 400/400 controlled offline mutations generated from the evaluated real-world identities. Controlled ablation demonstrated that, for the evaluated orthogonal mutation set, homoglyph canonicalization is necessary when lexical similarity falls below the fixed threshold, resolving the earlier Stage 5 evaluation confound."

---

## 7. Known Experimental Limitations

1. **Cooperative Context Propagation**: CO loop detection relies on preserved context headers (`x-context-id`, `x-delegation-chain`). In stateless gateways without orchestrator-level session tracing, header stripping evades inline tracking.
2. **Workload Proportion Sensitivity**: Availability preservation margins depend on the ratio of read-only to mutating requests and recovery patterns of burst callers.
3. **Local Loopback Latencies**: Measurements reflect Windows local loopback sockets; containerized cross-network latency validation is deferred due to host Docker unavailability.
4. **Offline Discovery Metadata Boundary**: Evaluated records are limited to public discovery documents; runtime headers and application payloads could not be probed under the read-only safety policy.
5. **Threshold-Collision Pressure in Registry Naming**: Real-world registry naming exhibits proximity up to 0.8475 (0.0025 below the 0.85 threshold), providing evidence that scalar lexical matching approaches a sensitivity boundary as registries grow.
