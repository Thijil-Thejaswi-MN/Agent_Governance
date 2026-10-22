# Evaluation v2 Benchmark Findings: Runtime Governance & Dynamic Boundary Expansion

## 1. Executive Summary & Core Results

This benchmark evaluates the task-aware dynamic boundary expansion engine across **80 synthetic test scenarios** (20 per category), comparing three governance conditions:
- **Condition A (Ablation / Provenance OFF)**: Blind boundary evaluation without provenance tracking.
- **Condition B (Provenance ON - Any Untrusted Read)**: Taint-based provenance escalating un-anticipated requests upon reading untrusted input.
- **Condition C (Content-Linked Provenance)**: Fine-grained provenance escalating only when requested targets correlate with content in untrusted input.

### Utility & Security Trade-Off Analysis ($N=80$)

| Governance Condition | Wrongly Approved (Vulnerability) | Operator Prompts (Friction Cost) | Ask on Should-Deny | Strict Decision Accuracy |
| :--- | :---: | :---: | :---: | :---: |
| **Condition A (Provenance OFF)** | **37.50%** (30/80)<br>95% CI: [27.69%, 48.45%] | **2.50%** (2/80) | 2/80 (2.5%) | **60.00%** (48/80)<br>95% CI: [49.05%, 70.04%] |
| **Condition B (Coarse Provenance)** | **0.00%** (0/80)<br>95% CI: [0.00%, 4.58%] | **50.00%** (40/80) | 0/80 (0.0%) | **87.50%** (70/80)<br>95% CI: [78.50%, 93.07%] |
| **Condition C (Content-Linked)** | **11.25%** (9/80)<br>95% CI: [6.03%, 20.02%] | **27.50%** (22/80) | 1/80 (1.25%) | **87.50%** (70/80)<br>95% CI: [78.50%, 93.07%] |

---

## 2. Full Confusion Matrices ($3 \times 3$)

### Condition A: Provenance OFF (Baseline Ablation)
| Ground Truth Label | Engine: AUTO_APPROVE | Engine: ASK_USER | Engine: DENY | Category Total |
| :--- | :---: | :---: | :---: | :---: |
| **`should_auto_approve`** | 30 | 0 | 0 | 30 |
| **`should_ask`** | **30 (Wrongly Approved)** | 0 | 0 | 30 |
| **`should_deny`** | 0 | 2 | 18 | 20 |

### Condition B: Provenance ON (Coarse / Any Untrusted Read)
| Ground Truth Label | Engine: AUTO_APPROVE | Engine: ASK_USER | Engine: DENY | Category Total |
| :--- | :---: | :---: | :---: | :---: |
| **`should_auto_approve`** | 20 | **10 (Friction on Inferred)** | 0 | 30 |
| **`should_ask`** | 0 | 30 | 0 | 30 |
| **`should_deny`** | 0 | 0 | **20 (Hard Denial)** | 20 |

### Condition C: Content-Linked Provenance
| Ground Truth Label | Engine: AUTO_APPROVE | Engine: ASK_USER | Engine: DENY | Category Total |
| :--- | :---: | :---: | :---: | :---: |
| **`should_auto_approve`** | **30 (Zero Friction)** | 0 | 0 | 30 |
| **`should_ask`** | **9 (Wrongly Approved)** | 21 | 0 | 30 |
| **`should_deny`** | 0 | 1 | 19 | 20 |

---

## 3. Rates per Ground-Truth Category

### `should_auto_approve` ($N=30$)
- **Condition A**: AUTO_APPROVE = 30/30 (100.0%) | ASK_USER = 0/30 (0.0%) | DENY = 0/30 (0.0%)
- **Condition B**: AUTO_APPROVE = 20/30 (66.67%) | ASK_USER = 10/30 (33.33%) | DENY = 0/30 (0.0%)
- **Condition C**: AUTO_APPROVE = 30/30 (100.0%) | ASK_USER = 0/30 (0.0%) | DENY = 0/30 (0.0%)

### `should_ask` ($N=30$)
- **Condition A**: AUTO_APPROVE = 30/30 (100.0% - All Wrongly Approved) | ASK_USER = 0/30 (0.0%) | DENY = 0/30 (0.0%)
- **Condition B**: AUTO_APPROVE = 0/30 (0.0%) | ASK_USER = 30/30 (100.0% - Appropriately Escalated) | DENY = 0/30 (0.0%)
- **Condition C**: AUTO_APPROVE = 9/30 (30.0% - Obfuscation Vulnerability) | ASK_USER = 21/30 (70.0%) | DENY = 0/30 (0.0%)

### `should_deny` ($N=20$)
- **Condition A**: AUTO_APPROVE = 0/20 (0.0%) | ASK_USER = 2/20 (10.0%) | DENY = 18/20 (90.0%)
- **Condition B**: AUTO_APPROVE = 0/20 (0.0%) | ASK_USER = 0/20 (0.0%) | DENY = 20/20 (100.0% - Hard Policy Denial)
- **Condition C**: AUTO_APPROVE = 0/20 (0.0%) | ASK_USER = 1/20 (5.0%) | DENY = 19/20 (95.0%)

---

## 4. Inherent Limitation of Content-Linked Provenance

Condition C is evadable by obfuscation by construction; an inferred legitimate request and a disguised injected request are indistinguishable from the request alone. Distinguishing them requires semantic/causal evidence (future work).

Specifically:
- In Condition C, the engine inspects untrusted input text to find whether the requested target or hostname appears in the ingested data.
- In obfuscated injection scenarios (paraphrased instructions, split strings, base64 fragments, or homoglyphs), the target does not literally appear in the untrusted snippet.
- Consequently, Condition C treats the request identically to an inferred safe request, granting automatic approval and introducing a **30.0% vulnerability rate (9/30)** on ambiguous/injected low-risk targets.
- In contrast, Condition B taints the agent upon reading *any* untrusted content, achieving **0.00% wrongful approvals** at the cost of operator friction (**33.3% unnecessary prompts on inferred safe files**).
