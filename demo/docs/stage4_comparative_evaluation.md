# Stage 4 — Comparative Security Policy Evaluation

## 1. Research Question & Hypothesis

### Research Question
> **Does graduated response provide a better security/availability trade-off than binary blocking for A2A protocol-level threats?**

### Hypothesis Formulation
- **Null Hypothesis ($H_0$)**: There is no significant difference in legitimate request availability between a binary quarantine policy and a graduated response policy when mitigating A2A protocol-level security violations.
- **Alternative Hypothesis ($H_1$)**: A graduated enforcement policy (distinguishing resource bursts, interface variances, and spoofing/cloaking attacks) preserves significantly higher legitimate request availability than binary quarantine while maintaining identical threat containment against high-severity attacks.

---

## 2. Experimental Design & Variables

### Independent Variable
The enforcement policy regime operating inside the mediation gateway:
1. **Policy A — PERMISSIVE BASELINE**: Inherent violation detection and telemetry logging occur, but all traffic is unconditionally permitted (`ALLOW`). Threat containment is intentionally unaddressed to establish an upper bound on availability and measure attacker exposure.
2. **Policy B — BINARY QUARANTINE BASELINE**: Any detected security anomaly (low, medium, or high severity) immediately results in a `QUARANTINE` action that persists across the evaluation session. All subsequent traffic from or to the identified entity is denied (HTTP 403) unless manually unblocked by an operator through administrative controls.
3. **Policy C — PROPOSED GRADUATED RESPONSE**: Tiered policy resolution based on threat severity:
   - **LOW Severity** (e.g. rate limit bursts): `RATE_LIMIT` (HTTP 429 with `Retry-After`; entity is not quarantined).
   - **MEDIUM Severity** (e.g. unapproved mutating task on restricted entity): `RESTRICT` (mutating tasks denied HTTP 403; safe read-only inspection permitted HTTP 200).
   - **HIGH Severity** (e.g. homoglyph spoofing, undeclared capability cloaking, circular delegation): `QUARANTINE` (HTTP 403, entity isolated).

### Dependent Variables
1. **Threat Containment Rate ($C_R$)**: Proportion of adversarial attack attempts prevented from contacting the upstream agent.
2. **Attacker Upstream Exposure ($E_R$)**: Proportion of malicious requests successfully forwarded to upstream agents.
3. **Legitimate Availability Rate ($A_R$)**: Proportion of legitimate/benign requests successfully completed.
4. **Collateral Disruption Rate ($D_R$)**: Proportion of legitimate requests denied due to prior anomaly triggers.
5. **Enforcement Distribution**: Categorical count of `ALLOW`, `RATE_LIMIT`, `RESTRICT`, and `QUARANTINE` actions.
6. **Processing Latency**: Microsecond round-trip time and gateway overhead across policy regimes.

### Control Conditions
- **Deterministic Workload Pairing**: A single workload containing 600 controlled trials was generated with random seed `42` and executed identically across all three policy regimes (1,800 total trials).
- **Workload Structure**:
  - `AS` (High-severity AgentCard Spoofing): $N=100$
  - `CC` (High-severity Capability Cloaking): $N=100$
  - `CO` (High-severity Cycle Overflow): $N=100$
  - `MEDIUM_VARIANCE` (Interface variance & restricted mutations vs safe reads): $N=100$
  - `LOW_BURST` (Rate limit consumption spikes): $N=100$
  - `POST_INCIDENT_BENIGN` (Subsequent legitimate requests from entities that triggered earlier anomalies): $N=100$
- **State Isolation**: Each policy regime was evaluated against an isolated SQLite database instance with clean inventory and rate limiter states.

---

## 3. Canonical Metrics Operational Definitions

To prevent ambiguity, every reported metric is operationally defined below with explicit event definitions, mathematical formulas, numerators, and denominators:

### 3.1. Threat Containment Rate ($C_R$)
- **Operational Event Definition**: An adversarial trial $t \in T_{\text{adv}}$ is counted as *contained* if and only if the gateway policy intercepts and terminates the request inline (HTTP 403 Forbidden or registration rejected), preventing the adversarial request from contacting the target upstream agent or registering unverified credentials in the trusted inventory.
- **Numerator ($N_{\text{contained}}$)**: Count of adversarial trials where `contained == True` (request terminated at gateway; upstream agent never contacted).
- **Denominator ($N_{\text{adv}}$)**: Total adversarial attempts evaluated ($N_{\text{adv}} = 350$, comprising 100 AS, 100 CC, 100 CO, and 50 mutating variance attempts).
- **Formula**:
  $$C_R = \frac{N_{\text{contained}}}{N_{\text{adv}}} = \frac{\sum_{t \in T_{\text{adv}}} \mathbb{I}(\text{contained}(t))}{N_{\text{adv}}}$$

### 3.2. Attacker Upstream Exposure Rate ($E_R$)
- **Operational Event Definition**: An adversarial trial $t \in T_{\text{adv}}$ where the gateway does *not* intercept the attack, permitting the malicious request to reach the upstream agent socket or successfully register into trusted inventory.
- **Numerator ($N_{\text{exposed}}$)**: Count of adversarial trials where `upstream_contacted == True`.
- **Denominator ($N_{\text{adv}}$)**: Total adversarial attempts ($N_{\text{adv}} = 350$).
- **Formula**:
  $$E_R = \frac{N_{\text{exposed}}}{N_{\text{adv}}} = 1 - C_R$$

### 3.3. Legitimate Security Availability Rate ($A_R^{\text{sec}}$)
- **Operational Event Definition**: A legitimate/benign trial $t \in T_{\text{legit}}$ is counted as *security-available* if and only if the request is **not denied or throttled by the gateway security enforcement layer** (i.e. status is neither HTTP 403 Forbidden nor HTTP 429 Too Many Requests).
- **Numerator ($N_{\text{sec\_avail}}$)**: Count of legitimate trials where `status_code not in {403, 429}`.
- **Denominator ($N_{\text{legit}}$)**: Total legitimate requests evaluated ($N_{\text{legit}} = 250$, comprising 100 LOW_BURST, 50 safe inspection under MEDIUM_VARIANCE, and 100 POST_INCIDENT_BENIGN requests).
- **Formula**:
  $$A_R^{\text{sec}} = \frac{N_{\text{sec\_avail}}}{N_{\text{legit}}} = \frac{\sum_{t \in T_{\text{legit}}} \mathbb{I}(\text{status\_code}(t) \notin \{403, 429\})}{N_{\text{legit}}}$$

### 3.4. Upstream Application Success Rate ($A_R^{\text{app}}$)
- **Operational Event Definition**: A legitimate trial $t \in T_{\text{legit}}$ that receives a successful operational completion response (HTTP 200 OK) from the target upstream agent.
- **Distinction from Security Availability**: Security availability measures absence of security-induced blocking at the gateway; application success measures end-to-end task execution. On the evaluated workload, upstream agents operated without internal crashes for all permitted legitimate requests, so $A_R^{\text{app}} = A_R^{\text{sec}}$ across all policy regimes. In contrast, among uncontained adversarial requests in Permissive mode, 50 CC requests produced upstream HTTP 500 errors because the target agent (`AgentAlice`) had no handler for unadvertised RPC methods.
- **Numerator ($N_{\text{app\_success}}$)**: Count of legitimate trials where `status_code == 200`.
- **Denominator ($N_{\text{legit}}$)**: Total legitimate requests ($N_{\text{legit}} = 250$).
- **Formula**:
  $$A_R^{\text{app}} = \frac{N_{\text{app\_success}}}{N_{\text{legit}}} = \frac{\sum_{t \in T_{\text{legit}}} \mathbb{I}(\text{status\_code}(t) == 200)}{N_{\text{legit}}}$$

### 3.5. Collateral Security Disruption Rate ($D_R$)
- **Operational Event Definition**: A legitimate trial $t \in T_{\text{legit}}$ denied or throttled by the gateway security layer (HTTP 403 due to active quarantine/restriction or HTTP 429 due to rate limiting).
- **Numerator ($N_{\text{blocked\_legit}}$)**: Count of legitimate trials where `status_code in {403, 429}`.
- **Denominator ($N_{\text{legit}}$)**: Total legitimate requests ($N_{\text{legit}} = 250$).
- **Formula**:
  $$D_R = \frac{N_{\text{blocked\_legit}}}{N_{\text{legit}}} = 1 - A_R^{\text{sec}}$$

### 3.6. Wilson Score 95% Confidence Interval for Proportions
Uncertainty around all binomial proportions ($\hat{p} = k/n$) is computed via the continuity-corrected Wilson score interval:
$$\tilde{p} = \frac{\hat{p} + \frac{z^2}{2n}}{1 + \frac{z^2}{n}}, \quad \text{Margin} = \frac{z}{1 + \frac{z^2}{n}}\sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}, \quad z = 1.95996$$

---

## 4. AUTHORITATIVE POST-AUDIT RESULTS

The authoritative empirical metrics below are derived directly from the immutable trial ledger `comparative_trials.jsonl` ($N=1,800$, Seed = 42) following the resolution of the permissive-policy enforcement gate:

### Summary Ledger Metrics

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

### Comparative Benchmark Summary ($N=1,800$ Total Trials)

| Policy Regime | Total Trials | Threat Containment ($C_R$) | 95% CI (Containment) | Legitimate Security Availability ($A_R^{\text{sec}}$) | 95% CI (Availability) | Blocked Legit Requests | Mean Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Policy A (PERMISSIVE)** | 600 | **0.0%** (0/350) | [0.0%, 1.1%] | **100.0%** (250/250) | [98.5%, 100.0%] | 0 | 127.09 ms |
| **Policy B (BINARY QUARANTINE)** | 600 | **100.0%** (350/350) | [98.9%, 100.0%] | **40.0%** (100/250) | [34.1%, 46.2%] | 150 | 38.08 ms |
| **Policy C (GRADUATED RESPONSE)** | 600 | **100.0%** (350/350) | [98.9%, 100.0%] | **70.0%** (175/250) | [64.1%, 75.3%] | 75 | 57.95 ms |

### Enforcement Action Breakdown

| Policy Regime | ALLOW | RATE_LIMIT | RESTRICT | QUARANTINE | Total |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Policy A (PERMISSIVE)** | 600 | 0 | 0 | 0 | 600 |
| **Policy B (BINARY QUARANTINE)** | 100 | 0 | 0 | 500 | 600 |
| **Policy C (GRADUATED RESPONSE)** | 175 | 75 | 50 | 300 | 600 |

### Workload Group Disaggregation

| Group | Category | Class | Permissive ($A_R^{\text{sec}} / C_R$) | Binary Quarantine ($A_R^{\text{sec}} / C_R$) | Graduated Response ($A_R^{\text{sec}} / C_R$) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **AS** ($N=100$) | AgentCard Spoofing | Adversarial | $C_R = 0\%$ (0/100) | $C_R = 100\%$ (100/100) | $C_R = 100\%$ (100/100) |
| **CC** ($N=100$) | Capability Cloaking | Adversarial | $C_R = 0\%$ (0/100) | $C_R = 100\%$ (100/100) | $C_R = 100\%$ (100/100) |
| **CO** ($N=100$) | Cycle Overflow | Adversarial | $C_R = 0\%$ (0/100) | $C_R = 100\%$ (100/100) | $C_R = 100\%$ (100/100) |
| **MEDIUM_VARIANCE (Mutating)** ($N=50$) | Unapproved Mutation | Adversarial | $C_R = 0\%$ (0/50) | $C_R = 100\%$ (50/50) | $C_R = 100\%$ (50/50) |
| **MEDIUM_VARIANCE (Safe Read)** ($N=50$) | Agent Card Read | Legitimate | $A_R^{\text{sec}} = 100\%$ (50/50) | $A_R^{\text{sec}} = 100\%$ (50/50) | $A_R^{\text{sec}} = 100\%$ (50/50) |
| **LOW_BURST** ($N=100$) | Rate Limit Burst | Legitimate | $A_R^{\text{sec}} = 100\%$ (100/100) | $A_R^{\text{sec}} = 50\%$ (50/100) | $A_R^{\text{sec}} = 50\%$ (50/100) |
| **POST_INCIDENT_BENIGN** ($N=100$) | Post-Anomaly Re-entry | Legitimate | $A_R^{\text{sec}} = 100\%$ (100/100) | $A_R^{\text{sec}} = 0\%$ (0/100) | $A_R^{\text{sec}} = 75\%$ (75/100) |

---

## 5. Security vs Availability Trade-Off Analysis

> **Scoped Empirical Conclusion**: Under the evaluated workload, graduated response achieved the same observed attack containment as binary quarantine while preserving 30 percentage points more legitimate security availability and reducing security-induced collateral blocking from 150 to 75 requests.

1. **Observed Containment Under the Evaluated Scenarios**:
   - On the evaluated scenario suite ($N=350$ adversarial attempts), both **Binary Quarantine** and **Graduated Response** achieved **100.0% observed containment** ([98.9%, 100.0%] 95% Wilson CI).
   - This finding is strictly scoped to the evaluated scenario vectors; it does not claim universal protection against arbitrary unmodeled threats.
   - The Permissive baseline allowed all 350 attacker requests to contact upstream agents, confirming that inline mediation is necessary for containment.

2. **Availability Preservation on the Tested Workload**:
   - Under **Binary Quarantine**, legitimate security availability collapsed to **40.0%** (100/250, [34.1%, 46.2%] 95% Wilson CI), inflicting 150 blocked legitimate requests. Because low-severity bursts triggered indiscriminate quarantine on caller identities, 100% of subsequent post-incident inquiries from those callers were completely blocked.
   - Under **Graduated Response**, legitimate security availability reached **70.0%** (175/250, [64.1%, 75.3%] 95% Wilson CI). Bursts were throttled with HTTP 429 rather than quarantined, allowing entities to recover once the window expired, and safe inspections were permitted under restricted mode.
   - For this specific experimental workload, this represents an observed **30.0 percentage point gain in legitimate security availability** and an observed **50.0% relative reduction in collateral disruption** ($150 \to 75$ blocked requests).

3. **Latency Profile**:
   - **Permissive mean latency (127.09 ms)**: Reflects complete upstream socket forwarding to the local backend agents (`HelloWorld` and `AgentAlice`) for all 600 requests.
   - **Binary quarantine mean latency (38.08 ms)**: Reflects rapid inline 403 rejection for 500/600 requests without touching upstream sockets.
   - **Graduated response mean latency (57.95 ms)**: Balances rapid inline rejection of mutating tasks (403) with upstream forwarding of permitted safe inspections (200) and lightweight rate limiting (429).

---

## 6. Threats to Validity

1. **Workload Proportion Sensitivity**: The measured availability gain (30.0 percentage points) depends on the ratio of benign read-only operations to mutating tasks during anomalous states, and the proportion of burst callers that resume benign traffic.
2. **Synthetic State Transitions**: Entities in the benchmark were transitioned into restricted mode based on predefined anomaly flags. Real-world adaptive threshold decay will introduce additional timing variance.
3. **Local Loopback Latencies**: Absolute latencies reflect Windows local socket round-trips to the sample Python agents (`HelloWorld` and `AgentAlice`). Containerized cross-network latencies were deferred due to host Docker unavailability.
