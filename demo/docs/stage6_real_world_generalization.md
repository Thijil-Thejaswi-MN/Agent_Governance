# Stage 6 — Real-World Agent Card Generalization Validation

## 1. Motivation & Research Objective

Prior evaluation stages (Stages 1 through 5) demonstrated high containment ($100.0\%$) and graduated availability preservation ($70.0\%$ vs $40.0\%$) within a controlled synthetic evaluation testbed. However, evaluating security controls solely against synthetic vectors introduces a prominent **threat to validity: synthetic scenario-construction bias**. If agent card structures, namespace conventions, and metadata fields in real-world deployments differ substantially from synthetic test fixtures, an admission-control detector risks either:
1. **Elevated False-Positive Rates**: Flagging legitimate third-party agents due to benign lexical proximity or unmodeled metadata variations.
2. **Brittle Attack Containment**: Failing to detect attacks when applied against diverse, real-world agent naming distributions.

### Research Objective
This study evaluates whether the A2A Security Monitor's AgentCard admission-control detector (`AS`) generalizes safely to publicly registered A2A Agent Cards under an offline evaluation design, measuring:
- **Observed offline benign-card false-positive rate** on real registry data under fixed production thresholds.
- **Controlled Real-World Mutation Detection**, evaluating whether 400 controlled mutations generated from real-world identities are detected offline.
- **Orthogonal Homoglyph Component Ablation**, resolving the Stage 5 evaluation confound to empirically assess isolated component contributions when lexical similarity falls below the fixed threshold.

---

## 2. Data Sources & Offline-Only Safety Boundary

### Data Provenance & Corpus Partitioning
Evaluations were performed across two static registry repositories stored under `demo/data/registry/` and `demo/external/`:
1. **Live Registry Snapshot Corpus** (`real_agents_2026-10-05.json` / `normalized_agents.json`):
   - 100 complete Agent Card records collected via read-only GET request to the public A2A Registry REST API (`https://a2aregistry.org/api/agents?limit=100`) on October 5, 2026.
   - Preserved in offline JSON repository with full provenance metadata (`collection_metadata.json`).
2. **Static Registry Corpus** (`demo/external/a2a-registry-dhyabi2/agents/*.json`):
   - 103 static pre-1.0 Agent Card JSON files providing legacy format vectors.

### Explicit Corpus Partitioning
> **Corpus Partitioning Specification**:
> - **Combined corpus size = 203 cards.**
> - The **benign offline admission FPR evaluation** was conducted on the **100-card live-registry snapshot**.
> - The **103-card static registry corpus** was used for **schema/normalization/parser regression and corpus analysis**.
> - The benign admission false-positive rate is reported strictly over the 100 live snapshot cards (denominator = 100), as the static corpus cards were utilized for parsing invariance rather than the live gateway admission trial set.

### Strict Operational Safety Boundary
> [!IMPORTANT]
> **Strict Read-Only & Offline Execution Guarantee**:
> - All registry data were treated strictly as **read-only offline metadata**.
> - **Zero remote agent endpoints were called or probed.**
> - **Zero A2A tasks or `message/send` requests were dispatched** to any third-party infrastructure.
> - Exactly zero network packets exited the host environment during this evaluation.
> - All evaluations represent **offline generalization evaluation using publicly registered Agent Card data**.

---

## 3. Real-Card Baseline Analysis & Corpus Quality

A corpus-quality analysis was performed across all $N=203$ available real-world agent cards ($N=100$ live registry snapshot cards + $N=103$ static registry cards).

### Corpus Characteristics Summary

| Characteristic | Live Registry Snapshot ($N=100$) | Static Registry Corpus ($N=103$) | Combined Inventory ($N=203$) |
| :--- | :---: | :---: | :---: |
| **Total Cards Evaluated** | 100 | 103 | **203** |
| **Schema Normalization Success** | 100 (100.0%) | 103 (100.0%) | **203 (100.0%)** |
| **Normalization Failures** | 0 (0.0%) | 0 (0.0%) | **0 (0.0%)** |
| **Valid Syntactic Endpoints** | 100 (100.0%) | 103 (100.0%) | **203 (100.0%)** |
| **Duplicate Agent Names** | 0 (0.0%) | 0 (0.0%) | **0 (0.0%)** |
| **HTTPS Transport** | 97 (97.0%) | 103 (100.0%) | **200 (98.5%)** |
| **HTTP Transport (Unencrypted)** | 3 (3.0%) | 0 (0.0%) | **3 (1.5%)** |
| **Declared Security Metadata Present** | 14 (14.0%) | 0 (0.0%) | **14 (6.9%)** |
| **Declared Security Metadata Empty/Omitted** | 86 (86.0%) | 103 (100.0%) | **189 (93.1%)** |

### Protocol Version Heterogeneity
Public registry records exhibit notable protocol version variance:
- **`0.3.0`**: 153 cards (75.4% combined; 50% in live snapshot, 100% in static corpus)
- **`1.0`**: 47 cards (23.2% combined; 47% in live snapshot)
- **`0.3`**: 2 cards (1.0% combined)
- **`1`**: 1 card (0.5% combined)

### Standardized Reporting Note on Security Metadata
> [!NOTE]
> **Reporting Standard on "Declared Security Metadata"**:
> Exactly 86.0% of the live snapshot cards and 100% of static cards contained empty or omitted `securitySchemes` metadata. This metric represents **declared security metadata** within public discovery documents. It must **NOT** be interpreted as proof of unauthenticated deployment in production; underlying agent services frequently enforce authentication (e.g. mTLS, OAuth2, API gateway keys) at outer reverse proxy perimeters without publishing credentials schemas in discovery records.

---

## 4. Benign Real-Card False-Positive Evaluation

### Evaluation Setup
- **Candidate Set**: All $N=100$ distinct real-world cards from the public registry snapshot.
- **Trusted Perimeter Baseline**: Official sample agents `HelloWorld` (`"Hello World Agent"`, port 9999) and `AgentAlice` (`"AgentAlice"`, port 8001).
- **Detector Configuration**: Production detector (`detect_spoofing`) with strictly fixed thresholds:
  - Lexical similarity threshold: `0.85`
  - Homoglyph canonicalization: Enabled (`NFKD` + confusable mapping)
  - Authority provenance validation: Enabled
- **Metric Definition**:
  $$\text{Observed offline benign-card false-positive rate} = \frac{\text{number of legitimate real-card records flagged}}{\text{number of valid legitimate real-card records evaluated}}$$
  *Denominator explicitly defined as the 100 live snapshot cards.*

### Empirical False-Positive Results
- **Legitimate Cards Evaluated**: 100
- **Flagged as Security Violations**: **0**
- **Observed offline benign-card false-positive rate**: **0.0%** (0/100, $[0.0\%, 3.7\%]$ 95% Wilson CI)
- **Admission Decision**: **100.0% ALLOW** (100/100 admitted to trusted inventory)
- **Mean Detector Evaluation Latency**: **0.103 ms** per card

### Lexical Proximity Distribution
- **Maximum Similarity Against Trusted Baseline**: **0.6364**
  - Closest pair: Candidate `"Agentropolis"` vs Trusted `"AgentAlice"` ($\text{ratio} = 0.6364$)
  - Safety margin below the 0.85 threshold: **0.2136**
- **Intra-Corpus Collision Simulation (All-Pairs 100 vs 100)**:
  - Evaluated every real-world agent card against all other 99 real-world agent cards.
  - Intra-corpus false positives flagged: **0**
  - Maximum intra-corpus similarity observed: **0.8475**
  - Closest intra-corpus pair: `"LangChain Login and Token Agent"` vs `"OpenAI Login and Token Agent"` ($\text{ratio} = 0.8475$)
  - Safety margin below the 0.85 threshold: **0.0025**
  - **Empirical Interpretation**: Evidence of threshold-collision pressure in a real-card naming corpus. While no false positives were observed on this sample, the presence of legitimate pairs within 0.0025 of the cutoff demonstrates that scalar lexical matching approaches a sensitivity boundary as registries grow.

---

## 5. Controlled Real-World Mutation Dataset

To assess whether identities derived from real-world agent cards can be reliably protected against known spoofing classes under fixed thresholds, a controlled offline mutation suite was generated across the 100 real agent cards ($N=400$ total mutation trials). Detector thresholds were **not tuned** against these mutations; the existing production configuration was held constant.

> **Methodological Scoping**:
> - Mutations are **synthetic transformations** generated from real registry names.
> - Source identities are genuine public registry records.
> - Evaluation was performed strictly offline.
> - This result demonstrates detection efficacy on the modeled mutation classes; it is **not a universal security guarantee for arbitrary real-world attacks**.

### Mutation Categories
1. **HOMOGLYPH ($N=100$)**: Replaces Latin characters with visually identical Cyrillic codepoints on rogue endpoints.
2. **TYPOSQUAT ($N=100$)**: Synthesizes single-character typosquatting clones ($\text{sim} \ge 0.85$) on rogue endpoints.
3. **PROVENANCE CONFLICT ($N=100$)**: Exact identical name claimed by an unauthorized rogue endpoint.
4. **COMBINED ATTACK ($N=100$)**: Homoglyph substitution combined with rogue endpoint delegation.

### Mutation Detection Results

| Mutation Class | Total Trials ($N$) | Detected ($k$) | Detection Rate | 95% Wilson CI | Expected Detector Component | Observed Violation Code |
| :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| **HOMOGLYPH** | 100 | 100 | **100.0%** | [96.3%, 100.0%] | Homoglyph Mapper | `AS_HOMOGLYPH_SPOOF` |
| **TYPOSQUAT** | 100 | 100 | **100.0%** | [96.3%, 100.0%] | SequenceMatcher ($\ge 0.85$) | `AS_TYPOSQUATTING_CLONE` |
| **PROVENANCE CONFLICT** | 100 | 100 | **100.0%** | [96.3%, 100.0%] | Authority Origin Validator | `AS_PROVENANCE_CONFLICT` |
| **COMBINED ATTACK** | 100 | 100 | **100.0%** | [96.3%, 100.0%] | Homoglyph Mapper | `AS_HOMOGLYPH_SPOOF` |
| **OVERALL** | **400** | **400** | **100.0%** | [99.0%, 100.0%] | — | — |

**Empirical Finding**: Under the evaluated mutation protocol, the detector identified **400/400 controlled offline mutations** generated from the evaluated real-world Agent Card identities.

---

## 6. Orthogonal Homoglyph vs Similarity Ablation Study

### Resolution of the Stage 5 Confound
In the Stage 5 ablation study, disabling homoglyph detection (`NO_HOMOGLYPH`) appeared to retain 100.0% recall on the synthetic test suite. This was an experimental confound: single-character substitutions in long names preserved high lexical similarity ($\ge 0.85$), which was masked by the similarity detector fallback.

To resolve this confound, an orthogonal ablation experiment was constructed across the real-world cards ($N=200$ total trials):

### Orthogonal Component Ablation Table ($N=200$)

| Condition | $N$ | FULL_DETECTOR | NO_HOMOGLYPH (Similarity Only) | NO_SIMILARITY (Homoglyph Only) | Expected Component Relationship | Observed Component Relationship |
| :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| **Condition A: Multi-glyph Homoglyphs ($\text{sim} < 0.85$)** | 100 | 100/100 (100.0%) | **0/100 (0.0%)** | 100/100 (100.0%) | Homoglyph mapper required when similarity fails | **Confirmed**: complete evasion (0%) without homoglyph mapper |
| **Condition B: Non-confusable Typosquats ($\text{sim} \ge 0.85$)** | 100 | 100/100 (100.0%) | 100/100 (100.0%) | **0/100 (0.0%)** | Similarity matcher required when skeleton differs | **Confirmed**: complete evasion (0%) without similarity matcher |

### Scoped Empirical Conclusions
- **Condition A (Homoglyph Necessity)**: When multi-glyph substitutions reduce raw SequenceMatcher similarity below the 0.85 threshold (observed range: $0.46 \dots 0.70$), the similarity matcher alone detects **0/100 cases**. The controlled ablation demonstrates that, for the evaluated orthogonal mutation set, homoglyph canonicalization is necessary to detect cases whose lexical similarity falls below the fixed threshold.
- **Condition B (Similarity Necessity)**: For non-confusable typosquats where the canonical skeleton differs, the homoglyph mapper alone detects **0/100 cases**. Lexical similarity matching is necessary for the evaluated non-confusable typosquat cases.
- **Boundary of Claim**: This result demonstrates component necessity **only for the controlled mutation distributions evaluated**; it does not claim that no other secondary heuristic could ever be devised.

---

## 7. Statistical Methodology Audit

### Audit of P-Values in Evaluation Artifacts
Prior to making research claims, `demo/data/evaluation/comparative/comparative_statistics.json` and all evaluation statistical scripts were audited:
- **Audit Finding**: Exactly **zero unjustified p-values** are present in `comparative_statistics.json` or Stage 6 artifacts.
- **Rationale for P-Value Removal**: Hypothesis testing p-values (e.g., paired Student's t-tests or Fisher exact tests) applied to deterministic, algorithmically generated simulation vectors often produce artificially microscopic numbers ($p < 10^{-15}$) that reflect sample size scale rather than real-world stochastic significance.
- **Adopted Statistical Rigor**:
  - Proportions are quantified strictly using **continuity-corrected 95% Wilson score confidence intervals** ($z = 1.95996$).
  - Continuous latency metrics are characterized via **full parametric and non-parametric distributions** (mean, median, standard deviation, P95, P99).
  - All comparisons report transparent empirical effect sizes (e.g., $+30.0\text{ pp}$ availability gain, $150 \to 75$ collateral disruption reduction).

---

## 8. Summary Comparison: Synthetic vs Real-World

| Metric / Property | Synthetic Baseline (Stage 4/5) | Real-Card Benign Corpus (Stage 6) | Mutated Real-Card Corpus (Stage 6) |
| :--- | :---: | :---: | :---: |
| **Card Data Origin** | Handcrafted / Testbed | Public Live Registry Snapshot | Controlled Mutations of Real Cards |
| **Total Cards / Trials** | 500 / 600 | 100 benign cards | 400 mutation trials |
| **Observed Benign FPR** | 0.0% (0/50) | **0.0%** (0/100, [0.0%, 3.7%] CI) | N/A (all adversarial) |
| **Mutation Detection Rate** | 100.0% (100/100) | N/A (all benign) | **100.0%** (400/400, [99.0%, 100.0%] CI) |
| **Max Benign Similarity** | 0.72 | 0.6364 (vs baseline), 0.8475 (intra-corpus) | N/A |
| **Mean Evaluation Latency** | 0.11 ms | 0.103 ms | 0.115 ms |
| **Homoglyph Confound Resolved** | Confounded (sim fallback) | N/A | **Resolved** ($0\%$ recall without homoglyph mapper) |

---

## 9. Threats to Validity & Generalization Boundaries

1. **Offline Discovery Metadata Boundary**: Evaluated records are limited to public discovery documents. Runtime headers, authorization handshakes, and application payloads could not be evaluated against remote agents under the read-only safety policy.
2. **Registry Sample Size ($N=100$)**: The public registry contained 516 registered agents at collection time; the evaluated sample comprises 100 cards ($19.4\%$ sample of the active registry). Broader longitudinal sampling is needed to assess long-tail namespace growth.
3. **Threshold-Collision Pressure in Growing Registries**: The intra-corpus comparison revealed two legitimate agents (`"LangChain Login and Token Agent"` and `"OpenAI Login and Token Agent"`) with similarity $0.8475$, just $0.0025$ below the $0.85$ threshold. This provides empirical evidence of threshold-collision pressure in a real-card naming corpus. As real-world agent registries expand and adopt standardized naming conventions (e.g. `"[Company] [Function] Agent"`), lexical similarity thresholds alone may experience false-positive pressure without multi-token or semantic scoping.
4. **Synthetic Mutations of Real Cards**: While the source identities are real-world cards, the attacks were generated via algorithmic transformations rather than captured from real-world adversarial adversary campaigns in the wild.

---

## 10. Research Conclusion

> **Empirical Generalization Conclusion**:
> Under offline generalization evaluation using publicly registered Agent Card data, the fixed-threshold A2A Security Monitor achieved an **observed offline benign-card false-positive rate of 0.0%** (0/100) across diverse real-world agent structures and detected **400/400 controlled offline mutations** generated from the evaluated real-world identities. Controlled ablation demonstrated that, for the evaluated orthogonal mutation set, homoglyph canonicalization is necessary when lexical similarity falls below the fixed threshold, resolving the earlier Stage 5 evaluation confound.
