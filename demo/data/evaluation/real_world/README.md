# Real-World Agent Card Generalization Dataset

## Overview & Offline Safety Boundary
This directory contains the machine-readable evaluation artifacts generated for **Stage 6 — Real-World Agent Card Generalization Validation**.

> **Strict Operational Boundary**:
> All evaluations conducted in this module operate **100% offline** on statically collected Agent Card JSON metadata from public registries (`a2aregistry.org`). Exactly **zero** outbound HTTP, RPC, or task requests were dispatched to any third-party agent endpoints. Remote infrastructure was never probed.

## Corpus Partitioning
- **Combined Corpus Size**: **203 cards**.
- **Live-Registry Snapshot (100 cards)**: Used for benign offline admission FPR evaluation and controlled mutation generation.
- **Static Registry Corpus (103 cards)**: Used for schema/normalization/parser regression and cross-version invariance analysis.

## Artifact Inventory & Trial Counts

| File | Description | Records / Trials |
| :--- | :--- | :---: |
| `real_card_baseline.json` | Corpus quality and schema analysis across public registry cards | 203 cards |
| `real_card_detector_results.jsonl` | Offline benign evaluation of real cards against production AS detector | **100** trials |
| `real_card_summary.json` | Aggregate False Positive Rate and similarity distributions | Summary |
| `real_card_mutations.jsonl` | Controlled mutations across Homoglyph, Typosquat, Provenance, and Combined | **400** trials |
| `real_card_mutations_summary.json` | Detection rates across mutation classes under fixed thresholds | Summary |
| `orthogonal_homoglyph_trials.jsonl` | Disaggregated trials isolating homoglyph mapper from similarity matcher | **200** trials |
| `orthogonal_homoglyph_summary.json` | Orthogonal ablation findings resolving Stage 5 confound | Summary |
| **Stage 6 Empirical Total** | **Sum of trial ledgers ($100 + 400 + 200$)** | **700 trials** |

## Key Findings (Publication-Safe)

1. **Observed Offline Benign-Card False-Positive Rate**:
   $$\text{Observed offline benign-card FPR} = \frac{0}{100} = 0.0\% \quad ([0.0\%, 3.7\%] \text{ 95% Wilson CI})$$
   Evaluated strictly over the 100 live-registry snapshot cards against baseline trusted agents. Max observed similarity was **0.6364** (`Agentropolis` vs `AgentAlice`), safely below the 0.85 threshold.
2. **Evidence of Threshold-Collision Pressure in Registry Naming**:
   Max intra-corpus similarity reached **0.8475** (`LangChain Login and Token Agent` vs `OpenAI Login and Token Agent`), just **0.0025** below the 0.85 threshold. While zero false positives occurred on this sample, this highlights that scalar lexical matching approaches a sensitivity limit as registries expand.
3. **Controlled Real-World Mutation Detection**:
   The detector identified **400/400 controlled offline mutations** generated from the evaluated real-world Agent Card identities under fixed production thresholds.
4. **Resolution of Homoglyph Confound**:
   When multi-glyph homoglyphs reduced raw SequenceMatcher similarity below 0.85 (observed range: $0.46 \dots 0.70$):
   - `NO_HOMOGLYPH` (similarity only): **0.0% detection** (0/100).
   - `NO_SIMILARITY` (homoglyph only): **100.0% detection** (100/100).
   - `FULL_DETECTOR`: **100.0% detection** (100/100).
   The controlled ablation demonstrates that, for the evaluated orthogonal mutation set, homoglyph canonicalization is necessary to detect cases whose lexical similarity falls below the fixed threshold.
