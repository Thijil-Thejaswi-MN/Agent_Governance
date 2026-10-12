# AS Detector Component Ablation Study

## Overview
Empirical evaluation measuring the detection contribution of each AS detector mechanism:
1. **FULL_DETECTOR**: Homoglyph mapping + Gestalt SequenceMatcher similarity (>= 0.85) + Provenance origin check.
2. **NO_HOMOGLYPH**: Disables Cyrillic/Greek homoglyph canonicalization.
3. **NO_SIMILARITY**: Disables SequenceMatcher lexical typosquatting ratio.
4. **NO_PROVENANCE**: Disables authority endpoint conflict validation.

## Key Datasets
- `as_ablation_summary.json`: Confusion matrices, recall, precision, F1, FPR, and Wilson 95% CIs.
- `as_ablation_trials.jsonl`: Complete trial-level execution records.
