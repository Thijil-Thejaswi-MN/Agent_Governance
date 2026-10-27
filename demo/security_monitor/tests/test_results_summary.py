"""Test for results summary recomputation (Phase 1).

Verifies that scripts/build_results_summary.py produces the exact
governance benchmark values required for the console rebuild.
"""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from scripts.build_results_summary import compute_results_summary


def test_results_summary_exact_values():
    summary = compute_results_summary()

    # 1. Harm (qwen, injected): A 14/32; B, C, D 0/32
    harm = summary["harm_injected"]
    assert harm["A"]["ratio"] == "14/32", f"Harm A expected 14/32, got {harm['A']['ratio']}"
    assert harm["B"]["ratio"] == "0/32", f"Harm B expected 0/32, got {harm['B']['ratio']}"
    assert harm["C"]["ratio"] == "0/32", f"Harm C expected 0/32, got {harm['C']['ratio']}"
    assert harm["D"]["ratio"] == "0/32", f"Harm D expected 0/32, got {harm['D']['ratio']}"

    # 2. Shell-only decoy exposure: B 8/128, C 0/128
    shell_decoy = summary["shell_only_decoy_exposure"]
    assert shell_decoy["B"]["ratio"] == "8/128", f"Shell decoy B expected 8/128, got {shell_decoy['B']['ratio']}"
    assert shell_decoy["C"]["ratio"] == "0/128", f"Shell decoy C expected 0/128, got {shell_decoy['C']['ratio']}"

    # 3. Shell attacks succeeded: B 8 of 8, C 0 of 10
    shell_attacks = summary["shell_attacks_succeeded"]
    assert shell_attacks["B"]["ratio"] == "8 of 8", f"Shell attacks B expected 8 of 8, got {shell_attacks['B']['ratio']}"
    assert shell_attacks["C"]["ratio"] == "0 of 10", f"Shell attacks C expected 0 of 10, got {shell_attacks['C']['ratio']}"

    # 4. Utility, anticipated correct: A 31/32, C 31/32
    utility = summary["utility_anticipated_correct"]
    assert utility["A"]["ratio"] == "31/32", f"Utility A expected 31/32, got {utility['A']['ratio']}"
    assert utility["C"]["ratio"] == "31/32", f"Utility C expected 31/32, got {utility['C']['ratio']}"

    # 5. Expansion chain (unanticipated, C): 32 / 32 / 32 / 31
    chain = summary["expansion_chain_unanticipated_c"]
    assert chain["chain"] == [32, 32, 32, 31], f"Expansion chain expected [32, 32, 32, 31], got {chain['chain']}"
    assert chain["chain_str"] == "32 / 32 / 32 / 31", f"Chain string mismatch: {chain['chain_str']}"

    # Ensure evaluation label is properly formatted
    assert summary["evaluation_label"] == "controlled evaluation, local 7–8B models"
