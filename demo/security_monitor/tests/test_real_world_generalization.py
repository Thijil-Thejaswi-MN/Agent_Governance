from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch
import pytest

from app.core.models import NormalizedAgentCard
from app.cards.normalizer import normalize_agent_card
from app.detection.squatting import detect_spoofing, _string_similarity, _skeleton_name
from evaluation.real_world_eval import (
    get_registry_dir,
    get_static_registry_dir,
    create_trusted_baseline_cards,
    REVERSE_HOMOGLYPH_MAP,
)


@pytest.fixture
def snapshot_cards():
    reg_dir = get_registry_dir()
    snap_file = reg_dir / "real_agents_2026-10-05.json"
    assert snap_file.is_file(), f"Snapshot file not found: {snap_file}"
    with open(snap_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    agents = data.get("agents", [])
    assert len(agents) == 100
    return agents


def test_real_card_schema_loading(snapshot_cards):
    """Verify loading and schema properties of the real-world registry snapshot."""
    for card in snapshot_cards:
        assert isinstance(card, dict)
        assert "name" in card
        assert "url" in card or "wellKnownURI" in card
        assert "protocolVersion" in card


def test_malformed_card_handling():
    """Verify that normalize_agent_card safely handles malformed or missing fields without throwing."""
    # Empty dictionary
    empty_norm = normalize_agent_card({})
    assert empty_norm.name == ""
    assert empty_norm.endpoint_url == ""
    assert empty_norm.protocol_version == "1.0"
    assert empty_norm.skills == []
    assert empty_norm.security_schemes == {}

    # Malformed types
    malformed = {
        "name": None,
        "url": None,
        "skills": "not-a-list",
        "securitySchemes": "not-a-dict",
        "supportedInterfaces": [{"url": None}],
    }
    norm = normalize_agent_card(malformed)
    assert norm.name == ""
    assert norm.endpoint_url == ""
    assert norm.skills == []
    assert norm.security_schemes == {}


def test_normalization(snapshot_cards):
    """Verify normalization on real-world cards produces valid NormalizedAgentCard models."""
    sample = snapshot_cards[0]
    norm = normalize_agent_card(sample)
    assert isinstance(norm, NormalizedAgentCard)
    assert len(norm.name) > 0
    assert norm.endpoint_url.startswith("http")
    assert isinstance(norm.skills, list)
    assert isinstance(norm.security_schemes, dict)


def test_detector_evaluation(snapshot_cards):
    """Verify benign real-card admission achieves zero false positives against trusted baseline."""
    trusted = create_trusted_baseline_cards()
    for raw in snapshot_cards:
        cand = normalize_agent_card(raw)
        violation = detect_spoofing(cand, trusted, similarity_threshold=0.85)
        assert violation is None, f"Legitimate real card falsely flagged: {cand.name} -> {violation}"


def test_mutation_generation(snapshot_cards):
    """Verify controlled mutations are mechanically generated and correctly flagged."""
    sample = normalize_agent_card(snapshot_cards[0])
    orig_name = sample.name

    # 1. Homoglyph mutation
    homo_chars = [REVERSE_HOMOGLYPH_MAP.get(ch, ch) for ch in orig_name]
    homo_name = "".join(homo_chars)
    if homo_name == orig_name:
        homo_name = orig_name + REVERSE_HOMOGLYPH_MAP["a"]
    homo_cand = NormalizedAgentCard(name=homo_name, endpoint_url="http://127.0.0.1:8999/rogue")
    v_homo = detect_spoofing(homo_cand, [sample], similarity_threshold=0.85)
    assert v_homo is not None
    assert v_homo.violation_code == "AS_HOMOGLYPH_SPOOF"

    # 2. Typosquat mutation
    typo_name = orig_name + "1" if _string_similarity(orig_name, orig_name + "1") >= 0.85 else orig_name + "s"
    typo_cand = NormalizedAgentCard(name=typo_name, endpoint_url="http://127.0.0.1:8999/rogue")
    v_typo = detect_spoofing(typo_cand, [sample], similarity_threshold=0.85)
    assert v_typo is not None
    assert v_typo.violation_code == "AS_TYPOSQUATTING_CLONE"

    # 3. Provenance conflict
    prov_cand = NormalizedAgentCard(name=orig_name, endpoint_url="http://127.0.0.1:8999/rogue")
    v_prov = detect_spoofing(prov_cand, [sample], similarity_threshold=0.85)
    assert v_prov is not None
    assert v_prov.violation_code == "AS_PROVENANCE_CONFLICT"


def test_no_external_network_access(snapshot_cards):
    """Verify that offline admission evaluation executes without any network socket connections."""
    trusted = create_trusted_baseline_cards()
    sample = normalize_agent_card(snapshot_cards[0])

    with patch("socket.socket.connect") as mock_connect:
        violation = detect_spoofing(sample, trusted)
        assert violation is None
        mock_connect.assert_not_called()


def test_reproducibility(snapshot_cards):
    """Verify that multiple evaluation passes yield deterministic identical results."""
    trusted = create_trusted_baseline_cards()
    sample = normalize_agent_card(snapshot_cards[0])

    res1 = detect_spoofing(sample, trusted)
    res2 = detect_spoofing(sample, trusted)
    assert res1 == res2


def test_preservation_of_frozen_stage4_5_datasets():
    """Verify that Stage 4 and Stage 5 frozen trial ledgers are strictly intact."""
    root = Path(__file__).resolve().parents[3]
    eval_dir = root / "demo" / "data" / "evaluation"

    comp_file = eval_dir / "comparative" / "comparative_trials.jsonl"
    as_file = eval_dir / "ablation" / "as_ablation_trials.jsonl"
    cc_file = eval_dir / "robustness" / "cc_robustness_trials.jsonl"
    co_file = eval_dir / "robustness" / "co_robustness_trials.jsonl"

    assert comp_file.is_file(), f"Missing {comp_file}"
    assert as_file.is_file(), f"Missing {as_file}"
    assert cc_file.is_file(), f"Missing {cc_file}"
    assert co_file.is_file(), f"Missing {co_file}"

    comp_count = len(comp_file.read_text(encoding="utf-8").strip().splitlines())
    as_count = len(as_file.read_text(encoding="utf-8").strip().splitlines())
    cc_count = len(cc_file.read_text(encoding="utf-8").strip().splitlines())
    co_count = len(co_file.read_text(encoding="utf-8").strip().splitlines())

    assert comp_count == 1800, f"Expected 1800, got {comp_count}"
    assert as_count == 600, f"Expected 600, got {as_count}"
    assert cc_count == 31, f"Expected 31, got {cc_count}"
    assert co_count == 14, f"Expected 14, got {co_count}"
    assert comp_count + as_count + cc_count + co_count == 2445


def test_preservation_of_stage6_and_manifest_dataset():
    """Verify Stage 6 trial counts, grand empirical total (3145), and manifest integrity."""
    root = Path(__file__).resolve().parents[3]
    eval_dir = root / "demo" / "data" / "evaluation"

    # Stage 6 files
    rw_dir = eval_dir / "real_world"
    det_file = rw_dir / "real_card_detector_results.jsonl"
    mut_file = rw_dir / "real_card_mutations.jsonl"
    ortho_file = rw_dir / "orthogonal_homoglyph_trials.jsonl"
    manifest_file = eval_dir / "RESEARCH_CORPUS_MANIFEST.json"

    assert det_file.is_file(), f"Missing {det_file}"
    assert mut_file.is_file(), f"Missing {mut_file}"
    assert ortho_file.is_file(), f"Missing {ortho_file}"
    assert manifest_file.is_file(), f"Missing {manifest_file}"

    det_count = len(det_file.read_text(encoding="utf-8").strip().splitlines())
    mut_count = len(mut_file.read_text(encoding="utf-8").strip().splitlines())
    ortho_count = len(ortho_file.read_text(encoding="utf-8").strip().splitlines())

    assert det_count == 100, f"Expected 100, got {det_count}"
    assert mut_count == 400, f"Expected 400, got {mut_count}"
    assert ortho_count == 200, f"Expected 200, got {ortho_count}"

    stage6_total = det_count + mut_count + ortho_count
    assert stage6_total == 700

    # Grand total: 2445 + 700 = 3145
    grand_total = 2445 + stage6_total
    assert grand_total == 3145

    # Check manifest JSON parsing
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["grand_empirical_total_trials"] == 3145
    assert manifest["status"] == "AUTHORITATIVE_RESEARCH_BASELINE_FROZEN"

