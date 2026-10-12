from __future__ import annotations

import unicodedata
from difflib import SequenceMatcher
from typing import Sequence
from ..core.models import NormalizedAgentCard, SecurityViolation

# Common Cyrillic and Greek homoglyphs mapped to ASCII equivalents
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K',
    '\u041c': 'M', '\u041d': 'H', '\u041e': 'O', '\u0420': 'P',
    '\u0421': 'C', '\u0422': 'T', '\u0425': 'X',
}


def _skeleton_name(name: str) -> str:
    """Produce a canonical ASCII skeleton of a name by mapping confusable glyphs."""
    decomposed = unicodedata.normalize('NFKD', name)
    chars = []
    for ch in decomposed:
        mapped = HOMOGLYPH_MAP.get(ch, ch)
        chars.append(mapped)
    return ''.join(chars).strip().lower()


def _string_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower().strip(), b.lower().strip()).ratio()


def detect_spoofing(
    candidate: NormalizedAgentCard,
    trusted_inventory: Sequence[NormalizedAgentCard],
    similarity_threshold: float = 0.85,
    enable_homoglyph: bool = True,
    enable_provenance: bool = True,
    enable_similarity: bool = True,
) -> SecurityViolation | None:
    """
    Evaluate candidate Agent Card against trusted inventory.
    Returns SecurityViolation if a homoglyph, provenance conflict, or typosquatting is detected.
    Ablation parameters allow empirical evaluation of individual component contributions.
    """
    cand_name = candidate.name.strip()
    cand_bytes = cand_name.encode('utf-8')
    cand_skeleton = _skeleton_name(cand_name)
    cand_endpoint = candidate.endpoint_url.strip().rstrip('/')

    for trusted in trusted_inventory:
        trusted_name = trusted.name.strip()
        trusted_bytes = trusted_name.encode('utf-8')
        trusted_skeleton = _skeleton_name(trusted_name)
        trusted_endpoint = trusted.endpoint_url.strip().rstrip('/')

        # 1. Direct Homoglyph Check
        # Skeletons match visually/phonetically, but raw byte sequences differ
        if enable_homoglyph and cand_skeleton == trusted_skeleton and cand_bytes != trusted_bytes:
            return SecurityViolation(
                violation_code="AS_HOMOGLYPH_SPOOF",
                description="Visual homoglyph impersonating trusted agent name with non-identical Unicode codepoints.",
                candidate_name=cand_name,
                candidate_endpoint=cand_endpoint,
                colliding_trusted_name=trusted_name,
                colliding_trusted_endpoint=trusted_endpoint,
                details={
                    "detection_type": "homoglyph",
                    "candidate_bytes_hex": cand_bytes.hex(),
                    "trusted_bytes_hex": trusted_bytes.hex(),
                },
            )

        # 2. Identical Name on Conflicting Endpoint (Provenance Conflict)
        if enable_provenance and cand_name.lower() == trusted_name.lower() and cand_endpoint != trusted_endpoint:
            return SecurityViolation(
                violation_code="AS_PROVENANCE_CONFLICT",
                description="Duplicate identity claimed by unauthorized network endpoint.",
                candidate_name=cand_name,
                candidate_endpoint=cand_endpoint,
                colliding_trusted_name=trusted_name,
                colliding_trusted_endpoint=trusted_endpoint,
                details={
                    "detection_type": "provenance_conflict",
                    "trusted_endpoint": trusted_endpoint,
                    "candidate_endpoint": cand_endpoint,
                },
            )

        # 3. High Lexical Similarity with Different Endpoint (Typosquatting)
        if enable_similarity:
            sim = _string_similarity(cand_name, trusted_name)
            if sim >= similarity_threshold and cand_endpoint != trusted_endpoint and cand_name.lower() != trusted_name.lower():
                return SecurityViolation(
                    violation_code="AS_TYPOSQUATTING_CLONE",
                    description=f"Typosquatted identity with {sim:.2f} similarity score against trusted agent.",
                    candidate_name=cand_name,
                    candidate_endpoint=cand_endpoint,
                    colliding_trusted_name=trusted_name,
                    colliding_trusted_endpoint=trusted_endpoint,
                    details={
                        "detection_type": "typosquatting",
                        "similarity_score": round(sim, 4),
                    },
                )

    return None
