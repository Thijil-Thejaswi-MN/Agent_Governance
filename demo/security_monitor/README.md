# A2A Security Monitor — Prototype Architecture & First Vertical Slice

## Overview

The **A2A Security Monitor** is an inline security gateway and registration gate for Agent-to-Agent (A2A) distributed multi-agent systems. It provides defensive monitoring, deterministic identity spoofing detection, automated policy enforcement (quarantine), and high-resolution telemetry.

This implementation delivers the **First Vertical Slice** of Phase 5A:
- Candidate Agent Card ingestion & normalization.
- Deterministic Homoglyph and Provenance Squatting Detection.
- Severity mapping (`HIGH`) and Policy enforcement (`QUARANTINE`).
- Inline gateway mediation (`/proxy/{agent_id}/...`) returning HTTP 403 on quarantined identities.
- High-resolution timing instrumentation via monotonic timers (`time.perf_counter_ns()`).

---

## Directory Structure

```
demo/security_monitor/
├── .venv/                     # Dedicated virtual environment
├── app/
│   ├── cards/
│   │   └── normalizer.py      # Normalizes v1.0 and v0.3 Agent Cards
│   ├── core/
│   │   └── models.py          # Domain data models (NormalizedAgentCard, SecurityViolation, etc.)
│   ├── detection/
│   │   └── squatting.py       # Deterministic homoglyph & provenance conflict detector
│   ├── gateway/
│   │   └── server.py          # FastAPI application & mediation proxy routes
│   ├── inventory/
│   │   └── store.py           # In-memory trusted inventory & quarantine store
│   ├── policy/
│   │   └── engine.py          # PolicyEngine resolving violation -> HIGH -> QUARANTINE
│   └── telemetry/
│       └── metrics.py         # Monotonic timing calculation & EventStore
├── tests/
│   ├── test_detection.py      # 5 unit tests for normalization, homoglyph, typosquatting
│   └── test_gateway.py        # 3 integration tests for health, registration, and quarantine
├── run_demonstration.py       # Live demonstration & empirical latency benchmark
└── README.md
```

---

## Detection Rule: Homoglyph & Provenance Squatting

The detector (`app/detection/squatting.py`) executes during candidate card registration against the in-memory trusted inventory:

1. **Exact Collisions**:
   If candidate name matches trusted name, but candidate endpoint $\neq$ trusted endpoint $\to$ **`AS_PROVENANCE_CONFLICT`**.
2. **Homoglyph Detection**:
   Computes visual canonical skeleton by mapping Cyrillic, Greek, and Unicode lookalikes to ASCII equivalents (e.g. Cyrillic `\u043e` to ASCII `o`).
   If skeleton matches a trusted agent name but raw UTF-8 bytes differ, or endpoint differs $\to$ **`AS_HOMOGLYPH_SPOOF`**.
3. **Typosquatting & High Similarity**:
   Calculates Levenshtein edit distance and sequence ratio. If normalized similarity $> 0.82$ with different endpoints $\to$ **`AS_TYPOSQUAT_SPOOF`**.

---

## Policy & Enforcement Rule

- **Severity**: All active spoofing violations are classified as **`HIGH`** severity.
- **Action**: **`QUARANTINE`**.
- **Enforcement**:
  1. The candidate identity, name, and endpoint are registered in the in-memory quarantine store.
  2. The registration endpoint returns **HTTP 403 Forbidden**.
  3. All future mediated proxy requests (`/proxy/{agent_id}/...`) are intercepted and short-circuited with **HTTP 403**, preventing adversarial traffic from reaching upstream agents.

---

## Controlled Test Fixture

- **Fixture File**: `demo/data/agent_cards/spoofed_helloworld_card.json`
- **Original Identity**: `"Hello World Agent"` at `http://127.0.0.1:9999`
- **Spoofed Identity**: `"Hellо World Agent"` (contains Cyrillic Small Letter O `\u043e`) at `http://127.0.0.1:8002`
- **Detection Rationale**: Visual homoglyph visually identical to trusted HelloWorld agent, but originating from an unauthorized local port (8002) with mismatched Unicode codepoints (`d0be` vs `6f`).

---

## Experimental Latency Telemetry

Measured on Windows with `time.perf_counter_ns()` without assuming or claiming any latency targets:

- **Detection Latency**: ~0.29 ms
- **Decision Latency**: ~0.007 ms
- **Enforcement Latency**: ~0.04 ms
- **Total Pipeline Latency**: ~0.35 ms
- **Persisted Record**: `demo/data/experiments/phase5a_first_vertical_slice_experiment.json`
