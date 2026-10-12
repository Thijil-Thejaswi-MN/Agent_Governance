# Agent Governance & Security Monitor (A2A)

This repository contains the research artifacts, security architecture, and evaluation suite for **Agent Governance and Defensive Monitoring in Agent-to-Agent (A2A) Multi-Agent Systems**.

---

## Repository Structure

```text
├── demo/
│   ├── security_monitor/       # Inline security gateway & mediation proxy (FastAPI)
│   │   ├── app/                # Detection engines, policy enforcement, inventory, dashboard
│   │   ├── tests/              # Full unit and integration test suite
│   │   └── evaluation/         # Benchmark runners, statistical models, ablation suites
│   ├── data/                   # Agent cards, empirical benchmark ledgers, and manifests
│   ├── docs/                   # Phased architecture, evaluation, and empirical study reports
│   └── README.md               # Detailed guide for running the demo and benchmarks
├── papers/                     # Core research papers on agent governance & execution control
├── v2.pptx                     # Architectural presentation slides
└── .gitignore                  # Git ignore rules for environments, cache, and dependencies
```

---

## Core Capabilities

- **Deterministic Squatting & Spoofing Detection**: Homoglyph mapping, edit-distance typosquatting, and provenance conflict detection.
- **Graduated Policy Enforcement**: Dynamic multi-tier policy enforcement (`ALLOW`, `RATE_LIMIT`, `RESTRICT`, `QUARANTINE`).
- **Capability Cloaking & Cycle Overflow Guards**: Detects runtime scope expansion and recursive delegation loops across multi-agent workflows.
- **Real-Time Security Operations Dashboard**: SPA UI providing topology visualization, live event streaming, and operator controls.
- **Empirical Research Corpus**: Over 3,100 verified trials evaluating permissive, binary quarantine, and graduated security policies across synthetic and real-world agent card snapshots.

---

## Quickstart

For full reproduction instructions and step-by-step documentation, see [`demo/README.md`](demo/README.md).

### 1. Set Up Environment

```bash
cd demo/security_monitor
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt  # or install fastapi uvicorn httpx pytest
```

### 2. Run Tests

```bash
pytest
```

### 3. Launch Security Gateway & Dashboard

```bash
uvicorn app.gateway.server:app --reload --port 8000
```
Navigate to `http://127.0.0.1:8000/dashboard` to access the Security Operations Dashboard.
