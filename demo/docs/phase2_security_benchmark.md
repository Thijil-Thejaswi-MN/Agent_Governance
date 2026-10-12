# Phase 2: A2ASecBench Setup & Offline Agent Squatting (AS) Benchmark

This document records the installation, execution, reproduction steps, and security analysis for **Phase 2** of the A2A Security Research project.

---

## 1. Overview & Objectives

- **Framework**: [A2ASecBench](https://github.com/SaFo-Lab/A2ASecBench) (commit `673f40d`)
- **Evaluation Mode**: Offline benchmark (`configs/offline/as.yaml`)
- **Evaluated Vulnerability**: **Agent Squatting (AS)** (analogous to Typosquatting/Combosquatting in package managers, but targeting agent discovery and routing)
- **System Under Test (SUT)**: Heuristic Agent Selector (`sut.as.heuristic_selector`), utilizing keyword-overlap ranking against candidate Agent Cards.
- **Environment Isolation**: Dedicated virtual environment at `demo/external/A2ASecBench/.venv` (Python 3.12).
- **Target Goal**: Execute 1 trial across the offline benchmark suite without external network calls or Docker dependencies, capture raw telemetry, and quantify Attack Success Rate (ASR).

---

## 2. Environment & Dependency Specifications

A2ASecBench was installed in an isolated environment to ensure separation from the official `a2a-samples` environment:

| Attribute | Specification |
| :--- | :--- |
| **Virtual Environment Path** | `demo/external/A2ASecBench/.venv` |
| **Python Version** | `3.12.10` (Windows x64) |
| **A2A SDK Version** | `0.3.26` (A2ASecBench requires `a2a-sdk[http-server]>=0.3.26,<1.0.0`) |
| **Key Dependencies** | `pyyaml`, `requests`, `starlette<0.49.0`, `sse-starlette<3.0`, `pydantic` |
| **Isolation Status** | Fully decoupled from `demo/external/a2a-samples/samples/python/agents/helloworld/.venv` (`a2a-sdk==1.1.0`) |

---

## 3. How to Reproduce

Execute the following commands from the repository root (`c:\Users\thiji\OneDrive\Documents\Projects\A2A`):

### Step 3.1: Activate Environment & Verify
```powershell
cd demo\external\A2ASecBench
.\.venv\Scripts\python.exe -c "import attacks, sut, utils, yaml; print('Environment OK')"
```

### Step 3.2: Run the Offline AS Benchmark
```powershell
.\.venv\Scripts\python.exe orchestration.py --config configs/offline/as.yaml --trials 1
```

The benchmark processes 100 test cases (`as_001` through `as_100`) against the heuristic selector.

### Step 3.3: Output Verification
- Benchmark summary: `demo/external/A2ASecBench/results/summary.json`
- Benchmark trial stream: `demo/external/A2ASecBench/results/run_<timestamp>.jsonl`
- Preserved artifacts:
  - `demo/data/results/phase2_a2asecbench_summary.json`
  - `demo/data/results/phase2_a2asecbench_as_offline.jsonl`
  - `demo/data/results/phase2_a2asecbench_as_offline.json`

---

## 4. Benchmark Results Summary

| Metric | Measured Value |
| :--- | :--- |
| **Total Test Cases** | 100 |
| **Total Trials** | 100 (1 per case) |
| **Successful Attacks** | **89** |
| **Failed Attacks** | 11 |
| **Attack Success Rate (ASR)** | **89.0%** (`0.89`) |
| **Execution Duration** | 0.67 seconds |
| **Failed Cases** | `as_008`, `as_025`, `as_029`, `as_043`, `as_045`, `as_051`, `as_053`, `as_055`, `as_072`, `as_084`, `as_098` |

---

## 5. Security Analysis & Implications for A2A

### What is Agent Squatting (AS)?
Agent Squatting is an adversarial discovery-phase attack. An adversary creates and registers an Agent Card that impersonates or closely mimics a benign agent. By copying domain-specific skill descriptions, tags, and semantic keywords, the squatted agent tricks client selection algorithms into routing confidential user tasks to the malicious agent rather than the intended legitimate service.

### Vulnerability of the System Under Test (SUT)
The offline benchmark evaluates a **Keyword-Overlap Heuristic Selector**:
1. When a client submits an intent (e.g. "Calculate federal tax liability"), candidate Agent Cards are scored by token overlap.
2. The squatted agent packs its `skills[].description` and `skills[].tags` with overlapping target terms.
3. In 89 out of 100 evaluated scenarios, the heuristic selector selected the squatted rogue agent (`selected_choice != benign_choice`).

### Real-World Implications for the A2A Ecosystem
1. **Unverified Agent Cards**: A2A's core discovery relies on `.well-known/agent-card.json`. Without strong registry-level provenance, any agent can publish an Agent Card claiming arbitrary capabilities.
2. **Autonomous Routing Blindspots**: LLM-based and heuristic-based orchestrators that dynamically select sub-agents are susceptible to prompt injection via metadata and keyword stuffing.
3. **Mitigation Requirements**:
   - Cryptographic signing of Agent Cards (DID / PKI verification).
   - Registry-enforced unique namespaces and verified publisher badges.
   - Capability attestation and behavioral sandboxing prior to task delegation.
