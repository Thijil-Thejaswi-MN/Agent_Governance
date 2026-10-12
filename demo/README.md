# A2A Security Research & Evaluation Demo Suite

This repository directory contains the structured artifacts, environments, and benchmark data generated across the phased A2A security research workflow.

## Directory Structure

```text
demo/
├── data/
│   ├── agent_cards/
│   │   ├── helloworld_agent_card.json         # Phase 1 verified Agent Card (.well-known/agent-card.json)
│   │   └── agent_alice_agent_card.json        # Phase 4 second controlled Agent Card (.well-known/agent.json)
│   ├── registry/
│   │   ├── real_agents_2026-10-05.json        # Phase 3 raw 100-record public registry snapshot
│   │   ├── collection_metadata.json           # Phase 3 collection provenance and safety metadata
│   │   ├── normalized_agents.json             # Phase 3 normalized schema records
│   │   ├── registry_analysis.json             # Phase 3 machine-readable variance & security metrics
│   │   └── static_registry_analysis.json      # Phase 3 offline static registry test vectors (103 cards)
│   ├── results/
│   │   ├── phase1_baseline_helloworld.json     # Phase 1 baseline execution evidence
│   │   ├── phase2_a2asecbench_as_offline.json  # Phase 2 offline benchmark metrics & metadata
│   │   ├── phase2_a2asecbench_as_offline.jsonl # Phase 2 raw trial telemetry (100 cases)
│   │   ├── phase2_a2asecbench_summary.json     # Phase 2 A2ASecBench summary report
│   │   └── phase4_inspector_helloworld_verification.json # Phase 4 Inspector verification telemetry
│   └── testbed/
│       ├── local_agents.json                  # Phase 4 machine-readable testbed topology inventory
│       └── README.md                          # Phase 4 testbed architecture and rationale
├── docs/
│   ├── agent_card_comparison.md               # Phase 3 local vs. real-world Agent Card comparison
│   ├── phase2_security_benchmark.md            # Phase 2 setup, reproduction & security analysis
│   └── phase3_registry_analysis.md            # Phase 3 empirical registry variance analysis
└── external/
    ├── a2a-samples/                            # Official A2A Python samples repository
    │   ├── samples/python/agents/helloworld/   # Verified official HelloWorld A2A server (port 9999)
    │   └── samples/python/agents/number_guessing_game/ # Verified AgentAlice server (port 8001)
    ├── a2a-inspector/                          # Official A2A Protocol Inspector tool (port 5001)
    ├── A2ASecBench/                            # Official A2ASecBench repository
    ├── a2a-registry-prassanna/                 # Cloned registry implementation (prassanna)
    └── a2a-registry-dhyabi2/                   # Cloned static registry implementation (dhyabi2)
```

## Phase Status Summary

| Phase / Stage | Scope & Description | Status | Evidence & Artifacts |
| :--- | :--- | :---: | :--- |
| **Stage 1** | Security Completeness & Graduated Enforcement (ALLOW, RATE_LIMIT, RESTRICT, QUARANTINE) | **PASS** | [server.py](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/security_monitor/app/gateway/server.py)<br>[test_restriction.py](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/security_monitor/tests/test_restriction.py) |
| **Stage 2** | Research Evaluation Framework (500-trial benchmark, Wilson 95% CIs, isolated states) | **PASS** | [stage2_research_evaluation.md](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/docs/stage2_research_evaluation.md)<br>[evaluation_summary.json](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/evaluation/evaluation_summary.json) |
| **Stage 3** | Security Operations & Research Dashboard (Real-time SPA UI, Topology, Operator Controls) | **PASS** | [stage3_security_operations_dashboard.md](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/docs/stage3_security_operations_dashboard.md)<br>[Dashboard UI](http://127.0.0.1:8000/dashboard) |
| **Stage 4** | Comparative Security Policy Evaluation (Permissive vs Binary vs Graduated, 1,800 trials) | **PASS** | [stage4_comparative_evaluation.md](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/docs/stage4_comparative_evaluation.md)<br>[comparative_summary.json](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/evaluation/comparative/comparative_summary.json) |
| **Stage 5** | Ablation & Robustness Study (AS component ablation, CC envelope boundaries, CO depth budgets) | **PASS** | [stage5_ablation_robustness.md](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/docs/stage5_ablation_robustness.md)<br>[as_ablation_summary.json](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/evaluation/ablation/as_ablation_summary.json) |
| **Data Audit & Freeze** | Grand Empirical Corpus Freeze & Manifest (3,145 total trials: Stage 4=1800, Stage 5=645, Stage 6=700) | **FROZEN** | [RESEARCH_BASELINE.md](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/evaluation/RESEARCH_BASELINE.md)<br>[RESEARCH_CORPUS_MANIFEST.json](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/evaluation/RESEARCH_CORPUS_MANIFEST.json) |
| **Stage 6** | Real-World Agent Card Generalization Validation (203 cards, 700 trials, orthogonal ablation) | **PASS** | [stage6_real_world_generalization.md](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/docs/stage6_real_world_generalization.md)<br>[real_card_summary.json](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/evaluation/real_world/real_card_summary.json) |

## Security Operations Dashboard (Stage 3)

The A2A Security Operations & Research Dashboard provides an operational and research interface over live mediated agent communications:

### Launching the Dashboard

1. **Activate Environment & Start Gateway**:
   ```powershell
   cd demo/security_monitor
   .\.venv\Scripts\Activate.ps1
   python -m uvicorn app.gateway.server:app --host 127.0.0.1 --port 8000
   ```

2. **Access the Web Dashboard**:
   Open a browser to:
   - **URL**: [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard) (or root [http://127.0.0.1:8000/](http://127.0.0.1:8000/))

3. **Key Features**:
   - **Overview & Live Topology**: Visual node diagram mapping Client -> Gateway -> AgentAlice / HelloWorld.
   - **Agent Inventory**: Verified card catalog, active quarantine rosters, and restricted entities.
   - **Security Audit Log**: Searchable and filterable table of recorded security violations with microsecond pipeline latency breakdowns.
   - **Evaluation Findings**: Empirical 500-trial benchmark results with 95% Wilson confidence intervals.
   - **Latency & Overhead**: Disaggregated proxy forwarding vs sub-millisecond intrinsic security computation.
   - **Operator Controls**: Local administrative controls to apply/release restrictions and quarantine with confirmation modals.

