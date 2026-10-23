# Milestone 5: LLM Boundary Derivation v2 & Governed Agent Architecture (Pipeline & Plumbing Validation)

> **Important Disclosure**: The results presented in this document represent **pipeline and plumbing validation only**. No evaluations in this initial checkpoint were executed against a real LLM. Boundary derivation was validated using an internal rule-based emulator (`provider: rule_emulator`), and agent tool execution was validated using a scripted mock provider (`MockLLMProvider`). Gold boundary scenarios in `demo/data/boundary_derivation_gold.json` were AI-generated (`authored_by: AI-generated (Antigravity), pending team review`). Real model evaluations will take place with Ollama following pilot benchmarking and explicit provider approval.

---

## 1. Scope & Architectural Components

Milestone 5 implements the structural interfaces and security controls required to operate an LLM-driven tool-using agent under governed execution:
1. **LLM Boundary Derivation v2 (`F2`)**: Schema-constrained boundary derivation converting user prompts into a `TaskBoundary` contract validated against an environmental `ServiceCatalog`. Features untrusted pasted content isolation, default review-first marking, and fallback to template derivation v1.
2. **Governed Tool-Using Agent (`F13.2`)**: An agent whose tool invocation surface is strictly limited to 6 broker-governed tools (`read_file`, `write_file`, `http_get`, `call_agent`, `request_access`, and `run_command` under M4 OS enforcement).
3. **API Key Protection & Containment**: Credentials remain in the broker's environment only. The agent never sees or inherits API keys, and calls `broker.llm_complete` or a local gateway for model inference.

---

## 2. Boundary Derivation v2 (`F2`)

### 2.1 Governance Controls & Schema
- **Strict JSON Schema**: Constrained via `DerivedBoundarySchema` requiring explicit target lists for `files_read`, `files_write`, `tools`, `network`, and `peer_agents`.
- **ServiceCatalog Bounds Validation**: Every derived capability must exist in `ServiceCatalog`. Unlisted tools, peer agents, or network destinations trigger fallback.
- **Strict Wildcard Prohibition**: Wildcards (`*`, `?`, `**`) are strictly prohibited in file paths, tools, and network destinations. Any wildcard triggers fallback.
- **Deterministic Fallback**: Schema errors or catalog violations trigger fallback to template derivation (`BoundaryDerivationV1`), logging `fallback_used: True` and `fallback_reason` in audit metadata.
- **Untrusted Pasted Content Isolation**: The `PastedContentDetector` detects pasted blocks (markdown fences, delimiters, email headers), isolates them as `[UNTRUSTED_PASTED_CONTENT_BLOCK_1]`, and flags `contains_pasted_content: True` and `requires_user_review: True`.
- **Audit Metadata**: Persists `prompt_hash`, `raw_llm_output`, `provider`, `model`, `model_digest_or_tag`, `temperature`, `seed`, `is_mock`, `git_commit`, and `is_git_dirty`.

### 2.2 Derivation Pipeline Validation Metrics (Rule Emulator)
Evaluated against 30 hand-written gold scenarios (`boundary_derivation_gold.json`, marked as `authored_by: AI-generated (Antigravity), pending team review`) across $N = 3$ repeated runs using `rule_based_llm_emulator` (`boundary_derivation_results_RULE_EMULATOR.json`):

- **Overall Pipeline Metrics**:
  - Mean Precision: **76.0%**
  - Mean Recall: **74.7%**
  - Mean Over-Grant Rate: **24.0%**
  - Repeats: $N = 3$
- **Category-Level Pipeline Metrics**:
  - `tools`: Precision 79.4%, Recall 78.3%, Over-Grant Rate 20.6%
  - `files_read`: Precision 63.9%, Recall 85.0%, Over-Grant Rate 36.1%
  - `files_write`: Precision 41.7%, Recall 46.7%, Over-Grant Rate 58.3%
  - `network`: Precision 95.0%, Recall 76.7%, Over-Grant Rate 5.0%
  - `peer_agents`: Precision 100.0%, Recall 86.7%, Over-Grant Rate 0.0%

---

## 3. Tool-Using Agent (`F13.2`) & API Key Protection

### 3.1 Governed Tool Surface
The agent is restricted to a fixed tool definition schema containing **only** 6 broker-governed tools:
1. `read_file(file_path: str)`: Mediated read within authorized task directory.
2. `write_file(file_path: str, content: str)`: Mediated write within authorized task output directory.
3. `http_get(url: str)`: Mediated outbound HTTP GET validated against host:port boundary.
4. `call_agent(target_agent: str, message: dict)`: Governed peer agent message dispatch.
5. `request_access(resource_type: str, resource_target: str, justification: str)`: Runtime boundary expansion request.
6. `run_command(command: str)`: Command execution inside M4 OS enforcement sandbox (`CgroupTaskRunner` on Linux ext4).

### 3.2 API Key Protection & Containment
- **Broker-Mediated Inference**: The agent calls `broker.llm_complete(token, messages)` or a local broker gateway. The broker authenticates the task token, audits the call (`GovernanceEvent`), and invokes the model provider using broker-held credentials.
- **Process Environment Scrubbing**: `CgroupTaskRunner` explicitly scrubs sensitive credentials (`OPENAI_API_KEY`, `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, etc.) before launching tasks.
- **Verification**: `test_api_key_protection_no_key_leak_to_agent_process` verified that credentials:
  - Do NOT appear in the agent process's `os.environ`.
  - Do NOT appear in `/proc/<pid>/environ` on Linux.
  - Do NOT appear in any files written to the workspace.

---

## 4. Agent Evaluation Pipeline Validation Metrics (Scripted Mock)

The agent tool-use loop was validated against the 80 synthetic injection scenarios from `demo/data/evaluation_v2/scenarios` across $N = 3$ repeated runs (240 trials) using `MockLLMProvider` (`llm_agent_evaluation_results_SCRIPTED_MOCK.json`):

- **Trial Counts**: 240 total runs (80 scenarios $\times$ 3 repeats)
- **Scripted Injection Attempts**: 9 / 240 (3.8%)
- **Prevented by Governance Boundary / Policy**: 9 / 9 (100.0% of attempts blocked)
- **Untrusted Reads Recorded & Flagged**: 210 / 240 (87.5%)
- **Unauthorized Actions Succeeded**: 0 / 240 (0.0%)
- **Tasks Completed**: 240 / 240 (100.0%)
- **User Prompts Recorded**: 0
- **Expansion Decisions Recorded**: `DENIED: 9`, `PENDING: 0`, `APPROVED: 0`

---

## 5. Automated Regression Test Status

- **Linux WSL2 Suite (Ubuntu 24.04, Kernel 6.18, `m4_venv`)**:
  - `pytest demo/security_monitor/tests/` -> **129 passed, 0 failed**
  - M4 OS enforcement tests: **11 passed**
  - M5 LLM Agent & Derivation tests: **9 passed**
- **Windows 11 Native Suite (Python 3.12)**:
  - `python -m pytest demo/security_monitor/tests/` -> **118 passed, 11 skipped (M4 Linux-only), 0 failed**

---

## 6. Next Steps Towards Real LLM Evaluation (Checkpoint 5b)
1. Configure Ollama local endpoint (`http://localhost:11434/v1`) in `ToolBroker.llm_complete`.
2. Await user model selection (`<FILL IN after I pull them>`).
3. Execute **Pilot Run**: 5 derivation tasks $\times$ 1 run, and 5 agent scenarios $\times$ 1 run per condition (Condition A: NO governance with throwaway decoy sandbox; Condition B: full governance).
4. Report wall-clock latency per call and projected full run duration, then await user approval for the full benchmark.
