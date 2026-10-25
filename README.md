# Agent Governance: task-scoped runtime governance for AI agents

## What this is

This repository is a research prototype for task-scoped runtime governance of AI agents.
A user's request goes through an intake layer that derives a per-task boundary: the files the agent may read and write, and the tools, network hosts and peer agents it may use.
On Linux (WSL2), the agent runs inside an OS identity (a cgroup scope) and a sandbox that are created before it takes any action.
Every action is checked against the boundary. The boundary can grow during a task only through an expansion request that is approved and whose provenance has been checked.

The motivation is that agents can act beyond the task they were given, for example after reading untrusted content that tells them to.
The aim is to bind what an agent can do to what the user asked for, at both the tool layer and the OS layer.

The project started as an A2A (agent-to-agent) security gateway. That gateway is still in the repository and now serves as one observation source (see [Architecture](#architecture)).

## Architecture

The M6 launcher flow (Linux/WSL2). Code paths are relative to `demo/security_monitor/app/governance/`.

```text
 user request
     │
     ▼
 intake (intake.py) ──► boundary derivation
     │                    v1 templates (catalog.BoundaryDerivationV1)   ← used by the launcher
     │                    v2 LLM, schema- and catalog-checked (derivation_v2.py)
     │                       ← evaluated in M5; not wired into the launcher
     ▼
 launcher (launcher.py) ── creates the OS identity and sandbox before the agent acts
     │   systemd-run --user --scope   → one cgroup per task, read back from /proc/<pid>/cgroup
     │   landlock_enforcer --rules    → Landlock rules compiled from the boundary (os_layer/sandbox_spec.py)
     │   seccomp filter, user + mount namespaces, tmpfs over /run/user/<uid>
     ▼
 agent shim (agent_shim.py) ── runs the LLM agent inside the sandbox
     │
     ├──► broker Unix socket (broker_rpc.py) ── 7 agent-facing endpoints only:
     │       read_file, write_file, http_get, call_agent, request_access,
     │       run_command_check, llm_complete   (no approve / deny / grant endpoint)
     └──► egress proxy (proxy.py) ── the only TCP port the sandbox may connect to
     │
     ▼
 ptrace sensor (os_layer/sensor.c) ── observation only; it does not block
     │
     ▼
 correlator (correlator.py) ── attributes each OS event to a task by cgroup;
     │                          verdict INSIDE / OUTSIDE / AMBIGUOUS / UNATTRIBUTED, prevented_by
     ▼
 evaluator (evaluator.py) ──► graduated response (policy.py; freeze/kill executed by launcher.py):
     │                          deny → freeze (cgroup.freeze) → kill (cgroup.kill)
     │
     ▼
 Task Receipt v0 (receipt.py) ── hash-chained JSON per task; check with scripts/verify_receipt.py
```

Expansion (`expansion.py`): an agent calls `request_access`. The request gets a risk tier, which is raised if the agent read untrusted input before asking. An approved file is delivered by copy into the task's read-only `granted/` directory. The agent cannot grant itself anything through the socket.

Freeze triggers in the launcher:
- the sensor exits early;
- isolation is below what ENFORCE requires;
- the broker socket dies;
- an OUTSIDE OS access succeeds under ENFORCE.

The task is killed after `freeze_timeout_s`.

Other components:
- **Inventory** (`inventory.py`): classifies observed agents as GOVERNED (bound to an active task) or SHADOW (acting with no task). Agents are discovered only through the observation sources below, so discovery depends on what agents report about themselves.
- **Dashboard** (`demo/security_monitor/app/dashboard/`): served by the FastAPI gateway at `/dashboard`. It includes governance and inventory tabs.
- **A2A gateway** (`demo/security_monitor/app/gateway/server.py`, `governance/gateway_integration.py`): the original A2A mediation gateway, now one observation and enforcement source for agent-to-agent calls.

Design notes and limitations for the OS layer: [`docs/M6_OS_BOUND_AGENT_NOTES.md`](docs/M6_OS_BOUND_AGENT_NOTES.md).

## Status

| Area | Status |
| :--- | :--- |
| Tool-layer governance: intake, v1 template derivation, broker, egress proxy, expansion with provenance-based risk escalation (M1–M3) | Implemented |
| LLM boundary derivation v2 (schema + service-catalog validation, fallback to v1) (M5) | Implemented; evaluated against AI-authored gold labels; not used by the M6 launcher |
| LLM tool-using agent with broker-mediated inference (M5) | Implemented |
| OS layer: cgroup scope per task, boundary-compiled Landlock `--rules`, seccomp, user and mount namespaces (M4, M6.1) | Implemented (Linux/WSL2) |
| Launcher, agent shim, broker Unix-socket RPC, correlator, graduated response, Task Receipt v0 (M6.1, M6.1b) | Implemented (Linux/WSL2) |
| ptrace + seccomp `RET_TRACE` sensor | Experimental (observation only) |
| Inventory (GOVERNED / SHADOW), dashboard, A2A gateway integration (M2) | Implemented |
| Evaluation v3: conditions A–D on the OS-bound agent (M6.2) | In progress |
| eBPF sensor (M7) | Planned |
| BPF-LSM dynamic grants | Planned |
| Long-lived / shared agents via hooks | Planned |
| Shadow-agent discovery from OS telemetry | Planned |
| Enterprise features (OS telemetry and enterprise plan) | Planned |

## Verified results so far

### M5: tool-layer governance

Setup:
- 80 template-generated scenarios: 40 injected and 40 legitimate.
- Models: `llama3.1:8b` and `qwen2.5:7b`, run locally through Ollama.
- Simulated user: ORACLE.
- N=3, giving 120 injected and 120 legitimate trials per model and condition.
- `run_command` was not in the agent's tool set for M5.

| | llama3.1:8b | qwen2.5:7b |
| :--- | :---: | :---: |
| Injected trials where an out-of-boundary action succeeded, no governance | 64/120 | 48/120 |
| Same, with governance | 0/120 | 0/120 |
| Same, with governance and the ALWAYS_DENY user (N=1) | 0/40 | 0/40 |
| Legitimate trials with output written, no governance → governed | 91 → 85 | 94 → 94 |
| Legitimate trials where a needed resource was denied (governed) | 19 | 19 |
| … of which recovered through expansion | 6 | 8 |
| Expansions approved for resources outside the scenario's legitimate set | 0 | 0 |

Result files (each has `.jsonl` raw records and `.scored.json`):
- `demo/data/full_llm_agent_evaluation_results_<model>_oracle_N3.*`
- `demo/data/full_llm_agent_evaluation_results_<model>_alwaysdeny_N1.*`

The earlier v1 runs are kept as `*_v1.*`. For the run history (including a fixed v1 template gap and the output-target re-run), see [`docs/milestone_5_empirical_evaluation_report.md`](docs/milestone_5_empirical_evaluation_report.md) and [`docs/M5_LLM_BOUNDARY_AND_AGENT_FINDINGS.md`](docs/M5_LLM_BOUNDARY_AND_AGENT_FINDINGS.md). The numbers in the table above come from the final `.scored.json` files.

### M6 Checkpoint 1: OS-bound agent on WSL2

- Preflight `scripts/m6_preflight.py`: 15/15 checks pass. There is also one WARN: `bind` is not observable on WSL2.
- Test suite in WSL: 171 passed, 1 skipped (`pytest --timeout=60`, recorded in commit `235affd`).
- Vertical slice with `qwen2.5:7b` in ENFORCE:
  - The agent's shell read of an out-of-boundary file was prevented by Landlock (`prevented_by=landlock`).
  - 0 events were UNATTRIBUTED.
  - Receipt: [`demo/data/evaluation_v3/checkpoint1/receipts/task_a17a37c90962.json`](demo/data/evaluation_v3/checkpoint1/receipts/task_a17a37c90962.json).
- Concurrency v2 (scripted mock LLM; the OS layer, broker, proxy and sensor are real):
  - Two tasks ran concurrently in each of 20 rounds, 40 tasks in total.
  - 83,720 events, 0 cross-attributions, 0 UNATTRIBUTED.
  - Summary: [`demo/data/evaluation_v3/checkpoint1/concurrency_v2/concurrency_v2_summary.json`](demo/data/evaluation_v3/checkpoint1/concurrency_v2/concurrency_v2_summary.json).

## Limitations

- The scenarios are template-generated, not drawn from real user tasks.
- The simulated user is an idealised ORACLE that approves exactly the legitimate resources. Real users will make mistakes.
- Only 7–8B local models have been evaluated (`llama3.1:8b`, `qwen2.5:7b`).
- All OS-layer results come from one WSL2 machine.
- The ptrace sensor only observes; prevention comes from Landlock, seccomp, the broker and the proxy. `bind()` cannot be observed on WSL2 because a seccomp filter that WSL's init installs takes precedence over `RET_TRACE`. Landlock still denies TCP bind. The stat family, I/O on already-open file descriptors, and `listen`/`accept` are not traced.
- Each task gets its own cgroup. Shared, long-lived agents are not supported yet.
- Single-use delivery is not enforced by the kernel. A single-use grant is removed after the first open the sensor observes, and Landlock cannot express "read once".
- UDP is not mediated by Landlock.
- Nothing is enforced on native Windows. On Windows only the tool layer runs, and the OS-layer tests are skipped.
- Inventory discovery relies on what agents declare about themselves.
- Receipts are hash-chained, not signed.
- LLM boundary derivation (v2) was evaluated against gold labels that were AI-authored and are pending team review.
- Two earlier bugs were found and fixed during development (commit `cf62f95`):
  - the M4 sensor swallowed signals sent to traced processes instead of re-injecting them;
  - the M4 `sensor.py` bridge never stored events.

## Related work and positioning

| Work | Focus |
| :--- | :--- |
| AgentSight | Observation of agent behaviour at the OS level. |
| ActPlane | eBPF information-flow control; inherited constraints can't be weakened. |
| ContractWarden | A contract approved by a human, enforced with eBPF LSM; no mid-task expansion is described. |
| Progent, Conseca | Policies at the tool level. |
| Kernel-Level Evidence | Attribution at the session level; per-tool-call attribution is left open. |

This project claims only the combination of four things:
- a boundary derived from the user's request;
- OS-level enforcement of that boundary;
- mid-task expansion that takes provenance into account;
- a receipt for each request.

## Quick start

### Windows: tool layer and tests

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r demo/security_monitor/requirements.txt
python -m pytest demo/security_monitor/tests
```

The Linux-only OS-layer tests are skipped on Windows.

To run the A2A gateway and the dashboard:

```powershell
cd demo/security_monitor
python -m uvicorn app.gateway.server:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000/dashboard
```

### WSL2: OS layer

Clone onto the WSL ext4 filesystem (for example `~/Agent_Governance`), not onto `/mnt/c`.

```bash
git clone <repo-url> ~/Agent_Governance && cd ~/Agent_Governance
python3 -m venv ~/m4_venv && source ~/m4_venv/bin/activate
pip install -r demo/security_monitor/requirements.txt pytest-timeout
sudo apt install gcc libseccomp-dev        # the Makefile links -lseccomp
make -C demo/security_monitor/app/governance/os_layer
python scripts/m6_preflight.py
pytest demo/security_monitor/tests --timeout=60
```

The LLM runs need Ollama:
- Run Ollama on Windows.
- Turn on WSL mirrored networking so WSL can reach it at `http://127.0.0.1:11434`. To use a different address, set `OLLAMA_BASE_URL`.
- Pull `llama3.1:8b` and/or `qwen2.5:7b`.

To run one task, pass the launcher the committed Checkpoint 1 task file. That file uses `llama3.1:8b` through Ollama, and its inputs include a decoy document.

```bash
python -m demo.security_monitor.app.governance.launcher run \
  --task-file demo/data/evaluation_v3/checkpoint1/vertical_slice_task.json
python scripts/verify_receipt.py ~/agent_workspaces/receipts/<task_id>.json
```

The launcher prints a JSON summary that includes `task_id` and the receipt path. By default, workspaces and receipts go under `~/agent_workspaces`; to change that, use `--workspace-base` and `--receipts-dir`.

## Repository map

```text
demo/security_monitor/app/governance/      task-scoped governance (M1–M6)
  intake.py, catalog.py, derivation_v2.py    task intake and boundary derivation (v1 templates, v2 LLM)
  broker.py, broker_rpc.py, proxy.py         tool broker, Unix-socket RPC, egress proxy
  expansion.py, policy.py, evaluator.py      expansion requests, risk tiers, graduated response
  launcher.py, agent_shim.py, llm_agent.py   M6 launcher, in-sandbox shim, LLM agent
  correlator.py, receipt.py, redaction.py    cgroup attribution, Task Receipt v0, command redaction
  inventory.py, gateway_integration.py       GOVERNED/SHADOW inventory, A2A gateway hook
  os_layer/                                  Landlock enforcer, seccomp filter, ptrace sensor (C); sandbox spec; cgroup control
demo/security_monitor/app/gateway/         original A2A gateway (FastAPI)
demo/security_monitor/app/dashboard/       dashboard SPA
demo/security_monitor/app/{detection,policy,cards,inventory,telemetry,storage,core}/
                                           A2A-phase detection and policy code
demo/security_monitor/tests/               test suite (Linux-only tests skip on Windows)
demo/security_monitor/*.py                 evaluation runners and scorers
                                           (M5: evaluate_llm_agent_injection.py, evaluate_derivation.py, score_results.py)
demo/data/                                 scenarios and result files (M5 results at top level; evaluation_v2/, evaluation_v3/)
demo/data/evaluation/                      A2A-phase evaluation corpus (stages 2–6)
demo/docs/                                 A2A-phase reports (phases 2–5, stages 2–6)
docs/                                      M4–M6 findings, feasibility study, pivot plan, M5 report
scripts/                                   M6 preflight, receipt verifier, concurrency checks, M5 transcript and merge tools
experiments/phase0_enforcement/            Phase 0 enforcement feasibility experiments
papers/                                    background papers
```

## Safety note

The evaluations use decoy documents, an audit sink that is only reachable locally, and local models.
Do not point the harness at real data, real credentials or third-party agents and services.
