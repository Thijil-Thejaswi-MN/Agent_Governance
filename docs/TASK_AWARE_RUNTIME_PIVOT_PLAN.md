> Historical planning document (Oct 2026). Some figures and wording here (e.g. test counts, ‘tamper-evident’) are superseded; see README.md for current, verified status.

# Task-Aware Runtime Governance for AI Agents: Feasibility Analysis & Architectural Pivot Plan

**Author:** Systems Security Researcher, Linux Runtime-Monitoring Engineer & AI-Agent Infrastructure Architect  
**Status:** Feasibility Assessment & Implementation Plan  
**Target File:** `docs/TASK_AWARE_RUNTIME_PIVOT_PLAN.md`  
**Date:** 2026-10-21  

---

## Executive Summary

This document establishes the technical feasibility, architectural design, and migration roadmap for pivoting our agent security research from **pre-execution HTTP request filtering** to **task-aware operating-system runtime governance**.

### The Core Research Questions
1. **Primary Research Question:**  
   *Can an AI agent's runtime behavior be continuously evaluated against a dynamically defined task boundary, with automated intervention when it deviates?*
2. **Secondary Research Question:**  
   *Can runtime actions (system calls, file modifications, process forks, and network sockets) be reliably attributed to the correct task and agent, particularly when multiple tasks execute concurrently?*

---

## 1. Existing Architecture & Implementation Evidence

We performed an audit of the active repository (`c:\Users\thiji\OneDrive\Documents\Projects\A2A`). The repository is clean on Git branch `main` at commit `40996d5` (*"Record verified test run (70/70) and pinned dependencies"*). The test suite passes 70/70 tests.

### 1.1 What the Current System Actually Does
The existing codebase implements an **in-memory HTTP mediation gateway and admission controller** for the Agent-to-Agent (A2A) protocol built on FastAPI:

1. **AgentCard Spoofing (`AS` - `app/detection/squatting.py`):**
   - Implements an admission-time heuristic that evaluates agent metadata during registration (`/api/v1/cards/register`) or proxy routing.
   - Computes Cyrillic homoglyph collision via Unicode NFKD decomposition and a fixed 17-character substitution table (`HOMOGLYPH_MAP`).
   - Computes string similarity using Python's `difflib.SequenceMatcher.ratio` against trusted names (threshold $\ge 0.85$).
   - Flags provenance conflicts where a known agent name is claimed by an unauthorized URL endpoint.

2. **Capability Cloaking (`CC` - `app/detection/capability_cloaking.py`):**
   - Intercepts incoming HTTP POST requests sent to `/proxy/{agent_id}`.
   - Inspects the JSON-RPC `"method"` field against declared capabilities in `NormalizedAgentCard.skills` or `STANDARD_A2A_PROTOCOL_METHODS` (`message/send`, `SendMessage`, etc.).
   - A static checker (`detect_manifest_capability_cloaking`) compares card skill lists against manifest lists.

3. **Cycle Overflow (`CO` - `app/detection/cycle_overflow.py`):**
   - Maintains an in-memory dictionary `DelegationTracker` that reads HTTP headers (`x-agent-id`, `x-sender-id`) or request context to trace delegation chains.
   - Detects cycles ($A \to B \to A$) and limits call depth to a maximum budget ($D \le 5$).

4. **Policy Engine & Rate Limiter (`app/policy/`):**
   - Maps violations to `LOW` (`RATE_LIMIT`), `MEDIUM` (`RESTRICT`), or `HIGH` (`QUARANTINE`).
   - Supports three global regimes: `PERMISSIVE` (always allows), `BINARY_QUARANTINE` (always blocks), and `GRADUATED` (tiered enforcement).
   - Rate limiter uses an in-memory sliding-window token bucket (`RateLimiter`).

5. **Storage & Web Dashboard (`app/storage/db.py`, `app/dashboard/`):**
   - Persists trusted agents, quarantine records, restriction records, and audit events to an SQLite database (`demo/data/security_monitor.db`).
   - Serves a Single-Page Application (SPA) dashboard visualizing topology, events, and metrics.

### 1.2 Empirical Validity Findings & Critical Limitations
A critical inspection of the implementation reveals substantial threats to empirical validity:

* **Synthetic Upstream Fallbacks:**  
  In `app/gateway/server.py` (lines 1999–2040), if the upstream agent endpoint is offline, `dispatch_agent_task` **synthesizes fake agent responses using hardcoded regular expressions**:
  - For `helloworld`: Computes math string formulas with regex (`re.search(r"(\d+)...")`), returns canned echo responses, or returns mock ping text.
  - For `agentalice`: Simulates a number-guessing game using hardcoded secret `42`.
* **Simulated Demonstration Endpoints:**  
  In `app/gateway/server.py` (lines 2169–2450), the demo endpoint `/api/v1/demo/scenario` does not execute real agent workloads. For scenarios `normal`, `burst`, `cloaking`, `spoof`, and `cycle`, it returns **hardcoded latencies** (e.g., `detection_ms: 0.045`, `decision_ms: 0.018`, `total_ms: 1.15`) and returns `upstream_contacted: True` without making any network call or running any agent.
* **Hardcoded Research Metrics:**  
  In `app/gateway/server.py` (lines 188–196), the dashboard overview API (`/api/v1/overview`) returns static strings:
  ```json
  "research_snapshot": {
      "empirical_trials": 3145,
      "tests_passing": "60/60",
      "containment_pct": 100.0,
      "graduated_availability_pct": 70.0,
      "binary_availability_pct": 40.0,
      "availability_delta_pp": 30.0
  }
  ```
* **Purely Application-Layer HTTP Scope (Zero OS Telemetry):**  
  The current system sits strictly as an HTTP reverse proxy. If an agent executes an unauthorized local binary (`subprocess.Popen`), reads an unauthorized file (`open('/etc/passwd')`), steals credentials, or opens a direct TCP socket, **the current gateway is completely blind**. It does not monitor the host operating system, processes, or kernel events.

---

## 2. Component-by-Component Reuse and Migration Assessment

We assess every major component in the active repository against the research pivot:

| Component | Active File Path | Assessment Classification | Technical Rationale & Migration Path |
| :--- | :--- | :--- | :--- |
| **SQLite Storage Manager** | `app/storage/db.py` | **Reusable** | High-quality SQLite schema management and query abstractions. Extend schema with tables for `task_contracts`, `os_runtime_events`, `process_lineage`, and `attribution_records`. |
| **Nanosecond Telemetry Timer** | `app/telemetry/metrics.py` | **Reusable** | Monotonic nanosecond timing (`time.perf_counter_ns`) and `compute_timing` pipeline breakdowns (`t_recv`, `t_detect`, `t_decide`, `t_enforce`) provide the necessary precision for real-time OS syscall latency measurement. |
| **Statistical Framework** | `evaluation/stats.py` | **Reusable** | Rigorous statistical methods, including Wilson score confidence intervals for Bernoulli proportions and nonparametric series metrics (`mean`, `median`, `p95`), are immediately usable for empirical benchmark reporting. |
| **Policy Engine** | `app/policy/engine.py` | **Supporting / Optional** | The tiered policy mapping (`PERMISSIVE`, `BINARY_QUARANTINE`, `GRADUATED`) can be adapted from HTTP actions (`ALLOW`, `RESTRICT`, `QUARANTINE`) to OS runtime actions (`ALLOW`, `AUDIT`, `ALERT`, `BLOCK`, `KILL`). |
| **Token Rate Limiter** | `app/policy/rate_limiter.py` | **Supporting / Optional** | Useful as a rate-limiting throttle on high-frequency runtime event ingestion to prevent denial-of-service on the correlation engine. |
| **Operations Dashboard UI** | `app/dashboard/` | **Supporting / Optional** | Can be repurposed to visualize real-time task contract boundaries, process trees, and kernel events. Must be decoupled from hardcoded snapshots and fed exclusively by live telemetry. |
| **AgentCard Normalizer** | `app/cards/normalizer.py` | **Legacy (Preserve)** | Specific to A2A protocol schema normalization. Retain for backwards compatibility; not relevant to OS-level runtime governance. |
| **Squatting Detector (`AS`)** | `app/detection/squatting.py` | **Legacy (Preserve)** | Valid static analysis for admission-time naming attacks, but orthogonal to runtime task execution governance. Preserve historical research results. |
| **Capability Cloaking (`CC`)** | `app/detection/capability_cloaking.py` | **Legacy (Preserve)** | Inspects HTTP JSON-RPC method strings against advertised AgentCard skills. Retain as an application-level guard, but cannot substitute for OS file/process isolation. |
| **Cycle Overflow Guard (`CO`)** | `app/detection/cycle_overflow.py` | **Legacy (Preserve)** | Inspects HTTP delegation hops. Retain as an application-level guard. |
| **Historical Evaluation Data** | `demo/data/evaluation/` | **Legacy (Preserve)** | Frozen benchmark ledgers and JSONL trial records (Stages 1–6). Must remain untouched to guarantee scientific reproducibility of prior papers. |
| **Task Dispatcher & Mocks** | `app/gateway/server.py` (`dispatch_agent_task`, `run_controlled_demo_scenario`) | **Unsupported / Reimplement** | Regex-based response synthesis and hardcoded mock latency dictionaries must be retired. Must be replaced with an authentic task runner that launches real agent processes. |
| **In-Memory HTTP Harness** | `evaluation/runner.py`, `comparative_runner.py` | **Unsupported / Reimplement** | TestClient-only synthetic payload loops cannot evaluate operating-system behavior. Must be replaced with execution tests that monitor real OS processes, file handles, and syscalls. |

---

## 3. Proposed Target Architecture & Data Flow

```
                      ┌──────────────────────────────────────┐
                      │          Task Contract               │
                      │  - Task ID & Agent ID                │
                      │  - Allowed Input / Output Paths      │
                      │  - Allowed / Prohibited Executables  │
                      │  - Permitted Network Endpoints       │
                      │  - Enforcement Mode (BLOCK / AUDIT)  │
                      └──────────────────┬───────────────────┘
                                         │ Ingest & Validate
                                         ▼
┌───────────────────────┐      ┌────────────────────────────────────────────────────────┐
│   Agent Task Runner   │─────▶│             Task Contract Registry & Store             │
│ (Spawns Agent in      │      │       (Maintains active contracts by task_id)          │
│  dedicated cgroup /   │      └──────────────────────────┬─────────────────────────────┘
│  process namespace)   │                                 │
└──────────┬────────────┘                                 │ Task Boundary Rules
           │ Launches                                     │
           ▼                                              ▼
┌───────────────────────┐      ┌────────────────────────────────────────────────────────┐
│ Operating System      │      │                Task-Event Correlator                   │
│ Execution Environment │─────▶│ - Resolves kernel event to active Task Contract        │
│ (Agent Process Tree)  │      │ - Maps via cgroup_id, (PID, start_time), ancestry      │
└──────────┬────────────┘      │ - Explicitly tags UNATTRIBUTED or AMBIGUOUS events     │
           │ Syscalls          └──────────────────────────┬─────────────────────────────┘
           ▼                                              │ Attributed Runtime Event
┌───────────────────────┐                                 ▼
│ Linux Runtime Sensor  │      ┌────────────────────────────────────────────────────────┐
│ (eBPF / Tetragon /    │─────▶│              Task Boundary Evaluator                   │
│  Seccomp-BPF / Audit) │      │ - Evaluates event against contract boundary            │
└───────────────────────┘      │ - Outputs EXPECTED, VIOLATION, or INSUFFICIENT_DATA    │
                               └──────────────────────────┬─────────────────────────────┘
                                                          │ Decision & Evidence
                                                          ▼
                               ┌────────────────────────────────────────────────────────┐
                               │             Enforcement & Evidence Ledger              │
                               │ - Kernel Intervention: Block syscall / Terminate proc  │
                               │ - Atomic SQLite Audit: Full provenance & decision log  │
                               └────────────────────────────────────────────────────────┘
```

### Component Breakdown
1. **Task Contract Engine & Registry:**  
   Parses, validates, and registers explicit task execution specifications. Translates high-level task constraints into low-level OS invariants (path canonicalization, realpath dereferencing, inode/device bounds).
2. **Task-Scoped Execution Environment (Agent Runner):**  
   Executes agent tasks in isolated process groups or cgroups (e.g., `/sys/fs/cgroup/agent_tasks/<task_id>`). Records initial root PID, thread group ID (TGID), and monotonic start timestamp.
3. **Runtime Observation Sensor:**  
   Captures security-relevant kernel events (`openat`, `unlink`, `execve`, `connect`, `bind`). Formats raw kernel events into normalized, strongly-typed event envelopes.
4. **Task-Event Correlator:**  
   Establishes unambiguous provenance linking observed OS events to the executing task and agent. Detects fork/clone ancestry, prevents PID reuse attacks, and flags unmapped events as `UNATTRIBUTED`.
5. **Deterministic Task-Boundary Evaluator:**  
   Performs fast, deterministic evaluation of normalized events against the contract's access rules. Requires no non-deterministic LLM calls in the inline enforcement path.
6. **Enforcement & Evidence Ledger:**  
   Executes enforcement (e.g., synchronous syscall denial via seccomp/LSM BPF, or immediate `SIGKILL` termination). Writes tamper-evident execution traces and decision evidence into the SQLite database.

---

## 4. Task-Contract Example and Event Schema

### 4.1 Task Contract Schema (JSON)
The contract specifies the exact security boundary for a given task:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "contract_version": "1.0.0",
  "task_id": "task_20261021_001",
  "agent_id": "agent_document_summarizer",
  "created_at_utc": "2026-10-21T07:30:00Z",
  "expires_at_utc": "2026-10-21T07:45:00Z",
  "resources": {
    "inputs": {
      "allowed_paths": [
        "/workspace/tasks/task_001/input/report.pdf"
      ],
      "access_mode": "READ_ONLY"
    },
    "outputs": {
      "allowed_directories": [
        "/workspace/tasks/task_001/output/"
      ],
      "allowed_files": [
        "/workspace/tasks/task_001/output/summary.txt"
      ],
      "max_file_size_bytes": 10485760
    },
    "prohibited_patterns": [
      "**/credentials*",
      "**/id_rsa*",
      "**/.env",
      "/etc/**",
      "/var/run/**"
    ]
  },
  "operations": {
    "allowed_executables": [
      "/usr/bin/python3",
      "/usr/bin/pdftotext"
    ],
    "prohibited_executables": [
      "/bin/sh",
      "/bin/bash",
      "/usr/bin/curl",
      "/usr/bin/wget",
      "/bin/nc"
    ],
    "allow_subprocesses": true,
    "max_process_count": 4
  },
  "network": {
    "allow_outbound": false,
    "allowed_destinations": []
  },
  "enforcement": {
    "mode": "BLOCK",
    "on_violation": "TERMINATE_PROCESS_GROUP",
    "record_evidence": true
  }
}
```

### 4.2 Normalized Runtime Event Schema
The sensor and correlator produce normalized events structured as follows:

```json
{
  "event_id": "evt_os_998124",
  "timestamp_ns": 1792567890123456,
  "timestamp_utc": "2026-10-21T07:31:02.123456Z",
  "sensor_source": "ebpf_tetragon",
  "process": {
    "pid": 48210,
    "tgid": 48210,
    "ppid": 48190,
    "comm": "python3",
    "binary_path": "/usr/bin/python3",
    "cgroup_id": 14022394,
    "cgroup_path": "/sys/fs/cgroup/agent_tasks/task_20261021_001",
    "start_time_boot_ns": 8941230000000
  },
  "operation": {
    "type": "FILE_OPEN",
    "syscall": "openat",
    "target_path": "/workspace/tasks/task_001/credentials.txt",
    "resolved_path": "/workspace/tasks/task_001/credentials.txt",
    "flags": ["O_RDONLY", "O_CLOEXEC"],
    "is_write": false
  },
  "attribution": {
    "task_id": "task_20261021_001",
    "agent_id": "agent_document_summarizer",
    "confidence": 1.0,
    "mechanism": "CGROUP_V2",
    "is_ambiguous": false,
    "notes": "Direct match on cgroup_path hierarchy"
  },
  "evaluation": {
    "verdict": "VIOLATION",
    "rule_code": "PROHIBITED_RESOURCE_ACCESS",
    "violated_constraint": "resources.prohibited_patterns (**/credentials*)",
    "enforcement_action": "BLOCK_AND_KILL",
    "enforcement_success": true,
    "operation_prevented": true
  }
}
```

---

## 5. Runtime Sensor Options & Practical Limitations

| Sensor Mechanism | Observation Latency | Syscall Interception / Blocking | Kernel / Privilege Requirements | Platform Portability | Practical Assessment & Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Cilium Tetragon (eBPF / LSM)** | **Sub-millisecond** ($< 50\,\mu\text{s}$) | **Synchronous via BPF LSM** (`BPF_PROG_TYPE_LSM`, `sigkill`, `override_return`) | Linux Kernel $\ge 5.4$ with BTF (`CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_LSM=y`), Root / `CAP_BPF` / `CAP_SYS_ADMIN` | Linux x86_64 / arm64 only | **Recommended target for Linux production.** Rich kernel context, structured JSON event emission, minimal overhead ($< 2\%$). Requires running Tetragon daemon in target Linux environment. |
| **Linux Seccomp-BPF + User Notification (`SECCOMP_RET_USER_NOTIF`)** | **Low** ($50\text{--}150\,\mu\text{s}$) | **Synchronous Blocking & Emulation** (Blocks before syscall executes; can return `-EACCES` or `-EPERM`) | Linux Kernel $\ge 5.0$, Unprivileged user namespaces or `CAP_SYS_ADMIN` | Standard Linux | **Excellent candidate for unprivileged supervisor.** Allows user-space supervisor to intercept `openat`, inspect the target path, and fail unauthorized operations *before* data is read. Overhead on every intercepted syscall. |
| **Linux ptrace Supervisor** | **Moderate** ($100\text{--}300\,\mu\text{s}$) | **Synchronous Interception** (Can inspect arguments and cancel syscall with `PTRACE_SYSCALL`) | Standard Linux, unprivileged (subject to `ptrace_scope`) | Standard POSIX / Linux | Robust and easily testable without root privileges. Tracee process experiences measurable syscall latency overhead. Multi-threading and child cloning require careful handling (`PTRACE_O_TRACECLONE`). |
| **Linux Audit Subsystem (`auditd` / `kauditd`)** | **High** ($1\text{--}5\,\text{ms}$) | **Asynchronous / Passive Only** (Cannot block; only records post-execution audit logs) | Linux Kernel, `auditd` service, root | Standard Linux | **Insufficient for runtime intervention.** Only records evidence after the file read or socket connection has already completed. Message drops occur under high system load. |
| **Linux Tracefs / Kprobes (`/sys/kernel/tracing`)** | **Low-Moderate** ($100\,\mu\text{s}$) | **Passive Only** (Kprobes monitor entry/exit; cannot block without BPF assistance) | Root access to debugfs/tracefs | Linux kernel with `CONFIG_KPROBES=y` | Good for zero-dependency passive telemetry. Unsuitable for preventative enforcement. |
| **Mock / Emulated Sensor** | **Negligible** | **Simulated / Unit Test Only** | Cross-platform (Windows, macOS, Linux) | Any | **Required for unit test suites and developer testing.** Must be strictly segregated from real evaluation datasets. Telemetry from mock sensors must never be reported as real OS observation. |

---

## 6. Task/Agent Attribution Strategy

### 6.1 The Fallacy of Caller-Supplied Identifiers
Relying on HTTP request headers (`x-task-id`, `x-agent-id`) or OpenTelemetry trace contexts as proof of security identity is fatally flawed:
- Any rogue, compromised, or prompt-injected agent can forge or omit headers.
- If an agent spawns a background utility (`cat credentials.txt > out.txt`), that subprocess does not send HTTP headers or OpenTelemetry spans.

### 6.2 Deterministic Attribution via Linux Cgroups v2
The primary attribution mechanism is **task-scoped cgroup v2 boundaries**:
1. When the Agent Task Runner receives a task contract, it creates a unique cgroup:  
   `/sys/fs/cgroup/agent_governance/<task_id>/`
2. The agent root process is launched with its PID written into the cgroup's `cgroup.procs`.
3. **Inalienable Child Process Inheritance:** Under Linux cgroups v2, any process created via `fork()`, `clone()`, or `clone3()` **automatically and unavoidably inherits the parent's cgroup**. Even if the child calls `setsid()` to detach, double-forks, or runs an arbitrary binary via `execve()`, it cannot escape its cgroup assignment without root privileges.
4. The eBPF/Tetragon sensor extracts the cgroup ID and path directly from the kernel `task_struct`. The correlator maps the cgroup path directly to the active `task_id`.

### 6.3 Secondary Attribution via Monotonic Process Tree Tracking
For environments where cgroups v2 cannot be created (e.g., non-root user containers):
1. The supervisor tracks the process hierarchy starting from the root agent process.
2. Every process identity is tracked as a tuple:  
   $$\text{ProcessKey} = (\text{pid}, \text{start\_time\_boot\_ns})$$  
   Reading `start_time` from `/proc/[pid]/stat` guarantees that **PID reuse / PID wrapping cannot cause misattribution**. If a process dies and its PID is recycled by the OS, the monotonic `start_time` will not match the registered task session.
3. Subprocess creation is monitored via `execve` and `clone` exit hooks, dynamically updating the child tree.

### 6.4 Handling Concurrency, Ambiguity, and Delayed Telemetry
- **Concurrent Execution:** Multiple tasks executing concurrently run in distinct cgroups (`/cgroup/task_A` and `/cgroup/task_B`). Each kernel event contains the originating cgroup ID, preventing cross-task interference.
- **Explicit Ambiguity Representation:** If an event occurs where the cgroup is the root host cgroup and the PID does not match any registered task lineage, it is classified as `attribution_status = "UNATTRIBUTED"`.
- **No Silent Assignment:** The correlator is strictly forbidden from assigning ambiguous events to the "most recent" or "currently active" task. Unattributed events are logged to a dedicated audit stream for triage.

---

## 7. Minimal End-to-End Enforcement Demonstration

To validate technical feasibility before any large-scale framework is developed, Milestone 1 focuses on a single vertical slice:

### 7.1 Scenario Definition
* **Task Contract:**  
  "Read `workspace/input/report.pdf` and write `workspace/output/summary.txt`."
  - Authorized input: `workspace/input/report.pdf`
  - Authorized output: `workspace/output/summary.txt`
  - Prohibited target: `workspace/credentials.txt`
  - Enforcement mode: `BLOCK`

### 7.2 Benign Execution Path
1. The runner spawns the agent process with the task contract active.
2. The agent executes a script opening `workspace/input/report.pdf` (`O_RDONLY`).
3. The sensor captures `openat`, correlator attributes it to the task, boundary evaluator verifies it matches `resources.inputs.allowed_paths`.
4. Decision: `ALLOW`. The read succeeds.
5. The agent writes `workspace/output/summary.txt` (`O_WRONLY | O_CREAT`).
6. Boundary evaluator verifies it matches `resources.outputs.allowed_files`.
7. Decision: `ALLOW`. The write succeeds.
8. The task completes with exit code 0. Both operations are attributed with confidence 1.0.

### 7.3 Violation Execution Path
1. The runner spawns the agent process under the same contract.
2. The agent attempts to open `workspace/credentials.txt` (`O_RDONLY`).
3. The sensor intercepts the attempt *at the kernel or supervisor boundary*.
4. Correlator attributes the event to the task via cgroup/PID ancestry.
5. Boundary evaluator flags `PROHIBITED_RESOURCE_ACCESS`.
6. **Enforcement Action:**
   - *Synchronous Interception (Seccomp / LSM BPF):* The syscall is denied, returning `-EACCES` or `-EPERM`. The file descriptor is never created; no bytes are read.
   - *Immediate Reactive Termination (Tetragon / Supervisor):* If synchronous blocking is not configured, the sensor issues `SIGKILL` to the process group before the data can be written or exfiltrated.
7. An immutable evidence record is committed to SQLite documenting: `task_id`, `process_pid`, `syscall=openat`, `target=workspace/credentials.txt`, `verdict=VIOLATION`, `enforcement=BLOCKED`, `timestamp_ns`.

---

## 8. Reproducible Evaluation Plan

### 8.1 Comparison Conditions
To demonstrate scientific contribution, the evaluation compares three conditions across identical agent workloads:
1. **Condition 0 (No Governance):** Unconstrained agent execution directly on the operating system. Serves as the latency baseline and confirms the exploitability of unauthorized actions (100% violation success).
2. **Condition 1 (Static Global Baseline):** Fixed, task-independent sandbox (e.g., standard container or static path whitelist). Demonstrates failure modes when multiple concurrent tasks require distinct, dynamic boundaries (e.g., Task A should not access Task B's workspace).
3. **Condition 2 (Dynamic Task-Aware Governance):** Proposed architecture with runtime contract enforcement and task-event correlation.

### 8.2 Evaluation Workloads & Test Cases
- **Legitimate Task Activity ($N=100$):** Tasks reading authorized inputs and generating authorized outputs across variable file sizes (1 KB to 50 MB) and execution times.
- **Unauthorized File Access ($N=100$):** Tasks attempting to read sensitive host files (`/etc/shadow`, `.env`, SSH keys) or workspaces belonging to concurrent tasks.
- **Unauthorized Process Spawning ($N=50$):** Tasks attempting to spawn shells (`/bin/bash`), interactive utilities (`netcat`), or compilers.
- **Concurrent Multi-Task Interference ($N=100$ pairs):** Simultaneous execution of Task 1 (authorized for File A) and Task 2 (authorized for File B) to measure cross-task misattribution and isolation.

### 8.3 Quantitative Metrics & Mathematical Formulations
All metrics are derived from verifiable system ledgers, not simulated outcomes:

1. **Attribution Precision & Recall:**  
   $$\text{Precision} = \frac{TP_{\text{attr}}}{TP_{\text{attr}} + FP_{\text{attr}}}, \quad \text{Recall} = \frac{TP_{\text{attr}}}{TP_{\text{attr}} + FN_{\text{attr}}}$$  
   Where $TP_{\text{attr}}$ represents events correctly attributed to the responsible task.
2. **Cross-Task Misattribution Rate ($R_{\text{cross}}$):**  
   $$R_{\text{cross}} = \frac{\text{Count of events from Task } i \text{ misattributed to Task } j}{\text{Total events generated by Task } i}$$
3. **Unauthorized Action Prevention Rate ($R_{\text{prevent}}$):**  
   $$R_{\text{prevent}} = \frac{\text{Violations confirmed prevented before execution}}{\text{Total attempted unauthorized operations}}$$
4. **False Positive Rate on Legitimate Actions ($\text{FPR}$):**  
   $$\text{FPR} = \frac{\text{Legitimate actions erroneously blocked or flagged}}{\text{Total legitimate actions executed}}$$
5. **Unattributed Event Rate ($R_{\text{unattr}}$):**  
   $$R_{\text{unattr}} = \frac{\text{Observed events with status UNATTRIBUTED}}{\text{Total observed runtime events}}$$
6. **Enforcement Decision Latency ($T_{\text{decision}}$):**  
   Monotonic nanosecond time from syscall entry to enforcement signal ($t_{\text{enforce}} - t_{\text{recv}}$), reported as mean, median, and 95th percentile ($p95$).
7. **Runtime Performance Overhead:**  
   Relative slowdown in task completion time:  
   $$\text{Overhead} = \frac{T_{\text{governed}} - T_{\text{baseline}}}{T_{\text{baseline}}} \times 100\%$$

---

## 9. Environment Prerequisites & Feasibility Blockers

### 9.1 Development Environment Audit
We inspected the active execution environment:
- **Host OS:** Windows 11 (Version 10.0.26300.9711), PowerShell.
- **Windows Subsystem for Linux (WSL):** Version 3.0.3.0 installed.
- **WSL Linux Distribution:** Ubuntu (Version 26.04.1 LTS `resolute`, stopped, WSL version 2).
- **WSL Kernel Version:** `6.18.54.1-microsoft-standard-WSL2` (x86_64).
- **Kernel Configuration Audit:**
  - `CONFIG_BPF=y`
  - `CONFIG_BPF_SYSCALL=y`
  - `CONFIG_BPF_JIT=y`
  - `CONFIG_BPF_LSM=y`
  - `CONFIG_DEBUG_INFO_BTF=y`
  - `/sys/fs/bpf`, `/sys/kernel/debug`, and `/sys/kernel/tracing` are present.

### 9.2 Critical Feasibility Blockers in Current State
1. **Tooling Absence:** In the stopped Ubuntu WSL instance, `docker`, `podman`, `tetragon`, and `bpftool` are **not installed**.
2. **WSL2 Systemd & Cgroup v2 Mounts:** Standard WSL2 default boots without full systemd initialization unless `[boot] systemd=true` is configured in `/etc/wsl.conf`. Tetragon and cgroups v2 resource tracking require systemd and mounted cgroup hierarchies.
3. **Safety & Policy Guardrail:** Per user guidelines, we must not unilaterally alter system security configuration, install kernel packages, reconfigure WSL, or provision cloud resources without explicit operator direction.

### 9.3 Reproducible Prerequisites for Live Linux Evaluation
To test live eBPF/Tetragon monitoring, the following environment must be provisioned or configured:
- **Option A (WSL2 Configuration):**
  1. In Ubuntu WSL, enable systemd in `/etc/wsl.conf`:
     ```ini
     [boot]
     systemd=true
     ```
  2. Run `wsl --shutdown` from Windows and reopen Ubuntu.
  3. Install Tetragon release binary or deploy via Docker (`cilium/tetragon:latest`).
- **Option B (Dedicated Linux Host / VM):**
  - Ubuntu 24.04 LTS or Debian 12 with Kernel $\ge 5.15$, `CONFIG_DEBUG_INFO_BTF=y`, and root/sudo privileges.

### 9.4 Interim Implementation Strategy
While live Linux eBPF integration is prepared:
1. Develop the complete **Task Contract Engine**, **Event Normalization Schemas**, **Attribution Correlator**, and **Boundary Evaluator** in Python.
2. Provide a **Seccomp/Ptrace-based local Linux supervisor** for WSL that runs without external daemon dependencies.
3. Provide a strictly marked **Sensor Mock Fixture** (`mock_sensor.py`) for unit tests and local Windows IDE execution. The mock sensor will be strictly gated and forbidden from generating benchmark evaluation artifacts.

---

## 10. Phased Implementation Milestones with Acceptance Criteria

```
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 1: Contract Engine, Schemas & Storage Migration                  │
│ [Acceptance: Validated Pydantic models, SQLite migrations, 100% tests] │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 2: Process Supervisor & Task Attribution Correlator              │
│ [Acceptance: Lineage tracking, PID-reuse resistance, unattr tagging]   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 3: Deterministic Boundary Evaluator                              │
│ [Acceptance: Sub-millisecond rule evaluation, zero false positives]   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 4: Minimal End-to-End Vertical Slice (Benign + Violation)        │
│ [Acceptance: Confirmed block on unauthorized read, atomic evidence]    │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 5: Linux eBPF / Tetragon Live Sensor Integration                 │
│ [Acceptance: Real kernel syscalls captured in live Ubuntu environment]  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 6: Empirical Evaluation, Baselines & Benchmark Ledgers           │
│ [Acceptance: Wilson CIs, overhead profiling, reproducible manifests]   │
└────────────────────────────────────────────────────────────────────────┘
```

### Milestone 1: Task Contract Engine & Schemas
- **Deliverables:** `app/contract/models.py`, `app/contract/validator.py`, updated `app/storage/db.py`.
- **Measurable Acceptance Criteria:**
  - 100% JSON schema validation coverage on valid and invalid contracts.
  - Path canonicalization correctly resolves symlinks and path-traversal escapes (`../../`).
  - Unit tests verify serialization, validation errors, and SQLite persistence.

### Milestone 2: Process Supervisor & Task Attribution Correlator
- **Deliverables:** `app/runtime/supervisor.py`, `app/runtime/correlator.py`.
- **Measurable Acceptance Criteria:**
  - Able to spawn an agent subprocess and record its root PID and start timestamp.
  - Correctly captures child processes spawned via `fork()`/`execve()`.
  - Distinguishes two concurrent tasks running different commands without cross-contamination.
  - Emits explicit `UNATTRIBUTED` status for events outside registered tasks.

### Milestone 3: Deterministic Task-Boundary Evaluator
- **Deliverables:** `app/policy/evaluator.py`.
- **Measurable Acceptance Criteria:**
  - Sub-millisecond ($< 0.1\,\text{ms}$) decision evaluation on normalized events.
  - Correctly evaluates allowed inputs, allowed outputs, prohibited paths, and unauthorized binaries.
  - 0% false positives on declared benign execution plans.

### Milestone 4: Minimal End-to-End Enforcement Demonstration
- **Deliverables:** `demo/run_task_governance_demo.py`.
- **Measurable Acceptance Criteria:**
  - Benign task (`report.pdf` $\to$ `summary.txt`) executes to completion with exit code 0.
  - Violation task (`credentials.txt`) is intercepted, prevented from reading, and terminated.
  - Evidence record in SQLite verifies `operation_prevented = true` and `enforcement_action = BLOCK`.

### Milestone 5: Live Linux eBPF / Tetragon Sensor Integration
- **Deliverables:** `app/sensor/tetragon_client.py` and Linux deployment script.
- **Measurable Acceptance Criteria:**
  - In a live Linux/WSL environment with Tetragon running, kernel `openat` and `execve` events stream directly into the correlator.
  - No synthetic or mock telemetry is used in this mode.

### Milestone 6: Comparative Evaluation & Ground-Truth Benchmarking
- **Deliverables:** Benchmark runners in `evaluation/`, automated statistical reporting.
- **Measurable Acceptance Criteria:**
  - 100 trials executed across Condition 0 (unconstrained), Condition 1 (static), and Condition 2 (task-aware).
  - Wilson 95% confidence intervals computed for prevention rate and FPR.
  - Monotonic nanosecond timing distributions published with mean, median, and p95.

---

## 11. Risks, Unresolved Research Questions, and Unsupported Claims

### 11.1 Unresolved Research Questions
1. **Asynchronous Race Conditions (TOCTOU in Filesystems):**  
   If an agent creates a symlink pointing to an unauthorized file right before calling `openat`, can user-space boundary evaluators detect this without race conditions?  
   *Investigation Plan:* Use kernel-level canonical path resolution (`audit_names` or eBPF dentry lookup) and open file descriptors with `O_NOFOLLOW` / `RESOLVE_BENEATH` (Linux `openat2`).
2. **Process Granularity for In-Process Agents:**  
   If multiple agent tasks run as threads or async coroutines inside a single Python interpreter process, operating-system kernel events cannot differentiate them because they share the same PID and cgroup.  
   *Research Boundary:* For OS-level governance, each task must execute in its own process or container boundary. In-process multi-tenant tasks are explicitly out of scope for OS-level runtime enforcement.

### 11.2 Critical Technical Risks
- **Syscall Interception Overhead:** Synchronous syscall interception (`ptrace` or `SECCOMP_RET_USER_NOTIF`) introduces latency on every file and network call. We must benchmark overhead against raw baseline.
- **eBPF Drop Rates under Event Storms:** High-frequency event bursts can cause BPF ring buffer dropouts. The correlator must detect buffer drops and handle `INSUFFICIENT_TELEMETRY` safely (fail-closed vs fail-open policy).

### 11.3 Claims That Must NOT Yet Be Made
To preserve scientific integrity:
- **DO NOT claim 100% universal security or detection:** Prior claims of 100% containment applied only to synthetic test fixtures. Real systems face edge cases, race conditions, and zero-day execution techniques.
- **DO NOT claim real eBPF enforcement has been verified:** Until Tetragon is executed against a live Linux kernel with BPF LSM programs loaded, we must state that eBPF integration is an architectural design target currently operating in design validation mode.
- **DO NOT present mock sensor outputs as empirical research findings:** Mock sensors are for unit testing only.
- **DO NOT claim zero-overhead governance:** Runtime interception incurs physical CPU and latency costs that must be rigorously measured and transparently reported.
