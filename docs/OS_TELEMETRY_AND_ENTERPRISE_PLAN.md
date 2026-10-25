# Prompt-to-OS Monitoring + Enterprise Feature Plan

**Scope.** This is the design for the main project, which follows the review phase. It answers two questions:
1. How do we monitor, from OS telemetry, what an agent does after a user prompts it, and do so safely?
2. Which features would make this valuable to enterprises and set it apart from existing products and papers?

Every external claim below was checked against the sources listed at the end. Vendor statements are their own claims; we have not tested their products.

---

## 1. The core idea: bind the prompt to the OS *before* the agent runs

Published systems take two approaches:
- **Guess after the fact.** AgentSight hooks the SSL libraries to read LLM traffic, then links syscalls to it using process lineage, a 100–500 ms time window and argument matching.
- **Fix one task per sandbox.** The Kernel-Level Evidence paper uses one Docker container plus strace per session.

Our system has an advantage neither of them uses: **the user's prompt already passes through our intake layer.** So we never need to read the prompt off the wire. Instead:

```
User prompt ─► Intake (task_id minted, boundary derived from the TRUSTED prompt only)
                 │
                 ▼
            Launcher/Binder ── creates OS identity for the task BEFORE the agent acts:
                 │              Linux: cgroup  agentgov/task_<id>  (+ Landlock + seccomp + userns)
                 │              Windows: Job Object per task (observation only, see §3)
                 ▼
            Agent runs inside that identity
                 │
   ┌─────────────┼───────────────────────────┬──────────────────────────┐
   ▼             ▼                           ▼                          ▼
 Tool broker   Egress proxy              OS sensor (eBPF; ptrace      Agent-side signals
 (per-task     (per-task token,          fallback) filtered by        (hooks, OTel GenAI spans,
  token)        exact-IP connect)        cgroup id                    MCP trace context) = ADVISORY
   └─────────────┴──────────────┬────────────┴──────────────────────────┘
                                ▼
                 Correlator: event → task_id (kernel identity is authoritative)
                                ▼
                 Evaluator INSIDE / OUTSIDE / AMBIGUOUS → graduated response
                                ▼
                 Task Receipt (per-request evidence) · Inventory · Dashboard · SIEM
```

**Why this is the safe route.**
- We never decrypt TLS and never hook SSL libraries.
- The prompt comes from our own intake.
- The sensor tags every kernel event in-kernel with the cgroup id of the process that caused it, so attribution comes from where the event happened, not from a heuristic.

## 2. Three agent shapes, and how each gets bound

| Agent shape | Example | Binding | Attribution quality |
|---|---|---|---|
| **A. Per-task process** (we launch it per prompt) | our `LLMAgent`; CLI agents in headless mode | cgroup + sandbox per task, created before exec | Exact by construction (this is what M4 built) |
| **B. Long-lived agent serving many prompts** | an IDE or CLI coding agent session, an agent server | `agentgov run -- <agent>` puts the session in a governed cgroup. Prompt start/stop hooks segment it into tasks. Tool executions go into sub-cgroups `task_<id>/call_<n>` | Exact for tool-spawned processes. The agent's **own** process is exact while one task is active and **AMBIGUOUS** when tasks overlap |
| **C. Agents we did not launch** (shadow) | anything else on the host | Not bound. Discovered from metadata only | **UNATTRIBUTED** by definition. Goes to the inventory as SHADOW |

**Concrete hook path for shape B (verified for Claude Code).**
- Claude Code supports `http` hooks, so each hook can POST to our intake.
- Hooks set in managed settings cannot be removed by users, and `allowManagedHooksOnly` blocks everyone else's hooks.
- Every hook receives `session_id`, `prompt_id` and `cwd`.
- How each event maps:
  - `UserPromptSubmit` → open a task. It can block the prompt.
  - `PreToolUse` (with `tool_name`, `tool_input`, `tool_use_id`) → ask the broker. It can deny the call.
  - `Stop` → close the task.
  - `SessionStart` → register the agent in the inventory.
- Hooks are **agent-side and advisory**. A compromised agent process could misreport, so hooks label events and can deny calls, but **only the OS layer grants or proves anything.**

## 3. Telemetry sources, per platform

| Platform | Source | Gives us | Privilege | Prevents or observes |
|---|---|---|---|---|
| Linux / WSL2 (primary) | **cgroup v2** | task identity of every process and its children; `cgroup.freeze` | delegated subtree, no root | identity + reversible pause |
| | **Landlock** (we use ABI 7) | file and TCP-port allowlist, inherited by children, scoping of abstract UNIX sockets and signals | unprivileged | **prevents** |
| | **seccomp** | blocks syscall classes (io_uring, bpf, perf_event_open, foreign ABIs) | unprivileged | **prevents** |
| | **eBPF sensor** (own small libbpf program or Tetragon) | exec / open / connect / rename / unlink with the cgroup id taken in-kernel | CAP_BPF + CAP_PERFMON, in a separate daemon | observes. Tetragon's Override can deny, but SIGKILL alone does not stop a write in progress (Tetragon docs) |
| | **ptrace sensor** (current) | the same events, with no kernel features needed | same uid | **observation only**. Our Phase 0 found a symlink-swap race (153/1000 leaks), so it must never be the enforcer |
| Windows (native) | **Job Object** per task | process grouping: children stay in the job unless breakaway is allowed | user | identity |
| | **ETW** kernel process/file/network providers, read by a user-mode consumer | process, file and network events, filtered to the job's PIDs | admin service | observes |
| | **Built-in Sysmon** (in Windows Insider preview builds from Feb 2026, off by default, logs to the Event Log; check current status before relying on it) | standard Sysmon events | admin | observes |
| | Windows **agent workspace / agent accounts** (Microsoft preview) | a separate standard account per agent, own desktop, known-folder scoping | OS feature | future integration point |
| macOS | Endpoint Security framework | process and file events | needs an Apple entitlement | out of scope for now |
| Any | Egress proxy (built) | host, port and bytes per task token, with no content | none | **prevents** |
| Any | Agent layer: hooks, OTel GenAI spans (`invoke_agent`, `execute_tool`), MCP W3C trace context | prompt and tool-call ids | none | advisory labels only. The OTel GenAI conventions were still in "Development" status as of May 2026 |

**Decision.** Enforced tasks run on Linux (WSL2 on the team laptops). Windows-native is **observation-only** in this project and is used for shadow discovery. We will not claim Windows enforcement parity.

## 4. Attribution rules (deterministic, testable)

- **R1. Bind before run.** A task's cgroup exists before the agent's first instruction for that task. All events from that cgroup map to the task.
- **R2. Born-in.** A process belongs to the task that was active in its parent when it was forked. Background processes started during prompt 1 stay attributed to prompt 1 even after prompt 2 begins.
- **R3. Per tool call.** The broker runs each tool call in a sub-cgroup `task_<id>/call_<n>`. Events in that sub-cgroup are attributed to that specific tool call.
- **R4. Shared-process residual.** Syscalls from a long-lived agent's own process:
  - with exactly one active task → that task;
  - with two or more → `AMBIGUOUS{candidates}`. The system never guesses, and any OUTSIDE decision applies the strictest candidate boundary.
- **R5. Handoffs** to processes that already exist (daemons, D-Bus, docker, cron):
  - the channel is blocked where possible (we already tmpfs `/run/user/<uid>`);
  - otherwise the event is logged `UNATTRIBUTED` and raises a deviation.
- **R6. Agent-supplied ids** (`prompt_id`, `tool_use_id`, trace ids) label events but **never** widen a boundary.

**This is the measurable research piece.** The Kernel-Level Evidence paper (Sep 2026) reports session-level attribution precision of 100% using a container per session, and states that per-tool-call attribution "is a harder open problem out of scope". We measure:
- attribution precision and recall for R2–R4 with N concurrent prompts in one long-lived agent;
- against an AgentSight-style heuristic baseline (lineage + time window + argument match).

## 5. "It must be safe": three senses, each with checkable rules

### S1. Safe for the machine
- No kernel modules or drivers. On Linux, only Landlock, seccomp and verifier-checked eBPF. On Windows, only a user-mode ETW consumer.
- Bounded ring buffers. Dropped events are **counted and shown** in the Task Receipt, never lost silently.
- **Freeze, don't kill.** On deviation or sensor loss, write `cgroup.freeze=1`. A human can resume or terminate. The pause is reversible and keeps the evidence.
- OBSERVE mode and a per-host sensor off-switch for rollout.

### S2. Safe from the agent (the agent is untrusted)
- The sensor, governor and logs run as a different user, outside the task cgroup.
- seccomp in the task denies `bpf`, `perf_event_open`, `ptrace` of others, io_uring and module/kexec syscalls.
- Landlock gives no write access to `/sys/fs/cgroup`, `/sys/fs/bpf`, the governance DB or the logs.
- **Heartbeat, fail-closed.** If the sensor stops, or drops more than a threshold of events, ENFORCE tasks freeze.
- Logs are hash-chained per task, with periodic anchors shipped off-host. Only call them "tamper-evident" once this is implemented and tested.
- Optional: signed BPF programs. Initial kernel support landed in Linux 6.18; the security policies around it are still being built.
- **Tamper suite (experiment E4).** The agent tries to:
  - kill or blind the sensor;
  - write the logs;
  - migrate its cgroup;
  - hand work to a daemon.

  The Kernel-Level Evidence paper lists sensor integrity under an adversarial agent as future work, so this is a measurable contribution.

### S3. Safe for people and data
- **No TLS decryption and no SSL-library hooks.** The prompt comes from our intake. LLM traffic is metadata only (host, bytes, timing) from the egress proxy.
- **Metadata, not content.** Record path, operation, result, size and optionally a hash. Never record file contents.
- Redact secret-looking strings from command lines before storing. Never store environment variables. The task token already travels over a pipe fd, not the environment.
- Full telemetry applies **only to governed task cgroups**. Other processes get metadata-only discovery (exe path, parent, uid, destinations).
- **Prompts:** store a hash, plus an encrypted copy with a configurable retention period and role-based access.
- Tell staff that agent actions are logged per request. Logs name the requester, so they are personal data under the applicable privacy law and internal policy.
- **Privacy audit (experiment E6).** Plant decoy secrets, then grep all stored telemetry and exports. The expected count is zero.

## 6. Where existing work stops (positioning; claim the combination, not "first")

| Work | Binds actions to the user's request? | OS enforcement | Mid-task expansion | Inventory | Per-request evidence |
|---|---|---|---|---|---|
| AgentSight (2508.02736) | Heuristic link to LLM traffic captured by SSL uprobes | None (observation only) | n/a | n/a | No |
| ActPlane (2606.25189) | Policies loaded by a privileged process before start; the agent adds deltas | eBPF IFC in the kernel | The agent may add rules, but inherited constraints cannot be weakened. More runtime updates are "future work". 78/106 unsafe behaviours prevented on OpenAgentSafety | No | No |
| ContractWarden (2609.38248) | Human-approved tri-state contract bound before execution | eBPF LSM | Not described | No | No |
| Kernel-Level Evidence (2609.28915) | Session = container; strace | None (detection study; Falco baseline AUROC 0.572 OOD) | n/a | n/a | n/a |
| CrowdStrike (Mar 2026) | Traces "to the originating process" | Endpoint isolation | n/a | Shadow AI discovery incl. MCP servers | Not stated |
| Microsoft Agent 365 (GA May 2026) | Not stated | Network controls GA; runtime blocking in preview | Not stated | Registry + endpoint discovery | Purview audit |
| Jamf AI Governance (Jun 2026) | No (device-level posture) | OS-level policy for Mac AI tools | n/a | Discovery of supported tools | Audit reports |
| Bitdefender AI Guardian (Oct 2026, macOS beta) | No (user-defined rules) | Checks agent actions before execution | n/a | Not stated | Decision log |
| C1 (Jul 2026) | Per-agent toolset ("governed scope"), not the prompt | Tool-call gateway | Holds high-risk calls for approval; expansion not described | Shadow AI discovery | Per decision |
| Apono (per vendor blog) | JIT task-scoped credentials; checks the **agent-stated** intent | Credential layer | Approval for sensitive actions | — | — |

**Defensible positioning.** We found no source that combines all of the following:
1. a boundary derived from the **user's** request (not the agent's stated intent);
2. enforced at the **OS** level across files, processes and network;
3. **mid-task expansion** approved by a human, with **provenance** of what the agent read before asking;
4. a **per-request evidence record**.

We claim that combination plus measured results. We do not claim "first task-scoped" or "first kernel enforcement": both already exist.

## 7. Enterprise features, ranked

### Tier 1: build first (what makes us stand out)
1. **Task Receipt.** One record per user request, answering "what did the agent do for this request, and who allowed it?" It contains:
   - who asked, the prompt hash, and the derived boundary;
   - every grant, with its approver and reason;
   - every file, host and process touched, each marked INSIDE, OUTSIDE or AMBIGUOUS;
   - blocked actions, dropped-event counts and the sensor state;
   - a hash chain;
   - export to JSON, PDF and OCSF (via the OWASP AOS mapping to API Activity 6003).

   Competitors log per agent or per decision. Per-request OS evidence is our unit. *Builds on:* storage, correlator, evaluator.
2. **Provenance-aware approval card.** When an agent asks for more access, the approver sees:
   - the exact resource;
   - the risk tier;
   - "requested after reading untrusted file X", with the snippet location;
   - single-use / expires-at-task-end.

   Shown in the dashboard, with optional Slack/Teams webhooks. *Builds on:* F8 ExpansionService (already enforces no self-approval and exact-resource grants).
3. **Freeze-and-review quarantine.** `cgroup.freeze` instead of a kill. The reviewer sees the receipt so far, then resumes, narrows or terminates. Enterprises hate losing work to false positives, and this makes ENFORCE mode adoptable.
4. **SOC context enrichment.** Sophos (Jul 2026) found Claude Code, Cursor and Codex triggering EDR rules built for attackers (DPAPI credential decryption, LOLBin downloads, persistence). It recommends scoping rules to agent processes. We can answer what an EDR alert cannot:
   - which request triggered this;
   - which user asked;
   - whether it was inside the boundary;
   - whether it was approved.

   Delivered as an enrichment API plus OCSF export. This turns the noise into either "expected for task T" or "deviation".

### Tier 2: high enterprise value
5. **Sensitive-data classes in the service catalog** (public / internal / confidential / regulated, e.g. health records, credentials). Regulated classes are **never auto-derived** and always need approval. This is the direct answer to the Medicare-portal motivation.
6. **Policy replay ("what-if").** Replay last week's receipts against a changed catalog or policy: "these 12 of 200 tasks would have been blocked". This removes the fear of tightening policy.
7. **Delegation attenuation.** When agent A delegates to agent B over A2A or MCP, B's boundary is a subset of A's task boundary and can never widen. This reuses the existing A2A gateway and is visible in the receipt.
8. **Canary resources per task.** Decoy credentials and files in each workspace. Any touch is a high-confidence deviation (we already use decoys in the M4 tests).
9. **Shadow-agent discovery + one-click onboarding.** Metadata signals: connections to LLM API hosts, MCP stdio server process patterns, A2A agent cards, known agent binaries. Each finding is GOVERNED or SHADOW, with owner uid and host. Discovery alone is already offered by vendors; the onboarding into a governed launch is our addition.
10. **Purpose-drift score per agent.** Tracks over time, per agent:
    - out-of-boundary attempts;
    - expansion requests;
    - approval rate;
    - UNATTRIBUTED events.

    This answers pillar 1, "is each agent doing its assigned task?", with numbers.

### Tier 3: research and later work
11. Per-tool-call attribution for long-lived agents (R2–R4, experiment E3).
12. Sensor tamper evaluation (E4).
13. Windows-native observation mode (Job Object + ETW / built-in Sysmon) for discovery on Windows endpoints.

## 8. Experiments these enable (all measured, none assumed)

- **E1. Condition C = tool layer + OS layer, with indirect-path scenarios.** `run_command` returns in a new suite, and the agent reads or exfiltrates files through shell or Python instead of the read tool. Expected outcome: the tool layer misses these and the OS layer prevents them. Report the measured result either way. This closes the M5 caveat that the OS layer was not active in the agent evaluation.
- **E2. Per-task container baseline** (only the task's files mounted, no network), compared with governed + expansion on utility and security.
- **E3. Attribution under concurrency** (R2–R4 vs the AgentSight-style heuristic).
- **E4. Tamper suite.**
- **E5. Overhead.** Wall time and syscall latency with the sensor on and off, reported as measured.
- **E6. Privacy audit** (decoy-secret grep = 0).

## 9. Build order

- **M6. Live OS-bound loop (WSL2).**
  - The `agentgov run` launcher binds prompt → task → cgroup → sandbox.
  - `LLMAgent` (Ollama) runs inside it.
  - Task Receipt v0.
  - E1 + E2.
- **M7. eBPF sensor.**
  - libbpf CO-RE, filtered by cgroup id.
  - Drop counters, heartbeat → freeze.
  - E4, E5.
  - The ptrace sensor stays as an observation-only fallback.
- **M8. Enterprise layer.**
  - Receipts with hash chain + exports.
  - Provenance approval card.
  - Freeze/resume.
  - Sensitivity classes.
  - Canaries.
  - SOC enrichment API.
  - E6.
- **M9. Long-lived agents + discovery.**
  - Hook integration (our own long-lived agent server first; Claude Code via managed HTTP hooks as an optional local demo).
  - Per-tool-call sub-cgroups.
  - Shadow discovery.
  - Drift score.
  - E3.

## 10. Claims we must not make

- "first" anything;
- "tamper-proof" or "immutable";
- "complete visibility";
- per-tool-call attribution "solved" in general;
- Windows enforcement parity;
- any overhead number before E5;
- "zero false positives";
- that hooks or OTel spans are trustworthy evidence.

---

## Sources

- [AgentSight: System-Level Observability for AI Agents Using eBPF (arXiv 2508.02736)](https://arxiv.org/html/2508.02736v2)
- [ActPlane: Programmable OS-Level Policy Enforcement for Agent Harnesses (arXiv 2606.25189)](https://arxiv.org/html/2606.25189v2)
- [ContractWarden: Kernel-Enforced Damage Boundaries for AI Agents (arXiv 2609.38248)](https://arxiv.org/abs/2609.38248)
- [On the Effectiveness of Kernel-Level Evidence for Agent Security (arXiv 2609.28915)](https://arxiv.org/html/2609.28915v1)
- [Tetragon: Enforcement](https://tetragon.io/docs/concepts/enforcement/)
- [Claude Code hooks reference](https://code.claude.com/docs/en/hooks)
- [OpenTelemetry GenAI semantic conventions status (Greptime, May 2026)](https://greptime.com/blogs/2026-05-09-opentelemetry-genai-semantic-conventions)
- [OWASP AOS: extending OCSF](https://aos.owasp.org/spec/trace/extend_ocsf/)
- [Windows agentic security (Microsoft Learn)](https://learn.microsoft.com/en-au/windows/security/book/operating-system-agentic-security)
- [Built-in Sysmon in Windows 11 (TechRepublic, Feb 2026)](https://www.techrepublic.com/article/news-windows-11-native-sysmon-support/)
- [Linux 6.18 BPF signed programs (Phoronix)](https://www.phoronix.com/news/Linux-6.18-BPF-Signed-Deferred)
- [eBPF Foundation threat model (The New Stack)](https://thenewstack.io/ebpf-foundation-releases-security-threat-model-and-audit-reports/)
- [Sophos: AI coding agents trigger endpoint rules (The Hacker News, Jul 2026)](https://thehackernews.com/2026/07/ai-coding-agents-found-triggering.html)
- [Microsoft Agent 365 GA (VentureBeat)](https://venturebeat.com/technology/microsoft-takes-agent-365-out-of-preview-as-shadow-ai-becomes-an-enterprise-threat)
- [CrowdStrike: endpoint as epicenter for AI security (Mar 2026)](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-establishes-the-endpoint-as-the-epicenter-for-ai-security/)
- [Jamf AI Governance for Mac fleets](https://letsdatascience.com/news/jamf-launches-ai-governance-for-mac-fleets-be62ccbc)
- [Bitdefender AI Guardian (SC World, Oct 2026)](https://www.scworld.com/brief/bitdefender-releases-ai-guardian-to-secure-autonomous-software-agents)
- [C1: agent runtime governance (Jul 2026)](https://www.c1.ai/blog/introducing-agent-runtime-governance)
- [Apono: top AI agent security solutions (vendor blog, Jul 2026)](https://www.apono.io/blog/top-ai-agent-security-solutions/)
- [Pillar Security: agentic AI security platforms compared (vendor-authored, Oct 2026)](https://www.pillar.security/blog/best-agentic-ai-security-platforms-enterprise-2026)
- [ARMO: prompt and tool call visibility (Apr 2026)](https://www.armosec.io/blog/prompt-and-tool-call-visibility/)
