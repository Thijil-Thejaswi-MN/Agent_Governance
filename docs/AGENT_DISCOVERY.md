# Agent Discovery Architecture and Governance

This document outlines the architecture, signals, privacy rules, operational limitations, and roadmap for agent discovery.

## 1. Overview

Agent discovery extends the organizational inventory by discovering, cataloguing, and classifying AI agents, model servers, MCP servers, and agent frameworks operating across host infrastructure and code repositories.

Agents are categorized into three states:
- **Governed**: Bound to an active governance task with enforced boundaries.
- **Known**: Acknowledged by an administrator with an assigned owner and purpose.
- **Shadow**: Detected agents running outside the governance boundary without assigned ownership.

Multi-tenant scoping is enforced across all discovery operations using `org_id`.

Discovery operates in two tiers:
1. **Discovery v1 (Periodic Host and Repository Scan)**: Polling-based inspection of `/proc`, local listening ports, configuration files, and git repository manifests.
2. **Discovery v2 (Kernel Event Streaming via eBPF)**: Active when `GOVERNANCE_DISCOVERY_EBPF=1`. Streams host-wide process executions, LLM connections, DNS queries, and child MCP server processes in real time, catching ephemeral actions that exit between polling intervals. Enforcement remains unchanged.

---

## 2. Detection Signals

Discovery aggregates signals across static, polling, and kernel event streams:

### A. Process Telemetry (`/proc`)
- **Framework Detection**: Inspects memory maps (`/proc/<pid>/maps`) and command lines (`/proc/<pid>/cmdline`) for loaded libraries and modules:
  - LangChain, LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, Claude Agent SDK, LlamaIndex, Semantic Kernel, and Model Context Protocol (MCP).
- **Environment Key Names**: Inspects process environment blocks (`/proc/<pid>/environ`) for credentials. Stores variable names only (e.g., `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`), never values.

### B. Local Model Endpoints
- Probes loopback ports for local inference servers:
  - Ollama (`:11434`, `/api/tags`)
  - LM Studio (`:1234`, `/v1/models`)

### C. Active LLM Network Connections
- Inspects `/proc/net/tcp` and `/proc/net/tcp6` to find established outbound connections.
- Matches destination IP addresses against resolved domains of LLM providers (e.g., OpenAI, Anthropic, Groq, Google Gemini, Azure OpenAI, AWS Bedrock).
- Attributes active connections to specific processes via socket inode mapping from `/proc/<pid>/fd`.

### D. Model Context Protocol (MCP) Server Configurations
- Discovers MCP configuration files across user home and repository locations:
  - `.mcp.json`
  - `~/.cursor/mcp.json`
  - `.vscode/mcp.json`
  - Claude desktop configurations
  - Windsurf and Gemini CLI configuration files
- Extracts server identifiers, commands, and credential names.

### E. Installed Coding Agents
- Identifies coding assistants on system `PATH` or install paths:
  - `claude`, `cursor`, `codex`, `gemini`, `aider`, and `antigravity`.

### F. A2A Agent Cards
- Resolves loopback `.well-known/agent.json` and `agent-card.json` endpoints using local HTTP queries with strict timeouts.

### G. Repository Manifests
- Static filesystem scanning without network calls:
  - Python: `requirements*.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`.
  - Node.js: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.
  - Container manifests: `Dockerfile` package instructions.
  - Cards: `.well-known/agent.json`, `agent-card.json`.

### H. eBPF Real-Time Kernel Signals (Discovery v2)
When `GOVERNANCE_DISCOVERY_EBPF=1`, a lightweight discovery mode attaches raw tracepoints to capture ephemeral events host-wide:
- `ebpf_exec_agent`: Execve of known binaries (`claude`, `codex`, `gemini`, `aider`, `cursor-agent`, `cursor`) or `python`/`node` executing an agent framework.
- `ebpf_llm_connect`: Outbound connect syscall directed to resolved LLM endpoints.
- `ebpf_llm_dns`: DNS query for known LLM domains (e.g. `api.openai.com`, `api.anthropic.com`).
- `ebpf_mcp_child`: Child processes spawned by agents executing MCP server commands (`npx ... @modelcontextprotocol/...`, `uvx mcp-server-...`, or binaries matching `*mcp*`).

---

## 3. Cgroup Identity and Grouping

Discovery v2 correlates ephemeral events by systemd unit or container ID extracted from the process cgroup hierarchy:
1. **Container Association**: Inode resolution extracts 64-character container IDs from `/sys/fs/cgroup` or `/proc/<pid>/cgroup` (e.g. Docker, containerd, Podman).
2. **Systemd Unit Association**: Systemd `.service` or `.scope` slices are parsed to group helper commands, interpreter invocations, and child processes under the owning service.
3. **Identity Fingerprint**: Stable discovery IDs are computed from `(host, kind, group_key)` so that repeated actions in the same service update the existing inventory card rather than creating duplicate entries.

---

## 4. Privacy Controls and Rules

The discovery subsystem enforces strict data privacy rules across storage, memory, and API layers:

1. **Credential Values Redacted**:
   - Only environment variable *names* (e.g. `OPENAI_API_KEY`) are retained.
   - Values are never stored in memory, DB records, or API responses.
2. **DNS Payload Privacy**:
   - The eBPF kernel program captures only the initial 256 bytes of UDP port 53 packets.
   - User space parses the Question domain name (QNAME) only.
   - The raw payload (including queries, answers, authority records, and query IDs) is discarded immediately in memory.
   - Raw packet bytes are never emitted, logged, or persisted.
3. **No Prompts or Content Ingestion**:
   - Repository code files, user prompts, training data, and environment blocks are never ingested or saved.
4. **Command-Line Sanitization**:
   - Command lines and argv lists are capped at 300 characters.
   - All authorization tokens (`Bearer ...`, `--token=...`), key values (`key=...`, `--api-key=...`), and sensitive flags are redacted via `sanitize_cmdline` and `redact_llm_error`.
5. **Tenant Scoping**:
   - Queries and updates are strictly partitioned by `org_id`.

---

## 5. Rate Limits and Resource Management

To prevent kernel ring buffer exhaustion or Denial-of-Service from high-frequency process churn:
- **Per-Cgroup Rate Limiting**: An LRU hash map tracks event counts within 1-second sliding windows. Each cgroup is capped at at most N events per second (default 200).
- **Accounting**: Events exceeding the per-cgroup threshold increment a per-CPU `rate_limited_events` array counter.
- **Observability**: Rate-limited drops are reported in loader heartbeats (`rate_limited_total`) and event metadata, distinguishing intentional throttling from unexpected packet drops.

### Workload Overhead Measurement (W3 Shell Benchmark)

Empirical CPU overhead measured across the shell-heavy W3 workload using `demo/security_monitor/measure_discovery_overhead.py` (5k file find, recursive grep, python reading 2k files, 50MB tar archive, and 500 binary executions):

| Metric | Discovery OFF | Discovery ON (`GOVERNANCE_DISCOVERY_EBPF=1`) | Delta |
|---|---|---|---|
| Total Workload Latency | 394.24 ms | 405.08 ms | +10.85 ms (+2.75%) |
| 500 Process Executions | 214.27 ms | 202.40 ms | -11.87 ms |
| File Find (5,000 files) | 38.32 ms | 27.42 ms | -10.90 ms |
| Content Grep | 21.89 ms | 23.44 ms | +1.55 ms |
| Python Read (2,000 files) | 42.81 ms | 57.20 ms | +14.39 ms |
| Tar Archive (50 MB) | 76.94 ms | 94.62 ms | +17.68 ms |

The measured overhead on heavy shell execution churn is ~2.75%, demonstrating that the in-kernel filter and per-cgroup rate limiting avoid burdensome runtime latency.

---

## 6. Operational Limitations and Unmonitored Vectors

1. **Unprivileged Execution**:
   - Scanning processes owned by other user accounts via `/proc` requires `root` or `CAP_SYS_PTRACE`.
   - When running unprivileged, unreadable processes are explicitly counted and reported:
     `partial scan: N processes not readable`.
     The system never claims an exhaustive scan when processes are unreadable.
   - eBPF discovery requires `CAP_BPF` and `CAP_PERFMON` on the loader binary.
2. **TLS SNI (Encrypted ClientHello)**:
   - eBPF discovery inspects UDP DNS queries and IP layer connect destinations. It does not inspect TLS Server Name Indication (SNI) or decrypted HTTPS traffic payloads.
3. **SaaS-Hosted Remote Agents**:
   - Cloud-native agents that do not execute on the monitored host or through a monitored network proxy cannot be detected via local `/proc` or kernel tracepoints.
4. **Remote Hosts**:
   - Agents running on external uninstrumented servers or developer laptops without the loader installed are not visible to host discovery.

---

## 7. Roadmap

- **Planned v3 (Enterprise Cloud Connectors)**:
  - Connectors for GitHub / GitLab organization repositories to discover agent configurations at pull request time.
  - Identity provider (IdP) integration for mapping agent credentials to enterprise owners.
