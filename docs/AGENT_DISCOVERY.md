# Agent Discovery Architecture and Governance

This document outlines the architecture, signals, privacy rules, operational limitations, and roadmap for agent discovery.

## 1. Overview

Agent discovery extends the organizational inventory by discovering, cataloguing, and classifying AI agents, model servers, MCP servers, and agent frameworks operating across host infrastructure and code repositories.

Agents are categorized into three states:
- **Governed**: Bound to an active governance task with enforced boundaries.
- **Known**: Acknowledged by an administrator with an assigned owner and purpose.
- **Shadow**: Detected agents running outside the governance boundary without assigned ownership.

Multi-tenant scoping is enforced across all discovery operations using `org_id`.

---

## 2. Detection Signals

Discovery aggregates seven distinct signal sources without requiring kernel modifications or external network probes during scanning:

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

---

## 3. Privacy Guarantees and Rules

The discovery subsystem enforces strict data privacy rules across storage and API layers:

1. **Credential Values Redacted**:
   - Only environment variable *names* (e.g. `OPENAI_API_KEY`) are retained.
   - Values are never stored in memory, DB records, or API responses.
2. **No Prompts or Content Ingestion**:
   - Repository code files, user prompts, training data, and environment blocks are never ingested or saved.
3. **Command-Line Sanitization**:
   - Command lines are capped at 300 characters.
   - All authorization tokens (`Bearer ...`, `--token=...`), key values (`key=...`), and sensitive flags are redacted via `redact_llm_error`.
4. **Tenant Scoping**:
   - Queries and updates are strictly partitioned by `org_id`.

---

## 4. Current Limitations

1. **Unprivileged Execution**:
   - Scanning processes owned by other user accounts requires `root` or `CAP_SYS_PTRACE`.
   - When running unprivileged, unreadable processes are explicitly counted and reported:
     `partial scan: N processes not readable`.
     The system never claims an exhaustive scan when processes are unreadable.
2. **SaaS-Hosted Remote Agents**:
   - Cloud-native agents that do not execute on the monitored host or through a monitored network proxy cannot be detected via local `/proc` inspection.
3. **Short-Lived Processes**:
   - Ephemeral CLI tasks executing between periodic scan intervals can terminate before detection occurs.

---

## 5. Planned Roadmap

- **Planned v2 (Kernel Event Monitoring)**:
  - Integration with eBPF probes (`tracepoint/syscalls/sys_enter_execve` and `sock:inet_sock_set_state`) to capture short-lived agent executions and network socket lifecycles continuously in real time.
- **Planned v3 (Enterprise Cloud Connectors)**:
  - Connectors for GitHub / GitLab organization repositories to discover agent configurations at pull request time.
  - Identity provider (IdP) integration for mapping agent credentials to enterprise owners.
