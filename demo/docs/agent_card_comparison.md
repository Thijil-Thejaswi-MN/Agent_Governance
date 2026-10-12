# Agent Card Comparison: Local Official HelloWorld vs. Real-World Registry Cards

This document provides a field-by-field comparative analysis between the official local baseline Agent Card ([helloworld_agent_card.json](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/agent_cards/helloworld_agent_card.json)) and real-world production cards indexed in the public A2A Registry ([normalized_agents.json](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/registry/normalized_agents.json)).

---

## 1. Comparative Matrix

| Schema Field | Local Official HelloWorld Agent | Real-World Registry Agents (Sample of 100) |
| :--- | :--- | :--- |
| **Identity (`name`, `description`)** | Minimal: `"Hello World Agent"`, `"Just a hello world agent"` | Rich, domain-specific descriptions (average ~250 chars) covering acceptance checks, crypto, orchestration, LLM bridges, etc. |
| **Provider / Author** | Absent (`null`) | 91% declare structured `provider` (`{organization, url}`); registry also exposes separate `author` field. |
| **Endpoint Definition** | Uses nested `supportedInterfaces: [{url, protocolBinding, protocolVersion}]` | Exposed as top-level `url` string and separate `wellKnownURI` pointing to `.well-known/agent-card.json`. |
| **Protocol Version** | Embedded in interface: `"protocolVersion": "1.0"` | Top-level string with significant divergence: `0.3.0` (50%), `1.0` (47%), `0.3` (2%), `1` (1%). |
| **Agent Software Version** | Fixed baseline: `"version": "0.0.1"` | SemVer ranging from `0.1.0` to `4.2.0` across 38 distinct versions. |
| **Protocol Binding** | Explicitly declared: `"protocolBinding": "JSONRPC"` | Implicit JSON-RPC per A2A conformance specification. |
| **Transport Protocol** | Clear-text local HTTP (`http://127.0.0.1:9999`) | 97% HTTPS (TLS-encrypted), 3% HTTP (clear-text). |
| **Capabilities** | `{"streaming": true, "extendedAgentCard": true}` | Extends to `pushNotifications`, `stateTransitionHistory`, and custom registry extension URIs (`extensions: [{uri: "...", params: {...}}]`). |
| **Input / Output Modes** | Primitive: `["text/plain"]` | Predominantly structured data: `["application/json"]` (with markdown, HTML, and binary payloads in specialized agents). |
| **Skills Declared** | 1 simple skill (`echo_bot`) | 1 to 81 skills per agent (average: 6.69 skills). Extensive tagging for registry discovery. |
| **Security Schemes Metadata** | Undeclared / absent | Exactly 86% of the 100 sampled registry records contained empty `securitySchemes` metadata; 14% define schemes (`apiKey`, `http` Bearer, `x402` micropayments, `openIdConnect`). |
| **Operational Telemetry** | None (static card) | Dynamic registry-managed metrics: `uptime_percentage`, `avg_response_time_ms`, `last_health_check`, `task_conformance`. |

---

## 2. Key Structural Differences

### A. Interface Declaration (`supportedInterfaces` vs Top-Level `url`)
The official A2A SDK `a2a-sdk 1.1.0` outputs an array of `supportedInterfaces`:
```json
"supportedInterfaces": [
  {
    "url": "http://127.0.0.1:9999",
    "protocolBinding": "JSONRPC",
    "protocolVersion": "1.0"
  }
]
```
The public registry flattens this representation for search and indexing, exposing `url`, `protocolVersion`, and `wellKnownURI` at the root object level. A production-grade parser or security proxy must seamlessly ingest both formats.

### B. Protocol Version Semantics
Local sample adheres strictly to protocol `1.0`. Real-world deployments are currently split nearly 50/50 between the legacy pre-1.0 draft (`0.3.0`) and the `1.0` standard. Security monitors and parsers cannot assume strict `1.0` compliance without dropping half the live ecosystem.

### C. Declared Metadata vs. Upstream Enforcement
The local HelloWorld card declares zero authentication. In the public registry sample, exactly 86% of records contain empty `securitySchemes` metadata. However, this is strictly a metadata observation: it cannot be concluded from Agent Cards alone that these endpoints lack authentication at upstream reverse proxies, firewalls, or API gateways. The 14% that do declare schemes introduce heterogeneous mechanisms (API keys, Bearer tokens, decentralized micropayments), requiring any mediation gateway to support multi-scheme negotiation.
