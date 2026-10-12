# Phase 3: Real-World A2A Registry Data Analysis

This document provides empirical analysis of a 100-record snapshot collected from the live public A2A Registry ([a2aregistry.org](https://a2aregistry.org)) on October 5, 2026.

---

## 1. Collection Summary

- **Source API Base**: `https://a2aregistry.org/api`
- **Endpoint Queried**: `GET /api/agents?limit=100`
- **Total Registered Agents in Ecosystem**: 516 (as reported by `/api/stats`)
- **Records Evaluated**: 100
- **Mode**: 100% Read-Only discovery metadata
- **Third-Party Task Probing**: Zero (`third_party_agent_task_requests = 0`)
- **Raw Data Artifact**: [real_agents_2026-10-05.json](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/registry/real_agents_2026-10-05.json)
- **Normalized Dataset**: [normalized_agents.json](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/registry/normalized_agents.json)
- **Machine-Readable Metrics**: [registry_analysis.json](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/registry/registry_analysis.json)

---

## 2. Empirical Observations (Real Observations vs. Inferences)

> [!NOTE]
> **Methodological Boundary**: Observations below reflect the 100 agents returned by the public registry API in this specific sample. They are concrete findings of this dataset and should not be over-generalized to all 516 agents without broader sampling.

### A. Protocol Version Disparity
The A2A specification defines `protocolVersion`, but live agents exhibit substantial variation:
- **`0.3.0`**: 50 agents (50%)
- **`1.0`**: 47 agents (47%)
- **`0.3`**: 2 agents (2%)
- **`1`**: 1 agent (1%)

**Security & Parsing Observation**:
A parser or security gateway expecting strictly semver strings (e.g., `1.0.0`) will fail or misclassify 48% of real-world cards (`1.0`, `0.3`, `1`). Agent orchestrators must implement relaxed or fuzzy version parsing to handle both legacy pre-1.0 and 1.0 representations.

### B. Agent Software Version Distribution
- 38 distinct version strings across 100 agents.
- Most common: `0.1.1` (21 agents), `1.0.0` (19 agents), `0.1.0` (13 agents), `1.1.0` (6 agents).
- Outliers observed: `4.2.0`, `4.0.0`.

### C. Declared Security Schemes Analysis
- **Declared active security requirements (`security: []`)**: 95 records (95%) had an empty `security` list. Only 5 records defined active `security` requirements.
- **`securitySchemes` presence**: Exactly 14 records (14%) published a non-empty `securitySchemes` dictionary.
- **Empty `securitySchemes` metadata**: Exactly 86% of the 100 sampled registry records contained empty `securitySchemes` metadata.
- Types of security schemes declared across those 14:
  - `apiKey`: 4
  - `http` (Bearer / Basic): 5
  - `x402` (payment/micropayments): 1
  - `openIdConnect`: 1
  - `unknown` / custom structure: 6

**Methodological Boundary**:
86% of the 100 sampled registry records contained empty `securitySchemes` metadata. However, it cannot be concluded from Agent Cards alone that these agents are completely unauthenticated in practice; underlying services may enforce authorization at reverse proxies, API gateways, or network perimeters without declaring it in public discovery metadata.

### D. Skill Richness & Extreme Variance
- All 100 agents declared at least 1 skill (`total_skills = 669`).
- Average skills per agent: **6.69**.
- Minimum skills: **1**.
- Maximum skills: **81** (e.g. large composite toolboxes / enterprise integrators).

### E. Layered Disambiguation: Protocol Version, Binding, and Transport

To prevent ambiguity, three distinct communication layers must be decoupled:

1. **Protocol Version**: Defines the A2A specification release schema:
   - Sample distribution: `0.3.0` (50%), `1.0` (47%), `0.3` (2%), `1` (1%).
2. **Protocol Binding**: Defines the RPC / message packaging convention:
   - Official baseline uses `JSONRPC` over HTTP.
   - Public registry metadata implies JSON-RPC invocation semantics per A2A specification conformance.
3. **Transport**: Defines the underlying network transmission protocol:
   - **HTTPS**: 97 records (TLS-encrypted transport).
   - **HTTP**: 3 records (plaintext clear-text transport).
   - Structural difference: The public registry REST API summarizes service reachability via a root `url` string rather than the A2A SDK's internal nested `supportedInterfaces: [{url, protocolBinding, protocolVersion}]` array.

### F. Registry Quality & Conformance Signals
- `conformance = True`: 100 / 100 in this batch.
- `is_healthy = True`: 100 / 100.
- `task_conformance.category = WORKING (passed=True)`: 100 / 100.
- Response times: Registry tracking shows an average ping of 523ms to 1535ms.

---

## 3. Data Normalization Rules Applied

In [normalized_agents.json](file:///c:/Users/thiji/OneDrive/Documents/Projects/A2A/demo/data/registry/normalized_agents.json), records are mapped deterministically:
1. **No Invented Fields**: If a property is not returned by the API (such as `supported_interfaces` or `license`), it is preserved as `null` or empty.
2. **Endpoint Disambiguation**: Differentiates between `url` (the live A2A service endpoint) and `well_known_uri` (the `.well-known/agent-card.json` metadata URL).
3. **Quality Separation**: Isolates operational signals (`health`, `conformance`, `task_conformance`) from intrinsic agent metadata (`skills`, `capabilities`, `provider`).
