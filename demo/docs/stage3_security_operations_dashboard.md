# Stage 3 — Security Operations & Research Dashboard

## 1. Overview & Architecture

The **A2A Security Operations & Research Dashboard** is a unified, real-time interface designed to monitor agent communications, inspect security violations, manage enforcement actions, and present empirical research evaluation benchmarks.

It operates directly on top of the live **Security Monitor Gateway**, consuming real backend state and historical evaluation datasets without mock data or duplicate databases.

```
┌─────────────────────────────────────────────────────────────┐
│                 Single-Page Operations UI                  │
│       Vanilla HTML5 + Modern CSS + Responsive JS (SPA)      │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / JSON REST
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              FastAPI Security Monitor Gateway               │
│                     (Port 8000 Inline)                      │
├──────────────────────────────┬──────────────────────────────┤
│ Live Telemetry & Middleware  │ REST Management & Eval API   │
└──────────────┬───────────────┴───────────────┬──────────────┘
               │                               │
               ▼                               ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
│      SQLite Ledger & Store   │ │    Research Artifacts      │
│  - app.state.inventory       │ │  - evaluation_summary.json │
│  - app.state.event_store     │ │  - evaluation_manifest.json│
│  - security_monitor.db       │ │  - *.jsonl trial records   │
└──────────────────────────────┘ └────────────────────────────┘
```

---

## 2. Dashboard Views

The dashboard is structured into 7 operational and research views:

1. **Overview & Topology (`overview`)**:
   - **System Status**: Live gateway heartbeat, host, version, and rate limiter status.
   - **Entity Counters**: Real-time counts of trusted agents, quarantined identities, restricted identities, and total recorded security events.
   - **Live Mediated Topology**: Visual map depicting the inbound client connection through the inline Security Gateway to registered upstream agent nodes (`HelloWorld`, `AgentAlice`).
   - **Enforcement Action Distribution**: Breakdown of graduated responses (`RATE_LIMIT`, `QUARANTINE`, `RESTRICT`, `ALLOW`).
   - **Research Benchmark Summary**: High-level detection metrics (AS, CC, CO) and observed FPR from the latest evaluated run.

2. **Agent Inventory (`inventory`)**:
   - Comprehensive card catalog of registered agents.
   - Details: Agent ID, Name, Endpoint URL, Protocol Binding/Version, Declared Skills, Security Schemes, and Status Badge (`TRUSTED`, `RESTRICTED`, `QUARANTINED`).
   - Active quarantine and restriction rosters with operator reason and timestamp.

3. **Security Audit Log (`events`)**:
   - Searchable, filterable audit log of security events.
   - Filters: Free-text search (ID, name, violation code), Severity filter (`HIGH`, `MEDIUM`, `LOW`), Action filter (`QUARANTINE`, `RESTRICT`, `RATE_LIMIT`, `ALLOW`).
   - Columns: Timestamp, Candidate/Caller ID, Candidate Endpoint, Violation Code, Severity, Enforcement Action, and Pipeline Timing (ns / ms).

4. **Security Findings (`findings`)**:
   - Empirical benchmark findings broken down by threat category:
     - **AgentCard Spoofing (AS)**: Homoglyph name spoofing and typosquatting detection with 95% Wilson confidence intervals.
     - **Capability Cloaking (CC)**: Undeclared runtime method invocation detection with 95% Wilson confidence intervals.
     - **Cycle Overflow (CO)**: Circular multi-hop delegation loop containment with 95% Wilson confidence intervals.
   - Benign workload false positive rate (FPR = 0.0%, 0/100).

5. **Performance & Latency (`performance`)**:
   - **Direct vs Protected Mediated Comparison**: Mean, Median, p95, and p99 round-trip latencies.
   - **Disaggregation Analysis**: Visually distinguishes intrinsic security computation (< 0.10 ms) from TCP/HTTP reverse proxy forwarding overhead (~4.8 ms on Windows loopback).

6. **Evaluation Runs (`evaluations`)**:
   - Dataset repository listing historical evaluation runs (`eval_YYYYMMDD_HHMMSS`).
   - Detailed run metadata: Trial count (100 per condition, 500 total), random seed (`42`), evaluation duration, and status (`VALIDATED`).
   - Allows inspection of individual category datasets.

7. **Operator Controls (`controls`)**:
   - Safe local-demo administrative interface.
   - **Apply Restricted Mode**: Transition candidate/caller into restricted mode (mutating actions blocked; safe reads permitted). Requires explicit modal confirmation.
   - **Release Restriction**: Remove restriction from active entity. Requires explicit confirmation.
   - **Release Quarantine**: Release identity or endpoint from quarantine. Requires explicit confirmation.
   - **Health Ping**: Verify gateway responsiveness.

---

## 3. Backend REST APIs

The dashboard is powered by the following REST API endpoints implemented in `app/gateway/server.py`:

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/overview` | `GET` | Returns aggregated status, active topology, action distribution, and latest evaluation summary. |
| `/api/v1/agents` | `GET` | Returns catalog of trusted agents, quarantined entities, and restricted entities. |
| `/api/v1/events` | `GET` | Filterable and searchable security audit log (`search`, `severity`, `action`, `limit`). |
| `/api/v1/evaluations` | `GET` | Lists historical evaluation datasets from `demo/data/evaluation/`. |
| `/api/v1/evaluations/{id}` | `GET` | Retrieves full evaluation summary and metrics for a given evaluation run. |
| `/api/v1/evaluations/{id}/trials` | `GET` | Retrieves raw JSONL trial records filtered by category (`AS`, `CC`, `CO`, `BENIGN`, `LATENCY`). |
| `/api/v1/performance` | `GET` | Returns latency disaggregation comparing intrinsic pipeline compute vs proxy overhead. |
| `/api/v1/restriction/apply` | `POST` | Operator endpoint to restrict an agent/caller identity. |
| `/api/v1/restriction/release` | `POST` | Operator endpoint to release restriction. |
| `/api/v1/quarantine/release` | `POST` | Operator endpoint to release an agent from quarantine. |
| `/dashboard` | `GET` | Serves the single-page HTML operations dashboard. |
| `/` | `GET` | Redirects to `/dashboard`. |

---

## 4. Live Verification

The dashboard was validated against live local services:
- **HelloWorld**: `http://127.0.0.1:9999`
- **AgentAlice**: `http://127.0.0.1:8001`
- **Security Gateway**: `http://127.0.0.1:8000`

### Browser Subagent Validation

An automated browser verification subagent visited `http://127.0.0.1:8000/dashboard` and completed full navigation and visual testing:
1. **Topology & Metrics**: Verified live cards (3 trusted agents, 5 quarantined entities, 84 audit events).
2. **Tab Navigation**: Successfully traversed all 7 views (`Overview`, `Agent Inventory`, `Audit Log`, `Evaluation Findings`, `Latency & Overhead`, `Evaluation Runs`, `Operator Controls`).
3. **Audit Filtering**: Verified event list with search input and dropdown filters.
4. **Research Alignment**: Verified 95% Wilson confidence intervals rendered accurately from `evaluation_summary.json`.
5. **No Layout Errors**: Zero uncaught JavaScript exceptions and clean responsive CSS rendering.

---

## 5. Security & Safety Controls

To maintain research integrity and prevent accidental state degradation:
- **Explicit Modal Confirmation**: All operator actions (apply restriction, release restriction, release quarantine) trigger an explicit confirmation modal displaying the target entity and planned impact.
- **Localhost Bound**: The dashboard and gateway are bound to `127.0.0.1` and intended for local research and capstone evaluation.
- **No Remote Administrative Backdoors**: The dashboard provides no arbitrary code execution or unvalidated system command execution.
- **Identity Isolation**: Ingestion quarantine targets the candidate identifier and endpoint URL, preventing spoofing attempts from denying service to legitimate agents with similar names.

---

## 6. Known Limitations

1. **Single-Node Testbed**: State is maintained in a local SQLite file (`security_monitor.db`) and in-memory caches, not distributed across a cluster.
2. **Synchronous Polling**: The frontend uses a 5-second polling interval for live state updates rather than WebSocket streaming.
3. **Scope Scoping**: Performance and detection metrics reflect the 500-trial controlled evaluation benchmark on Windows loopback, not unconstrained open-Internet traffic.
