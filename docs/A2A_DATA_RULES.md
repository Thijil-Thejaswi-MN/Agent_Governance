# Agent-to-Agent Data Flow Rules

Data flow rules enforce label-driven boundary mediation across multi-agent workflows.

## Context Labels

Every task carries two monotonic context labels:
- **Confidentiality**: `public` -> `internal` -> `secret`
- **Integrity**: `trusted` -> `untrusted`

Labels only elevate monotonically over a task lifecycle.

## Flow Rules

1. **Rule 1 (Confidentiality)**: While a task context is `secret`, outbound data transmissions (`http_post`, `http_get` containing query parameters, or messaging peer agents via `call_agent`/`call_agents`) require explicit operator or job owner approval.
2. **Rule 2 (Integrity)**: After a task reads untrusted content (e.g. peer agent replies or web responses), further communications and boundary expansions require operator or job owner review.

## Honest Limits

- Labels are per task context, not per value, so they are conservative.
- Shell egress through the proxy does not check labels.
- Tokens follow shapes of IETF Transaction Tokens and attenuated-delegation drafts; no claim of conformance.
- A2A v1.0 on the wire is A2A-3.
