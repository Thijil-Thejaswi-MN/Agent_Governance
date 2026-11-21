# Task Records (Receipts) and Verification

Every governed task run produces a structured JSON record (`receipt.py`) capturing what the agent was allowed, what it requested, what it did, and what was prevented.

## Three Integrity Layers

Task records provide three layers of integrity checking:

1. **Hash-chained events**: Each entry in the event list contains the SHA-256 hash of the previous entry, chaining from genesis to final hash.
2. **Whole-record document hash**: `hash_chain.document_sha256` covers the canonical JSON of the entire record (excluding the hash field and signature), verifying initial boundaries, expansions, approvals, approvers, deliveries, isolation level, and termination status.
3. **Ed25519 cryptographic signatures (v2)**: Each new record carries an Ed25519 signature over `document_sha256`, created with an organisation key (`signing_key.pem`, mode 0600) kept outside task workspaces and repositories.

## Signed Records

When a task record is sealed:
- The active organisation private key signs the raw bytes of `document_sha256`.
- The record includes a `signature` block:
  ```json
  {
    "alg": "Ed25519",
    "key_id": "<16-hex-chars>",
    "org_id": "default",
    "signed_at": "2026-11-21T10:00:00Z",
    "value": "<base64-signature>"
  }
  ```
- If signing is unavailable (e.g. filesystem permission error), the record is preserved as an unsigned `v1` document with reason recorded in `extra.signing`. A task never fails because of signing.

## Key Management and Rotation

- Keys reside under `$GOVERNANCE_KEYS_DIR/<org_id>/` (default: `~/.agent_governance/keys/<org_id>`).
- Folder mode is 0700; private key mode is 0600.
- Key rotation (`rotate_key(org_id)`) creates a fresh active key while preserving retired public keys in `public_keys.json`.
- Public keys are never deleted, allowing verification of historical records.
- Private keys are never exposed in API endpoints, responses, or logs.

## Offline and CLI Verification

Verify records using the verification script:

```bash
# Verify using local public key registry
python scripts/verify_receipt.py receipts/<task_id>.json

# Verify offline with an explicit public key file (PEM, JSON, or raw)
python scripts/verify_receipt.py receipts/<task_id>.json --pubkey /path/to/public_key.pem
```

Verification scopes:
- `signed`: Hash chain valid, whole-record hash valid, and Ed25519 signature verified.
- `whole_record`: Hash chain and whole-record hash valid (v1 unsigned).
- `events_only`: Hash chain valid (older v0 format).
- `unknown_key`: Valid signature format, but key id is unrecognized.
