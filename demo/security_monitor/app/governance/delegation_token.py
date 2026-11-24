"""Delegation Token Engine (A2A).

Implements compact JWS-style cryptographic delegation tokens:
base64url(header).base64url(payload).base64url(signature)
Header: {"alg":"EdDSA","kid":...,"typ":"agd+jwt"}
Payload: canonical JSON with sorted keys and no spaces.
Tokens are held server-side only; the agent process never holds a token.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import time
from typing import Any

from .models import TaskLifecycle
from .signing import (
    load_public_keys,
    parse_public_key,
    sign_bytes,
    verify_bytes,
)

MAX_DELEGATION_DEPTH = 4


def b64url_encode(data: bytes) -> str:
    """Encodes bytes into unpadded base64url text."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Decodes unpadded base64url text into raw bytes."""
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def canonical_json(obj: Any) -> str:
    """Returns canonical JSON text with sorted keys and no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_token_hash(token_text: str) -> str:
    """Computes SHA-256 hex digest of delegation token text."""
    return hashlib.sha256(token_text.encode("utf-8")).hexdigest()


def compute_intent_hash(request_text: str, root_boundary_scope: dict[str, Any] | Any) -> str:
    """Computes deterministic SHA-256 hex digest over initial request text and root boundary."""
    if hasattr(root_boundary_scope, "model_dump"):
        b_dict = root_boundary_scope.model_dump()
    elif hasattr(root_boundary_scope, "__dict__"):
        b_dict = {
            "tools": getattr(root_boundary_scope, "tools", []),
            "files_read": getattr(root_boundary_scope, "files_read", []),
            "files_write": getattr(root_boundary_scope, "files_write", []),
            "network": getattr(root_boundary_scope, "network", []),
            "peer_agents": getattr(root_boundary_scope, "peer_agents", []),
        }
    elif isinstance(root_boundary_scope, dict):
        b_dict = root_boundary_scope
    else:
        b_dict = str(root_boundary_scope)
    combined = f"{request_text}::{canonical_json(b_dict)}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def normalize_scope(boundary: Any) -> dict[str, list[str]]:
    """Extracts a normalized scope dictionary from a boundary specification."""
    if isinstance(boundary, dict):
        tools = boundary.get("tools", [])
        files_read = boundary.get("files_read", [])
        files_write = boundary.get("files_write", [])
        network = boundary.get("network", [])
        peer_agents = boundary.get("peer_agents", [])
    else:
        tools = getattr(boundary, "tools", []) or []
        files_read = getattr(boundary, "files_read", []) or []
        files_write = getattr(boundary, "files_write", []) or []
        network = getattr(boundary, "network", []) or []
        peer_agents = getattr(boundary, "peer_agents", []) or []

    return {
        "files_read": sorted(set(str(x) for x in files_read)),
        "files_write": sorted(set(str(x) for x in files_write)),
        "network": sorted(set(str(x) for x in network)),
        "peer_agents": sorted(set(str(x) for x in peer_agents)),
        "tools": sorted(set(str(x) for x in tools)),
    }


def is_single_pattern_subset(cp: str, pp: str) -> bool:
    """Treats as a subset only:
    - identical patterns
    - a literal path the parent pattern matches
    - dir/* or dir/** inside the same or a wider parent directory pattern
    Refuses anything with ?, [...] or [!..] on either side, .. or absolute paths.
    """
    for p in (cp, pp):
        if "?" in p or "[" in p or "]" in p or ".." in p:
            return False
        if p.startswith("/") or p.startswith("\\"):
            return False

    if cp == pp:
        return True

    # 2. A literal path the parent pattern matches
    if "*" not in cp:
        if pp == "*":
            return "/" not in cp
        if pp == "**":
            return True
        if pp.endswith("/**"):
            prefix = pp[:-3]
            return cp.startswith(prefix + "/")
        if pp.endswith("/*"):
            prefix = pp[:-2]
            if cp.startswith(prefix + "/"):
                rest = cp[len(prefix) + 1 :]
                return "/" not in rest
            return False
        return fnmatch.fnmatch(cp, pp)

    # 3. dir/* or dir/** inside the same or a wider parent directory pattern
    if cp == "**":
        return pp == "**"

    if cp == "*":
        return pp in ("*", "**")

    cp_is_deep = cp.endswith("/**")
    cp_is_shallow = cp.endswith("/*")
    if not (cp_is_deep or cp_is_shallow):
        return False

    cp_dir = cp[:-3] if cp_is_deep else cp[:-2]
    if "*" in cp_dir:
        return False

    if pp == "**":
        return True

    if pp.endswith("/**"):
        pp_dir = pp[:-3]
        if "*" in pp_dir:
            return False
        return cp_dir == pp_dir or cp_dir.startswith(pp_dir + "/")

    if pp.endswith("/*"):
        pp_dir = pp[:-2]
        if not pp_dir or "*" in pp_dir:
            return False
        if cp_is_shallow:
            return cp_dir == pp_dir or cp_dir.startswith(pp_dir + "/")
        return False

    return False


def is_pattern_subset(child_patterns: list[str], parent_patterns: list[str]) -> bool:
    """Checks that every pattern in child_patterns is covered by at least one parent pattern."""
    for cp in child_patterns:
        matched = False
        for pp in parent_patterns:
            if is_single_pattern_subset(cp, pp):
                matched = True
                break
        if not matched:
            return False
    return True


def is_scope_subset(child_scope: dict[str, list[str]], parent_scope: dict[str, list[str]]) -> bool:
    """Validates that child scope only narrows (is a subset of) parent scope."""
    if not set(child_scope.get("tools", [])).issubset(set(parent_scope.get("tools", []))):
        return False
    if not set(child_scope.get("peer_agents", [])).issubset(set(parent_scope.get("peer_agents", []))):
        return False
    if not is_pattern_subset(child_scope.get("files_read", []), parent_scope.get("files_read", [])):
        return False
    if not is_pattern_subset(child_scope.get("files_write", []), parent_scope.get("files_write", [])):
        return False
    if not is_pattern_subset(child_scope.get("network", []), parent_scope.get("network", [])):
        return False
    return True


def mint_delegation_token(
    *,
    org_id: str = "default",
    sub: str,
    txn: str,
    task_id: str,
    agent_id: str,
    chain: list[str],
    depth: int,
    scope: dict[str, list[str]],
    par_hash: str | None,
    intent: str,
    iat: int | None = None,
    exp: int,
    max_depth: int = MAX_DELEGATION_DEPTH,
) -> str:
    """Creates and endorses a new compact delegation token."""
    if int(depth) > int(max_depth):
        raise ValueError(f"Delegation depth {depth} exceeds max_depth {max_depth}")
    now_ts = int(time.time()) if iat is None else int(iat)
    payload_obj = {
        "agent": agent_id,
        "chain": list(chain),
        "depth": int(depth),
        "exp": int(exp),
        "iat": now_ts,
        "intent": intent,
        "iss": org_id,
        "max_depth": int(max_depth),
        "par_hash": par_hash,
        "scope": scope,
        "sub": sub,
        "task": task_id,
        "txn": txn,
        "v": 1,
    }
    payload_canon = canonical_json(payload_obj)
    payload_b64 = b64url_encode(payload_canon.encode("utf-8"))

    from .signing import get_or_create_signing_key

    _, key_id = get_or_create_signing_key(org_id)
    header_obj = {
        "alg": "EdDSA",
        "kid": key_id,
        "typ": "agd+jwt",
    }
    header_b64 = b64url_encode(canonical_json(header_obj).encode("utf-8"))

    # JWS signing input: ASCII(header_b64url + "." + payload_b64url)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig, signed_kid = sign_bytes(signing_input, org_id=org_id)
    if signed_kid != key_id:
        raise RuntimeError("Organisation key changed while the token was being signed")
    sig_b64 = b64url_encode(sig)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_delegation_token(token_text: str) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    """Splits and decodes token into (header, payload, signature_bytes)."""
    parts = token_text.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid delegation token structure: expected 3 dot-separated parts")
    header_json = b64url_decode(parts[0]).decode("utf-8")
    payload_json = b64url_decode(parts[1]).decode("utf-8")
    sig_bytes = b64url_decode(parts[2])

    header = json.loads(header_json)
    payload = json.loads(payload_json)
    return header, payload, sig_bytes


def verify_delegation_token(
    token_text: str,
    pubkey: Any = None,
    current_time: int | None = None,
    org_id: str | None = None,
    check_expiry: bool = True,
) -> tuple[bool, str, dict[str, Any]]:
    """Verifies a single delegation token offline.

    Checks:
    - structure and algorithms
    - expiry against current timestamp (skipped with check_expiry=False, for looking at a
      finished job later: its tokens have expired, but their signatures still verify)
    - Ed25519 signature verification against public key for kid
    """
    try:
        parts = token_text.strip().split(".")
        if len(parts) != 3:
            return False, "Invalid token structure: expected 3 parts", {}
        header, payload, sig_bytes = decode_delegation_token(token_text)
    except Exception as exc:
        return False, f"Token decoding failed: {exc}", {}

    if header.get("alg") != "EdDSA" or header.get("typ") != "agd+jwt":
        return False, f"Unsupported header parameters: alg={header.get('alg')} typ={header.get('typ')}", payload

    kid = header.get("kid")
    if not kid:
        return False, "Missing kid in header", payload

    token_org = payload.get("iss", "default")
    if org_id is not None and token_org != org_id:
        return False, f"Org mismatch: token issued for '{token_org}', expected '{org_id}'", payload

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

    # Locate public key
    target_pk = None
    if pubkey is not None:
        target_pk = parse_public_key(pubkey)

    if target_pk is None:
        pub_keys = load_public_keys(token_org)
        for pk_entry in pub_keys:
            if pk_entry.get("key_id") == kid:
                target_pk = parse_public_key(pk_entry.get("public_key"))
                break

    if target_pk is None:
        return False, f"Unknown public key identifier: {kid}", payload

    if not verify_bytes(target_pk, sig_bytes, signing_input):
        return False, "Cryptographic signature validation failed", payload

    now_ts = int(time.time()) if current_time is None else int(current_time)
    exp = payload.get("exp", 0)
    if check_expiry and now_ts > exp:
        return False, f"Token expired: expiry {exp} < current {now_ts}", payload

    return True, "Valid delegation token", payload


def verify_chain_tokens(
    tokens: list[str],
    storage: Any = None,
    current_time: int | None = None,
) -> tuple[bool, str]:
    """Verifies the whole token chain offline and confirms control plane state.

    Invariants enforced across sequence (ordered root -> leaf):
    - Valid signature on each token
    - par_hash chain: leaf par_hash == sha256(parent token) back to root (par_hash=None)
    - scope only narrows monotonically
    - exp monotonically non-increasing
    - depth increases by 1 each hop, <= max_depth (4)
    - no repeated agent in chain (cycle check)
    - sub, txn, intent constant throughout chain
    - Control plane: no task in chain is frozen, stopped or finished
    """
    if not tokens:
        return False, "Token chain cannot be empty"

    now_ts = int(time.time()) if current_time is None else int(current_time)
    decoded_payloads: list[dict[str, Any]] = []

    # 1. Verify individual token signatures and structure
    for idx, tok in enumerate(tokens):
        valid, msg, payload = verify_delegation_token(tok, current_time=now_ts)
        if not valid:
            return False, f"Token at index {idx} invalid: {msg}"
        decoded_payloads.append(payload)

    # 2. Check root token invariants
    root_payload = decoded_payloads[0]
    if root_payload.get("par_hash") is not None:
        return False, "Root token must have par_hash null"
    if root_payload.get("depth") != 0:
        return False, f"Root token depth must be 0, got {root_payload.get('depth')}"
    if root_payload.get("chain") != [root_payload.get("agent")]:
        return False, "Root token chain must hold only the root agent"
    if root_payload.get("txn") != root_payload.get("task"):
        return False, "Root token txn must be the root task id"

    root_sub = root_payload.get("sub")
    root_txn = root_payload.get("txn")
    root_intent = root_payload.get("intent")

    # 3. Stepwise chain verification
    for i in range(len(tokens)):
        curr_p = decoded_payloads[i]
        curr_tok = tokens[i]

        # Invariants: sub, txn, intent constant
        if curr_p.get("sub") != root_sub:
            return False, f"Chain invariant violated: sub changed at hop {i}"
        if curr_p.get("txn") != root_txn:
            return False, f"Chain invariant violated: txn changed at hop {i}"
        if curr_p.get("intent") != root_intent:
            return False, f"Chain invariant violated: intent changed at hop {i}"

        # No duplicate agents in chain list
        chain_list = curr_p.get("chain", [])
        if len(chain_list) != len(set(chain_list)):
            return False, f"Cycle detected in token chain: {chain_list}"

        # Depth check
        depth = curr_p.get("depth", 0)
        max_d = curr_p.get("max_depth", MAX_DELEGATION_DEPTH)
        if depth > max_d:
            return False, f"Delegation depth {depth} exceeds max_depth {max_d}"

        if i > 0:
            parent_tok = tokens[i - 1]
            parent_p = decoded_payloads[i - 1]

            # Parent hash link
            expected_par_hash = compute_token_hash(parent_tok)
            if curr_p.get("par_hash") != expected_par_hash:
                return False, f"Token par_hash mismatch at hop {i}"

            # Depth increment
            if depth != parent_p.get("depth", 0) + 1:
                return False, f"Token depth mismatch at hop {i}: expected {parent_p.get('depth', 0) + 1}, got {depth}"

            # Expiry narrowing: exp <= parent exp
            if curr_p.get("exp", 0) > parent_p.get("exp", 0):
                return False, f"Child expiry {curr_p.get('exp')} exceeds parent expiry {parent_p.get('exp')} at hop {i}"

            # Scope narrowing: child scope <= parent scope
            if not is_scope_subset(curr_p.get("scope", {}), parent_p.get("scope", {})):
                return False, f"Child scope widens parent scope at hop {i}"

            # Chain progression
            if chain_list != parent_p.get("chain", []) + [curr_p.get("agent")]:
                return False, f"Chain progression mismatch at hop {i}: {chain_list}"

    # 4. Control plane check: verify no task in chain is frozen, stopped or ended
    if storage is not None:
        for p in decoded_payloads:
            tid = p.get("task")
            if not tid:
                continue
            rec = storage.get_task(tid) if hasattr(storage, "get_task") else None
            if rec is not None:
                st = getattr(rec, "status", None)
                st_val = st.value if hasattr(st, "value") else str(st or "")
                # Only a task that is waiting to start or running may sit in a live chain.
                # Finished, failed, stopped (TERMINATED) and expired tasks may start nothing.
                if st_val.upper() not in (TaskLifecycle.PENDING.value, TaskLifecycle.ACTIVE.value):
                    return False, f"Task {tid} in delegation chain is {st_val}"

            if hasattr(storage, "is_task_frozen") and storage.is_task_frozen(tid):
                return False, f"Task {tid} in delegation chain is frozen"

    return True, "Chain validation successful"
