"""Comprehensive tests for A2A delegation tokens and context labels (Part 1 and Part 2)."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from demo.security_monitor.app.core.models import (
    PolicyAction,
    SecuritySeverity,
)
from demo.security_monitor.app.governance.models import (
    EventSource,
    EventVerdict,
    RiskTier,
    TaskAction,
)
from demo.security_monitor.app.gateway.server import create_app
from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.delegation import DelegationManager
from demo.security_monitor.app.governance.delegation_token import (
    MAX_DELEGATION_DEPTH,
    b64url_decode,
    b64url_encode,
    canonical_json,
    compute_intent_hash,
    compute_token_hash,
    decode_delegation_token,
    is_scope_subset,
    mint_delegation_token,
    normalize_scope,
    verify_chain_tokens,
    verify_delegation_token,
)
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    ExpansionRequest,
    ExpansionStatus,
    GovernanceEvent,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.receipt import (
    build_receipt,
    verify_delegation_links,
    verify_receipt,
)
from demo.security_monitor.app.governance.signing import get_or_create_signing_key, sign_bytes
from demo.security_monitor.app.governance.storage import GovernanceStorage


def _make_task(
    task_id: str,
    agent_id: str,
    root_id: str | None = None,
    depth: int = 0,
    chain: list[str] | None = None,
    ws: str = "/tmp/ws",
    status: TaskLifecycle = TaskLifecycle.ACTIVE,
) -> TaskRecord:
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return TaskRecord(
        task_id=task_id,
        agent_id=agent_id,
        owner="test_human",
        team="governance_team",
        status=status,
        created_at=now_utc,
        updated_at=now_utc,
        started_at=now_utc,
        request_text="Perform test task",
        request_hash=hashlib.sha256(b"Perform test task").hexdigest(),
        workspace_root=ws,
        root_task_id=root_id or task_id,
        parent_task_id=None if depth == 0 else root_id,
        depth=depth,
        chain=chain or [agent_id],
    )


# ============================================================================
# PART 1 TESTS: TOKENS AND CHAIN VERIFICATION
# ============================================================================

def test_token_forged_signature_refused():
    """Delegation token with forged signature is rejected offline."""
    scope = {"tools": ["read_file"], "files_read": ["*"], "files_write": [], "network": [], "peer_agents": []}
    tok = mint_delegation_token(
        sub="human_owner",
        txn="txn_root",
        task_id="task_001",
        agent_id="planner",
        chain=["planner"],
        depth=0,
        scope=scope,
        par_hash=None,
        intent="intent_hash_1",
        exp=int(time.time()) + 300,
    )
    parts = tok.split(".")
    forged_sig = b64url_encode(b"0" * 64)
    tampered_tok = f"{parts[0]}.{parts[1]}.{forged_sig}"
    ok, err, payload = verify_delegation_token(tampered_tok)
    assert not ok
    assert "signature" in err.lower() or "validation failed" in err.lower()


def test_token_widened_scope_refused(tmp_path: Path):
    """Child task scope widening relative to parent is rejected."""
    parent_scope = {"tools": ["read_file"], "files_read": ["in/*"], "files_write": [], "network": [], "peer_agents": ["budget"]}
    widened_child_scope = {"tools": ["read_file", "http_post"], "files_read": ["in/*"], "files_write": [], "network": [], "peer_agents": ["budget"]}
    assert not is_scope_subset(widened_child_scope, parent_scope)

    storage = GovernanceStorage(tmp_path / "test_scope.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    token = "tok_parent"
    caller_task_id = "task_caller"
    storage.save_token(token, caller_task_id, "planner")

    ws = tmp_path / "ws_caller"
    ws.mkdir(parents=True, exist_ok=True)
    task = _make_task(caller_task_id, "planner", ws=str(ws))
    storage.save_task(task)

    parent_boundary = TaskBoundary(
        task_id=caller_task_id,
        tools=["call_agent", "read_file"],
        files_read=["in/*"],
        files_write=["out/*"],
        network=[],
        peer_agents=["budget"],
        workspace_root=str(ws),
    )
    storage.save_boundary(parent_boundary)

    now_ts = int(time.time())
    par_tok = mint_delegation_token(
        sub="human",
        txn=caller_task_id,
        task_id=caller_task_id,
        agent_id="planner",
        chain=["planner"],
        depth=0,
        scope={"tools": ["read_file"], "files_read": ["in/*"], "files_write": ["out/*"], "network": [], "peer_agents": ["budget"]},
        par_hash=None,
        intent="intent_1",
        exp=now_ts + 600,
    )
    storage.save_delegation_token(caller_task_id, par_tok, None)


def test_token_replayed_for_another_task():
    """A delegation token minted for task_A cannot validate for task_B."""
    scope = {"tools": ["read_file"], "files_read": [], "files_write": [], "network": [], "peer_agents": []}
    tok = mint_delegation_token(
        sub="human",
        txn="txn_1",
        task_id="task_A",
        agent_id="planner",
        chain=["planner"],
        depth=0,
        scope=scope,
        par_hash=None,
        intent="intent_1",
        exp=int(time.time()) + 300,
    )
    ok, _, payload = verify_delegation_token(tok)
    assert ok
    assert payload["task"] == "task_A"
    assert payload["task"] != "task_B"


def test_token_expired_refused():
    """An expired delegation token fails validation."""
    scope = {"tools": [], "files_read": [], "files_write": [], "network": [], "peer_agents": []}
    past_ts = int(time.time()) - 100
    tok = mint_delegation_token(
        sub="human",
        txn="txn_1",
        task_id="task_exp",
        agent_id="planner",
        chain=["planner"],
        depth=0,
        scope=scope,
        par_hash=None,
        intent="intent_1",
        iat=past_ts - 200,
        exp=past_ts,
    )
    ok, err, _ = verify_delegation_token(tok)
    assert not ok
    assert "expired" in err


def test_token_wrong_org_key_refused():
    """Delegation token endorsed with unknown org key is rejected."""
    scope = {"tools": [], "files_read": [], "files_write": [], "network": [], "peer_agents": []}
    tok = mint_delegation_token(
        org_id="nonexistent_org",
        sub="human",
        txn="txn_1",
        task_id="task_bad_org",
        agent_id="planner",
        chain=["planner"],
        depth=0,
        scope=scope,
        par_hash=None,
        intent="intent_1",
        exp=int(time.time()) + 300,
    )
    ok, err, _ = verify_delegation_token(tok, org_id="default")
    assert not ok


def test_parent_frozen_refuses_child(tmp_path: Path):
    """If parent task is frozen after token issuance, child delegation is refused."""
    storage = GovernanceStorage(tmp_path / "test_frozen.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    token = "tok_frozen"
    caller_task_id = "task_caller_frozen"
    storage.save_token(token, caller_task_id, "planner")

    ws = tmp_path / "ws_frozen"
    ws.mkdir(parents=True, exist_ok=True)
    task = _make_task(caller_task_id, "planner", status=TaskLifecycle.ACTIVE, ws=str(ws))
    storage.save_task(task)
    storage.record_task_freeze(caller_task_id, "operator freeze")

    b = TaskBoundary(
        task_id=caller_task_id,
        tools=["call_agent", "read_file"],
        files_read=[],
        files_write=[],
        network=[],
        peer_agents=["budget"],
        workspace_root=str(ws),
    )
    storage.save_boundary(b)

    with pytest.raises(PermissionError) as exc:
        mgr.delegate_single(token, "budget", {"text": "hello"})
    assert "frozen" in str(exc.value).lower() or "not active" in str(exc.value).lower()


def test_cycle_caught_from_token_chain():
    """A delegation chain containing duplicate agent IDs is rejected."""
    chain = ["planner", "researcher", "planner"]
    assert len(chain) != len(set(chain))


def test_depth_limit_from_token():
    """Delegation tokens enforce maximum depth budget of 4."""
    assert MAX_DELEGATION_DEPTH == 4
    scope = {"tools": [], "files_read": [], "files_write": [], "network": [], "peer_agents": []}
    with pytest.raises(ValueError) as exc:
        mint_delegation_token(
            sub="human",
            txn="txn_1",
            task_id="task_deep",
            agent_id="agent_5",
            chain=["p", "r", "b", "k", "agent_5"],
            depth=5,
            scope=scope,
            par_hash=None,
            intent="intent_1",
            exp=int(time.time()) + 300,
        )
    assert "depth" in str(exc.value).lower()


def test_agent_process_never_holds_delegation_token(tmp_path: Path):
    """The agent execution environment and workspace files never receive the token text."""
    storage = GovernanceStorage(tmp_path / "test_env.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    token = "tok_agent_check"
    caller_task_id = "task_env_caller"
    storage.save_token(token, caller_task_id, "planner")

    ws = tmp_path / "ws_env"
    ws.mkdir(parents=True, exist_ok=True)
    task = _make_task(caller_task_id, "planner", ws=str(ws))
    storage.save_task(task)

    b = TaskBoundary(
        task_id=caller_task_id,
        tools=["call_agent", "read_file"],
        files_read=[],
        files_write=[],
        network=[],
        peer_agents=["budget"],
        workspace_root=str(ws),
    )
    storage.save_boundary(b)

    result = mgr.delegate_single(token, "budget", {"text": "Hello Budget"})
    assert result["status"] == "ok"
    child_id = result["child_task_id"]

    # Retrieve stored token text
    tok_text = storage.get_delegation_token_by_task_id(child_id)
    assert tok_text is not None

    # Inspect child workspace files: token text must NOT appear
    child_ws = tmp_path / "workspaces" / child_id
    if child_ws.exists():
        for f in child_ws.rglob("*"):
            if f.is_file():
                assert tok_text not in f.read_text(encoding="utf-8", errors="ignore")

    # Inspect a2a messages: token text must NOT appear
    msgs = storage.get_a2a_messages(root_task_id=caller_task_id)
    for m in msgs:
        assert tok_text not in json.dumps(m)


def test_receipt_verify_and_tampering(tmp_path: Path):
    """Receipt verifies child delegation token hashes and detects tampering."""
    storage = GovernanceStorage(tmp_path / "test_rcpt.db")
    root_id = "task_rcpt_root"
    child_id = "task_rcpt_child"

    root_task = _make_task(root_id, "planner")
    child_task = _make_task(child_id, "budget", root_id=root_id, depth=1, chain=["planner", "budget"])
    storage.save_task(root_task)
    storage.save_task(child_task)

    b_root = TaskBoundary(task_id=root_id, tools=["call_agent"], files_read=["in/*"], files_write=["out/*"], network=[], peer_agents=["budget"], workspace_root=str(tmp_path))
    b_child = TaskBoundary(task_id=child_id, tools=[], files_read=["in/*"], files_write=[], network=[], peer_agents=[], workspace_root=str(tmp_path))
    storage.save_boundary(b_root)
    storage.save_boundary(b_child)

    now_ts = int(time.time())
    root_tok = mint_delegation_token(
        sub="human",
        txn=root_id,
        task_id=root_id,
        agent_id="planner",
        chain=["planner"],
        depth=0,
        scope={"tools": ["call_agent"], "files_read": ["in/*"], "files_write": ["out/*"], "network": [], "peer_agents": ["budget"]},
        par_hash=None,
        intent="intent_root",
        exp=now_ts + 600,
    )
    storage.save_delegation_token(root_id, root_tok, None)
    root_tok_h = compute_token_hash(root_tok)

    child_tok = mint_delegation_token(
        sub="human",
        txn=root_id,
        task_id=child_id,
        agent_id="budget",
        chain=["planner", "budget"],
        depth=1,
        scope={"tools": [], "files_read": ["in/*"], "files_write": [], "network": [], "peer_agents": []},
        par_hash=root_tok_h,
        intent="intent_root",
        exp=now_ts + 600,
    )
    storage.save_delegation_token(child_id, child_tok, root_tok_h)
    child_tok_h = compute_token_hash(child_tok)

    r_parent = build_receipt(
        task=root_task,
        initial_boundary=b_root,
        requester="human",
        storage=storage,
        os_records=[],
        deliveries=[],
        sensor_status={"kind": "none"},
        isolation={"isolation_level": "process"},
        freeze_events=[],
        termination={"reason": "normal", "exit_code": 0},
        wall_time_s=0.5,
        os_identity=None,
    )

    r_child = build_receipt(
        task=child_task,
        initial_boundary=b_child,
        requester="planner",
        storage=storage,
        os_records=[],
        deliveries=[],
        sensor_status={"kind": "none"},
        isolation={"isolation_level": "process"},
        freeze_events=[],
        termination={"reason": "normal", "exit_code": 0},
        wall_time_s=0.3,
        os_identity=None,
    )

    # Verification passes
    v_res = verify_receipt(r_child, storage=storage, parent_receipt=r_parent)
    assert v_res["ok"]

    # Tampering test: tamper token_hash in child receipt
    tampered_child = json.loads(json.dumps(r_child))
    tampered_child["delegation_token"]["token_hash"] = "0" * 64
    v_bad = verify_receipt(tampered_child, storage=storage, parent_receipt=r_parent)
    assert not v_bad["ok"]


# ============================================================================
# PART 2 TESTS: CONTEXT LABELS AND FLOW RULES
# ============================================================================

def test_label_raising_for_each_source(tmp_path: Path):
    """Integrity and Confidentiality labels rise monotonically upon data ingest."""
    storage = GovernanceStorage(tmp_path / "test_labels.db")
    task_id = "task_label_test"
    token = "tok_lbl"
    storage.save_token(token, task_id, "planner")

    ws = tmp_path / "ws_lbl"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "doc.txt").write_text("Internal doc content", encoding="utf-8")
    (ws / "private_vault.txt").write_text("Private sensitive content", encoding="utf-8")

    task = _make_task(task_id, "planner", ws=str(ws))
    storage.save_task(task)
    storage.save_delegation_token(task_id, "tok_mock_r1", None)

    b = TaskBoundary(
        task_id=task_id,
        tools=["read_file", "http_get", "http_post"],
        files_read=["*"],
        files_write=[],
        network=["*"],
        peer_agents=[],
        workspace_root=str(ws),
        metadata={"private_files": [{"path": "private_vault.txt"}]},
    )
    storage.save_boundary(b)
    storage.update_task_context_label(task_id, integrity="trusted", confidentiality="public")

    broker = ToolBroker(storage)

    # 1. Read internal file raises confidentiality to internal
    broker.read_file(token, "doc.txt")
    lbl1 = storage.get_task_context_label(task_id)
    assert lbl1["confidentiality"] == "internal"
    assert lbl1["integrity"] == "trusted"

    # 2. Read private file raises confidentiality to secret
    broker.read_file(token, "private_vault.txt")
    lbl2 = storage.get_task_context_label(task_id)
    assert lbl2["confidentiality"] == "secret"

    # 3. Reading internal file afterwards does NOT lower confidentiality
    broker.read_file(token, "doc.txt")
    lbl3 = storage.get_task_context_label(task_id)
    assert lbl3["confidentiality"] == "secret"


def test_child_reply_raises_parent_confidentiality(tmp_path: Path):
    """Child final label raises parent label upon receiving child reply."""
    storage = GovernanceStorage(tmp_path / "test_child_lbl.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    token = "tok_parent_lbl"
    caller_task_id = "task_caller_lbl"
    storage.save_token(token, caller_task_id, "planner")

    ws = tmp_path / "ws_par_lbl"
    ws.mkdir(parents=True, exist_ok=True)
    task = _make_task(caller_task_id, "planner", ws=str(ws))
    storage.save_task(task)

    b = TaskBoundary(
        task_id=caller_task_id,
        tools=["call_agent", "read_file"],
        files_read=[],
        files_write=[],
        network=[],
        peer_agents=["budget"],
        workspace_root=str(ws),
    )
    storage.save_boundary(b)
    storage.update_task_context_label(caller_task_id, integrity="trusted", confidentiality="public")

    res = mgr.delegate_single(token, "budget", {"text": "Compute calculation"})
    assert res["status"] == "ok"

    # Receiving child reply raises integrity to untrusted and keeps/raises confidentiality
    broker = ToolBroker(storage)
    broker.delegation_manager = mgr
    par_lbl = storage.get_task_context_label(caller_task_id)
    assert par_lbl["integrity"] == "untrusted"


def test_rule1_secret_requires_flow_approval(tmp_path: Path):
    """Rule 1: while confidential=secret, http_post and call_agent require owner OK."""
    storage = GovernanceStorage(tmp_path / "test_r1.db")
    task_id = "task_r1"
    token = "tok_r1"
    storage.save_token(token, task_id, "planner")

    ws = tmp_path / "ws_r1"
    ws.mkdir(parents=True, exist_ok=True)
    task = _make_task(task_id, "planner", ws=str(ws))
    storage.save_task(task)
    storage.save_delegation_token(task_id, "tok_mock_r1", None)

    b = TaskBoundary(
        task_id=task_id,
        tools=["read_file", "http_post", "call_agent"],
        files_read=[],
        files_write=[],
        network=["127.0.0.1:*"],
        peer_agents=["budget"],
        workspace_root=str(ws),
        enforcement_mode=EnforcementMode.ENFORCE,
    )
    storage.save_boundary(b)
    storage.update_task_context_label(task_id, integrity="trusted", confidentiality="secret")

    broker = ToolBroker(storage)
    broker.default_approval_timeout = 0.2

    # Deny path: times out without operator grant
    with pytest.raises(PermissionError) as exc:
        broker.call_agent(token, "budget", {"text": "hello"})
    assert "denied" in str(exc.value).lower() or "timeout" in str(exc.value).lower()


def test_rule2_untrusted_requires_flow_approval(tmp_path: Path):
    """Rule 2: while integrity=untrusted, call_agent and http_post require owner OK."""
    storage = GovernanceStorage(tmp_path / "test_r2.db")
    task_id = "task_r2"
    token = "tok_r2"
    storage.save_token(token, task_id, "planner")

    ws = tmp_path / "ws_r2"
    ws.mkdir(parents=True, exist_ok=True)
    task = _make_task(task_id, "planner", ws=str(ws))
    storage.save_task(task)
    storage.save_delegation_token(task_id, "tok_mock_r1", None)

    b = TaskBoundary(
        task_id=task_id,
        tools=["read_file", "http_post", "call_agent"],
        files_read=[],
        files_write=[],
        network=["127.0.0.1:*"],
        peer_agents=["budget"],
        workspace_root=str(ws),
        enforcement_mode=EnforcementMode.ENFORCE,
    )
    storage.save_boundary(b)
    storage.update_task_context_label(task_id, integrity="untrusted", confidentiality="public")

    broker = ToolBroker(storage)
    broker.default_approval_timeout = 0.2

    # Deny path: times out without operator grant
    with pytest.raises(PermissionError) as exc:
        broker.call_agent(token, "budget", {"text": "hello"})
    assert "denied" in str(exc.value).lower() or "timeout" in str(exc.value).lower()


def test_observe_mode_records_event_without_blocking(tmp_path: Path):
    """In observe mode, flow policy violations are recorded without raising."""
    storage = GovernanceStorage(tmp_path / "test_obs.db")
    task_id = "task_obs"
    token = "tok_obs"
    storage.save_token(token, task_id, "planner")

    ws = tmp_path / "ws_obs"
    ws.mkdir(parents=True, exist_ok=True)
    task = _make_task(task_id, "planner", ws=str(ws))
    storage.save_task(task)
    storage.save_delegation_token(task_id, "tok_mock_r1", None)

    b = TaskBoundary(
        task_id=task_id,
        tools=["read_file", "http_post", "call_agent"],
        files_read=[],
        files_write=[],
        network=["127.0.0.1:*"],
        peer_agents=["budget"],
        workspace_root=str(ws),
        enforcement_mode=EnforcementMode.OBSERVE,
    )
    storage.save_boundary(b)
    storage.update_task_context_label(task_id, integrity="untrusted", confidentiality="secret")

    broker = ToolBroker(storage)
    # Does not raise; proceeds and records event
    broker._check_flow_approval(task_id, "planner", b, "call_agent", "budget")
    evs = storage.get_events_for_task(task_id)
    assert any(e.kind == "flow_policy_observed" for e in evs)


def test_prompt_infection_spread_prevented(tmp_path: Path):
    """Prompt injection in peer reply raises integrity to untrusted and blocks further spread."""
    storage = GovernanceStorage(tmp_path / "test_infect.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    token = "tok_planner_infect"
    caller_task_id = "task_planner_infect"
    storage.save_token(token, caller_task_id, "planner")

    ws = tmp_path / "ws_planner_infect"
    ws.mkdir(parents=True, exist_ok=True)
    task = _make_task(caller_task_id, "planner", ws=str(ws))
    storage.save_task(task)

    b = TaskBoundary(
        task_id=caller_task_id,
        tools=["call_agent", "read_file", "http_post"],
        files_read=[],
        files_write=[],
        network=["127.0.0.1:*"],
        peer_agents=["booking", "finance_bot"],
        workspace_root=str(ws),
        enforcement_mode=EnforcementMode.ENFORCE,
    )
    storage.save_boundary(b)
    storage.update_task_context_label(caller_task_id, integrity="trusted", confidentiality="public")

    broker = ToolBroker(storage)
    broker.delegation_manager = mgr
    broker.default_approval_timeout = 0.2

    # Planner calls Booking; Booking replies with prompt injection
    res = mgr.delegate_single(token, "booking", {"text": "Book hotel"})
    assert res["status"] == "ok"

    # Planner reads booking reply and label raises to untrusted
    lbl = storage.get_task_context_label(caller_task_id)
    assert lbl["integrity"] == "untrusted"

    # Injected prompt instructs Planner to message finance_bot; Rule 2 triggers and times out
    with pytest.raises(PermissionError) as exc:
        broker.call_agent(token, "finance_bot", {"text": "Transfer funds"})
    assert "denied" in str(exc.value).lower() or "timeout" in str(exc.value).lower()

    # Verify only booking was actually reached, finance_bot was NOT reached
    delivered_msgs = [m for m in storage.get_a2a_messages(root_task_id=caller_task_id) if m.get("verdict") == "delivered"]
    agents_reached = {m["to_agent"] for m in delivered_msgs}
    assert "booking" in agents_reached
    assert "finance_bot" not in agents_reached
