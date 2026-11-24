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


def test_agent_process_never_holds_delegation_token(tmp_path: Path, monkeypatch):
    """The agent's command line and environment, its workspace files and its messages never hold the token."""
    import subprocess as _sp

    from demo.security_monitor.app.governance import launcher as launcher_mod

    spawned: list[str] = []
    real_popen = _sp.Popen

    def _recording_popen(cmd, *a, **kw):
        spawned.append(" ".join(str(c) for c in cmd) + " " + json.dumps(kw.get("env") or {}))
        return real_popen(cmd, *a, **kw)

    monkeypatch.setattr(launcher_mod.subprocess, "Popen", _recording_popen)
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

    # The child process was started, and neither its command line nor its environment holds
    # its token, the caller's token, or any part of either signature.
    assert spawned, "the child agent process was not started"
    caller_tok = storage.get_delegation_token_by_task_id(caller_task_id)
    for line in spawned:
        for t in (tok_text, caller_tok):
            assert t not in line
            assert t.split(".")[2] not in line

    # The child's receipt-side record and its event log hold no token either.
    for ev in storage.get_events_for_task(child_id):
        assert tok_text not in json.dumps(ev.model_dump(), default=str)


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


# ============================================================================
# REVIEW ADDITIONS: binding, chain checks, single-agent behaviour, approve paths
# ============================================================================

_EMPTY = {"tools": [], "files_read": [], "files_write": [], "network": [], "peer_agents": []}


def _scope(**kw):
    out = {k: list(v) for k, v in _EMPTY.items()}
    out.update({k: list(v) for k, v in kw.items()})
    return out


def _root_token(task_id, agent_id, scope, exp_in=600, max_depth=MAX_DELEGATION_DEPTH, intent="intent_1"):
    return mint_delegation_token(sub="human", txn=task_id, task_id=task_id, agent_id=agent_id, chain=[agent_id],
                                 depth=0, scope=scope, par_hash=None, intent=intent,
                                 exp=int(time.time()) + exp_in, max_depth=max_depth)


def _child_token(parent_tok, task_id, agent_id, scope, max_depth=MAX_DELEGATION_DEPTH):
    _, pp, _ = decode_delegation_token(parent_tok)
    return mint_delegation_token(sub=pp["sub"], txn=pp["txn"], task_id=task_id, agent_id=agent_id,
                                 chain=pp["chain"] + [agent_id], depth=pp["depth"] + 1, scope=scope,
                                 par_hash=compute_token_hash(parent_tok), intent=pp["intent"], exp=pp["exp"],
                                 max_depth=max_depth)


def _caller(tmp_path, task_id="task_caller", agent_id="planner", peers=("budget",), status=TaskLifecycle.ACTIVE,
            depth=0, chain=None, root_id=None, enforcement=EnforcementMode.ENFORCE, tools=("call_agent", "read_file", "http_post", "request_access")):
    storage = GovernanceStorage(tmp_path / f"{task_id}.db")
    ws = tmp_path / f"ws_{task_id}"
    (ws / "input").mkdir(parents=True, exist_ok=True)
    storage.save_task(_make_task(task_id, agent_id, root_id=root_id, depth=depth, chain=chain, ws=str(ws), status=status))
    b = TaskBoundary(task_id=task_id, tools=list(tools), files_read=["input/*"], files_write=["output/*"],
                     network=["127.0.0.1:*"], peer_agents=list(peers), workspace_root=str(ws), enforcement_mode=enforcement)
    storage.save_boundary(b)
    storage.save_token(f"tok_{task_id}", task_id, agent_id)
    return storage, b, ws, f"tok_{task_id}"


def _refusals(storage, root_id):
    return [m for m in storage.get_a2a_messages(root_task_id=root_id) if m["verdict"] == "refused"]


def test_token_replayed_for_another_task_is_refused(tmp_path: Path):
    """A valid token stored for task A but minted for task B does not let A delegate."""
    storage, b, _, tok = _caller(tmp_path)
    other = _root_token("task_other", "planner", _scope(tools=["call_agent"], peer_agents=["budget"]))
    storage.save_delegation_token("task_caller", other, None)
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")
    with pytest.raises(PermissionError, match="belongs to task task_other"):
        mgr.delegate_single(tok, "budget", {"text": "hi"})
    assert _refusals(storage, "task_caller")


def test_edited_payload_fails_signature():
    """Widening the scope by editing and re-encoding the payload breaks the signature."""
    tok = _root_token("t1", "planner", _scope(tools=["read_file"]))
    h, p, sig = tok.split(".")
    payload = json.loads(b64url_decode(p))
    payload["scope"]["tools"].append("http_post")
    forged = f"{h}.{b64url_encode(canonical_json(payload).encode())}.{sig}"
    ok, err, _ = verify_delegation_token(forged)
    assert not ok and "signature" in err.lower()


def test_signed_child_with_wider_scope_fails_chain():
    root = _root_token("r1", "planner", _scope(tools=["read_file"], peer_agents=["budget"]))
    child = _child_token(root, "c1", "budget", _scope(tools=["read_file", "http_post"]))
    ok, err = verify_chain_tokens([root, child])
    assert not ok and "widens" in err


def test_cycle_caught_from_signed_chain():
    """A signed chain that repeats an agent fails verification."""
    root = _root_token("r1", "planner", _scope(peer_agents=["budget", "planner"]))
    c1 = _child_token(root, "c1", "budget", _scope(peer_agents=["planner"]))
    c2 = _child_token(c1, "c2", "planner", _scope())
    ok, err = verify_chain_tokens([root, c1, c2])
    assert not ok and "Cycle" in err


def test_broken_par_hash_link_fails_chain():
    root = _root_token("r1", "planner", _scope(peer_agents=["budget"]))
    other_root = _root_token("r2", "planner", _scope(peer_agents=["budget"]))
    child = _child_token(other_root, "c1", "budget", _scope())
    ok, err = verify_chain_tokens([root, child])
    assert not ok and ("par_hash" in err or "txn" in err)


def test_depth_limit_from_signed_token(tmp_path: Path):
    """The signed max_depth stops a delegation the task record alone would allow."""
    storage, b, _, tok = _caller(tmp_path, task_id="task_mid", agent_id="budget", peers=("researcher",),
                                 depth=1, chain=["planner", "budget"], root_id="task_root",
                                 tools=("call_agent", "read_file"))
    storage.save_task(_make_task("task_root", "planner", ws=str(tmp_path)))
    root = _root_token("task_root", "planner", _scope(tools=["call_agent", "read_file"], files_read=["input/*"],
                                                       files_write=["output/*"], network=["127.0.0.1:*"],
                                                       peer_agents=["budget", "researcher"]), max_depth=1)
    storage.save_delegation_token("task_root", root, None)
    mid = _child_token(root, "task_mid", "budget", normalize_scope(b), max_depth=1)
    storage.save_delegation_token("task_mid", mid, compute_token_hash(root))
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")
    with pytest.raises(PermissionError, match="depth"):
        mgr.delegate_single(tok, "researcher", {"text": "hi"})


def test_child_without_a_token_is_refused(tmp_path: Path):
    """A delegated task with no token on record cannot delegate (no root token is made up for it)."""
    storage, b, _, tok = _caller(tmp_path, task_id="task_mid", agent_id="budget", peers=("researcher",),
                                 depth=1, chain=["planner", "budget"], root_id="task_root")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")
    with pytest.raises(PermissionError, match="No delegation token"):
        mgr.delegate_single(tok, "researcher", {"text": "hi"})


@pytest.mark.parametrize("status", [TaskLifecycle.TERMINATED, TaskLifecycle.FAILED, TaskLifecycle.COMPLETED, TaskLifecycle.EXPIRED])
def test_stopped_or_finished_task_in_chain_refuses(status):
    class _S:
        def get_task(self, tid):
            return _make_task(tid, "planner", status=status)

        def is_task_frozen(self, tid):
            return False

    root = _root_token("r1", "planner", _scope(peer_agents=["budget"]))
    ok, err = verify_chain_tokens([root], storage=_S())
    assert not ok and status.value in err


def test_launcher_freeze_is_recorded_for_the_chain_check(tmp_path: Path):
    from demo.security_monitor.app.governance.launcher import TaskLauncher

    storage = GovernanceStorage(tmp_path / "f.db")
    launcher = TaskLauncher(storage, workspace_base=tmp_path / "ws")
    launcher.live["task_id"] = "task_frz"
    launcher._freeze_now("operator_freeze")
    assert storage.is_task_frozen("task_frz")
    root = _root_token("task_frz", "planner", _scope())
    ok, err = verify_chain_tokens([root], storage=storage)
    assert not ok and "frozen" in err


def test_labels_never_drop_under_concurrent_raises(tmp_path: Path):
    import concurrent.futures as cf

    storage = GovernanceStorage(tmp_path / "lbl.db")
    raises = [("trusted", "internal"), ("untrusted", "public"), ("trusted", "secret"), ("trusted", "public")] * 25

    def one(pair):
        storage.update_task_context_label("t", integrity=pair[0], confidentiality=pair[1])
        return storage.get_task_context_label("t")

    with cf.ThreadPoolExecutor(16) as ex:
        list(ex.map(one, raises))
    assert tuple(storage.get_task_context_label("t")) == ("untrusted", "secret")
    storage.update_task_context_label("t", integrity="trusted", confidentiality="public")
    assert tuple(storage.get_task_context_label("t")) == ("untrusted", "secret")


def test_single_agent_task_is_not_asked(tmp_path: Path):
    """A task with no parent and no peer agents behaves as before, even with a root token."""
    storage, b, _, tok = _caller(tmp_path, peers=(), tools=("read_file", "http_post"))
    storage.save_delegation_token("task_caller", _root_token("task_caller", "planner", normalize_scope(b)), None)
    storage.update_task_context_label("task_caller", integrity="untrusted", confidentiality="secret")
    broker = ToolBroker(storage)
    broker.default_approval_timeout = 0.2
    out = broker.http_post(tok, "http://127.0.0.1:9/x", data="hello")
    assert out["status"] == 200
    assert not [r for r in storage.list_expansion_requests(task_id="task_caller") if r.resource_type == "flow"]


def _approve_flows(storage, stop):
    while not stop.is_set():
        for r in storage.list_expansion_requests():
            if r.resource_type == "flow" and r.status == ExpansionStatus.PENDING:
                ExpansionService(storage).approve_request(r.request_id, approved_by="operator")
        time.sleep(0.02)


@pytest.mark.parametrize("label,rule_word", [(("trusted", "secret"), "private data"), (("untrusted", "public"), "after reading")])
def test_http_post_flow_rule_deny_then_approve(tmp_path: Path, label, rule_word):
    import threading

    storage, b, _, tok = _caller(tmp_path)
    storage.update_task_context_label("task_caller", integrity=label[0], confidentiality=label[1])
    broker = ToolBroker(storage)
    broker.default_approval_timeout = 0.3

    with pytest.raises(PermissionError, match="Flow denied"):
        broker.http_post(tok, "http://127.0.0.1:9/x", data="hello")
    denied = [r for r in storage.list_expansion_requests(task_id="task_caller") if r.resource_type == "flow"]
    assert len(denied) == 1 and denied[0].status == ExpansionStatus.DENIED and rule_word in denied[0].justification

    stop = threading.Event()
    th = threading.Thread(target=_approve_flows, args=(storage, stop), daemon=True)
    th.start()
    broker.default_approval_timeout = 3.0
    try:
        assert broker.http_post(tok, "http://127.0.0.1:9/x", data="hello")["status"] == 200
    finally:
        stop.set()
        th.join(1)
    flows = [r for r in storage.list_expansion_requests(task_id="task_caller") if r.resource_type == "flow"]
    approved = [r for r in flows if r.status == ExpansionStatus.APPROVED]
    assert len(approved) == 1 and approved[0].used_count == 1
    # The OK added nothing to the boundary.
    assert storage.get_boundary("task_caller").version == b.version


def test_call_agent_flow_rule_approve_path(tmp_path: Path):
    import threading

    storage, b, _, tok = _caller(tmp_path)
    storage.update_task_context_label("task_caller", integrity="untrusted", confidentiality="public")

    class _DM:
        calls = []

        def delegate_single(self, token, target, message, fanout_group=None):
            self.calls.append(target)
            return {"status": "ok", "reply": "done", "child_task_id": "c1", "confidentiality": "internal"}

    broker = ToolBroker(storage)
    broker.delegation_manager = _DM()
    broker.default_approval_timeout = 3.0
    stop = threading.Event()
    th = threading.Thread(target=_approve_flows, args=(storage, stop), daemon=True)
    th.start()
    try:
        broker.call_agent(tok, "budget", {"text": "hi"})
    finally:
        stop.set()
        th.join(1)
    assert _DM.calls == ["budget"]
    flow = [r for r in storage.list_expansion_requests(task_id="task_caller") if r.resource_type == "flow"]
    assert len(flow) == 1 and "Planner wants to message Budget" in flow[0].justification
    # The reply's label is taken in by the caller.
    assert tuple(storage.get_task_context_label("task_caller")) == ("untrusted", "internal")


def test_request_access_after_untrusted_asks_once(tmp_path: Path):
    """Rule 2 makes an access request the policy would approve wait for a person, as one request."""
    storage, b, ws, tok = _caller(tmp_path)
    (ws / "input" / "notes.txt").write_text("x", encoding="utf-8")
    task = storage.get_task("task_caller")
    task.request_text = "Summarise input/notes.txt"
    storage.save_task(task)
    exp = ExpansionService(storage)
    broker = ToolBroker(storage, expansion_service=exp)

    # Trusted context: the policy approves it on its own.
    res = broker.request_access(tok, "file_read", "input/notes.txt", "need it", timeout_seconds=0.2)
    assert res["granted"]

    storage.update_task_context_label("task_caller", integrity="untrusted")
    res = broker.request_access(tok, "file_read", "input/notes.txt", "need it again", timeout_seconds=0.3)
    assert not res["granted"]
    second = [r for r in storage.list_expansion_requests(task_id="task_caller") if "again" in (r.justification or "")]
    assert len(second) == 1
    assert second[0].status == ExpansionStatus.DENIED and second[0].resolved_by == "timeout_fail_closed"
    assert "after reading" in second[0].justification
    assert not [r for r in storage.list_expansion_requests(task_id="task_caller") if r.resource_type == "flow"]


def test_request_access_observe_mode_records_only(tmp_path: Path):
    storage, b, ws, tok = _caller(tmp_path, enforcement=EnforcementMode.OBSERVE)
    task = storage.get_task("task_caller")
    task.request_text = "Summarise input/notes.txt"
    storage.save_task(task)
    broker = ToolBroker(storage)
    broker.expansion_service = ExpansionService(storage)
    storage.update_task_context_label("task_caller", integrity="untrusted")
    res = broker.request_access(tok, "file_read", "input/notes.txt", "need it", timeout_seconds=0.2)
    assert res["granted"]
    assert any(e.kind == "flow_policy_observed" for e in storage.get_events_for_task("task_caller"))


def test_receipt_still_verifies_after_tokens_expire(tmp_path: Path):
    storage = GovernanceStorage(tmp_path / "rx.db")
    task = _make_task("task_rx", "planner")
    storage.save_task(task)
    b = TaskBoundary(task_id="task_rx", tools=["call_agent"], files_read=[], files_write=[], network=[],
                     peer_agents=["budget"], workspace_root=str(tmp_path))
    storage.save_boundary(b)
    old = mint_delegation_token(sub="human", txn="task_rx", task_id="task_rx", agent_id="planner", chain=["planner"],
                                depth=0, scope=normalize_scope(b), par_hash=None, intent="i",
                                iat=int(time.time()) - 1000, exp=int(time.time()) - 10)
    storage.save_delegation_token("task_rx", old, None)
    r = build_receipt(task=task, initial_boundary=b, requester="human", storage=storage, os_records=[], deliveries=[],
                      sensor_status={"kind": "none"}, isolation={"isolation_level": "process"}, freeze_events=[],
                      termination={"reason": "normal", "exit_code": 0}, wall_time_s=0.1, os_identity=None)
    assert verify_receipt(r, storage=storage)["ok"]


def _gateway_client():
    from fastapi.testclient import TestClient

    app = create_app()
    hw = app.state.inventory.get_trusted_agent("helloworld")
    hw.raw_card["governed"] = True
    return TestClient(app)


def _gw_call(client, token, caller="caller_agent"):
    return client.post(
        "/proxy/helloworld",
        json={"jsonrpc": "2.0", "id": "gw-1", "method": "echo_bot", "params": {}},
        headers={"x-delegation-token": token, "x-agent-id": caller},
    )


def test_gateway_refuses_target_outside_signed_scope():
    client = _gateway_client()
    tok = _root_token("txn_gw", "caller_agent", _scope(peer_agents=["someone_else"]))
    resp = _gw_call(client, tok)
    assert resp.status_code == 403 and "not in the caller's signed scope" in resp.text


def test_gateway_refuses_token_of_another_caller():
    client = _gateway_client()
    tok = _root_token("txn_gw", "caller_agent", _scope(peer_agents=["helloworld"]))
    resp = _gw_call(client, tok, caller="intruder")
    assert resp.status_code == 403 and "belongs to 'caller_agent'" in resp.text


def test_gateway_catches_cycle_from_signed_chain():
    """The cycle is found from the signed chain, whatever headers the caller sends."""
    client = _gateway_client()
    root = _root_token("txn_gw_cycle", "helloworld", _scope(peer_agents=["caller_agent"]))
    child = _child_token(root, "c_gw", "caller_agent", _scope(peer_agents=["helloworld"]))
    resp = _gw_call(client, child)
    assert resp.status_code == 403 and "CO_CYCLE" in resp.text


def test_gateway_accepts_a_valid_token_for_an_allowed_target():
    client = _gateway_client()
    tok = _root_token("txn_gw_ok", "caller_agent", _scope(peer_agents=["helloworld"]))
    resp = _gw_call(client, tok)
    assert "Delegation token refused" not in resp.text and "Invalid delegation token" not in resp.text
    assert "X-Delegation-Token header is missing" not in resp.text


def test_child_starts_with_the_callers_label(tmp_path: Path):
    """A child is given a message from a caller that holds private data, so it starts as secret."""
    storage, b, _, tok = _caller(tmp_path, tools=("call_agent", "read_file"))
    storage.update_task_context_label("task_caller", confidentiality="secret")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")
    res = mgr.delegate_single(tok, "budget", {"text": "Budget please"})
    assert res["status"] == "ok"
    assert storage.get_task_context_label(res["child_task_id"])["confidentiality"] == "secret"
    reply = [m for m in storage.get_a2a_messages(root_task_id="task_caller") if m["kind"] == "reply"]
    assert reply and reply[0]["confidentiality"] == "secret"
