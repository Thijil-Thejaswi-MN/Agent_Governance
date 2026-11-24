"""Tests for audit3 fixes across delegation, broker, boundaries, and API.

Items covered:
1. Child keeps parent's private-data settings
2. Rule 1 applies before private file sent
3. Child boundary ceiling cap caller
4. Network and peer tools checked against boundary
5. Pattern subsets strict validation
6. Freeze reaches starting child
7. Server-side input copy symlink race
8. One cap per root
9. Rule 1 covers http_get with data
10. Run stream view check
11. Data-rule OKs:
    a. Non-pending approval returns 409
    b. request_access refuses flow
    c. Delegation pre-checks run before flow check
    d. Job owner developer can answer flow requests
12. Messages show launcher failure as failed
13. read_file 1 MB limit
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from demo.security_monitor.app.gateway.server import create_app
from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.delegation import (
    DelegationManager,
    _GLOBAL_ROOT_CHILDREN_LOCK,
    _GLOBAL_RUNNING_CHILDREN_BY_ROOT,
)
from demo.security_monitor.app.governance.delegation_token import (
    compute_intent_hash,
    compute_token_hash,
    is_pattern_subset,
    is_scope_subset,
    is_single_pattern_subset,
    mint_delegation_token,
    normalize_scope,
)
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec
from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    ExpansionRequest,
    ExpansionStatus,
    RiskTier,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.roles import PermissionMatrix, Role, UserSession
from demo.security_monitor.app.governance.storage import GovernanceStorage


def _make_task_rec(
    task_id: str,
    agent_id: str,
    root_id: str | None = None,
    depth: int = 0,
    chain: list[str] | None = None,
    ws: str = "/tmp/ws",
    status: TaskLifecycle = TaskLifecycle.ACTIVE,
    owner: str = "test_owner",
    team: str = "governance_team",
) -> TaskRecord:
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return TaskRecord(
        task_id=task_id,
        agent_id=agent_id,
        owner=owner,
        team=team,
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


# ---------------------------------------------------------------------------
# Item 1: Child keeps parent's private-data settings
# ---------------------------------------------------------------------------
def test_item1_child_inherits_private_data_settings(tmp_path: Path):
    """Child boundary gets parent private-data settings and raises label to secret on read."""
    storage = GovernanceStorage(tmp_path / "item1.db")
    ws_base = tmp_path / "workspaces"
    mgr = DelegationManager(storage, workspace_base=ws_base)

    root_task_id = "task_p_root"
    tok_p = "tok_p_val"
    storage.save_token(tok_p, root_task_id, "planner")

    ws_p = ws_base / root_task_id
    (ws_p / "input").mkdir(parents=True, exist_ok=True)
    (ws_p / "input" / "budget_policy.txt").write_text("SUPER_CONFIDENTIAL_BUDGET", encoding="utf-8")

    parent_task = _make_task_rec(root_task_id, "planner", ws=str(ws_p))
    storage.save_task(parent_task)

    parent_boundary = TaskBoundary(
        task_id=root_task_id,
        tools=["read_file", "call_agent", "http_post"],
        files_read=["input/*", "input/budget_policy.txt"],
        files_write=["output/*"],
        network=["127.0.0.1:*"],
        peer_agents=["budget"],
        workspace_root=str(ws_p),
        metadata={
            "canary": "CANARY_ITEM1_SECRET",
            "private_files": [{"path": "input/budget_policy.txt"}],
            "sensitive_patterns": ["*credentials*"],
        },
    )
    storage.save_boundary(parent_boundary)

    root_tok = mint_delegation_token(
        sub="human",
        txn=root_task_id,
        task_id=root_task_id,
        agent_id="planner",
        chain=["planner"],
        depth=0,
        scope=normalize_scope(parent_boundary),
        par_hash=None,
        intent="intent_1",
        exp=int(time.time()) + 3600,
    )
    storage.save_delegation_token(root_task_id, root_tok, None)

    # Delegate to budget
    res = mgr.delegate_single(
        token=tok_p,
        target_agent="budget",
        message={"text": "Review budget"},
    )
    child_id = res["child_task_id"]
    child_b = storage.get_boundary(child_id)
    assert child_b is not None
    assert child_b.metadata.get("canary") == "CANARY_ITEM1_SECRET"
    assert child_b.metadata.get("private_files") == [{"path": "input/budget_policy.txt"}]
    assert child_b.metadata.get("sensitive_patterns") == ["*credentials*"]

    # Child reads private file: label rises to secret
    child_tok = f"child_tok_{child_id}"
    storage.save_token(child_tok, child_id, "budget")
    broker = ToolBroker(storage)
    broker.read_file(child_tok, "input/budget_policy.txt")

    lbl = storage.get_task_context_label(child_id)
    assert lbl["confidentiality"] == "secret"

    # With secret label, child http_post needs an OK
    broker.default_approval_timeout = 0.2
    with pytest.raises(PermissionError):
        broker.http_post(child_tok, "http://127.0.0.1:9000/report", data="leak")

    # Reply contains_private check from delegate_single
    msgs = storage.get_a2a_messages(root_task_id=root_task_id)
    reply_msg = next(m for m in msgs if m["kind"] == "reply")
    assert reply_msg["contains_private"] is True


# ---------------------------------------------------------------------------
# Item 2: Rule 1 applies before private file sent
# ---------------------------------------------------------------------------
def test_item2_http_post_private_file_path_triggers_flow_approval(tmp_path: Path):
    """Initial http_post with private file_path asks for an OK before egress."""
    storage = GovernanceStorage(tmp_path / "item2.db")
    task_id = "task_post_priv"
    tok = "tok_post_priv"
    storage.save_token(tok, task_id, "planner")

    ws = tmp_path / "ws_item2"
    (ws / "input").mkdir(parents=True, exist_ok=True)
    priv_file = ws / "input" / "vault.txt"
    priv_file.write_text("TOP_SECRET_PASSPORT", encoding="utf-8")

    task = _make_task_rec(task_id, "planner", ws=str(ws))
    storage.save_task(task)

    b = TaskBoundary(
        task_id=task_id,
        tools=["http_post", "read_file", "call_agent"],
        files_read=["input/*"],
        files_write=["output/*"],
        network=["127.0.0.1:*"],
        peer_agents=["budget"],
        workspace_root=str(ws),
        metadata={"private_files": [{"path": "input/vault.txt"}]},
    )
    storage.save_boundary(b)

    broker = ToolBroker(storage)
    broker.default_approval_timeout = 0.2

    # Denied by timeout: nothing sent, raises PermissionError
    with pytest.raises(PermissionError, match="Flow denied|timeout"):
        broker.http_post(tok, "http://127.0.0.1:9000/upload", file_path="input/vault.txt")

    # Label should now be secret because read_file was evaluated before the flow check
    lbl = storage.get_task_context_label(task_id)
    assert lbl["confidentiality"] == "secret"


# ---------------------------------------------------------------------------
# Item 3: Child boundary ceiling cap caller
# ---------------------------------------------------------------------------
def test_item3_child_boundary_not_derived_from_prompt_text(tmp_path: Path):
    """Message text does not grant child extra tools, hosts, or write paths."""
    storage = GovernanceStorage(tmp_path / "item3.db")
    launcher = TaskLauncher(storage, workspace_base=tmp_path / "workspaces")

    # Child token scope without http_get and without evil.com
    scope = {
        "tools": ["read_file", "write_file"],
        "files_read": ["input/*"],
        "files_write": ["output/*"],
        "network": [],
        "peer_agents": [],
    }
    tok = mint_delegation_token(
        sub="tester",
        txn="root_item3",
        task_id="child_item3",
        agent_id="budget",
        chain=["planner", "budget"],
        depth=1,
        scope=scope,
        par_hash="parent_hash",
        intent="intent_3",
        exp=int(time.time()) + 3600,
    )

    spec = TaskSpec(
        prompt="fetch https://evil.com and patch src/x.py",
        task_id="child_item3",
        agent_id="budget",
        parent_task_id="root_item3",
        root_task_id="root_item3",
        depth=1,
        chain=["planner", "budget"],
        agent_tools=["read_file", "write_file"],
        boundary_model="v1.1",
        files_read=["input/*"],
        output_targets=["output/*"],
        network=[],
        peer_agents=[],
    )

    ws_dir = tmp_path / "ws_item3"
    ws_dir.mkdir(parents=True, exist_ok=True)
    task, boundary = launcher.derive_boundary(spec, ws_dir, EnforcementMode.ENFORCE)

    assert "http_get" not in boundary.tools
    assert "evil.com" not in str(boundary.network)
    assert not any("src" in p for p in boundary.files_write)
    assert boundary.metadata.get("boundary_model") == "v1.1"


# ---------------------------------------------------------------------------
# Item 4: Network and peer tools checked against boundary
# ---------------------------------------------------------------------------
def test_item4_tool_evaluation_enforced_for_network_and_peer_tools(tmp_path: Path):
    """Task without http_post in tools cannot POST even if network host is listed."""
    storage = GovernanceStorage(tmp_path / "item4.db")
    task_id = "task_no_post"
    tok = "tok_no_post"
    storage.save_token(tok, task_id, "planner")

    ws = tmp_path / "ws_item4"
    ws.mkdir(parents=True, exist_ok=True)
    storage.save_task(_make_task_rec(task_id, "planner", ws=str(ws)))

    b = TaskBoundary(
        task_id=task_id,
        tools=["http_get", "read_file"],  # No http_post
        files_read=["*"],
        files_write=[],
        network=["127.0.0.1:*"],
        peer_agents=["budget"],
        workspace_root=str(ws),
    )
    storage.save_boundary(b)

    broker = ToolBroker(storage)
    with pytest.raises(PermissionError, match="not granted in task boundary"):
        broker.http_post(tok, "http://127.0.0.1:9000/data", data="test")

    # Task without call_agent in tools cannot delegate
    b_no_agent = TaskBoundary(
        task_id="task_no_agent",
        tools=["http_get", "read_file"],  # No call_agent
        files_read=["*"],
        files_write=[],
        network=["127.0.0.1:*"],
        peer_agents=["budget"],
        workspace_root=str(ws),
    )
    storage.save_task(_make_task_rec("task_no_agent", "planner", ws=str(ws)))
    storage.save_boundary(b_no_agent)
    storage.save_token("tok_no_agent", "task_no_agent", "planner")

    with pytest.raises(PermissionError, match="not granted in task boundary"):
        broker.call_agent("tok_no_agent", "budget", {"text": "hi"})


# ---------------------------------------------------------------------------
# Item 5: Pattern subsets strict validation
# ---------------------------------------------------------------------------
def test_item5_pattern_subsets_strict_validation():
    """Verify strict subset rules rejecting globs like ?, [...], [!...], and non-subsets."""
    # Disallowed syntax
    assert not is_single_pattern_subset("input/[!p]*", "input/*")
    assert not is_single_pattern_subset("data/?", "data/*")
    assert not is_single_pattern_subset("/etc/*", "*")
    assert not is_single_pattern_subset("../*", "*")
    assert not is_single_pattern_subset("**", "*")

    # Valid subsets
    assert is_single_pattern_subset("input/*", "input/*")
    assert is_single_pattern_subset("input/data.csv", "input/*")
    assert is_single_pattern_subset("dir/*", "dir/**")
    assert is_single_pattern_subset("dir/sub/*", "dir/*")
    assert is_single_pattern_subset("dir/sub/file.txt", "dir/**")

    # Wider parent check
    assert not is_single_pattern_subset("dir/**", "dir/*")


# ---------------------------------------------------------------------------
# Item 6: Freeze reaches starting child
# ---------------------------------------------------------------------------
def test_item6_freeze_during_input_copy_stops_child_start(tmp_path: Path):
    """Parent freeze before child starts prevents child from running."""
    storage = GovernanceStorage(tmp_path / "item6.db")
    parent_launcher = TaskLauncher(storage, workspace_base=tmp_path / "workspaces")
    parent_launcher.live["task_id"] = "parent_frz"

    def freeze_parent():
        parent_launcher._freeze_now("operator_freeze")

    mgr = DelegationManager(
        storage,
        workspace_base=tmp_path / "workspaces",
        test_hooks={"during_input_copy": freeze_parent},
    )

    root_task_id = "parent_frz"
    tok = "tok_frz"
    storage.save_token(tok, root_task_id, "planner")

    ws = tmp_path / "ws_item6"
    (ws / "input").mkdir(parents=True, exist_ok=True)
    (ws / "input" / "test.txt").write_text("input data", encoding="utf-8")
    storage.save_task(_make_task_rec(root_task_id, "planner", ws=str(ws)))

    b = TaskBoundary(
        task_id=root_task_id,
        tools=["call_agent"],
        files_read=["input/*"],
        files_write=[],
        network=[],
        peer_agents=["budget"],
        workspace_root=str(ws),
    )
    storage.save_boundary(b)
    root_tok = mint_delegation_token(
        sub="human",
        txn=root_task_id,
        task_id=root_task_id,
        agent_id="planner",
        chain=["planner"],
        depth=0,
        scope=normalize_scope(b),
        par_hash=None,
        intent="intent_6",
        exp=int(time.time()) + 3600,
    )
    storage.save_delegation_token(root_task_id, root_tok, None)

    # Calling delegate_single triggers the input copy hook, freezing parent & child
    mgr.parent_launcher = parent_launcher
    with pytest.raises(Exception):
        mgr.delegate_single(tok, "budget", {"text": "hello"})

    assert storage.is_task_frozen("parent_frz")


# ---------------------------------------------------------------------------
# Item 7: Server-side input copy symlink race
# ---------------------------------------------------------------------------
def test_item7_symlink_swap_race_cannot_escape_workspace(tmp_path: Path):
    """Directory-to-symlink swap race (100 tries) never copies outside file."""
    storage = GovernanceStorage(tmp_path / "item7.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    parent_ws = tmp_path / "parent_ws"
    input_dir = parent_ws / "input"
    input_dir.mkdir(parents=True, exist_ok=True)
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir(parents=True, exist_ok=True)
    (outside_dir / "secret.txt").write_text("HOST_DATA", encoding="utf-8")

    sub_target = input_dir / "target"
    sub_target.mkdir(exist_ok=True)
    (sub_target / "ok.txt").write_text("NORMAL_INPUT", encoding="utf-8")

    race_active = threading.Event()
    race_active.set()

    def swapper():
        while race_active.is_set():
            if sub_target.is_symlink():
                try:
                    sub_target.unlink()
                    sub_target.mkdir()
                    (sub_target / "ok.txt").write_text("NORMAL_INPUT", encoding="utf-8")
                except OSError:
                    pass
            else:
                try:
                    import shutil
                    shutil.rmtree(sub_target)
                    os.symlink(str(outside_dir), str(sub_target))
                except OSError:
                    pass
            time.sleep(0.0001)

    t = threading.Thread(target=swapper, daemon=True)
    t.start()

    try:
        for _ in range(100):
            copied = mgr._copy_authorized_inputs(
                parent_ws=parent_ws,
                child_ws=None,
                authorized_patterns=["input/**"],
            )
            # Must never contain outside files
            for path_key, content_str in copied.items():
                assert content_str != "HOST_DATA"
                assert "secret.txt" not in path_key
    finally:
        race_active.clear()
        t.join(timeout=1.0)


# ---------------------------------------------------------------------------
# Item 8: One cap per root
# ---------------------------------------------------------------------------
def test_item8_per_root_concurrency_cap_shared_across_managers(tmp_path: Path):
    """Multiple managers under same root respect the 8 children cap."""
    storage = GovernanceStorage(tmp_path / "item8.db")
    mgr1 = DelegationManager(storage, workspace_base=tmp_path / "workspaces")
    mgr2 = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    root_id = "root_cap_test"
    with _GLOBAL_ROOT_CHILDREN_LOCK:
        _GLOBAL_RUNNING_CHILDREN_BY_ROOT[root_id] = {f"c{i}" for i in range(8)}

    # Attempting to start another child raises cap error
    with pytest.raises(RuntimeError, match="Per-root cap of 8 running child tasks reached"):
        mgr1._track_child_start(root_id, "c_extra_1")

    with pytest.raises(RuntimeError, match="Per-root cap of 8 running child tasks reached"):
        mgr2._track_child_start(root_id, "c_extra_2")

    # Cleaning up
    with _GLOBAL_ROOT_CHILDREN_LOCK:
        _GLOBAL_RUNNING_CHILDREN_BY_ROOT.pop(root_id, None)

    # More than 8 calls in one call_agents request are refused, not quietly cut to 8.
    calls = [{"target": f"a{i}", "message": "hi"} for i in range(12)]
    with pytest.raises(PermissionError, match="at most 8 calls"):
        mgr1.delegate_parallel("tok_none", calls)


def test_item8_broker_refuses_more_than_8_calls(tmp_path: Path):
    from demo.security_monitor.app.governance.broker import ToolBroker
    from demo.security_monitor.app.governance.models import TaskBoundary

    storage = GovernanceStorage(tmp_path / "item8b.db")
    ws = tmp_path / "ws8"
    ws.mkdir()
    storage.save_boundary(TaskBoundary(task_id="t8", tools=["call_agents"], files_read=[], files_write=[],
                                       network=[], peer_agents=[f"a{i}" for i in range(12)], workspace_root=str(ws)))
    storage.save_token("tok8", "t8", "planner")
    calls = [{"target": f"a{i}", "message": "hi"} for i in range(9)]
    with pytest.raises(PermissionError, match="at most 8 calls per request; 9 were sent"):
        ToolBroker(storage).call_agents("tok8", calls)


def test_item13_read_file_does_not_hang_on_a_fifo(tmp_path: Path):
    """A FIFO the agent made in its workspace is refused at once instead of blocking the server."""
    import os
    import threading

    from demo.security_monitor.app.governance.broker import ToolBroker
    from demo.security_monitor.app.governance.models import TaskBoundary

    storage = GovernanceStorage(tmp_path / "fifo.db")
    ws = tmp_path / "wsf"
    (ws / "input").mkdir(parents=True)
    os.mkfifo(ws / "input" / "pipe.txt")
    storage.save_boundary(TaskBoundary(task_id="tf", tools=["read_file"], files_read=["input/*"], files_write=[],
                                       network=[], peer_agents=[], workspace_root=str(ws)))
    storage.save_token("tokf", "tf", "notes_bot")
    out: dict = {}

    def _read():
        try:
            ToolBroker(storage).read_file("tokf", "input/pipe.txt")
        except Exception as e:  # noqa: BLE001
            out["err"] = e

    th = threading.Thread(target=_read, daemon=True)
    th.start()
    th.join(5)
    assert not th.is_alive(), "read_file blocked on a FIFO"
    assert isinstance(out.get("err"), PermissionError)


def test_item7_input_copy_skips_a_fifo_without_blocking(tmp_path: Path):
    import os
    import threading

    parent = tmp_path / "parent_ws"
    (parent / "input").mkdir(parents=True)
    (parent / "input" / "a.txt").write_text("hello", encoding="utf-8")
    os.mkfifo(parent / "input" / "b.txt")
    mgr = DelegationManager(GovernanceStorage(tmp_path / "copy.db"), workspace_base=tmp_path / "workspaces")
    out: dict = {}
    th = threading.Thread(target=lambda: out.setdefault("copied", mgr._copy_authorized_inputs(parent, None, ["input/*"])),
                          daemon=True)
    th.start()
    th.join(5)
    assert not th.is_alive(), "input copy blocked on a FIFO"
    assert out["copied"] == {"input/a.txt": "hello"}


# ---------------------------------------------------------------------------
# Item 9: Rule 1 covers http_get with data
# ---------------------------------------------------------------------------
def test_item9_http_get_with_query_string_under_secret_triggers_flow(tmp_path: Path):
    """While multi-agent task is secret, http_get with query string needs an OK."""
    storage = GovernanceStorage(tmp_path / "item9.db")
    task_id = "task_get_data"
    tok = "tok_get_data"
    storage.save_token(tok, task_id, "planner")

    ws = tmp_path / "ws_item9"
    ws.mkdir(parents=True, exist_ok=True)
    storage.save_task(_make_task_rec(task_id, "planner", ws=str(ws)))

    b = TaskBoundary(
        task_id=task_id,
        tools=["http_get", "call_agent"],
        files_read=["*"],
        files_write=[],
        network=["127.0.0.1:*"],
        peer_agents=["budget"],
        workspace_root=str(ws),
    )
    storage.save_boundary(b)
    storage.update_task_context_label(task_id, confidentiality="secret")

    broker = ToolBroker(storage)
    broker.default_approval_timeout = 0.2

    # GET with query string raises flow denied
    with pytest.raises(PermissionError, match="Flow denied|timeout"):
        broker.http_get(tok, "http://127.0.0.1:9000/query?leak=secret_data")


# ---------------------------------------------------------------------------
# Item 10: Run stream view check
# ---------------------------------------------------------------------------
def test_item10_stream_run_checks_view_permission(tmp_path: Path):
    """Developer from another team gets 404 or 403 when trying to stream run."""
    storage = GovernanceStorage(tmp_path / "item10.db")
    task_id = "task_team_alpha"
    task = _make_task_rec(task_id, "planner", team="team_alpha", owner="alice")
    storage.save_task(task)

    app = create_app(governance_storage=storage)
    client = TestClient(app)

    # Dev token from team_beta
    headers = {
        "X-User-Name": "bob",
        "X-User-Role": "developer",
        "X-User-Team": "team_beta",
    }
    resp = client.get(f"/run/{task_id}/stream", headers=headers)
    assert resp.status_code in (403, 404)


# ---------------------------------------------------------------------------
# Item 11: Data-rule OKs
# ---------------------------------------------------------------------------
def test_item11a_approving_non_pending_request_returns_409(tmp_path: Path, monkeypatch):
    """Approving an expansion request that is not PENDING returns 409 Conflict."""
    db_path = tmp_path / "item11a.db"
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "test_admin_token")
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db_path))
    storage = GovernanceStorage(db_path)
    exp = ExpansionService(storage)
    req = ExpansionRequest(
        request_id="req_001",
        task_id="task_11a",
        agent_id="planner",
        resource_type="file_read",
        resource_target="notes.txt",
        justification="need it",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.LOW,
        status=ExpansionStatus.DENIED,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
    storage.save_expansion_request(req)

    # Calling through API endpoint returns HTTP 409 Conflict for DENIED request
    app = create_app(governance_storage=storage)
    client = TestClient(app)
    headers = {"Authorization": "Bearer test_admin_token"}
    resp = client.post("/api/governance/expansions/req_001/approve", json={"scope": "run"}, headers=headers)
    assert resp.status_code == 409

    # Calling through API endpoint returns HTTP 409 Conflict for APPROVED request
    req.status = ExpansionStatus.APPROVED
    storage.save_expansion_request(req)
    resp2 = client.post("/api/governance/expansions/req_001/approve", json={"scope": "run"}, headers=headers)
    assert resp2.status_code == 409


def test_item11b_request_access_refuses_flow_resource_type(tmp_path: Path):
    """request_access refuses resource_type='flow'."""
    storage = GovernanceStorage(tmp_path / "item11b.db")
    tok = "tok_11b"
    task_id = "task_11b"
    storage.save_token(tok, task_id, "planner")
    ws = tmp_path / "ws_11b"
    ws.mkdir(parents=True, exist_ok=True)
    storage.save_task(_make_task_rec(task_id, "planner", ws=str(ws)))
    b = TaskBoundary(
        task_id=task_id,
        tools=["request_access"],
        files_read=[],
        files_write=[],
        network=[],
        peer_agents=[],
        workspace_root=str(ws),
    )
    storage.save_boundary(b)

    broker = ToolBroker(storage, expansion_service=ExpansionService(storage))
    with pytest.raises(PermissionError, match="cannot be requested"):
        broker.request_access(tok, "flow", "http://127.0.0.1", "bypass")


def test_item11c_call_agent_prechecks_run_before_flow_approval(tmp_path: Path):
    """Delegation pre-checks (peer allowed, profile exists, cycle) run before flow check."""
    storage = GovernanceStorage(tmp_path / "item11c.db")
    task_id = "task_11c"
    tok = "tok_11c"
    storage.save_token(tok, task_id, "planner")
    ws = tmp_path / "ws_11c"
    ws.mkdir(parents=True, exist_ok=True)
    storage.save_task(_make_task_rec(task_id, "planner", ws=str(ws)))
    b = TaskBoundary(
        task_id=task_id,
        tools=["call_agent"],
        files_read=[],
        files_write=[],
        network=[],
        peer_agents=["budget"],  # researcher not in boundary
        workspace_root=str(ws),
    )
    storage.save_boundary(b)
    storage.update_task_context_label(task_id, confidentiality="secret")

    broker = ToolBroker(storage)
    # Target not in boundary peer_agents raises PermissionError without waiting for flow approval
    with pytest.raises(PermissionError, match="denied by boundary|unlisted peer agent"):
        broker.call_agent(tok, "researcher", {"text": "hi"})

    # Ensure no pending flow request was created
    reqs = storage.list_expansion_requests(task_id=task_id)
    assert len(reqs) == 0


def test_item11d_job_owner_developer_can_answer_flow_requests():
    """Job owner with developer role can answer flow requests for their own job."""
    dev_user = UserSession(
        name="alice",
        role=Role.DEVELOPER,
        team="governance_team",
    )
    can_decide = PermissionMatrix.can_decide_request(
        user=dev_user,
        task_team="governance_team",
        resource_type="flow",
        job_owner="alice",
    )
    assert can_decide is True

    # But cannot decide if not the job owner
    cannot_decide = PermissionMatrix.can_decide_request(
        user=dev_user,
        task_team="governance_team",
        resource_type="flow",
        job_owner="bob",
    )
    assert cannot_decide is False


# ---------------------------------------------------------------------------
# Item 12: Messages show launcher failure as failed
# ---------------------------------------------------------------------------
def test_item12_launcher_failure_leaves_request_failed_no_delivered(tmp_path: Path):
    """Launcher failure records verdict='failed' and no row says 'delivered'."""
    storage = GovernanceStorage(tmp_path / "item12.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    root_task_id = "task_root_12"
    tok = "tok_root_12"
    storage.save_token(tok, root_task_id, "planner")

    ws = tmp_path / "ws_item12"
    ws.mkdir(parents=True, exist_ok=True)
    storage.save_task(_make_task_rec(root_task_id, "planner", ws=str(ws)))

    b = TaskBoundary(
        task_id=root_task_id,
        tools=["call_agent", "read_file"],
        files_read=["*"],
        files_write=[],
        network=[],
        peer_agents=["budget"],
        workspace_root=str(ws),
    )
    storage.save_boundary(b)

    root_tok = mint_delegation_token(
        sub="human",
        txn=root_task_id,
        task_id=root_task_id,
        agent_id="planner",
        chain=["planner"],
        depth=0,
        scope=normalize_scope(b),
        par_hash=None,
        intent="intent_12",
        exp=int(time.time()) + 3600,
    )
    storage.save_delegation_token(root_task_id, root_tok, None)

    # Simulate launcher failure by monkeypatching TaskLauncher.run to raise
    with patch.object(TaskLauncher, "run", side_effect=RuntimeError("Workspace spawn error")):
        with pytest.raises(RuntimeError, match="Workspace spawn error"):
            mgr.delegate_single(tok, "budget", {"text": "hello"})

    msgs = storage.get_a2a_messages(root_task_id=root_task_id)
    assert len(msgs) == 1
    assert msgs[0]["verdict"] == "failed"
    assert "Workspace spawn error" in msgs[0]["reason"]
    assert not any(m["verdict"] == "delivered" for m in msgs)


# ---------------------------------------------------------------------------
# Item 13: read_file 1 MB limit
# ---------------------------------------------------------------------------
def test_item13_read_file_over_1mb_refused(tmp_path: Path):
    """read_file refuses files larger than 1 MB."""
    storage = GovernanceStorage(tmp_path / "item13.db")
    task_id = "task_read_limit"
    tok = "tok_read_limit"
    storage.save_token(tok, task_id, "planner")

    ws = tmp_path / "ws_item13"
    ws.mkdir(parents=True, exist_ok=True)
    storage.save_task(_make_task_rec(task_id, "planner", ws=str(ws)))

    b = TaskBoundary(
        task_id=task_id,
        tools=["read_file"],
        files_read=["*"],
        files_write=[],
        network=[],
        peer_agents=[],
        workspace_root=str(ws),
    )
    storage.save_boundary(b)

    # Create 2 MB file
    large_file = ws / "large.bin"
    large_file.write_bytes(b"A" * (2 * 1024 * 1024))

    broker = ToolBroker(storage)
    with pytest.raises((ValueError, PermissionError), match="exceeds 1 MB limit"):
        broker.read_file(tok, "large.bin")

    # Normal 100 KB file is read successfully
    small_file = ws / "small.txt"
    small_file.write_text("Hello under 1MB", encoding="utf-8")
    res = broker.read_file(tok, "small.txt")
    assert res == "Hello under 1MB"
