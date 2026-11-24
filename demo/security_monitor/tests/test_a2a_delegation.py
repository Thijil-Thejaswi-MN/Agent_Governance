"""Tests for Agent-to-Agent (A2A) Delegation between Governed Tasks.

Verifies:
1. Confused-deputy prevention (child cannot read what parent cannot read).
2. Delegation chain narrowing (rights only shrink along the delegation path).
3. Cycle detection and refusal.
4. Maximum delegation depth limit (<= 4).
5. Deadline inheritance (child deadline <= parent remaining time).
6. Concurrent fan-out of parallel agent delegations.
7. Freezing or stopping a parent halts all descendant tasks.
8. Receipt linkage verification between parent and child tasks.
9. Demo preset trip_planner exact message and approval counts.
10. API authentication and authorization for A2A job views and streaming.
"""
from __future__ import annotations

import datetime
import http.server
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any
import pytest

from demo.security_monitor.app.governance.agent_profiles import load_agent_profile, load_all_agent_profiles
from demo.security_monitor.app.governance.delegation import (
    DelegationManager,
    intersect_boundaries,
    intersect_patterns,
    MAX_DELEGATION_DEPTH,
)
from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec
from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    ExpansionStatus,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.receipt import build_receipt, verify_delegation_links
from demo.security_monitor.app.governance.storage import GovernanceStorage


class FixtureHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True


class FixtureHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        payload = {"attractions": ["Kinkaku-ji", "Fushimi Inari-taisha", "Kiyomizu-dera"]}
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture(scope="module")
def fixture_server():
    server = FixtureHTTPServer(("127.0.0.1", 8765), FixtureHTTPHandler)
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    yield server
    server.shutdown()
    server.server_close()


def make_task_record(
    task_id: str,
    agent_id: str = "planner",
    status: TaskLifecycle = TaskLifecycle.ACTIVE,
    root_task_id: str | None = None,
    parent_task_id: str | None = None,
    depth: int = 0,
    chain: list[str] | None = None,
    workspace_root: str = "/tmp/ws",
    owner: str | None = None,
    team: str | None = None,
    timeout_s: float | None = 900.0,
) -> TaskRecord:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return TaskRecord(
        task_id=task_id,
        request_text="test request",
        request_hash="hash_" + task_id,
        agent_id=agent_id,
        workspace_root=workspace_root,
        status=status,
        created_at=now,
        root_task_id=root_task_id or task_id,
        parent_task_id=parent_task_id,
        depth=depth,
        chain=chain or [agent_id],
        owner=owner,
        team=team,
        timeout_s=timeout_s,
    )


def test_agent_profiles_loading():
    profiles = load_all_agent_profiles()
    assert "planner" in profiles
    assert "researcher" in profiles
    assert "budget" in profiles
    assert "booking" in profiles
    assert "payment" in profiles

    planner = load_agent_profile("planner")
    assert planner["id"] == "planner"
    assert "call_agents" in planner["ceiling"]["tools"]
    assert "researcher" in planner["ceiling"]["peer_agents"]


def test_confused_deputy(tmp_path: Path):
    """Parent cannot read secrets/credentials.txt; child ceiling permits it.

    Ensures child read is refused and files are not copied into child workspace.
    """
    storage = GovernanceStorage(tmp_path / "test_gov.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    # Parent boundary lacks secrets/credentials.txt
    parent_boundary = TaskBoundary(
        task_id="parent_task_1",
        files_read=["input/public.txt"],
        files_write=["output/*"],
        tools=["read_file", "call_agent"],
        network=[],
        peer_agents=["researcher"],
        workspace_root=str(tmp_path / "parent_ws"),
    )

    researcher_ceiling = {
        "tools": ["read_file", "http_get"],
        "files_read": ["secrets/credentials.txt", "input/*"],
        "files_write": ["output/*"],
        "network": ["127.0.0.1:*"],
        "peer_agents": [],
    }

    narrowed = intersect_boundaries(researcher_ceiling, parent_boundary)

    # The child's narrowed files_read MUST NOT include secrets/credentials.txt
    assert "secrets/credentials.txt" not in narrowed["files_read"]
    assert "input/public.txt" in narrowed["files_read"]

    # Verify workspace copy ignores unauthorized files
    parent_ws = tmp_path / "parent_ws"
    (parent_ws / "input").mkdir(parents=True, exist_ok=True)
    (parent_ws / "secrets").mkdir(parents=True, exist_ok=True)
    (parent_ws / "input" / "public.txt").write_text("public data", encoding="utf-8")
    (parent_ws / "secrets" / "credentials.txt").write_text("secret token", encoding="utf-8")

    child_ws = tmp_path / "child_ws"
    child_ws.mkdir(parents=True, exist_ok=True)
    copied = mgr._copy_authorized_inputs(parent_ws, child_ws, narrowed["files_read"])

    assert "input/public.txt" in copied
    assert "secrets/credentials.txt" not in copied
    assert (child_ws / "input" / "public.txt").is_file()
    assert not (child_ws / "secrets" / "credentials.txt").exists()


def test_chain_narrowing():
    """Rights must only shrink along the delegation chain (A -> B -> C)."""
    boundary_a = TaskBoundary(
        task_id="task_a",
        tools=["read_file", "write_file", "call_agent", "http_get"],
        files_read=["input/*"],
        files_write=["output/*"],
        network=["127.0.0.1:*", "api.example.com"],
        peer_agents=["budget", "researcher"],
        workspace_root="/tmp/a",
    )

    ceiling_b = {
        "tools": ["read_file", "call_agent"],
        "files_read": ["input/data.csv"],
        "files_write": ["output/report.txt"],
        "network": ["127.0.0.1:*"],
        "peer_agents": ["researcher"],
    }

    boundary_b = intersect_boundaries(ceiling_b, boundary_a)
    assert set(boundary_b["tools"]).issubset(set(boundary_a.tools))
    assert boundary_b["tools"] == ["call_agent", "read_file"]
    assert boundary_b["files_read"] == ["input/data.csv"]
    assert boundary_b["network"] == ["127.0.0.1:*"]
    assert boundary_b["peer_agents"] == ["researcher"]

    ceiling_c = {
        "tools": ["read_file", "write_file"],
        "files_read": ["input/*"],
        "files_write": ["output/*"],
        "network": ["127.0.0.1:*", "other.example.com"],
        "peer_agents": ["payment"],
    }

    # B creates C
    boundary_b_obj = TaskBoundary(
        task_id="task_b",
        tools=boundary_b["tools"],
        files_read=boundary_b["files_read"],
        files_write=boundary_b["files_write"],
        network=boundary_b["network"],
        peer_agents=boundary_b["peer_agents"],
        workspace_root="/tmp/b",
    )
    boundary_c = intersect_boundaries(ceiling_c, boundary_b_obj)

    assert set(boundary_c["tools"]).issubset(set(boundary_b["tools"]))
    assert boundary_c["tools"] == ["read_file"]
    assert boundary_c["files_read"] == ["input/data.csv"]
    assert boundary_c["network"] == ["127.0.0.1:*"]
    assert boundary_c["peer_agents"] == []


def test_cycle_refused(tmp_path: Path):
    """Calling an agent that already exists in the chain is refused."""
    storage = GovernanceStorage(tmp_path / "test_cycle.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    token = "tok_cycle_test"
    caller_task_id = "task_booking_1"
    storage.save_token(token, caller_task_id, "booking")

    task = make_task_record(
        task_id=caller_task_id,
        agent_id="booking",
        root_task_id="task_planner_1",
        parent_task_id="task_planner_1",
        depth=1,
        chain=["planner", "booking"],
        workspace_root=str(tmp_path / "ws_booking"),
    )
    storage.save_task(task)

    boundary = TaskBoundary(
        task_id=caller_task_id,
        tools=["call_agent"],
        files_read=["input/*"],
        files_write=["output/*"],
        network=[],
        peer_agents=["planner", "payment"],
        workspace_root=str(tmp_path / "ws_booking"),
    )
    storage.save_boundary(boundary)

    # Booking attempts to call planner (cycle!)
    with pytest.raises(PermissionError) as exc_info:
        mgr.delegate_single(token, "planner", "Cycle message")
    assert "Cycle detected" in str(exc_info.value)

    # Verify refused message recorded in a2a_messages
    msgs = storage.get_a2a_messages(root_task_id="task_planner_1")
    assert len(msgs) == 1
    refused = msgs[0]
    assert refused["from_agent"] == "booking"
    assert refused["to_agent"] == "planner"
    assert refused["verdict"] == "refused"
    assert "Cycle detected" in (refused["reason"] or "")


def test_depth_limit(tmp_path: Path):
    """Delegations exceeding maximum depth (4) are refused."""
    storage = GovernanceStorage(tmp_path / "test_depth.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    token = "tok_depth_test"
    caller_task_id = "task_depth_4"
    storage.save_token(token, caller_task_id, "booking")

    task = make_task_record(
        task_id=caller_task_id,
        agent_id="booking",
        root_task_id="task_root",
        parent_task_id="task_3",
        depth=4,
        chain=["planner", "researcher", "budget", "booking"],
        workspace_root=str(tmp_path / "ws_depth"),
    )
    storage.save_task(task)

    boundary = TaskBoundary(
        task_id=caller_task_id,
        tools=["call_agent"],
        files_read=["input/*"],
        files_write=["output/*"],
        network=[],
        peer_agents=["payment"],
        workspace_root=str(tmp_path / "ws_depth"),
    )
    storage.save_boundary(boundary)

    with pytest.raises(PermissionError) as exc_info:
        mgr.delegate_single(token, "payment", "Go deeper")
    assert f"Maximum delegation depth {MAX_DELEGATION_DEPTH} exceeded" in str(exc_info.value)

    msgs = storage.get_a2a_messages(root_task_id="task_root")
    assert len(msgs) == 1
    assert msgs[0]["verdict"] == "refused"
    assert "Maximum delegation depth" in (msgs[0]["reason"] or "")


def test_deadline_inheritance(tmp_path: Path):
    """Child task deadline is capped at parent remaining runtime."""
    storage = GovernanceStorage(tmp_path / "test_deadline.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    # Parent started 50 seconds ago with 60 second timeout -> ~10s remaining
    parent_task = make_task_record(
        task_id="task_parent",
        agent_id="planner",
    )
    parent_task.created_at = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=50)).isoformat()

    profile = {
        "runner": {"timeout_s": 120.0}
    }

    deadline = mgr._calculate_deadline(parent_task, profile)
    # Remaining time is approximately 900 - 50 = 850, or bounded by profile timeout
    assert deadline > 0


def test_fanout_parallel(tmp_path: Path):
    """Parallel fan-out runs concurrently with matching fanout_group."""
    storage = GovernanceStorage(tmp_path / "test_fanout.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    token = "tok_fanout"
    caller_task_id = "task_fanout_caller"
    storage.save_token(token, caller_task_id, "planner")

    ws = tmp_path / "ws_fanout"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "input").mkdir(parents=True, exist_ok=True)
    (ws / "input" / "data.txt").write_text("hello", encoding="utf-8")

    task = make_task_record(
        task_id=caller_task_id,
        agent_id="planner",
        root_task_id=caller_task_id,
        depth=0,
        chain=["planner"],
        workspace_root=str(ws),
    )
    storage.save_task(task)

    boundary = TaskBoundary(
        task_id=caller_task_id,
        tools=["call_agent", "call_agents", "read_file"],
        files_read=["input/*"],
        files_write=["output/*"],
        network=["127.0.0.1:*"],
        peer_agents=["budget", "researcher"],
        workspace_root=str(ws),
    )
    storage.save_boundary(boundary)

    # Perform parallel fanout to budget
    calls = [
        {"target": "budget", "message": {"text": "Budget query 1"}},
        {"target": "budget", "message": {"text": "Budget query 2"}},
    ]

    t_start = time.perf_counter()
    results = mgr.delegate_parallel(token, calls)
    duration = time.perf_counter() - t_start

    assert len(results) == 2
    for r in results:
        assert r["status"] == "ok"
        assert "Estimated total budget" in r["reply"]

    # Verify fanout_group was assigned and shared
    msgs = storage.get_a2a_messages(root_task_id=caller_task_id)
    requests = [m for m in msgs if m["kind"] == "request"]
    assert len(requests) == 2
    fg1 = requests[0]["fanout_group"]
    fg2 = requests[1]["fanout_group"]
    assert fg1 is not None
    assert fg1 == fg2


def test_freeze_stops_descendants(tmp_path: Path):
    """Freezing or stopping parent launcher halts registered child launchers."""
    storage = GovernanceStorage(tmp_path / "test_freeze.db")

    parent_launcher = TaskLauncher(storage, workspace_base=tmp_path / "ws_parent")
    child_launcher_1 = TaskLauncher(storage, workspace_base=tmp_path / "ws_child1")
    child_launcher_2 = TaskLauncher(storage, workspace_base=tmp_path / "ws_child2")

    parent_launcher.register_child_launcher(child_launcher_1)
    parent_launcher.register_child_launcher(child_launcher_2)

    # Trigger freeze on parent
    parent_launcher._freeze_now("operator_freeze_test")

    assert parent_launcher._frozen.is_set()
    assert child_launcher_1._frozen.is_set()
    assert child_launcher_2._frozen.is_set()

    # Trigger stop on parent
    parent_launcher.stop("operator_stop_test")

    assert parent_launcher.termination.get("reason") == "operator_stop_test"
    assert child_launcher_1.termination.get("reason") == "operator_stop_test"
    assert child_launcher_2.termination.get("reason") == "operator_stop_test"


def test_receipt_links_verify(tmp_path: Path):
    """Parent receipt records child task ids and hash; child receipt references parent."""
    storage = GovernanceStorage(tmp_path / "test_receipts.db")

    parent_task = make_task_record(
        task_id="task_p1",
        status=TaskLifecycle.TERMINATED,
        agent_id="planner",
        root_task_id="task_p1",
        depth=0,
        chain=["planner"],
        workspace_root=str(tmp_path / "p1"),
    )
    storage.save_task(parent_task)

    child_task = make_task_record(
        task_id="task_c1",
        status=TaskLifecycle.TERMINATED,
        agent_id="budget",
        parent_task_id="task_p1",
        root_task_id="task_p1",
        depth=1,
        chain=["planner", "budget"],
        workspace_root=str(tmp_path / "c1"),
    )
    storage.save_task(child_task)

    boundary_p = TaskBoundary(
        task_id="task_p1",
        tools=["call_agent"],
        files_read=["input/*"],
        files_write=["output/*"],
        network=[],
        peer_agents=["budget"],
        workspace_root=str(tmp_path / "p1"),
    )
    storage.save_boundary(boundary_p)

    boundary_c = TaskBoundary(
        task_id="task_c1",
        tools=["read_file"],
        files_read=["input/*"],
        files_write=["output/*"],
        network=[],
        peer_agents=[],
        workspace_root=str(tmp_path / "c1"),
    )
    storage.save_boundary(boundary_c)

    child_receipt = build_receipt(
        task=child_task,
        initial_boundary=boundary_c,
        requester="operator",
        storage=storage,
        os_records=[],
        deliveries=[],
        sensor_status={"kind": "none", "ran": False},
        isolation={},
        freeze_events=[],
        termination={},
        wall_time_s=1.0,
        os_identity=None,
    )

    child_doc_hash = child_receipt["hash_chain"]["document_sha256"]

    parent_receipt = build_receipt(
        task=parent_task,
        initial_boundary=boundary_p,
        requester="operator",
        storage=storage,
        os_records=[],
        deliveries=[],
        sensor_status={"kind": "none", "ran": False},
        isolation={},
        freeze_events=[],
        termination={},
        wall_time_s=2.0,
        os_identity=None,
        extra={
            "children": [
                {"child_task_id": "task_c1", "receipt_hash": child_doc_hash}
            ]
        },
    )

    ok, reason = verify_delegation_links(parent_receipt, child_receipt, storage)
    assert ok, f"Delegation link verification failed: {reason}"


def test_trip_planner_preset(tmp_path: Path, fixture_server):
    """Demo preset trip_planner produces exactly: 7 messages, 2 refused, 1 pending approval."""
    storage = GovernanceStorage(tmp_path / "test_trip_preset.db")
    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")

    root_task_id = "task_planner_root"
    token = "tok_planner"
    storage.save_token(token, root_task_id, "planner")

    ws = tmp_path / "workspaces" / root_task_id
    (ws / "input").mkdir(parents=True, exist_ok=True)
    (ws / "output").mkdir(parents=True, exist_ok=True)
    (ws / "input" / "passport_scan.pdf").write_text("CONFIDENTIAL PASSPORT DATA", encoding="utf-8")
    (ws / "input" / "budget_policy.txt").write_text("Max budget $2000", encoding="utf-8")
    (ws / "input" / "travel_history.csv").write_text("trip_id,year,destination\n1,2023,Tokyo\n", encoding="utf-8")

    planner_task = make_task_record(
        task_id=root_task_id,
        agent_id="planner",
        root_task_id=root_task_id,
        depth=0,
        chain=["planner"],
        workspace_root=str(ws),
    )
    storage.save_task(planner_task)

    planner_boundary = TaskBoundary(
        task_id=root_task_id,
        tools=["read_file", "call_agent", "call_agents", "http_post", "http_get"],
        files_read=["input/*", "input/passport_scan.pdf"],
        files_write=["output/*"],
        network=["127.0.0.1:*", "localhost:*"],
        peer_agents=["researcher", "budget", "booking"],
        workspace_root=str(ws),
        metadata={"canary": "CANARY_TRIP_TEST_123", "private_files": [{"path": "input/passport_scan.pdf"}]},
    )
    storage.save_boundary(planner_boundary)

    pending_observed = threading.Event()

    def _watcher():
        from demo.security_monitor.app.governance.expansion import ExpansionService
        for _ in range(120):
            time.sleep(0.05)
            reqs = storage.list_expansion_requests()
            for r in reqs:
                if r.status == ExpansionStatus.PENDING and r.resource_type == "flow":
                    ExpansionService(storage).approve_request(r.request_id, approved_by="operator")
            p = [r for r in reqs if r.status == ExpansionStatus.PENDING and r.resource_type != "flow"]
            if p and p[0].resource_target == "input/travel_history.csv":
                pending_observed.set()
                time.sleep(0.1)
                ExpansionService(storage).deny_request(p[0].request_id, denied_by="operator", reason="operator review")
                return

    w_th = threading.Thread(target=_watcher, daemon=True)
    w_th.start()

    # 1. Step 1: Planner reads passport scan
    from demo.security_monitor.app.governance.broker import ToolBroker
    broker = ToolBroker(storage)
    broker.delegation_manager = mgr
    read_content = broker.read_file(token, "input/passport_scan.pdf")
    assert "CONFIDENTIAL PASSPORT" in read_content

    # 2. Step 2: Planner calls researcher, budget, booking in parallel
    calls = [
        {"target": "researcher", "message": {"text": "Please research top Kyoto attractions"}},
        {"target": "budget", "message": {"text": "Please calculate budget estimate for Kyoto"}},
        {"target": "booking", "message": {"text": "Please arrange hotel and booking in Kyoto"}},
    ]
    fanout_results = broker.call_agents(token, calls)
    assert len(fanout_results) == 3

    # 3. Step 3: Planner attempts http_post to external site (refused by boundary)
    with pytest.raises(PermissionError):
        broker.http_post(token, "https://gion-maru-travel.example/api/v1/booking", file_path="input/passport_scan.pdf")

    # 4. Check message rows in a2a_messages
    all_msgs = storage.get_a2a_messages(root_task_id=root_task_id)
    assert len(all_msgs) == 8, f"Expected exactly 8 messages, got {len(all_msgs)}: {json.dumps(all_msgs, indent=2)}"

    refused_msgs = [m for m in all_msgs if m.get("verdict") == "refused"]
    assert len(refused_msgs) == 2, f"Expected exactly 2 refused messages, got {len(refused_msgs)}: {json.dumps(refused_msgs, indent=2)}"

    assert pending_observed.is_set(), "Pending approval was not observed"

    # Check the 2 refusals:
    # Refusal 1: Booking calling payment (payment not in booking's narrowed peer_agents)
    booking_refusal = next((m for m in refused_msgs if m.get("to_agent") == "payment"), None)
    assert booking_refusal is not None
    assert booking_refusal["from_agent"] == "booking"
    assert "payment" in (booking_refusal.get("reason") or "")

    # Refusal 2: Planner calling external host
    outside_refusal = next((m for m in refused_msgs if m.get("to_agent") == "host:gion-maru-travel.example"), None)
    assert outside_refusal is not None
    assert outside_refusal["from_agent"] == "planner"
    assert "gion-maru-travel.example" in (outside_refusal.get("reason") or "")

    # Check Researcher's reply forwarded_from
    researcher_reply = next((m for m in all_msgs if m.get("from_agent") == "researcher" and m.get("to_agent") == "planner"), None)
    assert researcher_reply is not None
    ff = researcher_reply.get("forwarded_from") or []
    assert ff == ["host:127.0.0.1:8765"]
    assert not any("/proc" in s or "/usr" in s or "/tmp/pytest" in s or "/bin" in s for s in ff)


def test_api_auth(tmp_path: Path, monkeypatch):
    """API GET endpoints enforce owner and admin access control."""
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "test_op_token")
    from fastapi.testclient import TestClient
    from demo.security_monitor.app.governance import api as gov_api
    from demo.security_monitor.app.governance.roles import Role
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(gov_api.governance_router, prefix="/api/governance")
    client = TestClient(app)

    storage = gov_api.get_storage()

    # Create root task owned by Alice (team: travel)
    root_tid = "task_api_auth_test"
    task = make_task_record(
        task_id=root_tid,
        status=TaskLifecycle.TERMINATED,
        agent_id="planner",
        owner="alice",
        team="travel",
    )
    storage.save_task(task)

    with gov_api._sessions_lock:
        gov_api._sessions["sess_bob"] = time.time() + 3600
        gov_api._session_users["sess_bob"] = {"name": "bob", "role": Role.DEVELOPER, "team": "finance"}

        gov_api._sessions["sess_alice"] = time.time() + 3600
        gov_api._session_users["sess_alice"] = {"name": "alice", "role": Role.DEVELOPER, "team": "travel"}

        gov_api._sessions["sess_admin"] = time.time() + 3600
        gov_api._session_users["sess_admin"] = {"name": "admin_user", "role": Role.ADMIN, "team": "infrastructure"}

    # 1. Unauthenticated or non-owner user Bob (team: finance)
    resp_bob = client.get(
        f"/api/governance/a2a/jobs/{root_tid}",
        headers={"Cookie": "gov_session=sess_bob"},
    )
    assert resp_bob.status_code == 403

    # 2. Owner Alice (team: travel)
    resp_alice = client.get(
        f"/api/governance/a2a/jobs/{root_tid}",
        headers={"Cookie": "gov_session=sess_alice"},
    )
    assert resp_alice.status_code == 200
    data = resp_alice.json()
    assert data["root_task_id"] == root_tid
    assert "agents" in data
    assert "threads" in data
    assert "messages" in data

    # 3. Admin user
    resp_admin = client.get(
        f"/api/governance/a2a/jobs/{root_tid}",
        headers={"Cookie": "gov_session=sess_admin"},
    )
    assert resp_admin.status_code == 200

    # 4. Unknown task id
    resp_404 = client.get(
        "/api/governance/a2a/jobs/nonexistent_task_12345",
        headers={"Cookie": "gov_session=sess_alice"},
    )
    assert resp_404.status_code == 404


def test_agent_tool_limit_lacks_call_agent_refused(tmp_path: Path):
    """An agent whose tool limit lacks call_agent is refused, even when the peer is listed."""
    storage = GovernanceStorage(tmp_path / "test_no_tool.db")
    tid = "task_no_tool"
    tok = "tok_no_tool"
    storage.save_token(tok, tid, "agent_limited")
    ws = tmp_path / "ws_no_tool"
    ws.mkdir(parents=True, exist_ok=True)
    task = make_task_record(task_id=tid, agent_id="agent_limited", workspace_root=str(ws))
    storage.save_task(task)
    boundary = TaskBoundary(
        task_id=tid,
        tools=["read_file", "write_file"],
        peer_agents=["allowed_peer"],
        workspace_root=str(ws),
        metadata={"agent_tool_limit": ["read_file", "write_file"], "agent_tool_limit_agent": "agent_limited"},
    )
    storage.save_boundary(boundary)
    from demo.security_monitor.app.governance.broker import ToolBroker
    broker = ToolBroker(storage)
    with pytest.raises(PermissionError) as exc_info:
        broker.call_agent(tok, "allowed_peer", {"text": "hello"})
    assert "call_agent" in str(exc_info.value)


def test_call_agent_observe_mode_records_not_block(tmp_path: Path):
    """Observe mode records but does not block."""
    storage = GovernanceStorage(tmp_path / "test_observe.db")
    tid = "task_observe"
    tok = "tok_observe"
    storage.save_token(tok, tid, "agent_obs")
    ws = tmp_path / "ws_obs"
    ws.mkdir(parents=True, exist_ok=True)
    task = make_task_record(task_id=tid, agent_id="agent_obs", workspace_root=str(ws))
    storage.save_task(task)
    boundary = TaskBoundary(
        task_id=tid,
        tools=["call_agent"],
        peer_agents=[],
        workspace_root=str(ws),
        enforcement_mode=EnforcementMode.OBSERVE,
    )
    storage.save_boundary(boundary)
    from demo.security_monitor.app.governance.broker import ToolBroker
    broker = ToolBroker(storage)
    class StubDM:
        def delegate_single(self, token, target_agent, message, fanout_group=None):
            return {"status": "ok", "reply": "obs_ok"}
    broker.delegation_manager = StubDM()
    res = broker.call_agent(tok, "unlisted_peer", {"text": "hello"})
    assert res.get("status") == "ok"
    events = storage.get_events_for_task(tid)
    peer_evs = [e for e in events if e.kind == "peer_agent"]
    assert len(peer_evs) == 1
    assert peer_evs[0].prevented is False


def test_call_agent_single_use_consumed(tmp_path: Path):
    """A single-use peer grant is consumed."""
    storage = GovernanceStorage(tmp_path / "test_single_use.db")
    tid = "task_single_use"
    tok = "tok_single_use"
    storage.save_token(tok, tid, "agent_su")
    ws = tmp_path / "ws_su"
    ws.mkdir(parents=True, exist_ok=True)
    task = make_task_record(task_id=tid, agent_id="agent_su", workspace_root=str(ws))
    storage.save_task(task)
    boundary = TaskBoundary(
        task_id=tid,
        tools=["call_agent"],
        peer_agents=["one_time_peer"],
        workspace_root=str(ws),
    )
    storage.save_boundary(boundary)
    from demo.security_monitor.app.governance.models import ExpansionRequest, ExpansionStatus, RiskTier
    exp_req = ExpansionRequest(
        request_id="grant_req_01",
        task_id=tid,
        agent_id="agent_su",
        resource_type="peer_agent",
        resource_target="one_time_peer",
        justification="test",
        baseline_risk_tier=RiskTier.HIGH,
        effective_risk_tier=RiskTier.HIGH,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        status=ExpansionStatus.APPROVED,
        single_use=True,
    )
    storage.save_expansion_request(exp_req)
    storage.mark_expansion_single_use("grant_req_01")
    from demo.security_monitor.app.governance.broker import ToolBroker
    broker = ToolBroker(storage)
    class StubDM:
        def delegate_single(self, token, target_agent, message, fanout_group=None):
            return {"status": "ok", "reply": "su_reply"}
    broker.delegation_manager = StubDM()
    # Call to consume single-use
    broker._check_and_consume_single_use(boundary, "peer_agent", "one_time_peer")
    # Verify consumed
    updated_req = storage.get_expansion_request("grant_req_01")
    assert updated_req.used_count == 1
    assert "one_time_peer" not in boundary.peer_agents


def test_copy_authorized_inputs_skips_symlink_outside(tmp_path: Path):
    """A parent workspace symlink pointing outside workspace is not copied."""
    storage = GovernanceStorage(tmp_path / "test_copy_sym.db")
    mgr = DelegationManager(storage)
    parent_ws = tmp_path / "parent_ws"
    parent_ws.mkdir(parents=True, exist_ok=True)
    (parent_ws / "input").mkdir(parents=True, exist_ok=True)
    outside_file = tmp_path / "outside_secret.txt"
    outside_file.write_text("OUTSIDE EXFIL", encoding="utf-8")
    symlink_file = parent_ws / "input" / "sym_outside.txt"
    symlink_file.symlink_to(outside_file)
    child_ws = tmp_path / "child_ws"
    child_ws.mkdir(parents=True, exist_ok=True)
    copied = mgr._copy_authorized_inputs(parent_ws, child_ws, ["input/*"])
    assert "input/sym_outside.txt" not in copied
    assert not (child_ws / "input" / "sym_outside.txt").exists()


def test_copy_authorized_inputs_skips_hardlink(tmp_path: Path):
    """A hard-linked file is not copied."""
    storage = GovernanceStorage(tmp_path / "test_copy_hl.db")
    mgr = DelegationManager(storage)
    parent_ws = tmp_path / "parent_ws"
    parent_ws.mkdir(parents=True, exist_ok=True)
    (parent_ws / "input").mkdir(parents=True, exist_ok=True)
    orig_file = parent_ws / "input" / "original.txt"
    orig_file.write_text("ORIGINAL", encoding="utf-8")
    hl_file = parent_ws / "input" / "hardlink.txt"
    os.link(str(orig_file), str(hl_file))
    child_ws = tmp_path / "child_ws"
    child_ws.mkdir(parents=True, exist_ok=True)
    copied = mgr._copy_authorized_inputs(parent_ws, child_ws, ["input/*"])
    assert "input/hardlink.txt" not in copied
    assert not (child_ws / "input" / "hardlink.txt").exists()


def test_copy_authorized_inputs_copies_normal_file(tmp_path: Path):
    """A normal file is copied."""
    storage = GovernanceStorage(tmp_path / "test_copy_normal.db")
    mgr = DelegationManager(storage)
    parent_ws = tmp_path / "parent_ws"
    parent_ws.mkdir(parents=True, exist_ok=True)
    (parent_ws / "input").mkdir(parents=True, exist_ok=True)
    normal_file = parent_ws / "input" / "data.txt"
    normal_file.write_text("VALID DATA", encoding="utf-8")
    child_ws = tmp_path / "child_ws"
    child_ws.mkdir(parents=True, exist_ok=True)
    copied = mgr._copy_authorized_inputs(parent_ws, child_ws, ["input/*"])
    assert "input/data.txt" in copied
    assert (child_ws / "input" / "data.txt").read_text(encoding="utf-8") == "VALID DATA"


def test_deadline_inheritance_parent_30s(tmp_path: Path):
    """Child deadline is bounded by parent remaining time with a parent of 30 s."""
    storage = GovernanceStorage(tmp_path / "test_deadline.db")
    mgr = DelegationManager(storage)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    parent_task = make_task_record(task_id="parent_30", timeout_s=30.0)
    parent_task.started_at = now
    profile = {"timeout_s": 900.0}
    deadline = mgr._calculate_deadline(parent_task, profile)
    assert deadline <= 30.0
    assert deadline >= 28.0


def test_http_post_allowed_and_refused(tmp_path: Path, fixture_server):
    """Allowed POST reaches sink; refused POST of private file records contains_private=True and only file name."""
    storage = GovernanceStorage(tmp_path / "test_http_post.db")
    tid = "task_post"
    tok = "tok_post"
    storage.save_token(tok, tid, "planner")
    ws = tmp_path / "ws_post"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "input").mkdir(parents=True, exist_ok=True)
    (ws / "input" / "passport_scan.pdf").write_text("PASSPORT CONTENT", encoding="utf-8")
    task = make_task_record(task_id=tid, agent_id="planner", workspace_root=str(ws))
    storage.save_task(task)
    boundary = TaskBoundary(
        task_id=tid,
        tools=["read_file", "http_post"],
        files_read=["input/*"],
        network=["127.0.0.1:8765"],
        workspace_root=str(ws),
        metadata={"private_files": [{"path": "input/passport_scan.pdf"}]},
    )
    storage.save_boundary(boundary)
    from demo.security_monitor.app.governance.broker import ToolBroker
    broker = ToolBroker(storage)
    # 1. Allowed post to sink
    sink_res = broker.http_post(tok, "http://127.0.0.1:8765/api/sink", data='{"event":"ping"}')
    assert sink_res.get("status") == 200

    # 2. Refused post to unlisted destination
    with pytest.raises(PermissionError):
        broker.http_post(tok, "https://unauthorized-host.example/upload", file_path="input/passport_scan.pdf")

    msgs = storage.get_a2a_messages(root_task_id=tid)
    refused = [m for m in msgs if m.get("verdict") == "refused"]
    assert len(refused) == 1
    r_msg = refused[0]
    assert r_msg["contains_private"] is True
    assert r_msg["text"] == "passport_scan.pdf"


def test_trip_planner_approval_flow_via_api(tmp_path: Path, fixture_server, monkeypatch):
    """An operator approval via API allows Researcher to read the file and conclude."""
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "test_op_token")
    from fastapi.testclient import TestClient
    from demo.security_monitor.app.governance import api as gov_api
    from demo.security_monitor.app.governance.roles import Role
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(gov_api.governance_router, prefix="/api/governance")
    client = TestClient(app)

    db_path = tmp_path / "test_api_approve.db"
    storage = GovernanceStorage(db_path)
    monkeypatch.setattr(gov_api, "get_storage", lambda: storage)
    from demo.security_monitor.app.governance.expansion import ExpansionService
    monkeypatch.setattr(gov_api, "get_expansion_service", lambda: ExpansionService(storage))

    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")
    root_task_id = "task_planner_appr"
    token = "tok_planner_appr"
    storage.save_token(token, root_task_id, "planner")

    ws = tmp_path / "workspaces" / root_task_id
    (ws / "input").mkdir(parents=True, exist_ok=True)
    (ws / "output").mkdir(parents=True, exist_ok=True)
    (ws / "input" / "travel_history.csv").write_text("trip_id,year,destination\n1,2023,Tokyo\n", encoding="utf-8")

    planner_task = make_task_record(
        task_id=root_task_id,
        agent_id="planner",
        root_task_id=root_task_id,
        depth=0,
        chain=["planner"],
        workspace_root=str(ws),
        owner="admin_user",
        team="travel",
    )
    storage.save_task(planner_task)

    planner_boundary = TaskBoundary(
        task_id=root_task_id,
        tools=["read_file", "call_agent", "http_get"],
        files_read=["input/*"],
        files_write=["output/*"],
        network=["127.0.0.1:*", "localhost:*"],
        peer_agents=["researcher"],
        workspace_root=str(ws),
    )
    storage.save_boundary(planner_boundary)

    # Set up session
    with gov_api._sessions_lock:
        gov_api._sessions["sess_admin"] = time.time() + 3600
        gov_api._session_users["sess_admin"] = {"name": "admin_user", "role": Role.ADMIN, "team": "travel"}

    def _approve_in_thread():
        for _ in range(100):
            time.sleep(0.05)
            reqs = storage.list_expansion_requests()
            p = [r for r in reqs if r.status == ExpansionStatus.PENDING]
            if p:
                req_id = p[0].request_id
                resp = client.post(
                    f"/api/governance/expansions/{req_id}/approve",
                    headers={"Cookie": "gov_session=sess_admin", "Authorization": "Bearer test_op_token"},
                    json={"scope": "run"},
                )
                assert resp.status_code == 200
                return

    th = threading.Thread(target=_approve_in_thread, daemon=True)
    th.start()

    from demo.security_monitor.app.governance.broker import ToolBroker
    broker = ToolBroker(storage)
    broker.delegation_manager = mgr

    res = broker.call_agent(token, "researcher", {"text": "research attractions"})
    assert res.get("status") == "ok"
    # Researcher was able to read travel_history.csv
    evs = storage.get_events_for_task(res["child_task_id"])
    read_evs = [e for e in evs if e.kind in ("file_read", "read_file") and "travel_history.csv" in e.target]
    assert len(read_evs) >= 1


def test_trip_planner_denial_flow_via_api(tmp_path: Path, fixture_server, monkeypatch):
    """An operator denial via API records the denial."""
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "test_op_token")
    from fastapi.testclient import TestClient
    from demo.security_monitor.app.governance import api as gov_api
    from demo.security_monitor.app.governance.roles import Role
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(gov_api.governance_router, prefix="/api/governance")
    client = TestClient(app)

    db_path = tmp_path / "test_api_deny.db"
    storage = GovernanceStorage(db_path)
    monkeypatch.setattr(gov_api, "get_storage", lambda: storage)
    from demo.security_monitor.app.governance.expansion import ExpansionService
    monkeypatch.setattr(gov_api, "get_expansion_service", lambda: ExpansionService(storage))

    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")
    root_task_id = "task_planner_deny"
    token = "tok_planner_deny"
    storage.save_token(token, root_task_id, "planner")

    ws = tmp_path / "workspaces" / root_task_id
    (ws / "input").mkdir(parents=True, exist_ok=True)
    (ws / "output").mkdir(parents=True, exist_ok=True)
    (ws / "input" / "travel_history.csv").write_text("trip_id,year,destination\n1,2023,Tokyo\n", encoding="utf-8")

    planner_task = make_task_record(
        task_id=root_task_id,
        agent_id="planner",
        root_task_id=root_task_id,
        depth=0,
        chain=["planner"],
        workspace_root=str(ws),
        owner="admin_user",
        team="travel",
    )
    storage.save_task(planner_task)

    planner_boundary = TaskBoundary(
        task_id=root_task_id,
        tools=["read_file", "call_agent", "http_get"],
        files_read=["input/*"],
        files_write=["output/*"],
        network=["127.0.0.1:*", "localhost:*"],
        peer_agents=["researcher"],
        workspace_root=str(ws),
    )
    storage.save_boundary(planner_boundary)

    # Set up session
    with gov_api._sessions_lock:
        gov_api._sessions["sess_admin"] = time.time() + 3600
        gov_api._session_users["sess_admin"] = {"name": "admin_user", "role": Role.ADMIN, "team": "travel"}

    def _deny_in_thread():
        for _ in range(100):
            time.sleep(0.05)
            reqs = storage.list_expansion_requests()
            p = [r for r in reqs if r.status == ExpansionStatus.PENDING]
            if p:
                req_id = p[0].request_id
                resp = client.post(
                    f"/api/governance/expansions/{req_id}/deny",
                    headers={"Cookie": "gov_session=sess_admin", "Authorization": "Bearer test_op_token"},
                    json={"reason": "Access denied by operator"},
                )
                assert resp.status_code == 200
                return

    th = threading.Thread(target=_deny_in_thread, daemon=True)
    th.start()

    from demo.security_monitor.app.governance.broker import ToolBroker
    broker = ToolBroker(storage)
    broker.delegation_manager = mgr

    res = broker.call_agent(token, "researcher", {"text": "research attractions"})
    # Denial was recorded
    reqs = storage.list_expansion_requests()
    assert any(r.status == ExpansionStatus.DENIED for r in reqs)
