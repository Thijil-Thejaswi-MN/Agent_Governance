"""Milestone 2 Test Suite: Egress Proxy, A2A Gateway Governance, Inventory v1, and API.

Tests:
1. F5.2 Egress Network Proxy: Authentication via Proxy-Authorization Bearer token
2. F5.2 Egress Network Proxy: Allowed vs Blocked CONNECT destinations (Real-time prevention)
3. F5.2 Egress Network Proxy: Hostname and IP resolution checks
4. F5.3 A2A Gateway: Peer agent boundary enforcement with per-task tokens
5. F5.3 A2A Gateway: Shadow agent discovery when token is missing
6. F10 Agent Inventory: Dynamic classification of Governed vs Shadow agents
7. F12 Governance API: /tasks, /inventory, /alerts endpoints
"""
from __future__ import annotations

import asyncio
import os
import socket
from pathlib import Path
import pytest
import httpx

from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    EventVerdict,
    RiskTier,
    TaskAction,
    EventSource,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.proxy import EgressProxyServer
from demo.security_monitor.app.governance.gateway_integration import A2AGatewayGovernance
from demo.security_monitor.app.governance.inventory import AgentInventoryService
from demo.security_monitor.app.governance.intake import TaskIntakeService


@pytest.fixture
def m2_storage(tmp_path: Path) -> GovernanceStorage:
    db_file = tmp_path / "m2_governance.db"
    return GovernanceStorage(db_file)


@pytest.fixture
def m2_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace_m2"
    (ws / "input").mkdir(parents=True)
    (ws / "output").mkdir(parents=True)
    return ws


# --- 1. EGRESS PROXY AUTHENTICATION ---

@pytest.mark.asyncio
async def test_proxy_authentication(m2_storage: GovernanceStorage, m2_workspace: Path) -> None:
    intake = TaskIntakeService(m2_storage)
    task, boundary = intake.submit_task("Web research task", "agent_researcher", str(m2_workspace))
    valid_token = "gov_tok_proxy_valid_123"
    m2_storage.save_token(valid_token, task.task_id, task.agent_id)

    proxy = EgressProxyServer(storage=m2_storage, port=0)
    port = await proxy.start()

    try:
        # Request 1: Without Proxy-Authorization header -> 407 Proxy Authentication Required
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        writer.write(req)
        await writer.drain()

        resp_line = await reader.readline()
        assert b"407" in resp_line
        writer.close()
        await writer.wait_closed()

        # Check that UNATTRIBUTED event was recorded
        with m2_storage.get_connection() as conn:
            unattr = conn.execute("SELECT * FROM governance_events WHERE task_id IS NULL AND source = 'EGRESS_PROXY'").fetchall()
            assert len(unattr) >= 1
            assert unattr[0]["agent_id"] == "UNATTRIBUTED"
            assert unattr[0]["action_taken"] == "BLOCK_ACTION"
            assert unattr[0]["prevented"] == 1

        # Request 2: With invalid task token -> 407
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer invalid_token\r\n\r\n"
        writer.write(req)
        await writer.drain()

        resp_line = await reader.readline()
        assert b"407" in resp_line
        writer.close()
        await writer.wait_closed()

    finally:
        await proxy.stop()


# --- 2. EGRESS PROXY BOUNDARY ENFORCEMENT ---

@pytest.mark.asyncio
async def test_proxy_destination_enforcement(m2_storage: GovernanceStorage, m2_workspace: Path) -> None:
    # Setup a dummy local target server
    async def dummy_target(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readline()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello Target!")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    target_server = await asyncio.start_server(dummy_target, "127.0.0.1", 0)
    target_port = target_server.sockets[0].getsockname()[1]

    # Setup task allowing 127.0.0.1:<target_port>
    intake = TaskIntakeService(m2_storage)
    task, boundary = intake.submit_task("Web research task", "agent_researcher", str(m2_workspace))
    boundary.network = [f"127.0.0.1:{target_port}"]
    m2_storage.save_boundary(boundary)

    token = "gov_tok_proxy_enforce_456"
    m2_storage.save_token(token, task.task_id, task.agent_id)

    proxy = EgressProxyServer(storage=m2_storage, port=0)
    proxy_port = await proxy.start()

    try:
        # Case 1: Connect to ALLOWED local target
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        connect_req = f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nProxy-Authorization: Bearer {token}\r\n\r\n".encode()
        writer.write(connect_req)
        await writer.drain()

        resp_line = await reader.readline()
        assert b"200 Connection Established" in resp_line
        empty_line = await reader.readline()
        assert empty_line == b"\r\n"

        # Send HTTP GET through tunnel
        writer.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        await writer.drain()

        target_reply = await reader.readline()
        assert b"200 OK" in target_reply
        writer.close()
        await writer.wait_closed()

        # Case 2: Connect to BLOCKED destination (unlisted example.com:443) -> 403 Forbidden
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        blocked_req = f"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer {token}\r\n\r\n".encode()
        writer.write(blocked_req)
        await writer.drain()

        blocked_resp = await reader.readline()
        assert b"403 Forbidden" in blocked_resp
        writer.close()
        await writer.wait_closed()

        # Check recorded events
        events = m2_storage.get_events_for_task(task.task_id)
        assert len(events) >= 2

        allowed_evt = next(e for e in events if str(target_port) in e.target)
        assert allowed_evt.verdict == EventVerdict.INSIDE
        assert allowed_evt.action_taken == TaskAction.ALLOW
        assert allowed_evt.prevented is False

        blocked_evt = next(e for e in events if "example.com" in e.target)
        assert blocked_evt.verdict == EventVerdict.OUTSIDE
        assert blocked_evt.action_taken == TaskAction.BLOCK_ACTION
        assert blocked_evt.prevented is True  # Real-time prevention before TCP connect!

    finally:
        await proxy.stop()
        target_server.close()
        await target_server.wait_closed()


# --- 3. A2A GATEWAY PEER AGENT BOUNDARY CHECK & SHADOW DISCOVERY ---

def test_a2a_gateway_governance(m2_storage: GovernanceStorage, m2_workspace: Path) -> None:
    intake = TaskIntakeService(m2_storage)
    task, boundary = intake.submit_task("Summarise and consult Bob", "agent_alice", str(m2_workspace))
    # Grant only agent_bob in peer_agents
    boundary.peer_agents = ["agent_bob"]
    m2_storage.save_boundary(boundary)

    token = "gov_tok_a2a_001"
    m2_storage.save_token(token, task.task_id, task.agent_id)

    a2a_gov = A2AGatewayGovernance(m2_storage)

    # 1. Allowed peer agent call: calling agent_bob
    allowed, reason = a2a_gov.check_a2a_call(token, "agent_bob")
    assert allowed is True
    assert "Authorized" in reason

    # 2. Blocked peer agent call: calling unapproved agent_charlie -> BLOCKED
    allowed, reason = a2a_gov.check_a2a_call(token, "agent_charlie")
    assert allowed is False
    assert "denied by boundary" in reason

    # 3. Ungoverned / Shadow agent call: calling without task token
    allowed, reason = a2a_gov.check_a2a_call(None, "agent_bob", declared_caller_id="rogue_agent_x")
    assert allowed is True
    assert "Ungoverned" in reason

    # Verify events
    events = m2_storage.get_events_for_task(task.task_id)
    assert len(events) == 2

    bob_evt = next(e for e in events if e.target == "agent_bob")
    assert bob_evt.verdict == EventVerdict.INSIDE
    assert bob_evt.prevented is False

    charlie_evt = next(e for e in events if e.target == "agent_charlie")
    assert charlie_evt.verdict == EventVerdict.OUTSIDE
    assert charlie_evt.prevented is True

    # Check shadow agent discovery event
    with m2_storage.get_connection() as conn:
        shadow_evt = conn.execute("SELECT * FROM governance_events WHERE agent_id = 'rogue_agent_x'").fetchone()
        assert shadow_evt is not None
        assert shadow_evt["action_taken"] == "ALERT"


# --- 4. AGENT INVENTORY (GOVERNED VS SHADOW DISCOVERY) ---

def test_agent_inventory_service(m2_storage: GovernanceStorage, m2_workspace: Path) -> None:
    intake = TaskIntakeService(m2_storage)
    task, boundary = intake.submit_task("Doc analysis", "agent_doc_summarizer", str(m2_workspace))
    token = "gov_tok_inv_001"
    m2_storage.save_token(token, task.task_id, task.agent_id)

    # Simulate activity for agent_doc_summarizer
    a2a_gov = A2AGatewayGovernance(m2_storage)
    boundary.peer_agents = ["agent_bob"]
    m2_storage.save_boundary(boundary)
    a2a_gov.check_a2a_call(token, "agent_bob")
    a2a_gov.check_a2a_call(token, "agent_charlie")

    # Simulate ungoverned shadow activity
    a2a_gov.check_a2a_call(None, "agent_bob", declared_caller_id="shadow_crawler_007")

    inv_service = AgentInventoryService(m2_storage)
    inventory = inv_service.get_inventory()

    # Find agent_doc_summarizer
    governed_item = next((i for i in inventory if i.agent_id == "agent_doc_summarizer"), None)
    assert governed_item is not None
    assert governed_item.classification == "GOVERNED"
    assert governed_item.actions_inside == 1
    assert governed_item.actions_outside == 1
    assert governed_item.violations_count == 1

    # Find shadow_crawler_007
    shadow_item = next((i for i in inventory if i.agent_id == "shadow_crawler_007"), None)
    assert shadow_item is not None
    assert shadow_item.classification == "SHADOW"
    assert shadow_item.violations_count >= 1

    # Verify alerts list
    alerts = inv_service.get_alerts()
    assert len(alerts) >= 2
    assert any(a["agent_id"] == "shadow_crawler_007" and a["is_shadow"] for a in alerts)


# --- 5. GOVERNANCE API ROUTER ENDPOINTS ---

@pytest.mark.asyncio
async def test_governance_api_endpoints(m2_storage: GovernanceStorage, m2_workspace: Path) -> None:
    from fastapi import FastAPI
    from demo.security_monitor.app.governance.api import governance_router
    import demo.security_monitor.app.governance.api as gov_api_module

    # Temporarily bind test storage
    gov_api_module._storage = m2_storage
    gov_api_module._intake = TaskIntakeService(m2_storage)
    gov_api_module._inventory_service = AgentInventoryService(m2_storage)

    app = FastAPI()
    app.include_router(governance_router, prefix="/api/governance")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # 1. POST /api/governance/tasks
        res = await client.post(
            "/api/governance/tasks",
            json={
                "request_text": "Analyse financial report.pdf and write summary.txt",
                "agent_id": "agent_finance",
                "workspace_root": str(m2_workspace),
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert "task" in data
        assert "boundary" in data
        task_id = data["task"]["task_id"]

        # 2. GET /api/governance/tasks
        res = await client.get("/api/governance/tasks")
        assert res.status_code == 200
        tasks = res.json()
        assert len(tasks) >= 1
        assert any(t["task_id"] == task_id for t in tasks)

        # 3. GET /api/governance/tasks/{task_id}
        res = await client.get(f"/api/governance/tasks/{task_id}")
        assert res.status_code == 200
        detail = res.json()
        assert detail["task"]["task_id"] == task_id
        assert "boundary" in detail
        assert "summary" in detail

        # 4. GET /api/governance/inventory
        res = await client.get("/api/governance/inventory")
        assert res.status_code == 200
        inv = res.json()
        assert any(i["agent_id"] == "agent_finance" for i in inv)

        # 5. GET /api/governance/alerts
        res = await client.get("/api/governance/alerts")
        assert res.status_code == 200
