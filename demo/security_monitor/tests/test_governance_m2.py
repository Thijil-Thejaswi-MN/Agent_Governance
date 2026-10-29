"""Milestone 2 Test Suite: Egress Proxy, A2A Gateway Governance, Inventory v1, and API.

Tests:
1. F5.2 Egress Network Proxy: Authentication via Proxy-Authorization Bearer token
2. F5.2 Egress Network Proxy: Allowed vs Blocked CONNECT destinations (Real-time prevention)
3. F5.3 A2A Gateway: Peer agent boundary enforcement with per-task tokens
4. F10 Agent Inventory: Dynamic classification of Governed vs Shadow agents
5. F12 Governance API: /tasks, /inventory, /alerts endpoints
6. Shadow Agent Configurable Actions: Default BLOCK in ENFORCE, ALERT in OBSERVE, ASK_USER (Item 2)
7. Proxy Plain-HTTP Absolute-Form Requests (Item 4)
8. Proxy Connects to Exact Validated IP without Second DNS Lookup (Item 4)
9. Real A2A Route /proxy/{agent_id} Governance Enforcement (Item 3)
"""
from __future__ import annotations

import asyncio
import os
import socket
from pathlib import Path
from typing import Any
import pytest
from fastapi.testclient import TestClient

from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    EventVerdict,
    RiskTier,
    TaskAction,
    EventSource,
    TaskLifecycle,
    GovernanceEvent,
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

def test_proxy_authentication(m2_storage: GovernanceStorage, m2_workspace: Path) -> None:
    async def _test() -> None:
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

    asyncio.run(_test())


# --- 2. EGRESS PROXY BOUNDARY ENFORCEMENT ---

def test_proxy_destination_enforcement(m2_storage: GovernanceStorage, m2_workspace: Path) -> None:
    async def _test() -> None:
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

            # Verify persisted events
            events = m2_storage.get_events_for_task(task.task_id)
            assert len(events) == 2

            allowed_evt = next(e for e in events if e.target == f"127.0.0.1:{target_port}")
            assert allowed_evt.verdict == EventVerdict.INSIDE
            assert allowed_evt.action_taken == TaskAction.ALLOW
            assert allowed_evt.prevented is False

            blocked_evt = next(e for e in events if "example.com" in e.target)
            assert blocked_evt.verdict == EventVerdict.OUTSIDE
            assert blocked_evt.action_taken == TaskAction.BLOCK_ACTION
            assert blocked_evt.prevented is True

        finally:
            await proxy.stop()
            target_server.close()
            await target_server.wait_closed()

    asyncio.run(_test())


# --- 3. A2A GATEWAY PEER AGENT INTERCEPTION ---

def test_a2a_gateway_governance(m2_storage: GovernanceStorage, m2_workspace: Path) -> None:
    intake = TaskIntakeService(m2_storage)
    task, boundary = intake.submit_task("Summarise and consult Bob", "agent_alice", str(m2_workspace))
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
    # Default ENFORCE mode: blocked
    allowed, reason = a2a_gov.check_a2a_call(None, "agent_bob", declared_caller_id="rogue_agent_x")
    assert allowed is False
    assert "Ungoverned agent blocked" in reason

    # Verify events
    events = m2_storage.get_events_for_task(task.task_id)
    assert len(events) == 2

    bob_evt = next(e for e in events if e.target == "agent_bob")
    assert bob_evt.verdict == EventVerdict.INSIDE
    assert bob_evt.prevented is False

    charlie_evt = next(e for e in events if e.target == "agent_charlie")
    assert charlie_evt.verdict == EventVerdict.OUTSIDE
    assert charlie_evt.prevented is True


# --- 4. AGENT INVENTORY SERVICE ---

def test_agent_inventory_service(m2_storage: GovernanceStorage, m2_workspace: Path) -> None:
    intake = TaskIntakeService(m2_storage)
    task, boundary = intake.submit_task("Task 1", "agent_doc_summarizer", str(m2_workspace))
    task.status = TaskLifecycle.ACTIVE
    m2_storage.save_task(task)

    # Record some governed events
    m2_storage.record_event(
        GovernanceEvent(
            event_id="evt_test_001",
            timestamp="2026-10-21T10:00:00Z",
            source=EventSource.TOOL_BROKER,
            task_id=task.task_id,
            agent_id=task.agent_id,
            kind="file_read",
            target="input/report.pdf",
            verdict=EventVerdict.INSIDE,
            risk_tier=RiskTier.LOW,
            action_taken=TaskAction.ALLOW,
            prevented=False,
            rule_matched="allowed file read",
            boundary_version=1,
        )
    )
    m2_storage.record_event(
        GovernanceEvent(
            event_id="evt_test_002",
            timestamp="2026-10-21T10:01:00Z",
            source=EventSource.TOOL_BROKER,
            task_id=task.task_id,
            agent_id=task.agent_id,
            kind="file_read",
            target="credentials.json",
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.HIGH,
            action_taken=TaskAction.BLOCK_ACTION,
            prevented=True,
            rule_matched="denied file read outside boundary",
            boundary_version=1,
        )
    )

    # Record shadow agent event (task_id=None)
    m2_storage.record_event(
        GovernanceEvent(
            event_id="evt_test_003",
            timestamp="2026-10-21T10:02:00Z",
            source=EventSource.A2A_GATEWAY,
            task_id=None,
            agent_id="shadow_crawler_007",
            kind="peer_agent_call",
            target="agent_doc_summarizer",
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.HIGH,
            action_taken=TaskAction.ALERT,
            prevented=False,
            rule_matched="ungoverned agent activity detected",
            boundary_version=None,
        )
    )

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

def test_governance_api_endpoints(m2_storage: GovernanceStorage, m2_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import FastAPI
    from demo.security_monitor.app.governance.api import governance_router
    import demo.security_monitor.app.governance.api as gov_api_module

    # Temporarily bind test storage
    gov_api_module._storage = m2_storage
    gov_api_module._intake = TaskIntakeService(m2_storage)
    gov_api_module._inventory_service = AgentInventoryService(m2_storage)

    app = FastAPI()
    app.include_router(governance_router, prefix="/api/governance")

    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "m2_operator_token")
    client = TestClient(app, headers={"X-Operator-Token": "m2_operator_token"})

    # 1. POST /api/governance/tasks
    res = client.post(
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
    res = client.get("/api/governance/tasks")
    assert res.status_code == 200
    tasks = res.json()
    assert len(tasks) >= 1
    assert any(t["task_id"] == task_id for t in tasks)

    # 3. GET /api/governance/tasks/{task_id}
    res = client.get(f"/api/governance/tasks/{task_id}")
    assert res.status_code == 200
    detail = res.json()
    assert detail["task"]["task_id"] == task_id
    assert "boundary" in detail
    assert "summary" in detail

    # 4. GET /api/governance/inventory
    res = client.get("/api/governance/inventory")
    assert res.status_code == 200
    inv = res.json()
    assert any(i["agent_id"] == "agent_finance" for i in inv)

    # 5. GET /api/governance/alerts
    res = client.get("/api/governance/alerts")
    assert res.status_code == 200


# --- 6. SHADOW AGENT CONFIGURABLE ACTIONS (ITEM 2) ---

def test_shadow_agent_configurable_actions(m2_storage: GovernanceStorage) -> None:
    # 1. Default in ENFORCE mode: BLOCK_ACTION (fails closed)
    gov_enforce = A2AGatewayGovernance(storage=m2_storage, system_mode=EnforcementMode.ENFORCE)
    allowed, reason = gov_enforce.check_a2a_call(
        caller_token=None,
        target_agent_id="peer_target",
        declared_caller_id="untokened_bot",
    )
    assert allowed is False
    assert "Ungoverned agent blocked (BLOCK_ACTION)" in reason

    # 2. Default in OBSERVE mode: ALERT (allowed and audited)
    gov_observe = A2AGatewayGovernance(storage=m2_storage, system_mode=EnforcementMode.OBSERVE)
    allowed, reason = gov_observe.check_a2a_call(
        caller_token=None,
        target_agent_id="peer_target",
        declared_caller_id="untokened_bot",
    )
    assert allowed is True
    assert "Ungoverned agent activity audited (ALERT)" in reason

    # 3. Explicit ASK_USER configuration: blocks/pauses pending human approval
    gov_ask = A2AGatewayGovernance(
        storage=m2_storage,
        system_mode=EnforcementMode.OBSERVE,
        ungoverned_action=TaskAction.ASK_USER,
    )
    allowed, reason = gov_ask.check_a2a_call(
        caller_token=None,
        target_agent_id="peer_target",
        declared_caller_id="untokened_bot",
    )
    assert allowed is False
    assert "Ungoverned agent blocked (ASK_USER)" in reason


# --- 7. PROXY PLAIN-HTTP ABSOLUTE-FORM REQUESTS (ITEM 4) ---

def test_proxy_plain_http_absolute_form(m2_storage: GovernanceStorage, m2_workspace: Path) -> None:
    async def _test() -> None:
        # Target plain HTTP server
        async def dummy_http_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            req_line = await reader.readline()
            while True:
                line = await reader.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 14\r\n\r\nHello Upstream")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        http_server = await asyncio.start_server(dummy_http_server, "127.0.0.1", 0)
        target_port = http_server.sockets[0].getsockname()[1]
        target_url = f"http://127.0.0.1:{target_port}/api/data"

        # Setup task allowing this target
        intake = TaskIntakeService(m2_storage)
        task, boundary = intake.submit_task("HTTP fetch task", "agent_fetcher", str(m2_workspace))
        boundary.network = [f"127.0.0.1:{target_port}"]
        m2_storage.save_boundary(boundary)

        token = "gov_tok_plain_http_999"
        m2_storage.save_token(token, task.task_id, task.agent_id)

        proxy = EgressProxyServer(storage=m2_storage, port=0)
        proxy_port = await proxy.start()

        try:
            # Case A: Allowed absolute-form GET
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            raw_request = (
                f"GET {target_url} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"\r\n"
            ).encode("utf-8")
            writer.write(raw_request)
            await writer.drain()

            resp_line = await reader.readline()
            assert b"200 OK" in resp_line
            writer.close()
            await writer.wait_closed()

            # Case B: Disallowed absolute-form GET -> 403 Forbidden
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            forbidden_req = (
                f"GET http://forbidden-exfiltration.com/leak HTTP/1.1\r\n"
                f"Host: forbidden-exfiltration.com\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"\r\n"
            ).encode("utf-8")
            writer.write(forbidden_req)
            await writer.drain()

            resp_line = await reader.readline()
            assert b"403 Forbidden" in resp_line
            writer.close()
            await writer.wait_closed()

        finally:
            await proxy.stop()
            http_server.close()
            await http_server.wait_closed()

    asyncio.run(_test())


# --- 8. PROXY CONNECTS TO EXACT VALIDATED IP (NO SECOND DNS LOOKUP, ITEM 4) ---

def test_proxy_connects_to_exact_validated_ip(m2_storage: GovernanceStorage, m2_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def _test() -> None:
        async def echo_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readline()
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        srv = await asyncio.start_server(echo_server, "127.0.0.1", 0)
        real_port = srv.sockets[0].getsockname()[1]

        intake = TaskIntakeService(m2_storage)
        task, boundary = intake.submit_task("DNS test task", "agent_dns", str(m2_workspace))
        boundary.network = [f"my-service.local:{real_port}", f"127.0.0.1:{real_port}"]
        m2_storage.save_boundary(boundary)

        token = "gov_tok_dns_rebinding_111"
        m2_storage.save_token(token, task.task_id, task.agent_id)

        proxy = EgressProxyServer(storage=m2_storage, port=0)
        proxy_port = await proxy.start()

        dns_call_count = 0

        def mock_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
            nonlocal dns_call_count
            dns_call_count += 1
            if host == "my-service.local":
                if dns_call_count == 1:
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
                else:
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", port))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            connect_req = (
                f"CONNECT my-service.local:{real_port} HTTP/1.1\r\n"
                f"Host: my-service.local:{real_port}\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"\r\n"
            ).encode("utf-8")
            writer.write(connect_req)
            await writer.drain()

            resp_line = await reader.readline()
            assert b"200 Connection Established" in resp_line
            writer.close()
            await writer.wait_closed()
            assert dns_call_count == 1
        finally:
            await proxy.stop()
            srv.close()
            await srv.wait_closed()

    asyncio.run(_test())


# --- 9. REAL A2A ROUTE /proxy/{agent_id} GOVERNANCE ENFORCEMENT (ITEM 3) ---

def test_real_a2a_route_governance_enforcement(m2_storage: GovernanceStorage, m2_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from demo.security_monitor.app.gateway.server import create_app

    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(m2_storage.db_path))

    intake = TaskIntakeService(m2_storage)
    task, boundary = intake.submit_task("Collaboration task", "caller_agent", str(m2_workspace))
    boundary.peer_agents = ["helloworld"]
    m2_storage.save_boundary(boundary)

    token = "gov_tok_real_route_333"
    m2_storage.save_token(token, task.task_id, task.agent_id)

    # 1. Test in ENFORCE mode
    monkeypatch.setenv("GOVERNANCE_SYSTEM_MODE", "ENFORCE")
    app_enforce = create_app()
    client_enforce = TestClient(app_enforce)

    # Case 1A: With valid task token, calling ALLOWED peer agent "helloworld"
    res_allowed = client_enforce.get(
        "/proxy/helloworld/.well-known/agent-card.json",
        headers={"x-governance-task-token": token},
    )
    assert res_allowed.status_code == 200

    # Case 1B: With valid task token, calling FORBIDDEN peer agent "secret_peer" -> 403
    res_forbidden = client_enforce.get(
        "/proxy/secret_peer/.well-known/agent-card.json",
        headers={"x-governance-task-token": token},
    )
    assert res_forbidden.status_code == 403
    assert "Governance Policy Denied" in res_forbidden.json()["error"]["message"]

    # Case 1C: Under ENFORCE mode, untokened caller -> 403 Forbidden (no silent pass)
    res_untokened = client_enforce.get(
        "/proxy/helloworld/.well-known/agent-card.json",
        headers={"x-agent-id": "shadow_untokened_agent"},
    )
    assert res_untokened.status_code == 403
    assert "Ungoverned agent blocked" in res_untokened.json()["error"]["message"]

    # 2. Test in OBSERVE mode: untokened caller is audited but allowed to pass to legacy gateway
    monkeypatch.setenv("GOVERNANCE_SYSTEM_MODE", "OBSERVE")
    app_observe = create_app()
    client_observe = TestClient(app_observe)

    res_observe = client_observe.get(
        "/proxy/helloworld/.well-known/agent-card.json",
        headers={"x-agent-id": "shadow_observed_agent"},
    )
    assert res_observe.status_code == 200
