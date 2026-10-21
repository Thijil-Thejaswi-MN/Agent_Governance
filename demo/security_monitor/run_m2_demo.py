"""Milestone 2 Demonstration Runner.

Demonstrates:
1. Shared Local Egress Proxy (CONNECT tunnel enforcement):
   - Valid token + allowed destination -> 200 Connection Established, tunneled HTTP succeeds
   - Valid token + forbidden destination -> 403 Forbidden, boundary violation recorded
   - Missing/invalid token -> 407 Proxy Authentication Required
2. A2A Gateway Integration:
   - Peer agent call inside task boundary -> Allowed & attributed
   - Peer agent call outside task boundary -> Denied (403) & boundary violation recorded
   - Unauthenticated call without task token -> Discovered & cataloged as Shadow Agent
3. Agent Inventory Service & Governance API:
   - Real-time classification into Governed vs Shadow agents
   - Real metrics (active tasks, total calls, violations, compliance score) computed from SQLite
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

# Add project root to sys.path
repo_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(repo_root))

from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    TaskAction,
    EventVerdict,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.proxy import EgressProxyServer
from demo.security_monitor.app.governance.gateway_integration import A2AGatewayGovernance
from demo.security_monitor.app.governance.inventory import AgentInventoryService


async def main() -> None:
    print("=" * 80)
    print("TASK-AWARE RUNTIME AGENT GOVERNANCE LAYER - MILESTONE 2 DEMO")
    print("=" * 80)

    # 1. Setup isolated demo workspace and database
    demo_dir = repo_root / "demo" / "data" / "demo_m2_workspace"
    if demo_dir.exists():
        shutil.rmtree(demo_dir)
    demo_dir.mkdir(parents=True, exist_ok=True)
    (demo_dir / "input").mkdir(exist_ok=True)
    (demo_dir / "output").mkdir(exist_ok=True)

    db_path = repo_root / "demo" / "data" / "governance_m2_demo.db"
    if db_path.exists():
        db_path.unlink()

    storage = GovernanceStorage(db_path)
    intake = TaskIntakeService(storage)

    # Setup dummy internal destination server for CONNECT tunnel test
    async def dummy_target_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readline()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nHello From Target")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    local_server = await asyncio.start_server(dummy_target_server, "127.0.0.1", 0)
    target_port = local_server.sockets[0].getsockname()[1]
    target_addr = f"127.0.0.1:{target_port}"

    # Start Egress Proxy
    proxy = EgressProxyServer(storage=storage, port=0)
    proxy_port = await proxy.start()
    print(f"\n[+] Egress Proxy started on 127.0.0.1:{proxy_port}")
    print(f"[+] Dummy Internal Target running on {target_addr}")

    # 2. Intake Governed Task
    print(f"\n[1] TASK INTAKE & BOUNDARY DEFINITION")
    task_desc = "Fetch data from internal service and summarize"
    agent_id = "agent_researcher_v1"
    task, boundary = intake.submit_task(task_desc, agent_id, str(demo_dir))
    
    # Configure boundary network & peer agents
    boundary.network = [target_addr]
    boundary.peer_agents = ["peer_sentiment_analyst", "helloworld"]
    storage.save_boundary(boundary)

    # Issue task execution token
    task_token = "gov_tok_m2_demo_778899"
    storage.save_token(task_token, task.task_id, task.agent_id)

    print(f"    Task ID      : {task.task_id}")
    print(f"    Agent ID     : {agent_id}")
    print(f"    Task Token   : {task_token[:18]}...")
    print(f"    Allowed Net  : {boundary.network}")
    print(f"    Allowed Peer : {boundary.peer_agents}")

    # 3. Test Egress Proxy
    print(f"\n[2] EGRESS PROXY CONNECT ENFORCEMENT")

    # Case 2A: Allowed destination with valid token
    print("  -> Scenario 2A: Agent CONNECTs to allowed internal service...")
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    connect_req = f"CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Authorization: Bearer {task_token}\r\n\r\n".encode()
    writer.write(connect_req)
    await writer.drain()
    resp_line = await reader.readline()
    empty_line = await reader.readline()
    print(f"     Proxy Response: {resp_line.decode().strip()}")
    assert b"200 Connection Established" in resp_line

    # Send payload through established tunnel
    writer.write(b"GET /data HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    await writer.drain()
    target_resp = await reader.readline()
    print(f"     Target Reply  : {target_resp.decode().strip()} (Tunnel functional)")
    writer.close()
    await writer.wait_closed()

    # Case 2B: Blocked destination with valid token
    print("  -> Scenario 2B: Agent CONNECTs to unauthorized evil-exfiltration.com:443...")
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    connect_req = f"CONNECT evil-exfiltration.com:443 HTTP/1.1\r\nHost: evil-exfiltration.com:443\r\nProxy-Authorization: Bearer {task_token}\r\n\r\n".encode()
    writer.write(connect_req)
    await writer.drain()
    resp_line = await reader.readline()
    print(f"     Proxy Response: {resp_line.decode().strip()} (BLOCKED by Task Boundary)")
    assert b"403 Forbidden" in resp_line
    writer.close()
    await writer.wait_closed()

    # Case 2C: Missing token
    print("  -> Scenario 2C: Rogue client connects through proxy without token...")
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    connect_req = f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode()
    writer.write(connect_req)
    await writer.drain()
    resp_line = await reader.readline()
    print(f"     Proxy Response: {resp_line.decode().strip()} (BLOCKED by Authentication)")
    assert b"407 Proxy Authentication Required" in resp_line
    writer.close()
    await writer.wait_closed()

    # Case 2D: Plain-HTTP absolute-form request
    print("  -> Scenario 2D: Agent sends plain-HTTP absolute-form GET through proxy...")
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    raw_get = f"GET http://{target_addr}/data HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Authorization: Bearer {task_token}\r\n\r\n".encode()
    writer.write(raw_get)
    await writer.drain()
    http_resp_line = await reader.readline()
    print(f"     Proxy Response: {http_resp_line.decode().strip()} (Plain HTTP absolute GET succeeded)")
    assert b"200 OK" in http_resp_line
    writer.close()
    await writer.wait_closed()

    # 4. Test A2A Gateway Inter-Agent Governance
    print(f"\n[3] A2A GATEWAY INTER-AGENT GOVERNANCE")
    a2a_gov = A2AGatewayGovernance(storage, system_mode=EnforcementMode.ENFORCE)

    # Case 3A: Allowed peer call
    print("  -> Scenario 3A: Governed agent calls authorized peer 'peer_sentiment_analyst'...")
    allowed_3a, reason_3a = a2a_gov.check_a2a_call(
        caller_token=task_token,
        target_agent_id="peer_sentiment_analyst",
        declared_caller_id=agent_id,
        details={"type": "analyze_sentiment", "data": "Sample text"},
    )
    print(f"     Gateway Verdict: Allowed={allowed_3a}, Reason={reason_3a}")
    assert allowed_3a is True

    # Case 3B: Forbidden peer call
    print("  -> Scenario 3B: Governed agent attempts unauthorized call to 'peer_database_admin'...")
    allowed_3b, reason_3b = a2a_gov.check_a2a_call(
        caller_token=task_token,
        target_agent_id="peer_database_admin",
        declared_caller_id=agent_id,
        details={"type": "drop_table", "table": "users"},
    )
    print(f"     Gateway Verdict: Allowed={allowed_3b}, Reason={reason_3b}")
    assert allowed_3b is False

    # Case 3C: Shadow agent call (unauthenticated) under ENFORCE mode -> BLOCKED
    print("  -> Scenario 3C: Unregistered shadow agent 'shadow_crawler_007' calls gateway without token...")
    allowed_3c, reason_3c = a2a_gov.check_a2a_call(
        caller_token=None,
        target_agent_id="peer_sentiment_analyst",
        declared_caller_id="shadow_crawler_007",
        details={"type": "extract_feed"},
    )
    print(f"     Gateway Verdict: Allowed={allowed_3c}, Status={reason_3c} (BLOCKED in ENFORCE mode)")
    assert allowed_3c is False

    # Case 3D: Real Route /proxy/{agent_id} inspection
    print("  -> Scenario 3D: Calling real A2A route /proxy/{agent_id} with task token...")
    from fastapi.testclient import TestClient
    from demo.security_monitor.app.gateway.server import create_app
    os.environ["GOVERNANCE_DB_PATH"] = str(db_path)
    os.environ["GOVERNANCE_SYSTEM_MODE"] = "ENFORCE"
    gateway_app = create_app()
    client = TestClient(gateway_app)

    # Calling allowed peer on real route
    resp_route_allowed = client.get(
        "/proxy/helloworld/.well-known/agent-card.json",
        headers={"x-governance-task-token": task_token},
    )
    # Target peer_database_admin (not in boundary) on real route -> 403
    resp_route_blocked = client.get(
        "/proxy/peer_database_admin/.well-known/agent-card.json",
        headers={"x-governance-task-token": task_token},
    )
    print(f"     Real Route Allowed Check: Status={resp_route_allowed.status_code} (Passed)")
    print(f"     Real Route Blocked Check: Status={resp_route_blocked.status_code} ({resp_route_blocked.json()['error']['message']})")
    assert resp_route_allowed.status_code == 200
    assert resp_route_blocked.status_code == 403

    # 5. Agent Inventory Service
    print(f"\n[4] AGENT INVENTORY SERVICE (F10)")
    inventory_service = AgentInventoryService(storage)
    inventory = inventory_service.get_inventory()

    print(f"    Total Agents Registered / Discovered: {len(inventory)}")
    print("-" * 88)
    print(f"{'AGENT ID':<25} | {'CLASS':<10} | {'STATUS':<8} | {'INSIDE':<6} | {'OUTSIDE':<7} | {'VIOL':<5} | {'COMPLIANCE':<10}")
    print("-" * 88)
    for item in inventory:
        total = item.actions_inside + item.actions_outside
        comp = (item.actions_inside / total * 100) if total > 0 else 100.0
        print(f"{item.agent_id:<25} | {item.classification:<10} | {item.status:<8} | {item.actions_inside:<6} | {item.actions_outside:<7} | {item.violations_count:<5} | {comp:<9.1f}%")
    print("-" * 88)

    # 6. Governance Alerts Inspection
    alerts = inventory_service.get_alerts()
    print(f"\n[5] RECORDED GOVERNANCE ALERTS ({len(alerts)} ALERTS)")
    for alert in alerts:
        shadow_tag = "[SHADOW]" if alert["is_shadow"] else "[GOVERNED]"
        print(f"    [{alert['timestamp']}] {shadow_tag:<10} Agent={alert['agent_id']:<20} | Action={alert['action_taken']:<12} | Target={str(alert['target']):<25} | Rule={alert['rule_matched']}")

    # Clean up
    await proxy.stop()
    local_server.close()
    await local_server.wait_closed()
    print("\n[+] Milestone 2 Demonstration successfully completed.")


if __name__ == "__main__":
    asyncio.run(main())
