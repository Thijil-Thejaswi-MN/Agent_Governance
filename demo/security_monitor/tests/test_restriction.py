from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from app.core.models import SecuritySeverity, PolicyAction, SecurityViolation
from app.policy.engine import PolicyEngine
from app.inventory.store import InMemoryAgentInventory
from app.gateway.server import create_app


def test_restriction_policy_engine_mapping():
    engine = PolicyEngine()
    viol = SecurityViolation(
        violation_code="RESTRICTED_OPERATION_DENIED",
        description="Mutating task execution blocked under restricted mode",
    )
    severity, action = engine.evaluate(viol)
    assert severity == SecuritySeverity.MEDIUM
    assert action == PolicyAction.RESTRICT


def test_restricted_mode_blocks_mutating_allows_safe_inspection():
    """
    Verify restricted mode explicitly:
    - Permitted safe read-only operation (.well-known metadata) continues to pass.
    - Mutating task execution / unapproved methods are denied with HTTP 403.
    """
    inventory = InMemoryAgentInventory()
    app = create_app(inventory=inventory)
    client = TestClient(app)

    # Restrict the target agent helloworld
    inventory.restrict(
        identity="helloworld",
        reason="Suspicious runtime variance detected; entering restricted sandbox",
        allowed_operations=[".well-known/agent-card.json", ".well-known/agent.json", "status"],
    )
    assert inventory.is_restricted("helloworld") is True

    # 1. Permitted safe operation: reading agent card metadata
    # The gateway forwards this permitted safe inspection to upstream
    # (or returns upstream response). It must NOT be blocked by RESTRICT policy.
    resp_safe = client.get("/proxy/helloworld/.well-known/agent-card.json")
    # Upstream is running on 9999 so this should succeed with 200
    assert resp_safe.status_code == 200

    # 2. Blocked mutating operation: executing task / SendMessage / echo_bot
    resp_mutating = client.post(
        "/proxy/helloworld",
        json={"jsonrpc": "2.0", "id": "task-01", "method": "echo_bot", "params": {"message": "hello"}},
    )
    assert resp_mutating.status_code == 403
    data = resp_mutating.json()
    assert data["error"]["code"] == -32003
    assert data["error"]["action"] == "RESTRICT"
    assert data["error"]["violation"]["violation_code"] == "RESTRICTED_OPERATION_DENIED"

    # 3. Verify trusted unrestricted agent (agentalice) remains completely usable
    resp_alice_safe = client.get("/proxy/agentalice/.well-known/agent.json")
    assert resp_alice_safe.status_code == 200

    # 4. Release restriction and verify mutating operations resume normal flow
    inventory.release_restriction("helloworld")
    assert inventory.is_restricted("helloworld") is False

    resp_mutating_after = client.post(
        "/proxy/helloworld",
        json={"jsonrpc": "2.0", "id": "task-02", "method": "echo_bot", "params": {"message": "hello"}},
    )
    # With restriction released, request is processed by upstream HelloWorld (HTTP 200)
    assert resp_mutating_after.status_code == 200


def test_restricted_caller_enforcement():
    """Verify restriction applied to a specific caller identity blocks their mutating calls."""
    inventory = InMemoryAgentInventory()
    app = create_app(inventory=inventory)
    client = TestClient(app)

    # Restrict an untrusted or suspicious caller
    inventory.restrict(
        identity="suspicious_caller_99",
        reason="Rate threshold warning; restricted to safe inspection",
        allowed_operations=[".well-known/agent-card.json", "status"],
    )

    headers_restricted = {"x-agent-id": "suspicious_caller_99"}
    headers_normal = {"x-agent-id": "trusted_client_01"}

    # Suspicious caller reading metadata -> allowed
    resp_meta = client.get("/proxy/helloworld/.well-known/agent-card.json", headers=headers_restricted)
    assert resp_meta.status_code == 200

    # Suspicious caller sending task -> blocked with 403 code -32003
    resp_task = client.post(
        "/proxy/helloworld",
        json={"jsonrpc": "2.0", "id": "call-1", "method": "echo_bot", "params": {}},
        headers=headers_restricted,
    )
    assert resp_task.status_code == 403
    assert resp_task.json()["error"]["code"] == -32003

    # Normal caller sending task -> allowed (reaches upstream successfully)
    resp_normal = client.post(
        "/proxy/helloworld",
        json={"jsonrpc": "2.0", "id": "call-2", "method": "echo_bot", "params": {}},
        headers=headers_normal,
    )
    assert resp_normal.status_code == 200


def test_operator_restriction_api_endpoints():
    """Verify operator API endpoints for applying and releasing restrictions."""
    app = create_app()
    client = TestClient(app)

    # 1. Apply restriction via API
    resp_apply = client.post(
        "/api/v1/restriction/apply",
        json={
            "identity": "agent_alpha",
            "reason": "Operator maintenance restricted mode",
            "allowed_operations": [".well-known/agent-card.json"],
        },
    )
    assert resp_apply.status_code == 200
    assert resp_apply.json()["restricted"] is True

    # Verify status reflects restriction
    resp_status = client.get("/api/v1/status")
    assert resp_status.status_code == 200
    assert "agent_alpha" in resp_status.json()["restricted_agents"]

    # 2. Release restriction via API
    resp_release = client.post(
        "/api/v1/restriction/release",
        json={"identity": "agent_alpha"},
    )
    assert resp_release.status_code == 200
    assert resp_release.json()["released"] is True

    resp_status2 = client.get("/api/v1/status")
    assert "agent_alpha" not in resp_status2.json()["restricted_agents"]
