from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.models import SecuritySeverity, PolicyAction
from app.detection.cycle_overflow import DelegationTracker, detect_cycle_overflow
from app.policy.engine import PolicyEngine
from app.gateway.server import create_app


def test_delegation_tracker_normal_flow():
    """Verify acyclic progression across distinct agents produces no violation."""
    tracker = DelegationTracker(default_max_depth=5)
    ctx = "test_normal_ctx_01"

    # Hop 1: to helloworld
    v1 = tracker.check_violation(ctx, "helloworld")
    assert v1 is None
    tracker.record_hop(ctx, "helloworld")

    # Hop 2: to agentalice
    v2 = tracker.check_violation(ctx, "agentalice")
    assert v2 is None
    tracker.record_hop(ctx, "agentalice")

    assert tracker.get_chain(ctx) == ["helloworld", "agentalice"]


def test_delegation_tracker_cycle_detected():
    """Verify loop back to an existing agent in the context chain triggers CO_CYCLE_DETECTED."""
    tracker = DelegationTracker(default_max_depth=5)
    ctx = "test_cycle_ctx_02"

    tracker.record_hop(ctx, "helloworld")
    tracker.record_hop(ctx, "agentalice")

    # Loop back to helloworld: [helloworld, agentalice, helloworld]
    violation = tracker.check_violation(ctx, "helloworld")
    assert violation is not None
    assert violation.violation_code == "CO_CYCLE_DETECTED"
    assert violation.details["cycle_path"] == ["helloworld", "agentalice", "helloworld"]


def test_delegation_tracker_depth_exceeded():
    """Verify exceeding the max_depth budget triggers CO_DEPTH_EXCEEDED."""
    tracker = DelegationTracker(default_max_depth=3)
    ctx = "test_depth_ctx_03"

    tracker.record_hop(ctx, "agent_1")
    tracker.record_hop(ctx, "agent_2")
    tracker.record_hop(ctx, "agent_3")

    # 4th hop exceeds limit 3
    violation = tracker.check_violation(ctx, "agent_4")
    assert violation is not None
    assert violation.violation_code == "CO_DEPTH_EXCEEDED"
    assert violation.details["current_depth"] == 4


def test_policy_engine_co_mapping():
    """Verify PolicyEngine maps CO violations to HIGH severity and QUARANTINE."""
    engine = PolicyEngine()
    tracker = DelegationTracker()
    ctx = "test_policy_ctx_04"
    tracker.record_hop(ctx, "helloworld")

    viol = tracker.check_violation(ctx, "helloworld")
    severity, action = engine.evaluate(viol)

    assert severity == SecuritySeverity.HIGH
    assert action == PolicyAction.QUARANTINE


def test_gateway_cycle_overflow_blocking():
    """Verify gateway intercepts cyclic task delegations and rejects with HTTP 403."""
    app = create_app()
    client = TestClient(app)

    # Send request with explicit delegation chain header showing helloworld already visited
    resp = client.post(
        "/proxy/helloworld",
        json={"jsonrpc": "2.0", "id": "co-test-1", "method": "echo_bot", "params": {}},
        headers={
            "x-context-id": "co_simulated_cycle_ctx",
            "x-delegation-chain": "helloworld,agentalice",
            "x-agent-id": "adversarial_cycle_orchestrator",
        },
    )

    assert resp.status_code == 403
    data = resp.json()
    assert data["error"]["code"] == -32005
    assert data["error"]["violation"]["violation_code"] == "CO_CYCLE_DETECTED"
    assert data["error"]["action"] == "QUARANTINE"

    # Verify caller identity was quarantined
    resp_quarantined = client.post(
        "/proxy/agentalice",
        json={"jsonrpc": "2.0", "id": "co-test-2", "method": "message/send"},
        headers={"x-agent-id": "adversarial_cycle_orchestrator"},
    )
    assert resp_quarantined.status_code == 403
    assert "QUARANTINED" in resp_quarantined.text


def test_co_depth_boundary_semantics_depths_4_5_6():
    """
    REGRESSION TEST FOR ISSUE 2 — CO DEPTH BOUNDARY SEMANTICS.
    Configured MAX_DEPTH = 5.
    Intended Semantic: Option A (Maximum allowed depth is 5 hops; only depth > 5 is rejected).
    - Depth 4: prior chain of 3 agents + target = 4 total hops -> ALLOWED (None)
    - Depth 5: prior chain of 4 agents + target = 5 total hops -> ALLOWED (None)
    - Depth 6: prior chain of 5 agents + target = 6 total hops -> REJECTED (CO_DEPTH_EXCEEDED)
    """
    tracker = DelegationTracker(default_max_depth=5)

    # 1. Depth 4: prior chain has 3 hops -> target is 4th hop
    v_depth_4 = tracker.check_violation(
        context_id="ctx_depth_4",
        target_agent_id="agent_04",
        explicit_chain=["agent_01", "agent_02", "agent_03"],
        max_depth=5,
    )
    assert v_depth_4 is None, "Depth 4 path must be ALLOWED under MAX_DEPTH=5"

    # 2. Depth 5: prior chain has 4 hops -> target is 5th hop (boundary)
    v_depth_5 = tracker.check_violation(
        context_id="ctx_depth_5",
        target_agent_id="agent_05",
        explicit_chain=["agent_01", "agent_02", "agent_03", "agent_04"],
        max_depth=5,
    )
    assert v_depth_5 is None, "Depth 5 path must be ALLOWED under MAX_DEPTH=5"

    # 3. Depth 6: prior chain has 5 hops -> target is 6th hop (exceeds limit)
    v_depth_6 = tracker.check_violation(
        context_id="ctx_depth_6",
        target_agent_id="agent_06",
        explicit_chain=["agent_01", "agent_02", "agent_03", "agent_04", "agent_05"],
        max_depth=5,
    )
    assert v_depth_6 is not None, "Depth 6 path must be REJECTED under MAX_DEPTH=5"
    assert v_depth_6.violation_code == "CO_DEPTH_EXCEEDED"
    assert v_depth_6.details["current_depth"] == 6
    assert v_depth_6.details["max_depth_budget"] == 5
    assert len(v_depth_6.details["delegation_path"]) == 6

