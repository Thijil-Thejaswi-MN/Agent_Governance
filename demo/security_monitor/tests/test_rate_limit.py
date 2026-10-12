from __future__ import annotations

import time
import pytest
from fastapi.testclient import TestClient
from app.core.models import SecuritySeverity, PolicyAction
from app.policy.rate_limiter import RateLimiter
from app.policy.engine import PolicyEngine
from app.inventory.store import InMemoryAgentInventory
from app.telemetry.metrics import EventStore
from app.gateway.server import create_app


def test_rate_limiter_unit_sliding_window():
    limiter = RateLimiter(max_requests=3, window_seconds=0.5)

    # First 3 requests must pass
    res1 = limiter.check_rate_limit("caller_a")
    assert not res1.is_exceeded
    assert res1.current_count == 1

    res2 = limiter.check_rate_limit("caller_a")
    assert not res2.is_exceeded
    assert res2.current_count == 2

    res3 = limiter.check_rate_limit("caller_a")
    assert not res3.is_exceeded
    assert res3.current_count == 3

    # 4th request must be rate-limited
    res4 = limiter.check_rate_limit("caller_a")
    assert res4.is_exceeded
    assert res4.current_count == 3
    assert res4.retry_after_seconds > 0.0

    # Independent caller must NOT be rate limited
    res_b = limiter.check_rate_limit("caller_b")
    assert not res_b.is_exceeded
    assert res_b.current_count == 1

    # Wait for window to expire
    time.sleep(0.55)
    res_after = limiter.check_rate_limit("caller_a")
    assert not res_after.is_exceeded
    assert res_after.current_count == 1


def test_rate_limiter_per_key_overrides():
    limiter = RateLimiter(max_requests=2, window_seconds=1.0)
    limiter.set_key_limit("vip_caller", 10)

    # Normal caller limited at 2
    assert not limiter.check_rate_limit("normal_caller").is_exceeded
    assert not limiter.check_rate_limit("normal_caller").is_exceeded
    assert limiter.check_rate_limit("normal_caller").is_exceeded

    # VIP caller can send up to 10
    for _ in range(10):
        assert not limiter.check_rate_limit("vip_caller").is_exceeded
    assert limiter.check_rate_limit("vip_caller").is_exceeded


def test_rate_limiter_violation_and_policy_engine_mapping():
    limiter = RateLimiter(max_requests=5, window_seconds=1.0)
    engine = PolicyEngine()

    viol = limiter.create_violation("test_caller", current_count=5, retry_after=0.85)
    assert viol.violation_code == "RATE_LIMIT_EXCEEDED"

    severity, action = engine.evaluate(viol)
    assert severity == SecuritySeverity.LOW
    assert action == PolicyAction.RATE_LIMIT


def test_gateway_rate_limiting_enforcement():
    # Configure threshold with sufficient window for loopback network forwarding
    limiter = RateLimiter(max_requests=3, window_seconds=5.0)
    app = create_app(rate_limiter=limiter)
    client = TestClient(app)

    caller_id = "test_rapid_caller"
    headers = {"x-agent-id": caller_id}

    # Requests 1, 2, 3 return successfully (or 404/502 if upstream not running, but NOT 429)
    for i in range(3):
        resp = client.get("/proxy/helloworld/.well-known/agent-card.json", headers=headers)
        assert resp.status_code != 429

    # Request 4 must trigger HTTP 429 Too Many Requests
    resp_limited = client.get("/proxy/helloworld/.well-known/agent-card.json", headers=headers)
    assert resp_limited.status_code == 429
    assert "Retry-After" in resp_limited.headers
    data = resp_limited.json()
    assert data["error"]["code"] == -32029
    assert data["error"]["action"] == "RATE_LIMIT"
    assert data["error"]["violation"]["violation_code"] == "RATE_LIMIT_EXCEEDED"

    # Verify security event recorded in event store with LOW severity and RATE_LIMIT action
    events_resp = client.get("/api/v1/events")
    assert events_resp.status_code == 200
    events = events_resp.json()
    rl_events = [e for e in events if e.get("action_taken") == "RATE_LIMIT"]
    assert len(rl_events) >= 1
    assert rl_events[0]["severity"] == "LOW"

    # Different caller must NOT be affected
    other_caller_headers = {"x-agent-id": "unthrottled_caller"}
    resp_other = client.get("/proxy/helloworld/.well-known/agent-card.json", headers=other_caller_headers)
    assert resp_other.status_code != 429
