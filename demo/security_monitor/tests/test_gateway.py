import pytest
from fastapi.testclient import TestClient

from app.gateway.server import create_app
from app.inventory.store import InMemoryAgentInventory
from app.policy.engine import PolicyEngine
from app.telemetry.metrics import EventStore


@pytest.fixture
def client():
    inventory = InMemoryAgentInventory()
    policy_engine = PolicyEngine()
    event_store = EventStore()
    app = create_app(inventory, policy_engine, event_store)
    return TestClient(app)


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["inventory_summary"]["trusted_agents"][0]["agent_id"] == "helloworld"


def test_register_trusted_card_success(client):
    payload = {
        "candidate_id": "new_agent",
        "card": {
            "name": "Distinct New Agent",
            "url": "http://127.0.0.1:8005",
            "skills": [{"id": "s1", "name": "Skill 1"}],
        },
    }
    resp = client.post("/api/v1/cards/register", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ACCEPTED"
    assert data["action"] == "ALLOW"
    assert "timing" in data
    assert data["timing"]["total_pipeline_latency_ms"] >= 0.0


def test_register_spoof_card_quarantine(client):
    # Spoofed homoglyph card mimicking HelloWorld
    payload = {
        "candidate_id": "spoofed_agent_01",
        "card": {
            "name": "Hell\u043e World Agent",  # Cyrillic 'о'
            "url": "http://127.0.0.1:8002",
        },
    }
    resp = client.post("/api/v1/cards/register", json=payload)
    assert resp.status_code == 403
    data = resp.json()
    assert data["action"] == "QUARANTINE"
    assert data["severity"] == "HIGH"
    assert data["violation"]["violation_code"] == "AS_HOMOGLYPH_SPOOF"

    # Verify timing is recorded and non-negative
    timing = data["timing"]
    assert timing["detection_latency_ms"] >= 0.0
    assert timing["decision_latency_ms"] >= 0.0
    assert timing["enforcement_latency_ms"] >= 0.0
    assert timing["total_pipeline_latency_ms"] >= 0.0

    # Verify event recorded in event store
    events_resp = client.get("/api/v1/events")
    assert events_resp.status_code == 200
    events = events_resp.json()
    assert len(events) == 1
    assert events[0]["action_taken"] == "QUARANTINE"

    # Verify that future mediated requests to this quarantined identity are rejected with 403
    proxy_resp = client.post(
        "/proxy/spoofed_agent_01/",
        json={"jsonrpc": "2.0", "method": "message/send", "params": {}, "id": 1},
    )
    assert proxy_resp.status_code == 403
    assert "QUARANTINED" in proxy_resp.json()["error"]["message"]
