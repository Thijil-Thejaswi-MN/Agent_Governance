"""Tests for A2A Agent Card discovery on local endpoints (Feature 5)."""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
import time
from typing import Any
import pytest

from demo.security_monitor.app.governance.inventory import (
    AgentInventoryService,
    discover_local_a2a_cards,
    is_local_url,
)
from demo.security_monitor.app.governance.models import TaskLifecycle, TaskRecord
from demo.security_monitor.app.governance.storage import GovernanceStorage


class EphemeralHandler(http.server.BaseHTTPRequestHandler):
    data_to_serve: dict[str, Any] | str | None = None
    status_code: int = 200
    delay: float = 0.0

    def do_GET(self) -> None:
        if self.delay > 0:
            time.sleep(self.delay)
        self.send_response(self.status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if isinstance(self.data_to_serve, dict):
            body = json.dumps(self.data_to_serve).encode("utf-8")
        elif isinstance(self.data_to_serve, str):
            body = self.data_to_serve.encode("utf-8")
        else:
            body = b"{}"
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress console logging during tests


class EphemeralServer:
    def __init__(self, data: dict[str, Any] | str | None = None, status: int = 200, delay: float = 0.0) -> None:
        class ConfiguredHandler(EphemeralHandler):
            pass

        ConfiguredHandler.data_to_serve = data
        ConfiguredHandler.status_code = status
        ConfiguredHandler.delay = delay

        self.server = socketserver.TCPServer(("127.0.0.1", 0), ConfiguredHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def test_is_local_url() -> None:
    assert is_local_url("http://127.0.0.1:9999/.well-known/agent-card.json") is True
    assert is_local_url("http://localhost:8000/agent.json") is True
    assert is_local_url("http://127.0.0.1/card") is True

    # Fail closed on remote or non-local hosts
    assert is_local_url("http://example.com/card.json") is False
    assert is_local_url("https://google.com/card.json") is False
    assert is_local_url("http://192.168.1.50:9999/card.json") is False
    assert is_local_url("http://10.0.0.1/card.json") is False
    assert is_local_url("http://0.0.0.0:9999/card.json") is False
    assert is_local_url("file:///etc/passwd") is False
    assert is_local_url("not-a-url") is False


def test_discover_valid_a2a_card(tmp_path) -> None:
    card_data = {
        "name": "Travel Planner",
        "description": "Searches flights and manages travel itineraries.",
        "skills": ["flight_search", "itinerary_generator"],
        "provider": "Google A2A Samples",
        "version": "1.0.0",
    }
    server = EphemeralServer(data=card_data)
    server.start()
    try:
        url = f"http://127.0.0.1:{server.port}/.well-known/agent-card.json"
        storage = GovernanceStorage(str(tmp_path / "test.db"))

        # 1. No runs yet -> "Not governed yet"
        cards = discover_local_a2a_cards(urls=[url], storage=storage)
        assert len(cards) == 1
        card = cards[0]
        assert card["name"] == "Travel Planner"
        assert card["agent_id"] == "travel_planner"
        assert card["description"] == "Searches flights and manages travel itineraries."
        assert card["skills"] == ["flight_search", "itinerary_generator"]
        assert card["provider"] == "Google A2A Samples"
        assert card["governance_state"] == "Not governed yet"

        # 2. Run under Condition B (comparison mode) -> still "Not governed yet"
        task_b = TaskRecord(
            task_id="task-b",
            agent_id="travel_planner",
            request_text="Plan trip",
            request_hash="hash_b",
            workspace_root=str(tmp_path / "ws_b"),
            status=TaskLifecycle.COMPLETED,
            created_at="2026-11-13T10:00:00Z",
            condition="B",
        )
        storage.save_task(task_b)
        cards = discover_local_a2a_cards(urls=[url], storage=storage)
        assert cards[0]["governance_state"] == "Not governed yet"

        # 3. Run under Condition C (inside our fence) -> "Governed"
        task_c = TaskRecord(
            task_id="task-c",
            agent_id="travel_planner",
            request_text="Plan trip inside fence",
            request_hash="hash_c",
            workspace_root=str(tmp_path / "ws_c"),
            status=TaskLifecycle.COMPLETED,
            created_at="2026-11-13T10:05:00Z",
            condition="C",
        )
        storage.save_task(task_c)
        cards = discover_local_a2a_cards(urls=[url], storage=storage)
        assert cards[0]["governance_state"] == "Governed"
    finally:
        server.stop()


def test_discover_timeout_handling() -> None:
    # Server with 1.5s delay -> timeout is 1.0s, should fail closed and return []
    server = EphemeralServer(data={"name": "Slow Agent"}, delay=1.5)
    server.start()
    t0 = time.time()
    try:
        url = f"http://127.0.0.1:{server.port}/.well-known/agent-card.json"
        cards = discover_local_a2a_cards(urls=[url])
        assert cards == []
        elapsed = time.time() - t0
        assert elapsed < 1.4  # Timeout occurred cleanly at ~1.0s
    finally:
        server.stop()


def test_discover_fails_closed_on_malformed_card() -> None:
    # Missing description and skills
    server = EphemeralServer(data={"name": "Incomplete Bot"})
    server.start()
    try:
        url = f"http://127.0.0.1:{server.port}/.well-known/agent-card.json"
        assert discover_local_a2a_cards(urls=[url]) == []
    finally:
        server.stop()

    # Missing name
    server2 = EphemeralServer(data={"description": "Some description", "skills": ["skill1"]})
    server2.start()
    try:
        url = f"http://127.0.0.1:{server2.port}/.well-known/agent-card.json"
        assert discover_local_a2a_cards(urls=[url]) == []
    finally:
        server2.stop()

    # Non-json response
    server3 = EphemeralServer(data="<html>Not JSON</html>", status=200)
    server3.start()
    try:
        url = f"http://127.0.0.1:{server3.port}/.well-known/agent-card.json"
        assert discover_local_a2a_cards(urls=[url]) == []
    finally:
        server3.stop()


def test_discover_rejects_non_local_urls() -> None:
    cards = discover_local_a2a_cards(urls=[
        "http://example.com/.well-known/agent-card.json",
        "https://evil.internal:9999/agent.json",
        "http://10.0.0.5:9999/card.json",
    ])
    assert cards == []


def test_agent_inventory_service_integration(tmp_path, monkeypatch) -> None:
    card_data = {
        "name": "Acme Assistant",
        "description": "General office assistance.",
        "skills": ["calendar", "email_drafting"],
        "provider": "Acme Corp",
        "version": "2.1",
    }
    server = EphemeralServer(data=card_data)
    server.start()
    try:
        card_url = f"http://127.0.0.1:{server.port}/.well-known/agent-card.json"
        monkeypatch.setenv("A2A_AGENT_CARD_URLS", card_url)

        storage = GovernanceStorage(str(tmp_path / "inv_test.db"))
        service = AgentInventoryService(storage=storage)
        items = service.get_inventory()

        discovered = [i for i in items if i.agent_id == "acme_assistant"]
        assert len(discovered) == 1
        item = discovered[0]
        assert item.name == "Acme Assistant"
        assert item.classification == "DISCOVERED_A2A"
        assert item.description == "General office assistance."
        assert item.skills == ["calendar", "email_drafting"]
        assert item.governance_state == "Not governed yet"
        assert item.metadata.get("a2a_card") is True
    finally:
        server.stop()