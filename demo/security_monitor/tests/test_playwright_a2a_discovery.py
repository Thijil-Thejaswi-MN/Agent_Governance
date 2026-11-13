"""Playwright test for Feature 5: Local A2A Agent Card discovery."""
from __future__ import annotations

import json
import http.server
import socketserver
import threading
from pathlib import Path
from typing import Any
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import no_horizontal_scroll, sign_in, start_console_server
from demo.security_monitor.app.governance.models import TaskLifecycle, TaskRecord
from demo.security_monitor.app.governance.storage import GovernanceStorage

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed"),
]


class EphemeralCardHandler(http.server.BaseHTTPRequestHandler):
    data_to_serve: dict[str, Any] = {
        "name": "Travel Planner",
        "description": "Searches flights and manages travel itineraries across multiple airlines.",
        "skills": ["flight_search", "hotel_booking", "itinerary_generator"],
        "provider": "Google A2A Samples",
        "version": "1.0.0",
    }

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(self.data_to_serve).encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture(scope="module")
def a2a_card_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), EphemeralCardHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/.well-known/agent-card.json"
    yield url
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def a2a_console_server(tmp_path_factory, a2a_card_server):
    workdir = tmp_path_factory.mktemp("console_a2a_discovery")
    srv = start_console_server(
        workdir,
        env_overrides={"A2A_AGENT_CARD_URLS": a2a_card_server},
    )
    yield srv
    srv.stop()


def test_a2a_discovery_playwright(page: Page, a2a_console_server, tmp_path: Path):
    console_server = a2a_console_server
    screenshot_dir = tmp_path / "a2a_discovery"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    sign_in(page, console_server, path="/dashboard/inventory")
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{console_server.url}/dashboard/inventory")

    # 1. Verify discovered card appears with "Not governed yet"
    card = page.locator('#discovered-agents-list li[data-discovered-agent="Travel Planner"]')
    expect(card).to_be_visible()
    expect(card).to_contain_text("Travel Planner")
    expect(card.locator('[data-badge="discovered-card"]')).to_have_text("Discovered (A2A card)")
    expect(card).to_contain_text("Searches flights and manages travel itineraries")
    expect(card.locator('[data-skill="flight_search"]')).to_be_visible()
    expect(card.locator('[data-skill="hotel_booking"]')).to_be_visible()
    expect(card.locator('[data-testid="governance-state-badge"]')).to_have_text("Not governed yet")
    expect(card).to_have_attribute("data-governance-state", "Not governed yet")

    # Capture 1440 screenshot of discovery page
    page.screenshot(path=str(screenshot_dir / "agents_discovery_page_1440.png"), full_page=True)

    # 2. Simulate running a task for travel_planner inside fence (Condition C)
    storage = GovernanceStorage(str(console_server.db_path))
    task_run = TaskRecord(
        task_id="task_travel_planner_001",
        request_text="Plan trip to Zurich",
        request_hash="hash_zurich",
        agent_id="travel_planner",
        workspace_root="/tmp/ws_tp",
        status=TaskLifecycle.COMPLETED,
        created_at="2026-11-13T10:30:00Z",
        condition="C",
    )
    storage.save_task(task_run)

    # Reload page to check updated governance state
    page.reload()
    card_updated = page.locator('#discovered-agents-list li[data-discovered-agent="Travel Planner"]')
    expect(card_updated).to_be_visible()
    expect(card_updated.locator('[data-testid="governance-state-badge"]')).to_have_text("Governed")
    expect(card_updated).to_have_attribute("data-governance-state", "Governed")

    # 3. Mobile responsiveness at 390x844
    page.set_viewport_size({"width": 390, "height": 844})
    expect(card_updated).to_be_visible()
    assert no_horizontal_scroll(page)