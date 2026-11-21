"""Playwright test: Discovered tab shows table and drawer from seeded scan."""
from __future__ import annotations

import datetime
from pathlib import Path
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.app.governance.discovery.models import DiscoveredAgent, EvidenceItem
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.tests.playwright_server import save_evidence

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed"),
]


def _sign_in(page: Page, url: str, token: str) -> None:
    page.goto(f"{url}/dashboard/signin")
    page.locator("#operator-token-input").fill(token)
    page.locator("#sign-in-submit-btn").click()
    page.wait_for_url("**/dashboard/run")


def test_discovered_agents_tab_and_drawer(page: Page, console_server) -> None:
    # 1. Seed a discovered agent into console server storage
    storage = GovernanceStorage(console_server.db_path)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    seeded = DiscoveredAgent(
        org_id="default",
        discovery_id="disc_seeded_langgraph",
        host="worker-01",
        kind="process",
        name="LangGraph Researcher",
        frameworks=["langgraph", "langchain"],
        llm_endpoints=["api.openai.com"],
        key_names=["OPENAI_API_KEY"],
        evidence=[
            EvidenceItem(
                signal="process_cmdline",
                detail="python3 -m langgraph.researcher --task summary",
                first_seen=now,
                last_seen=now,
            )
        ],
        status="shadow",
        created_at=now,
        updated_at=now,
    )
    storage.save_discovered_agent(seeded)

    # 2. Sign in and open Inventory page
    _sign_in(page, console_server.url, console_server.token)
    page.goto(f"{console_server.url}/dashboard/inventory")

    # 3. Switch to Discovered tab
    disc_tab = page.locator("#tab-discovered")
    expect(disc_tab).to_be_visible()
    disc_tab.click()

    # 4. Verify table and seeded row
    table = page.locator("#discovered-agents-table")
    expect(table).to_be_visible()

    row = page.locator('[data-discovery-row="disc_seeded_langgraph"]')
    expect(row).to_be_visible()
    expect(row).to_contain_text("LangGraph Researcher")
    expect(row).to_contain_text("process")
    expect(row).to_contain_text("worker-01")
    expect(row).to_contain_text("langgraph")
    expect(row).to_contain_text("Shadow")

    # 5. Click row to open detail drawer
    row.click()
    drawer = page.locator("#discovered-detail-drawer")
    expect(drawer).to_be_visible()
    expect(drawer).to_contain_text("LangGraph Researcher")
    expect(drawer).to_contain_text("python3 -m langgraph.researcher")

    # 6. Verify governance actions in drawer
    expect(page.locator("#drawer-actions")).to_be_visible()
    mark_known_btn = page.get_by_role("button", name="Mark known")
    expect(mark_known_btn).to_be_visible()
    mark_known_btn.click()

    # Verify status changed to Known
    expect(drawer).to_contain_text("Known")
