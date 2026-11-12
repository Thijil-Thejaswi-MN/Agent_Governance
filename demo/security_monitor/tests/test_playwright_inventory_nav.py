"""Agent inventory cards and the grouped sidebar.

1. Empty database: the inventory says "No agents yet." and shows the empty state.
2. A seeded agent with a blocked action and a request prompted by a file it read gets a
   card with its counts and a Medium risk badge whose tooltip states the rule.
3. The admin sidebar shows the groups in order: Overview, Agent Inventory, Governance,
   Runtime Monitoring, Incidents, Audit & Reports (Settings has no page, so it is not
   shown); collapsed, the links keep their names for screen readers.
"""
from __future__ import annotations

import re
import time

import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import no_horizontal_scroll, save_evidence, seed_waiting_task

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]


def _sign_in(page: Page, url: str, token: str) -> None:
    page.goto(f"{url}/dashboard/signin")
    page.locator("#operator-token-input").fill(token)
    page.locator("#sign-in-submit-btn").click()
    page.wait_for_url("**/dashboard/run")


def test_inventory_empty(page: Page, empty_console_server):
    _sign_in(page, empty_console_server.url, empty_console_server.token)
    page.goto(f"{empty_console_server.url}/dashboard/inventory")
    expect(page.locator("#inventory-headline")).to_have_text("No agents yet.")
    expect(page.locator("#inventory-empty")).to_be_visible()


def test_inventory_card_and_grouped_sidebar(page: Page, console_server):
    agent = f"inv_bot_{int(time.time() * 1000)}"
    seed_waiting_task(console_server.db_path, agent, agent_id=agent)
    _sign_in(page, console_server.url, console_server.token)
    page.set_viewport_size({"width": 1440, "height": 900})

    rail = page.locator('aside[data-sidebar="rail"]')
    groups = rail.locator("[data-nav-group]")
    expect(groups).to_have_count(6)
    assert [groups.nth(i).get_attribute("aria-label") for i in range(6)] == [
        "Overview", "Agent Inventory", "Governance", "Runtime Monitoring", "Incidents", "Audit & Reports"]
    expect(rail.locator('[data-nav-group="governance"]').get_by_role("link")).to_have_text([re.compile(r"^Approvals\d*$"), "Policies"])  # Approvals may carry a badge
    expect(rail.locator('[data-nav-group="runtime"]').get_by_role("link")).to_have_text(["Run", "Fleet", "History"])
    expect(rail.locator('[data-nav-group="audit"]').get_by_role("link")).to_have_text(["Records", "Results"])

    rail.get_by_role("link", name="Agents").click()
    page.wait_for_url("**/dashboard/inventory")
    card = page.locator(f'#inventory-list li[data-agent="{agent}"]')
    expect(card).to_be_visible()
    expect(card).to_have_attribute("data-risk", "medium")
    expect(card).to_contain_text("Tasks run1")
    expect(card).to_contain_text("Blocked1")
    expect(card).to_contain_text("1 (1 prompted by a file)")
    badge = card.get_by_role("button", name="Medium risk")
    badge.hover()
    tip = card.get_by_role("tooltip")
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("This agent: 1 blocked action, 1 request (1 prompted by a file it read).")
    expect(tip).to_contain_text("High: 5 or more blocked actions")
    save_evidence(page, "inventory_1440")

    # Collapsed: no group headings, the links keep their names.
    page.locator("#sidebar-toggle").click()
    expect(rail).to_have_attribute("data-collapsed", "true")
    expect(rail.get_by_role("link", name="Agents")).to_be_visible()
    expect(rail.get_by_role("group", name="Runtime Monitoring")).to_be_visible()
    page.locator("#sidebar-toggle").click()

    page.set_viewport_size({"width": 390, "height": 844})
    expect(card).to_be_visible()
    assert no_horizontal_scroll(page)
