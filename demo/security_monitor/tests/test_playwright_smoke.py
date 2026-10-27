"""Playwright smoke test for Governance Console v2.

Asserts:
- Clicking every sidebar item navigates to /dashboard/<page> (no doubled basename)
- The page heading changed as expected
- A hard reload on /dashboard/tasks still renders the Tasks page (server fallback routing)
"""
from __future__ import annotations

import re
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

pytestmark = pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed")


def test_sidebar_navigation_and_reload(page: Page):
    base_url = "http://127.0.0.1:8000"

    # 1. Start at /dashboard
    page.goto(f"{base_url}/dashboard")
    expect(page).to_have_url(re.compile(r"/dashboard/?$"))
    expect(page.locator("h1")).to_contain_text("Bind AI Agent Capabilities")

    # 2. Click each nav item and verify URL + heading
    nav_targets = [
        {"name": "Tasks", "expected_url": "/dashboard/tasks", "heading": "Governed Tasks"},
        {"name": "Agents", "expected_url": "/dashboard/agents", "heading": "Agent Inventory"},
        {"name": "Live Activity", "expected_url": "/dashboard/activity", "heading": "Live Event Activity"},
        {"name": "Approvals", "expected_url": "/dashboard/approvals", "heading": "Expansion Approvals"},
        {"name": "Evaluation", "expected_url": "/dashboard/evaluation", "heading": "Empirical Evaluation Benchmarks"},
        {"name": "Architecture", "expected_url": "/dashboard/architecture", "heading": "System Architecture"},
        {"name": "Overview", "expected_url": "/dashboard", "heading": "Bind AI Agent Capabilities"},
    ]

    for item in nav_targets:
        # Click the sidebar NavLink by text
        link = page.locator("nav").get_by_role("link", name=item["name"])
        link.click()

        # Assert URL does NOT have doubled basename like /dashboard/dashboard/...
        expect(page).to_have_url(re.compile(f"{re.escape(item['expected_url'])}/?$"))
        assert "/dashboard/dashboard" not in page.url, f"Doubled basename detected in {page.url}"

        # Assert heading changed
        expect(page.locator("h1")).to_contain_text(item["heading"])

    # 3. Hard reload on /dashboard/tasks still renders Tasks page
    page.goto(f"{base_url}/dashboard/tasks")
    expect(page).to_have_url(re.compile(r"/dashboard/tasks/?$"))
    page.reload()
    expect(page).to_have_url(re.compile(r"/dashboard/tasks/?$"))
    expect(page.locator("h1")).to_contain_text("Governed Tasks")
