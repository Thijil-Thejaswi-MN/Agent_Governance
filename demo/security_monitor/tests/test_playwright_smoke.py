"""Playwright smoke test for the Governance Console (v3).

Asserts:
- /dashboard lands the signed-in admin on Run, inside the sidebar shell.
- Every sidebar item (Run, Fleet, History, Results) navigates to /dashboard/<page>
  (no doubled basename) and shows that page's headline; the active item is marked.
- Every v2 route redirects to its new home, so existing links keep working.
- A hard reload on a deep link still renders the page (server fallback routing).
"""
from __future__ import annotations

import re
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import sign_in

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]

NAV = [
    ("Run", "/dashboard/run", "What should the agent do?"),
    ("Fleet", "/dashboard/fleet", "at work|All quiet"),
    ("History", "/dashboard/history", "Past runs"),
    ("Results", "/dashboard/results", "Full results"),
]

REDIRECTS = [
    ("/dashboard/tasks", "/dashboard/history"),
    ("/dashboard/tasks/task_from_v2_link", "/dashboard/history/task_from_v2_link"),
    ("/dashboard/approvals", "/dashboard/fleet"),
    ("/dashboard/activity", "/dashboard/fleet"),
    ("/dashboard/agents", "/dashboard/fleet"),
    ("/dashboard/evaluation", "/dashboard/results"),
    ("/dashboard/architecture", "/dashboard/run"),  # via /dashboard, which lands the admin on Run
    ("/dashboard/no-such-page", "/dashboard/run"),
]


def test_top_navigation(page: Page, console_server):
    base_url = console_server.url
    sign_in(page, console_server)
    page.goto(f"{base_url}/dashboard")
    expect(page).to_have_url(re.compile(r"/dashboard/run/?$"))
    expect(page.locator("h1")).to_contain_text("What should the agent do?")
    expect(page.locator('aside[data-sidebar="rail"]')).to_be_visible()

    nav = page.get_by_role("navigation", name="Main")
    expect(nav.get_by_role("link")).to_have_count(9)  # admin: 4 role homes + Run, History, Incidents, Fleet, Results
    for name, url, heading in NAV:
        link = nav.get_by_role("link", name=name, exact=True)
        link.click()
        expect(page).to_have_url(re.compile(f"{re.escape(url)}/?$"))
        assert "/dashboard/dashboard" not in page.url, f"Doubled basename detected in {page.url}"
        expect(page.locator("h1")).to_contain_text(re.compile(heading))
        expect(link).to_have_attribute("aria-current", "page")


@pytest.mark.parametrize("old,new", REDIRECTS)
def test_old_routes_redirect(page: Page, console_server, old, new):
    sign_in(page, console_server)
    page.goto(f"{console_server.url}{old}")
    expect(page).to_have_url(re.compile(f"{re.escape(new)}/?$"))


def test_deep_link_reload(page: Page, console_server):
    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/history")
    page.reload()
    expect(page).to_have_url(re.compile(r"/dashboard/history/?$"))
    expect(page.locator("h1")).to_contain_text("Past runs")
