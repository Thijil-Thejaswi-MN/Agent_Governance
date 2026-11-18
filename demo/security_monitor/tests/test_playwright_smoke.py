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
]


def test_top_navigation(page: Page, console_server):
    base_url = console_server.url
    sign_in(page, console_server)
    page.goto(f"{base_url}/dashboard")
    expect(page).to_have_url(re.compile(r"/dashboard/run/?$"))
    expect(page.locator("h1")).to_contain_text("What should the agent do?")
    expect(page.locator('aside[data-sidebar="rail"]')).to_be_visible()

    nav = page.get_by_role("navigation", name="Main")
    expect(nav.get_by_role("link")).to_have_count(10)  # admin: Overview, Agents, Approvals, Policies, Run, Fleet, History, Incidents, Records, Results
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


def test_page_header_single_heading_and_topbar_breadcrumb(page: Page, console_server):
    """Assert /overview, /fleet, /history and /records each have exactly one visible h1
    heading and TopBar shows the page name only as breadcrumb text."""
    pages_to_check = [
        ("/dashboard/overview", "Overview"),
        ("/dashboard/fleet", "Fleet"),
        ("/dashboard/history", "History"),
        ("/dashboard/records", "Records"),
    ]
    sign_in(page, console_server)
    for path, page_name in pages_to_check:
        page.goto(f"{console_server.url}{path}")
        # Exactly one visible h1 heading element on the page
        expect(page.locator("h1:visible")).to_have_count(1)
        # TopBar contains no heading element
        expect(page.locator("[data-topbar] h1, [data-topbar] h2, [data-topbar] [role='heading']")).to_have_count(0)
        # TopBar displays the page name only as breadcrumb text
        breadcrumb = page.locator("[data-topbar] [aria-label='Breadcrumb']")
        expect(breadcrumb).to_contain_text(page_name)


def test_overview_agent_map_kpis_and_report_print(page: Page, console_server):
    """Overview agent map has no dashed border and all five KPI cards are visible;
    Report page in print emulation has a white background."""
    from demo.security_monitor.tests.playwright_server import seed_finished_task
    seed_task_id = seed_finished_task(console_server.db_path, "smoke_report")

    sign_in(page, console_server, path="/dashboard/overview")
    page.goto(f"{console_server.url}/dashboard/overview")

    # 1. Five KPI cards are visible
    for kpi_id in ["#kpi-active", "#kpi-runs", "#kpi-stopped", "#kpi-waiting", "#kpi-records"]:
        expect(page.locator(kpi_id)).to_be_visible()

    # 2. Overview's agent map has no dashed border
    map_locator = page.locator("#live-agent-map")
    expect(map_locator).to_be_visible()
    border_style = map_locator.evaluate("el => getComputedStyle(el).borderStyle")
    assert border_style != "dashed", f"Expected non-dashed border style, got {border_style}"

    # 3. Report page in print emulation has a white background
    page.goto(f"{console_server.url}/dashboard/report/{seed_task_id}")
    expect(page.locator("#report-sheet")).to_be_visible()
    page.emulate_media(media="print")
    sheet_bg = page.locator("#report-sheet").evaluate("el => getComputedStyle(el).backgroundColor")
    assert sheet_bg in ["rgb(255, 255, 255)", "#ffffff", "white", "rgba(0, 0, 0, 0)"], (
        f"Expected white background in print mode, got {sheet_bg}"
    )

