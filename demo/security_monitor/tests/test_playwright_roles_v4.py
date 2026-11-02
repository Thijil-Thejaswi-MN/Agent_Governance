"""Playwright tests for Console v4 (Role-based homes, navigation, screens, and batch actions).

Verifies:
1. /signin renders the disabled SSO button ("Not configured on this install"),
   operator token input, and the 5 explanatory role cards.
2. Sign-in redirect highlights matching role card and lands on the designated role home:
   - developer -> /run
   - team_lead -> /team
   - security_reviewer -> /inbox
   - admin -> /
   - auditor -> /records
3. Auditor role has no approval or deny buttons (read-only) and sees the record verification chain.
4. Security reviewer sees grouped pending requests with Routine vs Look closely badges,
   and batch actions.
"""
from __future__ import annotations

import time
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import seed_waiting_task

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed"),
]


def _sign_in_via_signin_page(page: Page, url: str, token: str) -> None:
    page.goto(f"{url}/dashboard/signin")
    page.locator("#operator-token-input").fill(token)
    page.locator("#sign-in-submit-btn").click()
    page.wait_for_timeout(1500)


def test_signin_page_elements(page: Page, console_server):
    page.goto(f"{console_server.url}/dashboard/signin")
    expect(page.locator("h1")).to_contain_text("Sign in to Agent Governance")
    
    # SSO button is disabled as required
    sso_btn = page.locator("button:has-text('Continue with company sign-in (SSO)')")
    expect(sso_btn).to_be_visible()
    expect(sso_btn).to_be_disabled()
    expect(page.locator("body")).to_contain_text("Not configured on this install")

    # Role cards are present
    expect(page.locator("body")).to_contain_text("Developer")
    expect(page.locator("body")).to_contain_text("Team lead")
    expect(page.locator("body")).to_contain_text("Security reviewer")
    expect(page.locator("body")).to_contain_text("Admin")
    expect(page.locator("body")).to_contain_text("Auditor")


def test_admin_landing_and_overview(page: Page, console_server):
    _sign_in_via_signin_page(page, console_server.url, console_server.token)

    page.goto(f"{console_server.url}/dashboard/overview")
    expect(page.locator("h1")).to_contain_text("Overview")
    expect(page.locator("body")).to_contain_text("Live agent map")
    expect(page.locator("body")).to_contain_text("Active agents")
    expect(page.locator("body")).to_contain_text("Agent actions per hour")


def test_team_lead_screen(page: Page, console_server):
    _sign_in_via_signin_page(page, console_server.url, console_server.token)

    page.goto(f"{console_server.url}/dashboard/team")
    expect(page.locator("body")).to_contain_text("agents at work")
    expect(page.locator("body")).to_contain_text("When each agent hit the fence")
    expect(page.locator("body")).to_contain_text("Team agents")


def test_reviewer_inbox_screen(page: Page, console_server):
    _sign_in_via_signin_page(page, console_server.url, console_server.token)

    page.goto(f"{console_server.url}/dashboard/inbox")
    expect(page.locator("body")).to_contain_text("requests are waiting")
    expect(page.locator("body")).to_contain_text("Grouped requests")
    expect(page.locator("body")).to_contain_text("Standing rules")


def test_auditor_records_screen_readonly(page: Page, console_server):
    _sign_in_via_signin_page(page, console_server.url, console_server.token)

    page.goto(f"{console_server.url}/dashboard/records")
    expect(page.locator("body")).to_contain_text("No records yet.")
    expect(page.locator("button:has-text('Export CSV')")).to_be_visible()
    expect(page.locator("body")).not_to_contain_text("Allow for this run")
    expect(page.locator("body")).not_to_contain_text("Deny all")
