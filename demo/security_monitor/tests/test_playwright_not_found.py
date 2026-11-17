"""Playwright tests for the 404 page (v4).

Asserts:
a) signed out: /dashboard/no-such-page shows the heading and the path; "Go back home" ends on
   /dashboard/signin.
b) signed in: same page shows; the button goes to the person's home, not sign-in.
c) the legacy redirects still work: /dashboard/tasks -> /dashboard/history,
   /dashboard/approvals -> /dashboard/fleet.
d) no horizontal scroll at 375 px.
"""
from __future__ import annotations

import re
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import no_horizontal_scroll, sign_in

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(
        not HAS_PLAYWRIGHT,
        reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)",
    ),
]


def test_not_found_signed_out(page: Page, console_server):
    page.goto(f"{console_server.url}/dashboard/no-such-page")
    expect(page.locator("h1")).to_have_text("This page doesn't exist.")
    expect(page.locator("code")).to_contain_text("/no-such-page")

    # "Go back home" ends on /dashboard/signin for signed-out visitors
    page.get_by_role("link", name="Go back home").click()
    expect(page).to_have_url(re.compile(r"/dashboard/signin/?$"))


def test_not_found_signed_in(page: Page, console_server):
    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/no-such-page")
    expect(page.locator("h1")).to_have_text("This page doesn't exist.")
    expect(page.locator("code")).to_contain_text("/no-such-page")

    # For signed-in operators, RootRedirect lands on their role's home page (not signin)
    page.get_by_role("link", name="Go back home").click()
    expect(page).not_to_have_url(re.compile(r"/dashboard/signin/?$"))
    expect(page).to_have_url(re.compile(r"/dashboard/(overview|run)/?$"))


def test_legacy_redirects_still_work(page: Page, console_server):
    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/tasks")
    expect(page).to_have_url(re.compile(r"/dashboard/history/?$"))

    page.goto(f"{console_server.url}/dashboard/approvals")
    expect(page).to_have_url(re.compile(r"/dashboard/fleet/?$"))


def test_not_found_background_covers_main(page: Page, console_server):
    page.goto(f"{console_server.url}/dashboard/no-such-page")
    bg = page.locator("[data-testid='not-found-grid']")
    expect(bg).to_be_visible()
    main = page.locator("#main")
    expect(main).to_be_visible()

    bg_box = bg.bounding_box()
    main_box = main.bounding_box()
    assert bg_box is not None, "Background layer has no bounding box"
    assert main_box is not None, "#main has no bounding box"
    assert bg_box["width"] >= 0.95 * main_box["width"], (
        f"Background width ({bg_box['width']}) is less than 95% of #main width ({main_box['width']})"
    )


def test_not_found_no_horizontal_scroll_at_375px(page: Page, console_server):
    page.set_viewport_size({"width": 375, "height": 667})

    # Unauthenticated visitor at 375 px
    page.goto(f"{console_server.url}/dashboard/no-such-page")
    expect(page.locator("h1")).to_have_text("This page doesn't exist.")
    bg = page.locator("[data-testid='not-found-grid']")
    expect(bg).to_be_visible()
    assert no_horizontal_scroll(page), "Page has horizontal scroll at 375 px"

    # Authenticated operator at 375 px
    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/no-such-page")
    expect(page.locator("h1")).to_have_text("This page doesn't exist.")
    expect(bg).to_be_visible()
    assert no_horizontal_scroll(page), "Page has horizontal scroll at 375 px (authenticated)"
