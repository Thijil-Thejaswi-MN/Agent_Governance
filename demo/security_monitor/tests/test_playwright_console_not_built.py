"""Playwright: a fresh clone without dashboard_v2/dist shows 'Console not built', not the legacy UI."""
from __future__ import annotations

import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import save_evidence

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]


def test_console_not_built_page(page: Page, unbuilt_console_server):
    resp = page.goto(f"{unbuilt_console_server.url}/dashboard/run")
    assert resp is not None and resp.status == 503
    expect(page.locator("h1")).to_contain_text("Console not built")
    expect(page.locator("h1")).to_contain_text("npm ci && npm run build")
    save_evidence(page, "console_not_built")

    page.locator("a[href='/legacy-dashboard']").click()
    expect(page).to_have_url(f"{unbuilt_console_server.url}/legacy-dashboard")
    assert "Console not built" not in page.content()
    log = unbuilt_console_server.log_path.read_text(errors="replace")
    assert "Governance Console not built" in log
