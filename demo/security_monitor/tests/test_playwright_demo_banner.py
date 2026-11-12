"""Demo data is never shown as live: it needs GOVERNANCE_DEMO_DATA=1 (its own database), and
then every page carries the "Demo data: not real activity" banner. A live server shows no banner.
"""
from __future__ import annotations

import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import sign_in, start_console_server

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]

BANNER = "Demo data: not real activity"


@pytest.fixture(scope="module")
def demo_server(tmp_path_factory):
    td = tmp_path_factory.mktemp("demo_banner")
    srv = start_console_server(td, {"GOVERNANCE_DEMO_DATA": "1", "GOVERNANCE_DEMO_SIZE": "200",
                                    "GOVERNANCE_DEMO_DB_PATH": str(td / "demo.db")})
    yield srv
    srv.stop()


def test_demo_mode_shows_the_banner_on_the_map(page: Page, demo_server):
    sign_in(page, demo_server, path="/dashboard/overview")
    page.goto(f"{demo_server.url}/dashboard/overview")
    expect(page.locator("section[data-mode]")).to_have_attribute("data-mode", "teams")
    expect(page.get_by_text(BANNER)).to_be_visible()


def test_live_server_has_no_banner(page: Page, console_server):
    sign_in(page, console_server, path="/dashboard/overview")
    page.goto(f"{console_server.url}/dashboard/overview")
    expect(page.locator("section[data-mode]")).to_be_visible()
    expect(page.get_by_text(BANNER)).to_have_count(0)
