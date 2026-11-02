"""Scale tests for Console v4 Live Agent Map.

Tests:
1. Unit tests for layout_mode(count) at edges: 0, 20, 21, 500, 501, 1500, 1501.
2. Playwright browser tests using demo data at sizes:
   - 5 agents: asserts data-mode="individual"
   - 200 agents: asserts data-mode="teams"
   - 2000 agents: asserts data-mode="canvas"
"""
from __future__ import annotations

import re
import pytest

from demo.security_monitor.app.governance.scale import layout_mode

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


def test_layout_mode_exact_edges():
    """Assert exact layout mode edges required by Section 4."""
    assert layout_mode(0) == "individual"
    assert layout_mode(20) == "individual"
    assert layout_mode(21) == "teams"
    assert layout_mode(500) == "teams"
    assert layout_mode(501) == "canvas"
    assert layout_mode(1500) == "canvas"
    assert layout_mode(1501) == "canvas"


pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed"),
]


@pytest.fixture(scope="session")
def demo_server_5(tmp_path_factory):
    from demo.security_monitor.tests.playwright_server import start_console_server
    td = tmp_path_factory.mktemp("demo_5")
    srv = start_console_server(
        td,
        env_overrides={
            "GOVERNANCE_DEMO_DATA": "1",
            "GOVERNANCE_DEMO_SIZE": "5",
            "GOVERNANCE_DEMO_DB_PATH": str(td / "governance_demo_5.db"),
        },
    )
    yield srv
    srv.stop()


@pytest.fixture(scope="session")
def demo_server_200(tmp_path_factory):
    from demo.security_monitor.tests.playwright_server import start_console_server
    td = tmp_path_factory.mktemp("demo_200")
    srv = start_console_server(
        td,
        env_overrides={
            "GOVERNANCE_DEMO_DATA": "1",
            "GOVERNANCE_DEMO_SIZE": "200",
            "GOVERNANCE_DEMO_DB_PATH": str(td / "governance_demo_200.db"),
        },
    )
    yield srv
    srv.stop()


@pytest.fixture(scope="session")
def demo_server_2000(tmp_path_factory):
    from demo.security_monitor.tests.playwright_server import start_console_server
    td = tmp_path_factory.mktemp("demo_2000")
    srv = start_console_server(
        td,
        env_overrides={
            "GOVERNANCE_DEMO_DATA": "1",
            "GOVERNANCE_DEMO_SIZE": "2000",
            "GOVERNANCE_DEMO_DB_PATH": str(td / "governance_demo_2000.db"),
        },
    )
    yield srv
    srv.stop()


def test_admin_overview_scale_5_agents(page: Page, demo_server_5):
    from demo.security_monitor.tests.playwright_server import sign_in
    sign_in(page, demo_server_5, path="/dashboard/overview")
    page.goto(f"{demo_server_5.url}/dashboard/overview")
    map_section = page.locator("section[data-mode]")
    expect(map_section).to_have_attribute("data-mode", "individual")


def test_admin_overview_scale_200_agents(page: Page, demo_server_200):
    from demo.security_monitor.tests.playwright_server import sign_in
    sign_in(page, demo_server_200, path="/dashboard/overview")
    page.goto(f"{demo_server_200.url}/dashboard/overview")
    map_section = page.locator("section[data-mode]")
    expect(map_section).to_have_attribute("data-mode", "teams")


def test_admin_overview_scale_2000_agents(page: Page, demo_server_2000):
    from demo.security_monitor.tests.playwright_server import sign_in
    sign_in(page, demo_server_2000, path="/dashboard/overview")
    page.goto(f"{demo_server_2000.url}/dashboard/overview")
    map_section = page.locator("section[data-mode]")
    expect(map_section).to_have_attribute("data-mode", "canvas")
