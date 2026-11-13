"""Playwright test for named agents: finance_bot and notes_bot runs, visible in Agents, Fleet and Overview."""
from __future__ import annotations

import re
from pathlib import Path
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import sign_in, start_console_server

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed"),
    pytest.mark.os_layer,
]


@pytest.fixture(scope="module")
def named_agents_console_server(tmp_path_factory):
    srv = start_console_server(tmp_path_factory.mktemp("console_named_agents"))
    yield srv
    srv.stop()


def test_named_agents_playwright(page: Page, named_agents_console_server, tmp_path: Path):
    console_server = named_agents_console_server
    screenshot_dir = tmp_path / "named_agents"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    sign_in(page, console_server)
    page.set_viewport_size({"width": 1440, "height": 900})

    # --- Run 1: finance_bot ---
    page.goto(f"{console_server.url}/dashboard/run")
    expect(page.locator("#agent-selector")).to_be_visible()
    page.locator("#agent-selector").select_option("finance_bot")

    preset_btn = page.locator("#preset-summarise_csv")
    expect(preset_btn).to_be_visible()
    preset_btn.click()

    page.locator("#model-selector").select_option("scripted")
    page.locator("#start-run-btn").click()

    expect(page).to_have_url(re.compile(r"/dashboard/run/(task_[0-9a-f]+)$"), timeout=15000)
    match1 = re.search(r"/(task_[0-9a-f]+)$", page.url)
    assert match1 is not None

    status = page.locator("#run-status")
    expect(status).to_have_attribute("data-state", "completed", timeout=60000)

    # --- Run 2: notes_bot ---
    page.goto(f"{console_server.url}/dashboard/run")
    expect(page.locator("#agent-selector")).to_be_visible()
    page.locator("#agent-selector").select_option("notes_bot")
    expect(page.locator("#agent-selector")).to_have_value("notes_bot")

    preset_btn2 = page.locator("#preset-summarise_csv")
    expect(preset_btn2).to_be_visible()
    preset_btn2.click()

    page.locator("#model-selector").select_option("scripted")
    page.locator("#start-run-btn").click()

    expect(page).to_have_url(re.compile(r"/dashboard/run/(task_[0-9a-f]+)$"), timeout=15000)
    match2 = re.search(r"/(task_[0-9a-f]+)$", page.url)
    assert match2 is not None

    status2 = page.locator("#run-status")
    expect(status2).to_have_attribute("data-state", "completed", timeout=60000)

    # --- Verify Agents (Team) page ---
    page.goto(f"{console_server.url}/dashboard/team")
    expect(page.locator("text=Team agents")).to_be_visible(timeout=10000)
    expect(page.get_by_role("cell", name="finance_bot")).to_be_visible()
    expect(page.get_by_role("cell", name="notes_bot")).to_be_visible()
    expect(page.get_by_role("cell", name="Ana Dev")).to_be_visible()
    expect(page.get_by_role("cell", name="Ravi K")).to_be_visible()

    agents_screenshot = screenshot_dir / "agents_page_1440.png"
    page.screenshot(path=str(agents_screenshot), full_page=True)

    # --- Verify Fleet page ---
    page.goto(f"{console_server.url}/dashboard/fleet")
    expect(page.locator("#fleet-headline")).to_be_visible(timeout=10000)
    fleet_screenshot = screenshot_dir / "fleet_page_1440.png"
    page.screenshot(path=str(fleet_screenshot), full_page=True)

    # --- Verify Overview page ---
    page.goto(f"{console_server.url}/dashboard/overview")
    expect(page.locator("text=Live agent map")).to_be_visible(timeout=10000)
    expect(page.locator('[data-agent="finance_bot"]')).to_be_visible()
    expect(page.locator('[data-agent="notes_bot"]')).to_be_visible()

    overview_screenshot = screenshot_dir / "overview_page_1440.png"
    page.screenshot(path=str(overview_screenshot), full_page=True)
