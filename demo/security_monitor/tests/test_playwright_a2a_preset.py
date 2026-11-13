"""Playwright test for the Google A2A travel planner agent preset."""
from __future__ import annotations

import http.server
import json
import re
import threading
from pathlib import Path
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import sign_in, start_console_server
from demo.security_monitor.tests.test_a2a_governed_agent import MockOpenAIHandler

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed"),
    pytest.mark.os_layer,
]


@pytest.fixture(scope="module")
def a2a_console_server(tmp_path_factory):
    mock_server = None
    try:
        mock_server = http.server.ThreadingHTTPServer(("127.0.0.1", 11434), MockOpenAIHandler)
        threading.Thread(target=mock_server.serve_forever, daemon=True).start()
    except OSError:
        mock_server = None

    srv = start_console_server(tmp_path_factory.mktemp("console_a2a"))
    yield srv
    srv.stop()
    if mock_server is not None:
        mock_server.shutdown()
        mock_server.server_close()


def test_a2a_preset_playwright(page: Page, a2a_console_server, tmp_path: Path):
    console_server = a2a_console_server
    screenshot_dir = tmp_path / "a2a_preset"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/run")
    page.set_viewport_size({"width": 1440, "height": 900})

    # Select the A2A agent preset
    preset_btn = page.locator("#preset-a2a_agent")
    expect(preset_btn).to_be_visible(timeout=10000)
    expect(preset_btn).to_have_text("Google A2A travel planner inside fence")
    preset_btn.click()

    page.locator("#model-selector").select_option("scripted")
    expect(page.locator("#allow-preview")).to_contain_text("summary.txt")

    # Start the run
    page.locator("#start-run-btn").click()
    expect(page).to_have_url(re.compile(r"/dashboard/run/(task_[0-9a-f]+)$"), timeout=15000)
    match = re.search(r"/(task_[0-9a-f]+)$", page.url)
    assert match is not None
    task_id = match.group(1)

    # Wait for completion
    status = page.locator("#run-status")
    expect(status).to_have_attribute("data-state", "completed", timeout=60000)
    expect(page.locator("#output-preview")).to_contain_text("summary.txt")

    # Screenshot 1: Run page
    run_screenshot_path = screenshot_dir / "run_page.png"
    page.screenshot(path=str(run_screenshot_path), full_page=True)

    # Screenshot 2: Incidents page
    page.goto(f"{console_server.url}/dashboard/incidents")
    expect(page.locator("h1")).to_contain_text("blocked action")

    # Check for Landlock incident
    landlock_item = page.locator("li").filter(has_text="private_archive.txt")
    expect(landlock_item).to_be_visible(timeout=10000)
    expect(landlock_item).to_contain_text("Stopped by: Kernel (Landlock)")

    # Check for Proxy incident
    proxy_item = page.locator("li").filter(has_text="192.0.2.1")
    expect(proxy_item).to_be_visible(timeout=10000)
    expect(proxy_item).to_contain_text("Stopped by: Network proxy")

    incident_screenshot_path = screenshot_dir / "incident_page.png"
    page.screenshot(path=str(incident_screenshot_path), full_page=True)

    # Screenshot 3: Task report page
    page.goto(f"{console_server.url}/dashboard/report/{task_id}")
    report_sheet = page.locator("#report-sheet")
    expect(report_sheet).to_be_visible(timeout=10000)
    blocked_section = page.locator("#report-blocked")
    expect(blocked_section).to_contain_text("Kernel (Landlock)")
    expect(blocked_section).to_contain_text("Network proxy")

    report_screenshot_path = screenshot_dir / "report_page.png"
    page.screenshot(path=str(report_screenshot_path), full_page=True)
