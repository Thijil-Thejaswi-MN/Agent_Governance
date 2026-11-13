"""Playwright test for the egress proxy preset: 'A file tells the agent to send data to a website'."""
from __future__ import annotations

import re
import shutil
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
def proxy_console_server(tmp_path_factory):
    srv = start_console_server(tmp_path_factory.mktemp("console_proxy"))
    yield srv
    srv.stop()


def test_proxy_preset_playwright(page: Page, proxy_console_server, tmp_path: Path):
    console_server = proxy_console_server
    screenshot_dir = tmp_path / "proxy_preset"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/run")
    page.set_viewport_size({"width": 1440, "height": 900})

    # Select the network exfiltration preset
    preset_btn = page.locator("#preset-network_exfiltration")
    expect(preset_btn).to_be_visible()
    expect(preset_btn).to_have_text("A file tells the agent to send data to a website")
    preset_btn.click()

    page.locator("#model-selector").select_option("scripted")
    expect(page.locator("#allow-preview")).to_contain_text("network_task.txt")
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
    incident_item = page.locator("li").filter(has_text="192.0.2.1")
    expect(incident_item).to_be_visible(timeout=10000)
    expect(incident_item).to_contain_text("Stopped by: Network proxy")
    expect(incident_item).to_contain_text("192.0.2.1")

    incident_screenshot_path = screenshot_dir / "incident_page.png"
    page.screenshot(path=str(incident_screenshot_path), full_page=True)

    # Screenshot 3: Task report page
    page.goto(f"{console_server.url}/dashboard/report/{task_id}")
    report_sheet = page.locator("#report-sheet")
    expect(report_sheet).to_be_visible(timeout=10000)
    blocked_section = page.locator("#report-blocked")
    expect(blocked_section).to_contain_text("Network proxy")
    expect(blocked_section).to_contain_text("192.0.2.1")

    report_screenshot_path = screenshot_dir / "report_page.png"
    page.screenshot(path=str(report_screenshot_path), full_page=True)

    # Also copy to artifacts dir for review if artifacts dir is available
    artifact_dir = Path("/mnt/c/Users/thiji/.gemini/antigravity/brain/9de88f23-be6b-4436-b365-c08419b61dd8")
    if artifact_dir.exists():
        shutil.copy(run_screenshot_path, artifact_dir / "run_proxy_page_1440.png")
        shutil.copy(incident_screenshot_path, artifact_dir / "incident_proxy_page_1440.png")
        shutil.copy(report_screenshot_path, artifact_dir / "report_proxy_page_1440.png")
