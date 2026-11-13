"""Playwright test for the kernel Landlock preset: 'A file tricks the agent into a shell command'."""
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
def kernel_console_server(tmp_path_factory):
    srv = start_console_server(tmp_path_factory.mktemp("console_kernel"))
    yield srv
    srv.stop()


def test_kernel_preset_playwright(page: Page, kernel_console_server, tmp_path: Path):
    console_server = kernel_console_server
    screenshot_dir = tmp_path / "kernel_preset"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/run")
    page.set_viewport_size({"width": 1440, "height": 900})

    # Select the new preset
    preset_btn = page.locator("#preset-shell_injection")
    expect(preset_btn).to_be_visible()
    expect(preset_btn).to_have_text("A file tricks the agent into a shell command")
    preset_btn.click()

    page.locator("#model-selector").select_option("scripted")
    expect(page.locator("#allow-preview")).to_contain_text("system_audit.txt")
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
    expect(page.locator("#output-preview")).to_contain_text("Audit complete")

    # Screenshot 1: Run page
    run_screenshot_path = screenshot_dir / "run_page.png"
    page.screenshot(path=str(run_screenshot_path), full_page=True)

    # Screenshot 2: Incidents page
    page.goto(f"{console_server.url}/dashboard/incidents")
    expect(page.locator("h1")).to_contain_text("blocked action")
    incident_item = page.locator(f'li[data-incident*="{task_id}"]')
    expect(incident_item).to_be_visible(timeout=10000)
    expect(incident_item).to_contain_text("Stopped by: Kernel (Landlock)")
    expect(incident_item).to_contain_text("private_archive.txt")

    incident_screenshot_path = screenshot_dir / "incident_page.png"
    page.screenshot(path=str(incident_screenshot_path), full_page=True)

    # Screenshot 3: Task report page
    page.goto(f"{console_server.url}/dashboard/report/{task_id}")
    report_sheet = page.locator("#report-sheet")
    expect(report_sheet).to_be_visible(timeout=10000)
    blocked_section = page.locator("#report-blocked")
    expect(blocked_section).to_contain_text("Kernel (Landlock)")
    expect(blocked_section).to_contain_text("private_archive.txt")

    report_screenshot_path = screenshot_dir / "report_page.png"
    page.screenshot(path=str(report_screenshot_path), full_page=True)
