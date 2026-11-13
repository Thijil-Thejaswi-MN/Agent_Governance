"""Playwright test for Feature 3: 'Kernel off' comparison mode (admin only)."""
from __future__ import annotations

import re
import os
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
def comparison_console_server(tmp_path_factory):
    srv = start_console_server(tmp_path_factory.mktemp("console_comparison"))
    yield srv
    srv.stop()


def test_comparison_mode_playwright(page: Page, comparison_console_server, tmp_path: Path):
    console_server = comparison_console_server
    screenshot_dir = tmp_path / "comparison_mode"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/run")
    page.set_viewport_size({"width": 1440, "height": 900})

    # A preset without decoys cannot be compared: the toggle is disabled
    page.locator("#preset-summarise_csv").click()
    expect(page.locator("#comparison-mode-toggle")).to_be_disabled()

    # Select shell_injection preset
    preset_btn = page.locator("#preset-shell_injection")
    expect(preset_btn).to_be_visible()
    preset_btn.click()

    page.locator("#model-selector").select_option("scripted")

    # Verify admin comparison mode toggle is present and check it
    cmp_toggle = page.locator("#comparison-mode-toggle")
    expect(cmp_toggle).to_be_visible()
    cmp_toggle.check()

    # Start the run
    page.locator("#start-run-btn").click()
    expect(page).to_have_url(re.compile(r"/dashboard/run/(task_[0-9a-f]+)$"), timeout=15000)
    match = re.search(r"/(task_[0-9a-f]+)$", page.url)
    assert match is not None
    task_id = match.group(1)

    # Verify comparison banner on Watch / Run page
    cmp_banner = page.locator("#comparison-run-banner")
    expect(cmp_banner).to_be_visible()
    expect(cmp_banner).to_contain_text("Comparison run: kernel lock off, for demonstration")

    # Wait for completion
    status = page.locator("#run-status")
    expect(status).to_have_attribute("data-state", "completed", timeout=60000)
    expect(page.locator("#output-preview")).to_contain_text("Audit complete")

    # Screenshot 1: Run page in comparison mode
    run_screenshot_path = screenshot_dir / "run_comparison_page_1440.png"
    page.screenshot(path=str(run_screenshot_path), full_page=True)

    # Check History page badge
    page.goto(f"{console_server.url}/dashboard/history")
    history_link = page.locator(f'a[data-task-id="{task_id}"]')
    expect(history_link).to_be_visible(timeout=10000)
    expect(history_link.locator('[data-badge="comparison"]')).to_be_visible()
    expect(history_link.locator('[data-badge="comparison"]')).to_have_text("Comparison")

    # Screenshot 2: Incidents page with comparison warning
    page.goto(f"{console_server.url}/dashboard/incidents")
    expect(page.locator("h1")).to_contain_text("blocked action")
    incident_item = page.locator(f'li[data-incident*="{task_id}"]')
    expect(incident_item).to_be_visible(timeout=10000)
    expect(incident_item).to_contain_text("Comparison run: decoy was read (would be blocked by the kernel lock)")
    expect(incident_item).to_contain_text("private_archive.txt")

    incident_screenshot_path = screenshot_dir / "incident_comparison_page_1440.png"
    page.screenshot(path=str(incident_screenshot_path), full_page=True)

    # Screenshot 3: Task report page
    page.goto(f"{console_server.url}/dashboard/report/{task_id}")
    report_sheet = page.locator("#report-sheet")
    expect(report_sheet).to_be_visible(timeout=10000)
    blocked_section = page.locator("#report-blocked")
    expect(blocked_section).to_contain_text("Comparison run: decoy was read (would be blocked by the kernel lock)")
    expect(blocked_section).to_contain_text("private_archive.txt")

    report_screenshot_path = screenshot_dir / "report_comparison_page_1440.png"
    page.screenshot(path=str(report_screenshot_path), full_page=True)

    # Save to UI_EVIDENCE_DIR if specified
    evidence_dir = os.getenv("UI_EVIDENCE_DIR")
    if evidence_dir:
        dest = Path(evidence_dir)
        dest.mkdir(parents=True, exist_ok=True)
        import shutil
        shutil.copy(run_screenshot_path, dest / "run_comparison_page_1440.png")
        shutil.copy(incident_screenshot_path, dest / "incident_comparison_page_1440.png")
        shutil.copy(report_screenshot_path, dest / "report_comparison_page_1440.png")