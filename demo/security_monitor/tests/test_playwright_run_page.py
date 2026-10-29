"""Playwright tests for the Run page (each test starts its own server; see conftest.py).

1. Preset 1 (Summarise a CSV), scripted provider: steps stream in, the run ends
   'Completed' with output and a verified hash-chained receipt.
2. Preset 2 (Compare with a target), scripted provider: the inline approval card
   appears with the fail-closed countdown; approving lets the run finish.
3. A host without the OS layer: Start shows the 503 reason and the page stays idle.
4. Stop pressed while the sandbox is being prepared: the run ends 'Stopped'
   (operator_stop) and the agent never starts.

1, 2 and 4 run the real launcher (scripted MOCK LLM; OS layer, broker, sensor are
real) and carry the os_layer marker.
"""
from __future__ import annotations

import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import save_evidence, sign_in

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]


def _open_run_page(page: Page, server, preset: str) -> None:
    sign_in(page, server)
    page.goto(f"{server.url}/dashboard/run")
    page.locator(f"#preset-{preset}").click()
    page.locator("#model-selector").select_option("scripted")


@pytest.mark.os_layer
def test_run_page_preset_1_scripted(page: Page, console_server):
    _open_run_page(page, console_server, "summarise_csv")

    expect(page.locator("span:has-text('input/sales_data.csv')").first).to_be_visible()
    expect(page.locator("span:has-text('output/summary.txt')").first).to_be_visible()

    page.locator("#start-run-btn").click()
    expect(page.locator("text=#1").first).to_be_visible(timeout=15000)

    expect(page.locator("#run-status")).to_have_attribute("data-state", "completed", timeout=60000)
    expect(page.locator("text=Hash-chained Task Receipt")).to_be_visible(timeout=15000)
    expect(page.locator("text=Verified (SHA-256 hash chain intact)")).to_be_visible()
    expect(page.locator("text=Download receipt (JSON)")).to_be_visible()


@pytest.mark.os_layer
def test_run_page_preset_2_scripted_inline_approval(page: Page, console_server):
    _open_run_page(page, console_server, "compare_target")
    page.locator("#start-run-btn").click()

    inline_card = page.locator('[id^="inline-approval-card-"]')
    expect(inline_card).to_be_visible(timeout=25000)
    expect(inline_card).to_contain_text("input/target_metrics.csv")
    expect(inline_card).to_contain_text("until fail-closed DENY")

    approve_btn = inline_card.locator('[id^="inline-approve-btn-"]')
    expect(approve_btn).to_be_visible()
    approve_btn.click()

    expect(page.locator("#run-status")).to_have_attribute("data-state", "completed", timeout=60000)
    expect(page.locator("text=Hash-chained Task Receipt")).to_be_visible(timeout=15000)
    expect(page.locator("text=Verified (SHA-256 hash chain intact)")).to_be_visible()


def test_run_page_failed_start_shows_error_and_stays_idle(page: Page, unsupported_host_server):
    _open_run_page(page, unsupported_host_server, "summarise_csv")
    page.locator("#start-run-btn").click()

    error = page.locator("#run-error")
    expect(error).to_be_visible(timeout=15000)
    expect(error).to_contain_text("OS-layer execution needs Linux/WSL2 with systemd --user, Landlock and cgroup v2")
    expect(error).to_contain_text("systemd-run not found")
    expect(page.locator("#run-status")).to_have_attribute("data-state", "idle")
    expect(page.locator("#start-run-btn")).to_be_visible()
    expect(page.locator("#stop-run-btn")).to_have_count(0)
    save_evidence(page, "run_page_503_unsupported_host")


@pytest.mark.os_layer
def test_run_page_stop_during_preparation_ends_stopped(page: Page, preparing_console_server):
    _open_run_page(page, preparing_console_server, "summarise_csv")
    page.locator("#start-run-btn").click()

    status = page.locator("#run-status")
    expect(status).to_have_attribute("data-state", "preparing", timeout=15000)
    expect(page.locator("text=Compiled Landlock sandbox rules")).to_be_visible(timeout=15000)

    page.locator("#stop-run-btn").click()

    expect(status).to_have_attribute("data-state", "stopped", timeout=20000)
    expect(page.locator("#run-end-reason")).to_contain_text("operator_stop")
    expect(page.locator("text=Task lifecycle termination: operator_stop")).to_be_visible()
    expect(page.locator("text=Agent process launched")).to_have_count(0)
    expect(page.locator("#start-run-btn")).to_be_visible()
