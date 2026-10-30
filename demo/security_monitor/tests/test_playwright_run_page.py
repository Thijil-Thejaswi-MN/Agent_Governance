"""Playwright tests for Run: Ask -> Watch -> Done (each test starts its own server; see conftest.py).

1. Preset 1 (Summarise a file), scripted provider: Ask -> Watch at /run/<task_id> -> Done
   with the output preview, 'Record checked: no entries changed' and Download record; the
   drawer keeps the technical labels and the hash-chain verification.
2. Preset 2 (Needs one more file), scripted provider: the decision card appears with the
   file name, the plain warning and the countdown; Allow for this run lets the run finish.
3. A host without the OS layer: Start shows a plain line (the server's 503 reason in
   Details) and the page stays on Ask; nothing was started.
4. Stop pressed while the sandbox is being prepared: the run ends 'stopped'
   (operator_stop) and the agent never starts.

1, 2 and 4 run the real launcher (scripted MOCK LLM; OS layer, broker, sensor are
real) and carry the os_layer marker.
"""
from __future__ import annotations

import re
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import (
    FIRST_SCREEN_JARGON,
    NEVER_SAY,
    banned_words_in,
    save_evidence,
    sign_in,
    visible_text_outside_details,
)

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]


def _open_ask(page: Page, server, preset: str) -> None:
    sign_in(page, server)
    page.goto(f"{server.url}/dashboard/run")
    page.locator(f"#preset-{preset}").click()
    page.locator("#model-selector").select_option("scripted")


def _assert_plain(page: Page) -> None:
    text = visible_text_outside_details(page)
    assert banned_words_in(text, FIRST_SCREEN_JARGON + NEVER_SAY) == [], text


@pytest.mark.os_layer
def test_ask_watch_done_preset_1_scripted(page: Page, console_server):
    _open_ask(page, console_server, "summarise_csv")
    expect(page.locator("#allow-preview")).to_contain_text("read sales_data.csv")
    expect(page.locator("#allow-preview")).to_contain_text("write summary.txt")

    page.locator("#start-run-btn").click()
    expect(page).to_have_url(re.compile(r"/dashboard/run/task_[0-9a-f]+$"), timeout=15000)
    expect(page.locator("#fence")).to_be_visible()
    expect(page.locator('#fence [data-chip="inside"]').first).to_be_visible()

    status = page.locator("#run-status")
    expect(status).to_have_attribute("data-state", "completed", timeout=60000)
    expect(status).to_have_text("Done. The agent stayed inside its fence.")
    expect(page.locator("#output-preview")).to_contain_text("summary.txt")
    expect(page.locator("#output-preview")).to_contain_text("120,000")
    expect(page.locator("#record-status")).to_have_text("Record checked: no entries changed", timeout=15000)
    expect(page.locator("#download-record")).to_be_visible()
    expect(page.locator("#stop-run-btn")).to_have_count(0)
    _assert_plain(page)

    # Details: the honest technical layer.
    page.locator("#show-what-happened").click()
    drawer = page.locator("#details-drawer")
    expect(drawer).to_be_visible()
    expect(drawer.locator("#receipt-verification")).to_have_text("Verified (SHA-256 hash chain intact)")
    expect(drawer.locator("#network-marker")).to_have_text("network: none")
    expect(drawer.locator("#boundary-version")).to_have_text("Boundary version 1")
    expect(drawer).to_contain_text("enforced · tool broker")
    expect(drawer).to_contain_text("read_file allowed: input/sales_data.csv")


@pytest.mark.os_layer
def test_preset_2_decision_card_allow_continues(page: Page, console_server):
    _open_ask(page, console_server, "compare_target")
    page.locator("#start-run-btn").click()

    card = page.locator('[id^="inline-approval-card-"]')
    expect(card).to_be_visible(timeout=25000)
    expect(page.locator("#run-status")).to_have_attribute("data-state", "waiting_approval")
    expect(page.locator("#run-status")).to_have_text("The agent wants one more file.")
    expect(card).to_contain_text("target_metrics.csv")
    expect(card.locator("#decision-warning")).to_contain_text("only learned about this file from inside sales_data.csv")
    expect(card.locator("#decision-countdown")).to_contain_text(re.compile(r"Decide within \d+:\d\d, or it stays blocked\."))
    expect(page.locator('#fence [data-chip="requested"]')).to_contain_text("target_metrics.csv")
    _assert_plain(page)

    allow = card.locator('[id^="inline-approve-btn-"]')
    expect(allow).to_have_text("Allow for this run")
    allow.click()
    expect(card).to_have_count(0, timeout=15000)

    status = page.locator("#run-status")
    expect(status).to_have_attribute("data-state", "completed", timeout=60000)
    expect(status).to_have_text("Done. 1 attempt was stopped.")
    expect(page.locator("#record-status")).to_have_text("Record checked: no entries changed", timeout=15000)
    # Once allowed, the file is inside the fence, and the boundary version says why it changed.
    expect(page.locator('#fence [data-chip="inside"]', has_text="target_metrics.csv")).to_be_visible()
    page.locator("#show-what-happened").click()
    expect(page.locator("#details-drawer #boundary-version")).to_have_text("Boundary version 2 (after 1 approval)")


def test_ask_failed_start_shows_plain_reason_and_stays(page: Page, unsupported_host_server):
    _open_ask(page, unsupported_host_server, "summarise_csv")
    page.locator("#start-run-btn").click()

    error = page.locator("#run-error")
    expect(error).to_be_visible(timeout=15000)
    expect(error).to_contain_text("This computer can't run a fenced agent right now.")
    # The server's reason is one click away, unchanged.
    expect(error).to_contain_text("OS-layer execution needs Linux/WSL2 with systemd --user, Landlock and cgroup v2")
    expect(error).to_contain_text("systemd-run not found")
    _assert_plain(page)
    expect(page).to_have_url(re.compile(r"/dashboard/run/?$"))
    expect(page.locator("#start-run-btn")).to_be_visible()
    expect(page.locator("#stop-run-btn")).to_have_count(0)
    save_evidence(page, "run_page_503_unsupported_host")


@pytest.mark.os_layer
def test_stop_during_preparation_ends_stopped(page: Page, preparing_console_server):
    _open_ask(page, preparing_console_server, "summarise_csv")
    page.locator("#start-run-btn").click()

    status = page.locator("#run-status")
    expect(status).to_have_attribute("data-state", "preparing", timeout=15000)
    expect(status).to_have_text("Setting up a fenced space for the agent…")

    # Wait until the sandbox rules are compiled (the drawer shows the stored steps).
    page.locator("#show-what-happened").click()
    expect(page.locator("#details-drawer")).to_contain_text("Compiled Landlock sandbox rules", timeout=15000)
    page.keyboard.press("Escape")
    expect(page.locator("#details-drawer")).to_have_count(0)

    page.locator("#stop-run-btn").click()

    expect(status).to_have_attribute("data-state", "stopped", timeout=20000)
    expect(status).to_have_text("Stopped before the agent started. It never ran.")
    page.locator("#show-what-happened").click()
    drawer = page.locator("#details-drawer")
    expect(drawer.locator("#run-end-reason")).to_contain_text("operator_stop")
    expect(drawer).to_contain_text("Task lifecycle termination: operator_stop")
    expect(drawer.locator("text=Agent process launched")).to_have_count(0)
    page.keyboard.press("Escape")
    expect(page.get_by_role("link", name="Start another")).to_be_visible()
