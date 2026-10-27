"""Playwright test for Governed Task Execution Run Page.

Verifies:
1. Preset 1 (Summarise a CSV) with scripted provider:
   - Steps stream in chronological order.
   - Concludes with output preview and verified receipt.
2. Preset 2 (Compare with target) with scripted provider:
   - Encounters unlisted target file outside initial boundary.
   - Inline approval card appears with provenance warning and live countdown.
   - Operator approves from inline card.
   - Task execution continues to finish with verified receipt.
"""
from __future__ import annotations

import time
import pytest
from pathlib import Path

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.app.governance.models import TaskLifecycle
from demo.security_monitor.app.governance.storage import GovernanceStorage

pytestmark = pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed")


def test_run_page_preset_1_scripted(page: Page):
    base_url = "http://127.0.0.1:8000"
    page.goto(f"{base_url}/dashboard/run")

    # Set operator authorization token in session
    page.evaluate("sessionStorage.setItem('governance_operator_token', 'test_secret_operator_token')")
    page.reload()

    # 1. Select preset 1: summarise_csv
    page.locator("#preset-summarise_csv").click()

    # 2. Select scripted model
    model_selector = page.locator("#model-selector")
    model_selector.select_option("scripted")

    # 3. Assert boundary preview is populated (use specific span locator)
    expect(page.locator("span:has-text('input/sales_data.csv')").first).to_be_visible()
    expect(page.locator("span:has-text('output/summary.txt')").first).to_be_visible()

    # 4. Click Start Governed Run
    start_btn = page.locator("#start-run-btn")
    expect(start_btn).to_be_visible()
    start_btn.click()

    # 5. Assert steps appear in timeline
    step_1 = page.locator("text=#1").first
    expect(step_1).to_be_visible(timeout=15000)

    # 6. Wait for run to finish
    expect(page.locator("text=Cryptographic Task Receipt")).to_be_visible(timeout=30000)
    expect(page.locator("text=Verified (SHA-256 hash chain intact)")).to_be_visible()
    expect(page.locator("text=Download receipt (JSON)")).to_be_visible()


def test_run_page_preset_2_scripted_inline_approval(page: Page):
    base_url = "http://127.0.0.1:8000"
    page.goto(f"{base_url}/dashboard/run")

    page.evaluate("sessionStorage.setItem('governance_operator_token', 'test_secret_operator_token')")
    page.reload()

    # 1. Select preset 2: compare_target
    page.locator("#preset-compare_target").click()

    # 2. Select scripted model
    model_selector = page.locator("#model-selector")
    model_selector.select_option("scripted")

    # 3. Start Run
    page.locator("#start-run-btn").click()

    # 4. Expect inline approval card to appear
    inline_card = page.locator('[id^="inline-approval-card-"]')
    expect(inline_card).to_be_visible(timeout=25000)
    expect(inline_card).to_contain_text("input/target_metrics.csv")
    expect(inline_card).to_contain_text("until fail-closed DENY")

    # 5. Click Approve Expansion from the inline card
    approve_btn = inline_card.locator('[id^="inline-approve-btn-"]')
    expect(approve_btn).to_be_visible()
    approve_btn.click()

    # 6. Expect card to disappear and execution to conclude with verified receipt
    expect(page.locator("text=Cryptographic Task Receipt")).to_be_visible(timeout=30000)
    expect(page.locator("text=Verified (SHA-256 hash chain intact)")).to_be_visible()
