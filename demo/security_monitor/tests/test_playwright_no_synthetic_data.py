"""No made-up live data on the Team lead and Inbox pages.

1. Empty database: the Team lead page shows zero counts, "—" and empty states, and none of
   the names that used to be filled in (Meera S., finance-agent, finance-report-bot, ...).
   The Inbox shows "—" for the median decision time.
2. One seeded blocked action: its agent's heatmap row marks the hour of that event's real
   timestamp (in the browser's local time) as stopped.
"""
from __future__ import annotations

import time

import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.tests.playwright_server import save_evidence, seed_waiting_task

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]

OLD_PLACEHOLDERS = ["Meera S.", "finance-agent", "finance-report-bot", "invoice-matcher", "tax-prep-bot",
                    "targets.csv", "gst.gov.in", "1m 48s"]


def _sign_in(page: Page, url: str, token: str) -> None:
    page.goto(f"{url}/dashboard/signin")
    page.locator("#operator-token-input").fill(token)
    page.locator("#sign-in-submit-btn").click()
    page.wait_for_url("**/dashboard/run")


def test_empty_team_and_inbox_show_no_invented_values(page: Page, empty_console_server):
    _sign_in(page, empty_console_server.url, empty_console_server.token)
    page.goto(f"{empty_console_server.url}/dashboard/team")
    expect(page.locator("#team-headline")).to_have_text("0 of 0 agents at work. Nothing needs you.")
    expect(page.locator("#kpi-running [data-value]")).to_have_text("—")
    expect(page.locator("#kpi-waiting [data-value]")).to_have_text("0")
    expect(page.locator("#kpi-stopped [data-value]")).to_have_text("0")
    expect(page.locator("#heat-empty")).to_be_visible()
    expect(page.locator("#team-agents-empty")).to_be_visible()
    expect(page.locator("#needs-you-empty")).to_be_visible()
    body = page.locator("body").inner_text()
    assert [p for p in OLD_PLACEHOLDERS if p in body] == []
    save_evidence(page, "team_empty")

    page.goto(f"{empty_console_server.url}/dashboard/inbox")
    expect(page.locator("#kpi-median-decision")).to_have_text("—")
    expect(page.locator("#kpi-timed-out")).to_have_text("0")
    expect(page.locator("#kpi-by-rules")).to_have_text("0")
    assert "1m 48s" not in page.locator("body").inner_text()


def test_heatmap_marks_the_real_hour(page: Page, console_server):
    task_id, _ = seed_waiting_task(console_server.db_path, f"heat_{int(time.time() * 1000)}", agent_id="heat_bot")
    ts = [e.timestamp for e in GovernanceStorage(console_server.db_path).get_events_for_task(task_id) if e.prevented][0]
    _sign_in(page, console_server.url, console_server.token)
    page.goto(f"{console_server.url}/dashboard/team")
    row = page.locator('#heatmap [data-agent="heat_bot"]')
    expect(row).to_be_visible()
    hour = page.evaluate("ts => new Date(ts).getHours()", ts)
    expect(row.locator(f'[data-hour="{hour}"]')).to_have_attribute("data-cell", "stopped")
    # Every other hour of this row is not "stopped".
    assert row.locator('[data-cell="stopped"]').count() == 1
