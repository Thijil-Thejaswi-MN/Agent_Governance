"""Task report end to end.

1. A finished run with an approval, a blocked action and a stored record: History opens
   the run, "Task report" opens the report with requester, boundary, the approval with who
   and when, the blocked action with its layer, and "Record checked: no entries changed".
2. Print media hides the sidebar, top bar and buttons; the PDF is one A4 page.
3. JSON and CSV downloads carry the same facts.
4. At 390 px there is no horizontal scroll.
"""
from __future__ import annotations

import csv
import datetime
import io
import json
import re
import time

import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.app.governance.models import (
    EventSource,
    EventVerdict,
    ExpansionRequest,
    ExpansionStatus,
    GovernanceEvent,
    RiskTier,
    TaskAction,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.receipt import GENESIS_HASH, chain_entries
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.tests.playwright_server import no_horizontal_scroll, save_evidence

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]


def seed_finished_run(server, suffix: str) -> str:
    s = GovernanceStorage(server.db_path)
    now = datetime.datetime.now(datetime.timezone.utc)
    ts = lambda sec: (now - datetime.timedelta(seconds=sec)).isoformat()  # noqa: E731
    tid = f"task_report_{suffix}"
    s.save_task(TaskRecord(task_id=tid, request_text="Summarise the Q3 minutes", request_hash="h",
                           agent_id="minutes_bot", workspace_root="/tmp/ws_report", status=TaskLifecycle.COMPLETED,
                           created_at=ts(300), started_at=ts(298), completed_at=ts(200), owner="Ana Dev", team="core", requested_by="Thijil"))
    s.save_boundary(TaskBoundary(task_id=tid, version=1, workspace_root="/tmp/ws_report",
                                 files_read=["input/minutes.txt"], files_write=["output/summary.md"], tools=["read_file"]))
    s.save_boundary(TaskBoundary(task_id=tid, version=2, workspace_root="/tmp/ws_report",
                                 files_read=["input/minutes.txt", "docs/agenda.txt"], files_write=["output/summary.md"],
                                 tools=["read_file"]))
    s.save_expansion_request(ExpansionRequest(
        request_id=f"exp_report_{suffix}", task_id=tid, agent_id="minutes_bot", resource_type="file_read",
        resource_target="docs/agenda.txt", justification="need the agenda", baseline_risk_tier=RiskTier.MEDIUM,
        effective_risk_tier=RiskTier.MEDIUM, status=ExpansionStatus.APPROVED, created_at=ts(260),
        resolved_at=ts(250), resolved_by="operator:test_lead_operator"))
    s.record_event(GovernanceEvent(
        event_id=f"ev_report_{suffix}", timestamp=ts(240), source=EventSource.TOOL_BROKER, task_id=tid,
        agent_id="minutes_bot", kind="file_read", target="input/payroll.csv", verdict=EventVerdict.OUTSIDE,
        risk_tier=RiskTier.MEDIUM, action_taken=TaskAction.BLOCK_ACTION, prevented=True, rule_matched="not in boundary"))
    for kind, summary in (("phase", "Boundary derived"), ("phase", "Run finished")):
        s.record_task_step(tid, kind=kind, layer="intake", verdict="ALLOW", summary=summary, source_label="enforced")
    events = [{"timestamp": ts(290), "kind": "file_read", "target": "input/minutes.txt"},
              {"timestamp": ts(240), "kind": "file_read", "target": "input/payroll.csv"}]
    final = chain_entries(events)
    server.receipts_dir.mkdir(parents=True, exist_ok=True)
    (server.receipts_dir / f"{tid}.json").write_text(json.dumps({
        "task_id": tid, "events": events,
        "hash_chain": {"algorithm": "sha256", "count": 2, "genesis": GENESIS_HASH, "final_hash": final}}))
    return tid


def _sign_in(page: Page, url: str, token: str) -> None:
    page.goto(f"{url}/dashboard/signin")
    page.locator("#operator-token-input").fill(token)
    page.locator("#sign-in-submit-btn").click()
    page.wait_for_url("**/dashboard/run")


def test_task_report(page: Page, console_server):
    tid = seed_finished_run(console_server, str(int(time.time() * 1000)))
    _sign_in(page, console_server.url, console_server.token)
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{console_server.url}/dashboard/history/{tid}")
    page.locator("#task-report-link").click()
    page.wait_for_url(f"**/dashboard/report/{tid}")

    sheet = page.locator("#report-sheet")
    expect(sheet).to_be_visible()
    expect(page.locator("#report-requester")).to_have_text("Thijil")
    expect(page.locator("#report-agent-owner")).to_have_text("Ana Dev (core)")
    expect(page.locator("#report-outcome")).to_have_text("Done")
    expect(page.locator("#report-boundary")).to_contain_text("docs/agenda.txt")
    expect(page.locator("#report-approvals")).to_contain_text("Allowed for this run")
    expect(page.locator("#report-approvals")).to_contain_text("test_lead_operator (operator)")
    expect(page.locator("#report-blocked")).to_contain_text("input/payroll.csv")
    expect(page.locator("#report-blocked")).to_contain_text("Tool broker")
    expect(page.locator("#report-blocked")).to_contain_text("Attempted, not successful")
    expect(page.locator("#report-record-line")).to_have_text("Record checked: no entries changed")
    save_evidence(page, "task_report_1440")

    # Print: no sidebar, top bar or buttons; one A4 page.
    page.emulate_media(media="print")
    expect(page.locator('aside[data-sidebar="rail"]')).to_be_hidden()
    expect(page.locator("#report-print-btn")).to_be_hidden()
    expect(sheet).to_be_visible()
    pdf = page.pdf(format="A4", print_background=True)
    assert len(re.findall(rb"/Type\s*/Page[^s]", pdf)) == 1
    page.emulate_media(media="screen")

    with page.expect_download() as dl:
        page.locator("#report-json-btn").click()
    data = json.loads(dl.value.path().read_text())
    assert data["task"]["requester"] == "Thijil" and data["record"]["verified"] is True
    assert dl.value.suggested_filename == f"task_report_{tid}.json"

    with page.expect_download() as dl:
        page.locator("#report-csv-link").click()
    rows = list(csv.DictReader(io.StringIO(dl.value.path().read_text())))
    assert any(r["section"] == "approval" and r["target"] == "docs/agenda.txt" for r in rows)
    assert any(r["section"] == "blocked" and r["outcome"] == "attempted, not successful" for r in rows)

    page.set_viewport_size({"width": 390, "height": 844})
    page.reload()
    expect(sheet).to_be_visible()
    assert no_horizontal_scroll(page)
    save_evidence(page, "task_report_390")
