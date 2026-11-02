"""Playwright tests for Fleet (real data only).

1. Empty store: the calm empty state "All quiet. No agents are running.", nothing waiting,
   nothing blocked.
2. Seeded store: the headline shows the real counts (2 agents at work, 1 needs you), equal
   to GET /api/governance/fleet/summary; one dot per inventory agent; Needs you and the
   grouped blocked row; a waiting dot opens that task's Watch; "See every blocked action"
   opens History filtered to blocked.
3. Above 1,500 dots the field is drawn on a <canvas> (summary intercepted for this check).
"""
from __future__ import annotations

import json
import re
import time
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.app.governance.models import TaskLifecycle, TaskRecord
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.tests.playwright_server import seed_waiting_task, sign_in

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]


def test_fleet_empty_state(page: Page, empty_console_server):
    sign_in(page, empty_console_server, "/dashboard/fleet")
    page.goto(f"{empty_console_server.url}/dashboard/fleet")
    headline = page.locator("#fleet-headline")
    expect(headline).to_have_text("All quiet.No agents are running.")
    expect(headline).to_have_attribute("data-quiet", "true")
    expect(page.locator("#fleet-empty")).to_be_visible()
    expect(page.locator("#needs-you-empty")).to_have_text("Nothing is waiting for a decision.")
    expect(page.locator("#blocked-empty")).to_have_text("Nothing was blocked.")
    expect(page.locator("#dot-field")).to_have_count(0)


def test_fleet_real_counts(page: Page, seeded_console_server):
    srv = seeded_console_server
    stamp = int(time.time() * 1000)
    waiting_task, req_id = seed_waiting_task(srv.db_path, f"fleet_a_{stamp}", agent_id="finance_bot")
    storage = GovernanceStorage(srv.db_path)
    storage.save_task(TaskRecord(
        task_id=f"task_fleet_b_{stamp}", request_text="Tidy the build logs", request_hash="h", agent_id="build_agent",
        workspace_root="/tmp/ws_b", status=TaskLifecycle.ACTIVE, created_at="2026-10-30T00:00:00+00:00"))

    sign_in(page, srv, "/dashboard/fleet")
    page.goto(f"{srv.url}/dashboard/fleet")
    expect(page.locator("#fleet-headline")).to_have_text("2 agents at work.1 needs you.")

    api = page.request.get(f"{srv.url}/api/governance/fleet/summary", headers={"X-Operator-Token": srv.token}).json()
    assert (api["agents_at_work"], api["need_you"]) == (2, 1)
    assert api["dots"]["basis"] == "inventory"

    dots = page.locator("#dot-field [data-dot-state]")
    expect(page.locator("#dot-field")).to_have_attribute("data-render", "dom")
    expect(dots).to_have_count(len(api["dots"]["items"]))
    expect(page.locator('#dot-field [data-dot-state="waiting"]')).to_have_count(1)
    expect(page.locator("#dot-basis")).to_contain_text("Each dot is one agent we know about.")

    row = page.locator(f"#needs-you-{req_id}")
    expect(row).to_contain_text("Finance bot wants quarterly_revenue.csv")
    expect(row).to_contain_text("learned of it from inside briefing.txt")

    group = page.locator('[data-group="mentioned_in_input"]')
    expect(group).to_contain_text("1")
    expect(group).to_contain_text("attempt to open a file that was only mentioned inside another file")

    page.locator('#dot-field [data-dot-state="waiting"]').click()
    expect(page).to_have_url(f"{srv.url}/dashboard/run/{waiting_task}")
    expect(page.locator(f"#inline-approval-card-{req_id}")).to_be_visible()

    page.goto(f"{srv.url}/dashboard/fleet")
    page.locator("#see-blocked").click()
    expect(page).to_have_url(re.compile(r"/dashboard/history\?filter=blocked$"))
    expect(page.locator(f'#history-list [data-task-id="{waiting_task}"]')).to_be_visible()
    expect(page.locator(f'#history-list [data-task-id="task_fleet_b_{stamp}"]')).to_have_count(0)


def test_fleet_canvas_above_threshold(page: Page, empty_console_server):
    srv = empty_console_server
    sign_in(page, srv, "/dashboard/fleet")
    items = [{"id": f"a{i}", "label": f"agent {i}", "state": "waiting" if i == 7 else "working",
              "task_id": f"t{i}", "view": "watch"} for i in range(2000)]
    fake = {
        "generated_at": "2026-10-30T00:00:00+00:00", "agents_at_work": 2000, "need_you": 1,
        "running_tasks": [], "dots": {"basis": "tasks", "items": items, "counts": {"working": 1999, "waiting": 1}},
        "needs_you": [], "blocked": {"window_hours": 24, "total": 0, "groups": []},
        "inventory_size": 0, "known_tasks": 2000,
    }
    page.route("**/api/governance/fleet/summary", lambda route: route.fulfill(
        status=200, content_type="application/json", body=json.dumps(fake)))
    page.goto(f"{srv.url}/dashboard/fleet")
    expect(page.locator("#fleet-headline")).to_have_text("2,000 agents at work.1 needs you.")
    expect(page.locator("canvas#dot-field")).to_have_attribute("data-render", "canvas")
    expect(page.locator("[data-dot-state]")).to_have_count(0)
