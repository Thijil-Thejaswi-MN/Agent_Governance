"""Fence picture geometry at every viewport.

- Every outside chip (requested or stopped) is fully outside the dashed ring: no point of
  the chip is within the circle, and either its left edge clears the ring's rightmost point
  by more than the 22 px (horizontal) knock animation, or, on narrow screens, the whole chip
  is below the ring; so it never touches the ring while knocking.
- Every inside chip lies fully inside the circle.
- Nothing leaves the page (no horizontal scroll).
Checked on a waiting run (requested chip) and on a finished run with long names and more
stopped attempts than fit (the '+N more stopped' chip), from 1920 px down to 320 px.
Motion is reduced so the chips are measured at rest; the gap check covers the knock.
"""
from __future__ import annotations

import datetime
import time
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.app.governance.models import TaskBoundary, TaskLifecycle, TaskRecord
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.tests.playwright_server import no_horizontal_scroll, seed_waiting_task, sign_in

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]

KNOCK_PX = 22
WIDTHS = [1920, 1440, 1024, 768, 600, 390, 320]

LONG_BLOCKED = [
    "/home/u/projects/archive/q3_private_notes_with_a_long_name.txt",
    "/home/u/.config/acme/settings_private.txt",
    "/home/u/.ssh/id_ed25519",
    "/etc/very_long_system_configuration_file_name.conf",
    "/home/u/Documents/payroll_2026.xlsx",
]


def _seed_many_blocked(db_path, suffix: str) -> str:
    storage = GovernanceStorage(db_path)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    task_id = f"task_geo_{suffix}"
    storage.save_task(TaskRecord(task_id=task_id, request_text="Summarise the quarterly sales report", request_hash="h",
                                 agent_id="report_bot", workspace_root="/tmp/ws_geo", status=TaskLifecycle.COMPLETED,
                                 created_at=now, completed_at=now))
    storage.save_boundary(TaskBoundary(
        task_id=task_id, workspace_root="/tmp/ws_geo",
        files_read=["input/quarterly_sales_report_for_the_board.csv", "input/regions.csv", "input/notes.txt",
                    "input/currency_rates.csv", "input/extra.csv"],
        files_write=["output/summary.txt"], network=[], tools=["read_file", "write_file"], peer_agents=[]))
    storage.record_task_step(task_id, kind="phase", layer="launcher", verdict="ALLOW",
                             summary="Agent process launched (pid 1)", source_label="enforced")
    for target in LONG_BLOCKED:
        storage.record_task_step(task_id, kind="sensor", layer="landlock", verdict="BLOCK_ACTION",
                                 summary=f"Landlock blocked file_read on {target}", source_label="enforced")
    storage.record_task_step(task_id, kind="finished", layer="launcher", verdict="COMPLETED",
                             summary="Run ended: completed", source_label="enforced")
    return task_id


GEOMETRY_JS = """() => {
    const ring = document.querySelector('#fence-ring').getBoundingClientRect();
    const cx = ring.left + ring.width / 2, cy = ring.top + ring.height / 2, r = ring.width / 2;
    const dist = (x, y) => Math.hypot(x - cx, y - cy);
    const out = { r, ringRight: ring.right, ringBottom: ring.bottom, vw: document.documentElement.clientWidth, outside: [], inside: [] };
    for (const el of document.querySelectorAll('#fence [data-chip]')) {
        const b = el.getBoundingClientRect();
        // Nearest point of the chip to the ring's centre, and its farthest corner.
        const nx = Math.max(b.left, Math.min(cx, b.right)), ny = Math.max(b.top, Math.min(cy, b.bottom));
        const far = Math.max(dist(b.left, b.top), dist(b.right, b.top), dist(b.left, b.bottom), dist(b.right, b.bottom));
        const item = { kind: el.dataset.chip, text: el.textContent, nearest: dist(nx, ny), far, left: b.left, right: b.right, top: b.top };
        (['inside', 'inside-more'].includes(el.dataset.chip) ? out.inside : out.outside).push(item);
    }
    return out;
}"""


def _check(page: Page, name: str, width: int, expect_outside: int) -> None:
    g = page.evaluate(GEOMETRY_JS)
    where = f"{name} @ {width}px"
    assert len(g["outside"]) == expect_outside, f"{where}: {g['outside']}"
    for c in g["outside"]:
        assert c["nearest"] > g["r"], f"{where}: outside chip {c['text']!r} overlaps the ring ({c})"
        beside = c["left"] - g["ringRight"] > KNOCK_PX
        below = c["top"] - g["ringBottom"] >= 8
        assert beside or below, f"{where}: {c['text']!r} would touch the ring while knocking ({c}, {g['ringRight']}, {g['ringBottom']})"
        assert c["right"] <= g["vw"], f"{where}: {c['text']!r} leaves the page"
    for c in g["inside"]:
        assert c["far"] < g["r"], f"{where}: inside chip {c['text']!r} crosses the ring ({c})"
    assert no_horizontal_scroll(page), f"{where} scrolls horizontally"


def test_outside_chips_never_touch_the_ring(page: Page, console_server):
    stamp = int(time.time() * 1000)
    waiting, req_id = seed_waiting_task(console_server.db_path, f"geo_{stamp}",
                                        target="input/quarterly_revenue_reference_table_2026.csv")
    many = _seed_many_blocked(console_server.db_path, str(stamp))
    page.emulate_media(reduced_motion="reduce")
    sign_in(page, console_server)
    for width in WIDTHS:
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(f"{console_server.url}/dashboard/run/{waiting}")
        expect(page.locator(f"#inline-approval-card-{req_id}")).to_be_visible()
        expect(page.locator('#fence [data-chip="requested"]')).to_be_visible()
        _check(page, "waiting", width, expect_outside=1)

        page.goto(f"{console_server.url}/dashboard/history/{many}")
        expect(page.locator("#run-status")).to_have_attribute("data-state", "completed")
        expect(page.locator('#fence [data-chip="outside-more"]')).to_have_text("+2 more stopped")
        expect(page.locator('#fence [data-chip="inside-more"]')).to_have_text("+3 more")
        _check(page, "many stopped", width, expect_outside=4)
