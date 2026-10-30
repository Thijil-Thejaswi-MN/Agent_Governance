"""Plain language on every first screen, at 1440 px and 390 px.

For Home, Ask, Watch (waiting), Done, Fleet and History:
- the visible text outside any Details drawer or panel contains none of the technical
  words (Landlock, seccomp, cgroup, provenance, hash chain, boundary v1/v2, broker, SSE,
  ABI) and none of the words the console never says (safe, secure, guaranteed,
  tamper-proof, first);
- the page has no horizontal scroll.
The technical labels are still there, one click away: the Done drawer shows
'enforced · kernel (Landlock)'. Results may stay technical, but never says the
forbidden words either.

Watch and Done use seeded tasks, so this runs without the OS layer.
"""
from __future__ import annotations

import time
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
    no_horizontal_scroll,
    seed_finished_task,
    seed_waiting_task,
    sign_in,
    visible_text_outside_details,
)

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]


@pytest.fixture(scope="module")
def seeded_ids(console_server):
    stamp = int(time.time() * 1000)
    waiting, req_id = seed_waiting_task(console_server.db_path, f"plain_{stamp}")
    done = seed_finished_task(console_server.db_path, f"plain_{stamp}")
    return {"waiting": waiting, "request": req_id, "done": done}


def _screens(ids):
    return [
        ("home", "/dashboard", "#metric-harm"),
        ("ask", "/dashboard/run", "#start-run-btn"),
        ("watch_waiting", f"/dashboard/run/{ids['waiting']}", f"#inline-approval-card-{ids['request']}"),
        ("done", f"/dashboard/run/{ids['done']}", '#run-status[data-state="completed"]'),
        ("fleet", "/dashboard/fleet", "#fleet-headline"),
        ("history", "/dashboard/history", "#history-list li"),
    ]


@pytest.mark.parametrize("width,height", [(1440, 900), (390, 844)])
def test_first_screens_are_plain(page: Page, console_server, seeded_ids, width, height):
    page.set_viewport_size({"width": width, "height": height})
    sign_in(page, console_server)
    for name, path, ready in _screens(seeded_ids):
        page.goto(f"{console_server.url}{path}")
        expect(page.locator(ready).first).to_be_visible(timeout=15000)
        page.wait_for_timeout(300)
        text = visible_text_outside_details(page)
        assert banned_words_in(text, FIRST_SCREEN_JARGON) == [], f"{name} @ {width}px: {text}"
        assert banned_words_in(text, NEVER_SAY) == [], f"{name} @ {width}px: {text}"
        assert no_horizontal_scroll(page), f"{name} @ {width}px scrolls horizontally"


def test_done_sentence_and_technical_labels_one_click_away(page: Page, console_server, seeded_ids):
    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/run/{seeded_ids['done']}")
    expect(page.locator("#run-status")).to_have_text("Done. 1 attempt was stopped.")
    expect(page.locator("#record-status")).to_have_text("No record was saved for this run.")
    expect(page.locator('#fence [data-chip="blocked"]')).to_have_text("q3_private_notes.txt")
    page.locator("#show-what-happened").click()
    drawer = page.locator("#details-drawer")
    expect(drawer).to_contain_text("enforced · kernel (Landlock)")
    expect(drawer).to_contain_text("Landlock blocked file_read on /home/u/projects/archive/q3_private_notes.txt")
    expect(drawer.locator("#network-marker")).to_have_text("network: none")


def test_history_detail_is_read_only(page: Page, console_server, seeded_ids):
    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/history/{seeded_ids['waiting']}")
    card = page.locator(f"#inline-approval-card-{seeded_ids['request']}")
    expect(card).to_be_visible()
    expect(card).to_contain_text("Open it from Run to decide.")
    expect(card.locator("button")).to_have_count(0)
    expect(page.locator("#stop-run-btn")).to_have_count(0)
    # The full technical timeline, with the stored governance events, is in Details.
    page.locator("#show-what-happened").click()
    expect(page.locator("#details-drawer #event-table")).to_contain_text("input/quarterly_revenue.csv")


def test_results_never_says_forbidden_words(page: Page, console_server):
    page.goto(f"{console_server.url}/dashboard/results")
    expect(page.locator("h1")).to_have_text("Full results")
    expect(page.locator("#utility-timings")).to_contain_text("6.4s")
    expect(page.locator("#utility-timings")).to_contain_text("7.4s")
    assert banned_words_in(page.locator("body").inner_text(), NEVER_SAY) == []
