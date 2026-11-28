"""Playwright checks for Conversations & Inventory views on a trip_planner_outside run."""
from __future__ import annotations

import os
import re
from pathlib import Path
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import (
    NEVER_SAY,
    banned_words_in,
    no_horizontal_scroll,
    save_evidence,
    sign_in,
    start_console_server,
    visible_text_outside_details,
)

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed"),
    pytest.mark.os_layer,
]


@pytest.fixture(scope="module")
def outside_console_server(tmp_path_factory):
    srv = start_console_server(tmp_path_factory.mktemp("console_outside_a2a"))
    yield srv
    srv.stop()


def test_trip_planner_outside_conversations_and_inventory_playwright(
    page: Page, outside_console_server, tmp_path: Path
):
    console_server = outside_console_server
    sign_in(page, console_server)

    # 1. Start a real trip_planner_outside run via Console UI / Run page
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{console_server.url}/dashboard/run")

    preset_btn = page.locator("#preset-trip_planner_outside")
    expect(preset_btn).to_be_visible(timeout=15000)
    preset_btn.click()

    expect(page.locator("#model-selector")).to_contain_text("scripted")
    page.locator("#start-run-btn").click()

    expect(page).to_have_url(re.compile(r"/dashboard/run/(task_[0-9a-f]+)$"), timeout=15000)
    match = re.search(r"/(task_[0-9a-f]+)$", page.url)
    assert match is not None
    task_id = match.group(1)

    status = page.locator("#run-status")
    expect(status).to_have_attribute("data-state", "completed", timeout=60000)

    # 2. Check Conversations page for outside agent marking and card verification status
    page.goto(f"{console_server.url}/dashboard/conversations/{task_id}")
    expect(page.locator("#outside-agents-strip")).to_be_visible(timeout=15000)
    strip = page.locator("#outside-agents-strip")
    expect(strip).to_contain_text("outside agent (A2A)")
    expect(strip).to_contain_text(re.compile(r"signature verified \(key [^)]+\)"))

    # Check desktop layout & zero banned words (plus 'signed')
    text_conv = visible_text_outside_details(page)
    assert banned_words_in(text_conv, NEVER_SAY + ["signed", "securely", "complete"]) == [], text_conv
    assert no_horizontal_scroll(page)

    save_evidence(page, "outside_a2a_conversations_1440")
    shot_dir = os.getenv("OUTSIDE_A2A_SCREENSHOTS")
    if shot_dir:
        Path(shot_dir).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(Path(shot_dir) / "conversations_outside_1440.png"), full_page=True)

    # Check mobile viewport on Conversations page
    page.set_viewport_size({"width": 390, "height": 844})
    page.wait_for_timeout(200)
    assert no_horizontal_scroll(page)
    if shot_dir:
        page.screenshot(path=str(Path(shot_dir) / "conversations_outside_390.png"), full_page=True)

    # 3. Check Inventory page for outside agent card with status and ceiling
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{console_server.url}/dashboard/inventory")
    oa_section = page.locator("#outside-agents-section")
    expect(oa_section).to_be_visible(timeout=15000)
    oa_card = oa_section.locator('[data-outside-agent-card="hostile_partner"]')
    expect(oa_card).to_be_visible(timeout=10000)
    expect(oa_card).to_contain_text("outside agent (A2A)")
    expect(oa_card).to_contain_text("verified")
    expect(oa_card.locator("[data-outside-ceiling]")).to_contain_text("planner")
    expect(oa_card.locator("[data-outside-ceiling]")).to_contain_text("hotel_prices")
    expect(oa_card.locator("[data-outside-ceiling]")).to_contain_text("internal")

    text_inv = visible_text_outside_details(page)
    assert banned_words_in(text_inv, NEVER_SAY + ["signed", "securely", "complete"]) == [], text_inv
    assert no_horizontal_scroll(page)

    save_evidence(page, "outside_a2a_inventory_1440")
    if shot_dir:
        page.screenshot(path=str(Path(shot_dir) / "inventory_outside_1440.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        page.wait_for_timeout(200)
        assert no_horizontal_scroll(page)
        page.screenshot(path=str(Path(shot_dir) / "inventory_outside_390.png"), full_page=True)


def test_outside_agent_refusal_reason_conversations_and_inventory_playwright(
    page: Page, outside_console_server, tmp_path: Path
):
    from demo.security_monitor.app.governance.models import TaskBoundary, TaskLifecycle, TaskRecord
    from demo.security_monitor.app.governance.storage import GovernanceStorage

    console_server = outside_console_server
    storage = GovernanceStorage(console_server.db_path)

    # Register an outside agent with an explicit card signature refusal reason
    storage.save_outside_agent({
        "agent_id": "bad_sig_partner",
        "name": "Bad Sig Partner",
        "description": "External agent with failed signature check.",
        "card_url": "https://partner.example/.well-known/agent-card.json",
        "interface_url": "https://partner.example/",
        "jwk_anchor": {"kty": "OKP", "crv": "Ed25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "kid": "k-pin"},
        "allowed_callers": ["planner"],
        "allowed_skills": ["quote"],
        "max_label": "public",
        "auth_type": "none",
        "card": None,
        "card_hash": None,
        "card_kid": None,
        "card_skills": [],
        "extra_skills": [],
        "status": "refused",
        "failure_reason": "bad signature",
        "verified_at": None,
        "disabled": False,
    })

    tid = "task_oa_refused_pw"
    storage.save_task(TaskRecord(
        task_id=tid,
        request_text="Ask bad_sig_partner for quote",
        request_hash="h_refused",
        agent_id="planner",
        workspace_root=str(tmp_path),
        status=TaskLifecycle.COMPLETED,
        created_at="2026-11-28T10:00:00+00:00",
        root_task_id=tid,
        owner="test_lead_operator",
    ))
    storage.save_boundary(TaskBoundary(task_id=tid, workspace_root=str(tmp_path), peer_agents=["bad_sig_partner"]))
    storage.save_a2a_message({
        "message_id": "msg_refused_pw_1",
        "root_task_id": tid,
        "parent_task_id": tid,
        "child_task_id": None,
        "from_agent": "planner",
        "to_agent": "bad_sig_partner",
        "kind": "request",
        "fanout_group": None,
        "reply_to": None,
        "sent_at": "2026-11-28T10:00:01+00:00",
        "text": "quote please",
        "verdict": "refused",
        "reason": "Outside agent 'bad_sig_partner' card not verified: bad signature",
        "integrity": "trusted",
        "forwarded_from": [],
        "contains_private": False,
        "transport": "a2a_v1",
    })
    storage.flush(tid)

    sign_in(page, console_server)
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{console_server.url}/dashboard/conversations/{tid}")
    strip = page.locator("#outside-agents-strip")
    expect(strip).to_be_visible(timeout=15000)
    expect(strip.locator('[data-outside-agent="bad_sig_partner"]')).to_contain_text("outside agent (A2A)")
    expect(strip.locator('[data-outside-agent="bad_sig_partner"]')).to_contain_text("bad signature")

    page.goto(f"{console_server.url}/dashboard/inventory")
    card = page.locator('[data-outside-agent-card="bad_sig_partner"]')
    expect(card).to_be_visible(timeout=15000)
    expect(card).to_contain_text("outside agent (A2A)")
    expect(card).to_contain_text("refused")
    expect(card).to_contain_text("bad signature")
    expect(card.locator("[data-outside-ceiling]")).to_contain_text("public")
