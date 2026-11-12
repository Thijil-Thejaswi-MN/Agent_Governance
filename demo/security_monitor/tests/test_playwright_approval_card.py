"""Approval card: plain preview, risk, provenance warning and the four decisions.

1. A waiting, non-escalated request for docs/minutes.txt shows the name, folder, size
   and "Medium risk"; Always for this agent allows it and saves an allow rule; the page
   says which rule was saved.
2. A request prompted by a file the agent read shows the "Be careful" warning, and
   Always for this agent is disabled with the reason; Allow once marks it single-use.
3. At 390 px the card fits without horizontal scroll.
"""
from __future__ import annotations

import datetime
import time
from pathlib import Path

import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.app.governance.models import (
    ExpansionRequest,
    ExpansionStatus,
    RiskTier,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.tests.playwright_server import (
    OPERATOR_NAME,
    no_horizontal_scroll,
    save_evidence,
    seed_waiting_task,
)

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]


def _seed_plain(db_path: Path, ws: Path, suffix: str) -> tuple[str, str]:
    (ws / "docs").mkdir(parents=True, exist_ok=True)
    (ws / "docs" / "minutes.txt").write_text("m" * 2048)
    storage = GovernanceStorage(db_path)
    now = datetime.datetime.now(datetime.timezone.utc)
    task_id, req_id = f"task_card_{suffix}", f"exp_card_{suffix}"
    storage.save_task(TaskRecord(task_id=task_id, request_text="Summarise the minutes", request_hash="h",
                                 agent_id="minutes_bot", workspace_root=str(ws), status=TaskLifecycle.ACTIVE,
                                 created_at=(now - datetime.timedelta(seconds=30)).isoformat()))
    storage.save_boundary(TaskBoundary(task_id=task_id, workspace_root=str(ws), files_read=["input/request.txt"],
                                       files_write=["output/summary.txt"]))
    storage.save_expansion_request(ExpansionRequest(
        request_id=req_id, task_id=task_id, agent_id="minutes_bot", resource_type="file_read",
        resource_target="docs/minutes.txt", justification="The minutes are needed for the summary",
        baseline_risk_tier=RiskTier.MEDIUM, effective_risk_tier=RiskTier.MEDIUM, escalated_by_provenance=False,
        status=ExpansionStatus.PENDING, created_at=now.isoformat(), timeout_seconds=600))
    storage.record_task_step(task_id, kind="expansion", layer="broker", verdict="PENDING",
                             summary="Expansion access requested for docs/minutes.txt (MEDIUM risk)",
                             source_label="enforced")
    return task_id, req_id


def _sign_in(page: Page, url: str, token: str) -> None:
    page.goto(f"{url}/dashboard/signin")
    page.locator("#operator-token-input").fill(token)
    page.locator("#sign-in-submit-btn").click()
    page.wait_for_url("**/dashboard/run")


def test_card_preview_and_scopes(page: Page, console_server, tmp_path):
    storage = GovernanceStorage(console_server.db_path)
    stamp = str(int(time.time() * 1000))
    task_id, req_id = _seed_plain(console_server.db_path, tmp_path / "ws", stamp)
    _sign_in(page, console_server.url, console_server.token)

    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{console_server.url}/dashboard/run/{task_id}")
    card = page.locator(f"#inline-approval-card-{req_id}")
    expect(card).to_be_visible()
    expect(card.locator("#decision-preview")).to_contain_text("minutes.txt")
    expect(card.locator("#decision-facts")).to_have_text("in docs · 2.0 KB")
    expect(card.locator("#decision-risk")).to_have_text("Medium risk")
    expect(card.locator("#decision-warning")).to_have_count(0)
    for bid in ("inline-approve-btn", "allow-once-btn", "deny-btn", "always-btn"):
        expect(card.locator(f"#{bid}-{req_id}")).to_be_visible()
    expect(card.locator(f"#always-btn-{req_id}")).to_be_enabled()
    save_evidence(page, "approval_card_1440")

    card.locator(f"#always-btn-{req_id}").click()
    expect(card).to_have_count(0)
    after = storage.get_expansion_request(req_id)
    assert after.status == ExpansionStatus.APPROVED and after.resolved_by == f"operator:{OPERATOR_NAME}"
    rules = [r for r in storage.list_standing_rules() if r["target"] == "docs/minutes.txt"]
    assert len(rules) == 1 and rules[0]["agent_or_profile"] == "minutes_bot" and rules[0]["response"] == "allow"
    expect(page.locator("#decision-note")).to_have_text(
        "Rule saved: When minutes_bot asks to read docs/minutes.txt: allow it and log it.")

    # Prompted by a file the agent read: warning shown, no rule possible, Allow once works.
    esc_task, esc_req = seed_waiting_task(console_server.db_path, f"card_{stamp}")
    page.goto(f"{console_server.url}/dashboard/run/{esc_task}")
    esc_card = page.locator(f"#inline-approval-card-{esc_req}")
    expect(esc_card).to_be_visible()
    expect(esc_card.locator("#decision-warning")).to_contain_text("Be careful")
    expect(esc_card.locator(f"#always-btn-{esc_req}")).to_be_disabled()
    expect(esc_card.locator(f"#always-why-{esc_req}")).to_contain_text("always go to a person")
    expect(esc_card.locator("#decision-facts")).to_contain_text("in input")

    page.set_viewport_size({"width": 390, "height": 844})
    expect(esc_card).to_be_visible()
    assert no_horizontal_scroll(page)
    save_evidence(page, "approval_card_390")

    esc_card.locator(f"#allow-once-btn-{esc_req}").click()
    expect(esc_card).to_have_count(0)
    once = storage.get_expansion_request(esc_req)
    assert once.status == ExpansionStatus.APPROVED and once.single_use is True
    assert once.reason == "Allowed once in the console"
