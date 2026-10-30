"""Playwright tests for operator decisions (console v3: Fleet -> Review -> decision card).

1. Seed a running task with a pending request escalated by provenance.
2. Without signing in, Fleet shows the "sign in" state and none of the request data
   (reads need the token header or a session cookie); the request stays PENDING.
3. Signing in through the token modal shows the request under "Needs you" with its plain
   reason; Review opens Watch with the decision card (file name, plain warning, countdown).
4. Allow for this run records APPROVED by operator:<GOVERNANCE_OPERATOR_NAME> and the card goes.
5. Don't allow needs a reason: the button stays disabled until one is typed; the request
   is then DENIED with that reason.
"""
from __future__ import annotations

import time
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.app.governance.models import ExpansionStatus
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.tests.playwright_server import seed_waiting_task

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]


def _sign_in_via_modal(page: Page, token: str) -> None:
    page.locator("#sign-in-btn").click()
    modal = page.locator('div[role="dialog"]')
    expect(modal).to_be_visible()
    expect(modal.locator("#operator-auth-title")).to_contain_text("Operator Authentication")
    modal.locator("#operator-token-input").fill(token)
    modal.locator("#operator-signin-btn").click()
    expect(modal).not_to_be_visible()


def test_review_and_allow_with_and_without_token(page: Page, console_server):
    storage = GovernanceStorage(console_server.db_path)
    task_id, req_id = seed_waiting_task(console_server.db_path, f"appr_{int(time.time() * 1000)}")

    # Not signed in: the sign-in state, and none of the request data.
    page.goto(f"{console_server.url}/dashboard/fleet")
    page.evaluate("sessionStorage.clear()")
    page.reload()
    expect(page.locator("#sign-in-required")).to_be_visible()
    expect(page.locator(f"#needs-you-{req_id}")).to_have_count(0)
    expect(page.locator("body")).not_to_contain_text("quarterly_revenue.csv")
    assert storage.get_expansion_request(req_id).status == ExpansionStatus.PENDING

    _sign_in_via_modal(page, console_server.token)

    row = page.locator(f"#needs-you-{req_id}")
    expect(row).to_be_visible()
    expect(row).to_contain_text("Finance bot wants quarterly_revenue.csv")
    expect(row).to_contain_text("learned of it from inside briefing.txt")
    page.locator(f"#review-{req_id}").click()

    expect(page).to_have_url(f"{console_server.url}/dashboard/run/{task_id}")
    card = page.locator(f"#inline-approval-card-{req_id}")
    expect(card).to_be_visible()
    expect(page.locator("#run-status")).to_have_text("The agent wants one more file.")
    expect(card).to_contain_text("It tried to open quarterly_revenue.csv.")
    expect(card.locator("#decision-warning")).to_have_text(
        "Be careful: it only learned about this file from inside briefing.txt.")
    expect(card.locator("#decision-countdown")).to_contain_text("or it stays blocked.")

    allow = page.locator(f"#inline-approve-btn-{req_id}")
    expect(allow).to_have_text("Allow for this run")
    allow.click()
    expect(card).to_have_count(0)

    final_req = storage.get_expansion_request(req_id)
    assert final_req is not None
    assert final_req.status == ExpansionStatus.APPROVED
    assert final_req.resolved_by == "operator:test_lead_operator"

    # The technical record of the decision is in the drawer.
    page.locator("#show-what-happened").click()
    drawer = page.locator("#details-drawer")
    expect(drawer).to_contain_text("APPROVED")
    expect(drawer).to_contain_text("operator:test_lead_operator")
    expect(drawer).to_contain_text("yes: requested after reading untrusted content")
    expect(drawer.locator("#boundary-version")).to_have_text("Boundary version 2 (after 1 approval)")


def test_dont_allow_requires_a_reason(page: Page, console_server):
    storage = GovernanceStorage(console_server.db_path)
    task_id, req_id = seed_waiting_task(console_server.db_path, f"deny_{int(time.time() * 1000)}")

    page.goto(f"{console_server.url}/dashboard/run/{task_id}")
    page.evaluate("sessionStorage.clear()")
    page.reload()
    _sign_in_via_modal(page, console_server.token)

    card = page.locator(f"#inline-approval-card-{req_id}")
    expect(card).to_be_visible()
    page.locator(f"#deny-btn-{req_id}").click()
    confirm = page.locator("#confirm-deny-btn")
    expect(confirm).to_be_disabled()
    page.locator("#deny-reason-input").fill("   ")
    expect(confirm).to_be_disabled()
    assert storage.get_expansion_request(req_id).status == ExpansionStatus.PENDING

    page.locator("#deny-reason-input").fill("Not needed for a summary")
    expect(confirm).to_be_enabled()
    confirm.click()
    expect(card).to_have_count(0)

    final_req = storage.get_expansion_request(req_id)
    assert final_req.status == ExpansionStatus.DENIED
    assert final_req.reason == "Not needed for a summary"
    assert final_req.resolved_by == "operator:test_lead_operator"
    # Refused: it stays outside the fence.
    expect(page.locator('#fence [data-chip="blocked"]', has_text="quarterly_revenue.csv")).to_be_visible()
