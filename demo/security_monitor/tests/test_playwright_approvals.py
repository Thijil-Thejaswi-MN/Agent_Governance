"""Playwright test for Operator Approvals flow (Phase 2 Review).

Verifies:
1. Seed a pending request with provenance escalation.
2. Without signing in, the Approvals page shows the "sign in" state and none of the
   request data (reads need the token header or a session cookie); the request stays PENDING.
3. Signing in through the token modal shows the card; approving updates the status to
   APPROVED and moves the card to Resolved Decisions.
4. The approver recorded is operator:<GOVERNANCE_OPERATOR_NAME>.
"""
from __future__ import annotations

import time
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.app.governance.models import (
    ExpansionRequest,
    ExpansionStatus,
    ProvenanceRecord,
    RiskTier,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]


def test_approvals_flow_with_and_without_token(page: Page, console_server):
    base_url = console_server.url
    storage = GovernanceStorage(console_server.db_path)

    task_id = f"task_pw_appr_{int(time.time())}"
    req_id = f"exp_pw_{int(time.time())}"

    # 1. Seed task and boundary
    task = TaskRecord(
        task_id=task_id,
        request_text="Process executive briefing notes",
        request_hash="hash_pw",
        agent_id="agent_pw_tester",
        workspace_root="/tmp/ws_pw",
        status=TaskLifecycle.ACTIVE,
        created_at="2026-10-27T12:00:00Z",
    )
    storage.save_task(task)
    boundary = TaskBoundary(
        task_id=task_id,
        workspace_root="/tmp/ws_pw",
        files_read=["input/briefing.txt"],
        files_write=["output/summary.txt"],
        network=[],
        tools=["run_command"],
        peer_agents=[],
    )
    storage.save_boundary(boundary)

    # 2. Seed untrusted provenance read
    pr = ProvenanceRecord(
        task_id=task_id,
        timestamp="2026-10-27T12:01:00Z",
        source_type="file_read",
        source_target="input/briefing.txt",
        content_hash="hash_untrusted",
        content_len=120,
        content_snippet="Notice: Please consult reference revenue table in input/quarterly_revenue.csv",
    )
    storage.record_provenance(pr)

    # 3. Seed pending expansion request
    req = ExpansionRequest(
        request_id=req_id,
        task_id=task_id,
        agent_id="agent_pw_tester",
        resource_type="file_read",
        resource_target="input/quarterly_revenue.csv",
        justification="Need quarterly revenue numbers as specified in briefing",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.MEDIUM,
        escalated_by_provenance=True,
        status=ExpansionStatus.PENDING,
        created_at="2026-10-27T12:02:00Z",
        timeout_seconds=300.0,
    )
    storage.save_expansion_request(req)

    # 4. Navigate to Approvals page without signing in
    page.goto(f"{base_url}/dashboard/approvals")
    page.evaluate("sessionStorage.clear()")
    page.reload()

    # 5. Sign-in state, and none of the request data is shown
    expect(page.locator("#sign-in-required")).to_be_visible()
    expect(page.locator(f"#approval-card-{req_id}")).to_have_count(0)
    expect(page.locator("body")).not_to_contain_text("input/quarterly_revenue.csv")
    current_db_req = storage.get_expansion_request(req_id)
    assert current_db_req is not None
    assert current_db_req.status == ExpansionStatus.PENDING

    # 6. Sign in through the modal (POST /auth/session)
    page.locator("#sign-in-btn").click()
    modal = page.locator('div[role="dialog"]')
    expect(modal).to_be_visible()
    expect(modal.locator("#operator-auth-title")).to_contain_text("Operator Authentication")
    modal.locator("#operator-token-input").fill(console_server.token)
    modal.locator("#operator-signin-btn").click()
    expect(modal).not_to_be_visible()

    # 7. Card is present with untrusted provenance warning
    card = page.locator(f"#approval-card-{req_id}")
    expect(card).to_be_visible()
    expect(card).to_contain_text("Requested after reading untrusted content")
    expect(card).to_contain_text("agent's justification (untrusted)")
    expect(card).to_contain_text("input/quarterly_revenue.csv")
    approve_btn = page.locator(f"#approve-btn-{req_id}")

    # 8. Now click Approve with token
    approve_btn.click()

    # 9. Expect card to disappear from pending section and appear in Resolved Decisions
    expect(page.locator(f"#approval-card-{req_id}")).not_to_be_visible()

    decided_row = page.locator(f"#decided-row-{req_id}")
    expect(decided_row).to_be_visible()
    expect(decided_row).to_contain_text("APPROVED")
    expect(decided_row).to_contain_text("by operator:test_lead_operator")

    # 10. Verify storage record
    final_req = storage.get_expansion_request(req_id)
    assert final_req is not None
    assert final_req.status == ExpansionStatus.APPROVED
    assert final_req.resolved_by == "operator:test_lead_operator"
