"""Policies page (standing rules) end to end, on a server started with GOVERNANCE_STANDING_RULES=1.

1. Signed in as the operator (admin), the page says rules are on.
2. Adding a Block rule for one agent and one exact file shows it in plain English.
3. The watcher denies a waiting, non-escalated request for that file, recorded as
   standing_rule:<id> with the owner in the reason.
4. A provenance-escalated request for the same file stays waiting for a person.
5. Switch off marks the rule switched off; no horizontal scroll at 390 px.
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
    banned_words_in,
    no_horizontal_scroll,
    save_evidence,
    start_console_server,
)

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]

AGENT = "notes_bot"
TARGET = "docs/q3_minutes.txt"


@pytest.fixture(scope="module")
def rules_server(tmp_path_factory):
    srv = start_console_server(tmp_path_factory.mktemp("console_rules"), {"GOVERNANCE_STANDING_RULES": "1"})
    yield srv
    srv.stop()


def _seed(db_path, suffix: str, escalated: bool) -> str:
    storage = GovernanceStorage(db_path)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    task_id, req_id = f"task_rules_{suffix}", f"exp_rules_{suffix}"
    storage.save_task(TaskRecord(task_id=task_id, request_text="Summarise the minutes", request_hash="h",
                                 agent_id=AGENT, workspace_root="/tmp/ws_rules", status=TaskLifecycle.ACTIVE,
                                 created_at=now))
    storage.save_boundary(TaskBoundary(task_id=task_id, workspace_root="/tmp/ws_rules"))
    storage.save_expansion_request(ExpansionRequest(
        request_id=req_id, task_id=task_id, agent_id=AGENT, resource_type="file_read", resource_target=TARGET,
        justification="need the minutes", baseline_risk_tier=RiskTier.MEDIUM if not escalated else RiskTier.LOW,
        effective_risk_tier=RiskTier.MEDIUM, escalated_by_provenance=escalated, status=ExpansionStatus.PENDING,
        created_at=now, timeout_seconds=600))
    return req_id


def _sign_in(page: Page, url: str, token: str) -> None:
    page.goto(f"{url}/dashboard/signin")
    page.locator("#operator-token-input").fill(token)
    page.locator("#sign-in-submit-btn").click()
    page.wait_for_url("**/dashboard/run")


def _wait_status(storage: GovernanceStorage, req_id: str, want: ExpansionStatus, seconds: float = 10) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if storage.get_expansion_request(req_id).status == want:
            return
        time.sleep(0.1)
    raise AssertionError(f"{req_id} is {storage.get_expansion_request(req_id).status}, wanted {want}")


def test_block_rule_decides_plain_request_and_leaves_escalated_one(page: Page, rules_server):
    storage = GovernanceStorage(rules_server.db_path)
    _sign_in(page, rules_server.url, rules_server.token)
    page.goto(f"{rules_server.url}/dashboard/standing-rules")

    expect(page.locator("h1")).to_have_text("Policies")
    expect(page.locator("#rules-status")).to_have_attribute("data-enabled", "true")
    expect(page.locator("#rules-empty")).to_be_visible()
    assert banned_words_in(page.locator("main").inner_text(), ["safe", "secure", "guaranteed", "tamper-proof", "first", "complete", "signed"]) == []

    # A pattern is refused in the browser, before anything is sent.
    page.locator("#rule-agent").fill(AGENT)
    page.locator("#rule-target").fill("docs/*.txt")
    page.locator("#rule-save-btn").click()
    expect(page.locator("#rule-problems")).to_contain_text("Patterns such as * are not allowed")

    page.locator("#rule-target").fill(TARGET)
    page.get_by_label("Block").check()
    expect(page.locator("#rule-preview")).to_have_text(f"When {AGENT} asks to read {TARGET}: block it.")
    page.locator("#rule-save-btn").click()

    card = page.locator("#rules-list li").first
    expect(card).to_contain_text(f"When {AGENT} asks to read {TARGET}: block it.")
    expect(card.locator("[data-response]")).to_have_text("Block")
    expect(card).to_contain_text(f"owner {OPERATOR_NAME}")
    rule_id = card.get_attribute("data-rule-id")
    assert rule_id and rule_id.startswith("rule_")
    save_evidence(page, "policies_1440")

    plain = _seed(rules_server.db_path, f"plain_{int(time.time() * 1000)}", escalated=False)
    escalated = _seed(rules_server.db_path, f"esc_{int(time.time() * 1000)}", escalated=True)
    _wait_status(storage, plain, ExpansionStatus.DENIED)
    decided = storage.get_expansion_request(plain)
    assert decided.resolved_by == f"standing_rule:{rule_id}"
    assert decided.reason == f"Blocked by rule {rule_id} (owner {OPERATOR_NAME})"
    time.sleep(1.0)  # several watcher passes
    assert storage.get_expansion_request(escalated).status == ExpansionStatus.PENDING

    page.set_viewport_size({"width": 390, "height": 844})
    page.reload()
    expect(page.locator("#rules-list li").first).to_be_visible()
    assert no_horizontal_scroll(page)
    save_evidence(page, "policies_390")

    page.get_by_role("button", name=f"Switch off rule {rule_id}").click()
    expect(page.locator(f'#rules-list li[data-rule-id="{rule_id}"]')).to_have_attribute("data-state", "switched_off")
