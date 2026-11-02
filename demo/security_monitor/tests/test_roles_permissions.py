import pytest
import os
from demo.security_monitor.app.governance.roles import Role, UserSession, PermissionMatrix, authenticate_token, hash_token
from demo.security_monitor.app.governance.inbox import group_pending
from demo.security_monitor.app.governance.scale import layout_mode, is_demo_data_enabled
from demo.security_monitor.app.governance.models import ExpansionRequest, RiskTier, ExpansionStatus
from demo.security_monitor.app.governance.standing_rules import StandingRule, match_rule, is_standing_rules_enabled


def test_permission_matrix_all_cells():
    dev = UserSession(name="Alex", role=Role.DEVELOPER, team="core")
    lead = UserSession(name="Sarah", role=Role.TEAM_LEAD, team="core")
    reviewer = UserSession(name="Morgan", role=Role.SECURITY_REVIEWER, team="sec")
    admin = UserSession(name="Dana", role=Role.ADMIN, team=None)
    auditor = UserSession(name="Riley", role=Role.AUDITOR, team="audit")

    # Start run
    assert PermissionMatrix.can_start_run(dev) is True
    assert PermissionMatrix.can_start_run(lead) is True
    assert PermissionMatrix.can_start_run(reviewer) is False
    assert PermissionMatrix.can_start_run(admin) is True
    assert PermissionMatrix.can_start_run(auditor) is False

    # Stop run
    assert PermissionMatrix.can_stop_run(dev, task_owner="Alex", task_team="core") is True
    assert PermissionMatrix.can_stop_run(dev, task_owner="Other", task_team="core") is False
    assert PermissionMatrix.can_stop_run(lead, task_owner="Other", task_team="core") is True
    assert PermissionMatrix.can_stop_run(lead, task_owner="Other", task_team="other_team") is False
    assert PermissionMatrix.can_stop_run(reviewer, task_owner="Alex", task_team="core") is False
    assert PermissionMatrix.can_stop_run(admin, task_owner="Any", task_team="any") is True
    assert PermissionMatrix.can_stop_run(auditor, task_owner="Any", task_team="any") is False

    # View run
    assert PermissionMatrix.can_view_run(dev, task_owner="Alex", task_team="core") is True
    assert PermissionMatrix.can_view_run(dev, task_owner="Other", task_team="core") is False
    assert PermissionMatrix.can_view_run(lead, task_owner="Other", task_team="core") is True
    assert PermissionMatrix.can_view_run(lead, task_owner="Other", task_team="other_team") is False
    assert PermissionMatrix.can_view_run(reviewer, task_owner="Any", task_team="any") is True
    assert PermissionMatrix.can_view_run(admin, task_owner="Any", task_team="any") is True
    assert PermissionMatrix.can_view_run(auditor, task_owner="Any", task_team="any") is True

    # Approve/deny request
    assert PermissionMatrix.can_decide_request(dev, task_team="core", escalated_by_provenance=False) is False
    assert PermissionMatrix.can_decide_request(lead, task_team="core", escalated_by_provenance=False) is True
    # Team lead cannot approve provenance-escalated requests!
    assert PermissionMatrix.can_decide_request(lead, task_team="core", escalated_by_provenance=True) is False
    assert PermissionMatrix.can_decide_request(lead, task_team="other", escalated_by_provenance=False) is False
    assert PermissionMatrix.can_decide_request(reviewer, task_team="any", escalated_by_provenance=True) is True
    assert PermissionMatrix.can_decide_request(admin, task_team="any", escalated_by_provenance=True) is True
    assert PermissionMatrix.can_decide_request(auditor, task_team="core", escalated_by_provenance=False) is False

    # Batch decisions
    assert PermissionMatrix.can_batch_decide(dev) is False
    assert PermissionMatrix.can_batch_decide(lead) is False
    assert PermissionMatrix.can_batch_decide(reviewer) is True
    assert PermissionMatrix.can_batch_decide(admin) is True
    assert PermissionMatrix.can_batch_decide(auditor) is False

    # Standing rules manage (create/expire)
    assert PermissionMatrix.can_manage_standing_rules(dev) is False
    assert PermissionMatrix.can_manage_standing_rules(lead) is False
    assert PermissionMatrix.can_manage_standing_rules(reviewer) is True
    assert PermissionMatrix.can_manage_standing_rules(admin) is True
    assert PermissionMatrix.can_manage_standing_rules(auditor) is False

    # Standing rules view
    assert PermissionMatrix.can_view_standing_rules(dev) is False
    assert PermissionMatrix.can_view_standing_rules(lead) is False
    assert PermissionMatrix.can_view_standing_rules(reviewer) is True
    assert PermissionMatrix.can_view_standing_rules(admin) is True
    assert PermissionMatrix.can_view_standing_rules(auditor) is True

    # Download / verify records
    assert PermissionMatrix.can_download_or_verify_record(dev, task_owner="Alex", task_team="core") is True
    assert PermissionMatrix.can_download_or_verify_record(dev, task_owner="Other", task_team="core") is False
    assert PermissionMatrix.can_download_or_verify_record(lead, task_owner="Other", task_team="core") is True
    assert PermissionMatrix.can_download_or_verify_record(lead, task_owner="Other", task_team="other") is False
    assert PermissionMatrix.can_download_or_verify_record(reviewer, task_owner="Any", task_team="any") is True
    assert PermissionMatrix.can_download_or_verify_record(admin, task_owner="Any", task_team="any") is True
    assert PermissionMatrix.can_download_or_verify_record(auditor, task_owner="Any", task_team="any") is True


def test_layout_mode_scaling():
    assert layout_mode(0) == "individual"
    assert layout_mode(15) == "individual"
    assert layout_mode(20) == "individual"
    assert layout_mode(21) == "teams"
    assert layout_mode(250) == "teams"
    assert layout_mode(500) == "teams"
    assert layout_mode(501) == "canvas"
    assert layout_mode(2000) == "canvas"


def test_demo_data_flag_off_by_default(monkeypatch):
    monkeypatch.delenv("GOVERNANCE_DEMO_DATA", raising=False)
    assert is_demo_data_enabled() is False


def test_group_pending_requests():
    req1 = ExpansionRequest(
        request_id="exp_1",
        task_id="t1",
        agent_id="bot_a",
        resource_type="file_read",
        resource_target="input/metrics.csv",
        justification="need metrics",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.LOW,
        escalated_by_provenance=False,
        created_at="2026-11-02T10:00:00Z",
    )
    req2 = ExpansionRequest(
        request_id="exp_2",
        task_id="t2",
        agent_id="bot_a",
        resource_type="file_read",
        resource_target="input/metrics.csv",
        justification="also need metrics",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.LOW,
        escalated_by_provenance=False,
        created_at="2026-11-02T10:01:00Z",
    )
    req_escalated = ExpansionRequest(
        request_id="exp_3",
        task_id="t3",
        agent_id="bot_b",
        resource_type="file_read",
        resource_target="input/secret.csv",
        justification="learned from file",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.MEDIUM,
        escalated_by_provenance=True,
        created_at="2026-11-02T10:02:00Z",
    )

    groups = group_pending([req1, req2, req_escalated])
    assert len(groups) == 2

    # Escalated group comes first due to Look closely sort
    esc_group = groups[0]
    assert esc_group["risk_flag"] == "Look closely"
    assert esc_group["escalated_by_provenance"] is True
    assert esc_group["can_batch_allow"] is False
    assert esc_group["count"] == 1

    routine_group = groups[1]
    assert routine_group["risk_flag"] == "Routine"
    assert routine_group["can_batch_allow"] is True
    assert routine_group["count"] == 2
    assert routine_group["request_ids"] == ["exp_1", "exp_2"]


def test_standing_rules_inactive_by_default(monkeypatch):
    monkeypatch.delenv("GOVERNANCE_STANDING_RULES", raising=False)
    assert is_standing_rules_enabled() is False


def test_standing_rules_never_active_during_eval(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_STANDING_RULES", "1")
    monkeypatch.setenv("GOVERNANCE_EVALUATION_ACTIVE", "1")
    assert is_standing_rules_enabled() is False


def test_standing_rules_matching(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_STANDING_RULES", "1")
    monkeypatch.delenv("GOVERNANCE_EVALUATION_ACTIVE", raising=False)
    assert is_standing_rules_enabled() is True

    rule = StandingRule(
        rule_id="rule_1",
        agent_or_profile="finance_bot",
        action="file_read",
        target="input/rates.csv",
        owner="Morgan Reviewer",
        created_at="2026-11-01T10:00:00Z",
        expires_at="2026-12-01T10:00:00Z",
        team="finance",
        is_active=True,
    )

    req_matching = ExpansionRequest(
        request_id="exp_match",
        task_id="t_match",
        agent_id="finance_bot",
        resource_type="file_read",
        resource_target="input/rates.csv",
        justification="rates lookup",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.LOW,
        escalated_by_provenance=False,
        created_at="2026-11-02T10:00:00Z",
    )

    # 1. Matching request matches
    matched = match_rule([rule], req_matching, task_team="finance")
    assert matched is not None
    assert matched.rule_id == "rule_1"

    # 2. Wrong team fails
    assert match_rule([rule], req_matching, task_team="marketing") is None

    # 3. Provenance-escalated request NEVER matches standing rule
    req_escalated = req_matching.model_copy(update={"escalated_by_provenance": True})
    assert match_rule([rule], req_escalated, task_team="finance") is None

    # 4. HIGH risk request NEVER matches standing rule
    req_high = req_matching.model_copy(update={"effective_risk_tier": RiskTier.HIGH})
    assert match_rule([rule], req_high, task_team="finance") is None
