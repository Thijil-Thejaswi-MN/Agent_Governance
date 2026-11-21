"""Policy decisions against expected values written by hand (independent audit #2, F-10).

test_policy_sim.py checks that the simulator and the live path agree. Both call
ExpansionService.assess_request, so that comparison cannot catch a wrong rule in the shared
code. The tables here state what the policy is meant to decide, independent of the code:
risk tiers, provenance escalation, team scoping of standing rules (F-08), rule precedence
and target normalisation.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.models import ExpansionRequest, ExpansionStatus, RiskTier
from demo.security_monitor.app.governance.policy_sim import PolicySimulator
from demo.security_monitor.app.governance.standing_rules import StandingRule, match_rule, pick_rule
from demo.security_monitor.app.governance.storage import GovernanceStorage

UTC = dt.timezone.utc
L, M, H = RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH

# --- risk tiers -----------------------------------------------------------------------------

RISK = [
    # reads
    ("file_read", "input/data.csv", L),
    ("file_read", "input/sub/notes.txt", L),
    ("file_read", "docs/notes.txt", M),
    ("file_read", "reference/policy.pdf", M),
    ("file_read", "/etc/passwd", H),
    ("file_read", "../outside.txt", H),
    ("file_read", "input/../../x", H),
    ("file_read", "C:/Users/x.txt", H),
    ("file_read", ".ssh/id_rsa", H),
    ("file_read", "home/.aws/config", H),
    ("file_read", "input/.env", H),
    ("file_read", "input/db_password.txt", H),
    ("file_read", "input/server.key", H),
    ("file_read", "input/vault.kdbx", H),
    ("file_read", "input\\secret.txt", H),
    # writes
    ("file_write", "output/summary.txt", M),
    ("file_write", "output/x", M),
    ("file_write", "OUTPUT/x", H),
    ("file_write", "Output/x", H),
    ("file_write", "input/data.csv", H),
    ("file_write", "docs/notes.txt", H),
    ("file_write", "output/credentials.txt", H),
    # network and peers
    ("network", "127.0.0.1:8080", M),
    ("network", "localhost:9000", M),
    ("network", "internal.reports:443", M),
    ("network", "api.example.com:443", H),
    ("network", "169.254.169.254:80", H),
    ("peer_agent", "agent_bob", M),
]


@pytest.mark.parametrize("rtype,target,tier", RISK)
def test_risk_tier(rtype: str, target: str, tier: RiskTier) -> None:
    assert ExpansionService.classify_resource_risk(rtype, target) == tier


@pytest.mark.parametrize("rtype,target", [("file_read", ""), ("file_read", "   "), ("", "input/a.txt")])
def test_empty_requests_are_refused(rtype: str, target: str) -> None:
    with pytest.raises(ValueError):
        ExpansionService.classify_resource_risk(rtype, target)


# --- outcome of an agent's request (no standing rules) ---------------------------------------

REQUEST_TEXT = "Read input/notes.txt and write output/summary.txt"

# (resource_type, target, untrusted reads before it) -> (outcome, baseline, effective, escalated)
OUTCOMES = [
    ("file_read", "input/payroll.csv", 0, ("allow", L, L, False)),
    ("file_read", "docs/notes.txt", 0, ("ask", M, M, False)),
    ("file_read", "input/payroll.csv", 1, ("ask", L, M, True)),
    ("file_read", "docs/notes.txt", 1, ("deny", M, H, True)),
    ("file_read", ".ssh/id_rsa", 0, ("deny", H, H, False)),
    ("file_write", "output/extra.txt", 0, ("ask", M, M, False)),
    ("file_write", "input/notes.txt", 0, ("deny", H, H, False)),
    ("network", "127.0.0.1:8080", 0, ("ask", M, M, False)),
    ("network", "api.example.com:443", 0, ("deny", H, H, False)),
    ("peer_agent", "agent_bob", 0, ("ask", M, M, False)),
    ("peer_agent", "agent_bob", 1, ("deny", M, H, True)),
    # The user's own request names this file: an untrusted read does not raise it.
    ("file_read", "input/notes.txt", 1, ("allow", L, L, False)),
    ("file_read", "input/*", 0, ("deny", None, None, None)),
]


def _task(tmp_path: Path):
    storage = GovernanceStorage(tmp_path / "g.db")
    ws = tmp_path / "ws"
    for d in ("input", "output"):
        (ws / d).mkdir(parents=True)
    task, boundary = TaskIntakeService(storage).submit_task(REQUEST_TEXT, "notes_bot", str(ws))
    return storage, task, boundary


def _reads(storage, task, n: int) -> list:
    svc = ExpansionService(storage)
    for i in range(n):
        svc.record_untrusted_read(task.task_id, "file_read", f"input/r{i}.txt", "some text")
    return storage.get_provenance_for_task(task.task_id)


@pytest.mark.parametrize("rtype,target,reads,expected", OUTCOMES)
def test_request_outcome(tmp_path: Path, rtype, target, reads, expected) -> None:
    storage, task, boundary = _task(tmp_path)
    reads_list = _reads(storage, task, reads)
    d = PolicySimulator(rules_enabled=False).access_request(
        boundary, REQUEST_TEXT, rtype, target, untrusted_reads=reads_list)
    outcome, base, eff, esc = expected
    assert d["outcome"] == outcome, d
    if base is not None:
        assert (d["baseline_risk"], d["effective_risk"], d["escalated_by_provenance"]) == (base.value, eff.value, esc)
    # The live path reaches the same status (a person is asked for "ask").
    if base is not None:
        live = ExpansionService(storage).evaluate_request(task.task_id, task.agent_id, rtype, target, "needed")
        status = {"allow": ExpansionStatus.APPROVED, "deny": ExpansionStatus.DENIED, "ask": ExpansionStatus.PENDING}
        assert live.status == status[outcome]


# --- standing rules: team scope, precedence, normalisation ----------------------------------

def _rule(rid: str, response: str = "allow", target: str = "docs/notes.txt", *, team: str | None = None,
          agent: str = "*", action: str = "file_read", hours: float = 24) -> StandingRule:
    now = dt.datetime.now(UTC)
    return StandingRule(rule_id=rid, agent_or_profile=agent, action=action, target=target, owner="asha",
                        created_at=now.isoformat(), expires_at=(now + dt.timedelta(hours=hours)).isoformat(),
                        team=team, response=response)


def _pending(target: str = "docs/notes.txt", *, tier: RiskTier = M, escalated: bool = False,
             action: str = "file_read", agent: str = "notes_bot") -> ExpansionRequest:
    return ExpansionRequest(
        request_id="exp_x", task_id="t", agent_id=agent, resource_type=action, resource_target=target,
        justification="j", baseline_risk_tier=tier if not escalated else M, effective_risk_tier=tier,
        escalated_by_provenance=escalated, status=ExpansionStatus.PENDING,
        created_at=dt.datetime.now(UTC).isoformat())


@pytest.mark.parametrize("rule_team,task_team,matches", [
    (None, None, True),
    (None, "core", True),
    ("core", "core", True),
    ("core", "other", False),
    ("core", None, False),  # F-08: a team rule never matches a task without a team
])
def test_team_scope(rule_team, task_team, matches) -> None:
    got = match_rule([_rule("r", team=rule_team)], _pending(), task_team=task_team, force_enabled=True)
    assert (got is not None) == matches


@pytest.mark.parametrize("order", [("allow", "ask", "block"), ("block", "allow", "ask"), ("ask", "allow", "block")])
def test_strictest_rule_wins_whatever_the_order(order) -> None:
    rules = [_rule(f"r_{r}", r) for r in order]
    assert pick_rule(rules, _pending(), force_enabled=True).response == "block"
    rules = [_rule(f"r_{r}", r) for r in order if r != "block"]
    assert pick_rule(rules, _pending(), force_enabled=True).response == "ask"


@pytest.mark.parametrize("req", [
    _pending(tier=H),
    _pending(tier=H, escalated=True),
    _pending(tier=M, escalated=True),
], ids=["high", "high_escalated", "escalated"])
def test_no_rule_decides_high_risk_or_escalated(req) -> None:
    rules = [_rule("r_allow", "allow"), _rule("r_block", "block")]
    assert pick_rule(rules, req, force_enabled=True) is None


def test_rules_that_do_not_apply() -> None:
    req = _pending()
    assert match_rule([_rule("r", hours=-1)], req, force_enabled=True) is None              # expired
    assert match_rule([_rule("r", agent="other_bot")], req, force_enabled=True) is None     # other agent
    assert match_rule([_rule("r", action="file_write")], req, force_enabled=True) is None   # other action
    assert match_rule([_rule("r", target="docs/notes.txt.bak")], req, force_enabled=True) is None
    assert match_rule([_rule("r", target="docs")], req, force_enabled=True) is None          # no prefixes
    inactive = _rule("r")
    inactive.is_active = False
    assert match_rule([inactive], req, force_enabled=True) is None
    assert match_rule([_rule("r", agent="notes_bot")], req, force_enabled=True) is not None


@pytest.mark.parametrize("rule_target,req_target,matches", [
    ("docs/notes.txt", "./docs/notes.txt", True),
    ("./docs/notes.txt", "docs/notes.txt", True),
    ("docs\\notes.txt", "docs/notes.txt", True),
    ("docs/notes.txt", " docs/notes.txt ", True),
    (".docs/notes.txt", "docs/notes.txt", False),  # a leading dot is part of the name
    ("docs/Notes.txt", "docs/notes.txt", False),   # exact, case-sensitive
])
def test_target_normalisation(rule_target, req_target, matches) -> None:
    got = match_rule([_rule("r", target=rule_target)], _pending(req_target), force_enabled=True)
    assert (got is not None) == matches


def test_rules_are_off_unless_enabled(monkeypatch) -> None:
    monkeypatch.delenv("GOVERNANCE_STANDING_RULES", raising=False)
    assert pick_rule([_rule("r")], _pending()) is None
    monkeypatch.setenv("GOVERNANCE_STANDING_RULES", "1")
    assert pick_rule([_rule("r")], _pending()) is not None
