"""Standing-rule watcher (Console v4).

Decides waiting approval requests that match a standing rule, the same way a person
clicking Allow or Block would: through ExpansionService.approve_request / deny_request.
It sits outside the tool broker and changes no enforcement: Landlock, seccomp, the
launcher and the broker's own decisions are untouched.

Guarantees:
- Off unless GOVERNANCE_STANDING_RULES=1, and always off during evaluations
  (standing_rules.is_standing_rules_enabled).
- Never decides HIGH risk or provenance-escalated requests; those always wait for a person.
- Every decision is recorded with the rule ID and its owner.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Callable

from .models import ExpansionStatus
from .standing_rules import (
    StandingRule,
    is_high_risk_or_escalated,
    is_standing_rules_enabled,
    pick_rule,
)

log = logging.getLogger(__name__)

RULE_DECIDER_PREFIX = "standing_rule:"


def rule_decider(rule: StandingRule) -> str:
    return f"{RULE_DECIDER_PREFIX}{rule.rule_id}"


def rule_reason(rule: StandingRule) -> str:
    verb = "Allowed and logged" if rule.response == "allow" else "Blocked"
    return f"{verb} by rule {rule.rule_id} (owner {rule.owner})"


def decide_with_rules(storage: Any, service: Any, rules: list[StandingRule]) -> list[dict[str, Any]]:
    """One pass over the waiting requests. Returns what was decided (empty when rules are off)."""
    if not is_standing_rules_enabled():
        return []
    decided: list[dict[str, Any]] = []
    for req in storage.list_expansion_requests(status=ExpansionStatus.PENDING.value):
        if is_high_risk_or_escalated(req):
            continue  # always a person's decision
        task = storage.get_task(req.task_id)
        rule = pick_rule(rules, req, task_team=task.team if task else None)
        if rule is None or rule.response == "ask":
            continue
        # A person may have decided it in the meantime.
        current = storage.get_expansion_request(req.request_id)
        if current is None or current.status != ExpansionStatus.PENDING:
            continue
        if rule.response == "allow":
            service.approve_request(req.request_id, approved_by=rule_decider(rule), reason=rule_reason(rule))
            outcome = "APPROVED"
        else:
            service.deny_request(req.request_id, denied_by=rule_decider(rule), reason=rule_reason(rule))
            outcome = "DENIED"
        decided.append({
            "request_id": req.request_id,
            "task_id": req.task_id,
            "rule_id": rule.rule_id,
            "owner": rule.owner,
            "status": outcome,
        })
    return decided


class StandingRuleWatcher:
    """Background thread that runs decide_with_rules every `interval` seconds."""

    def __init__(
        self,
        get_storage: Callable[[], Any],
        get_service: Callable[[], Any],
        get_rules: Callable[[], list[StandingRule]],
        interval: float = 0.25,
    ) -> None:
        self._get_storage = get_storage
        self._get_service = get_service
        self._get_rules = get_rules
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self) -> list[dict[str, Any]]:
        rules = [r for r in self._get_rules() if r.is_active]
        if not rules:
            return []
        return decide_with_rules(self._get_storage(), self._get_service(), rules)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.run_once()
            except Exception:  # keep watching; a person can still decide
                log.exception("standing-rule watcher pass failed")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="standing-rule-watcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None
