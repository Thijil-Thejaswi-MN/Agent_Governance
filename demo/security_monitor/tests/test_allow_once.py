""""Allow once": a waiting request marked single-use before approval uses the existing
single-use code paths (no broker or launcher changes):

- the granted/ copy is removed after the first open the sensor reports, and
- a second read through the broker is refused (the grant is consumed).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.launcher import ExpansionDelivery
from demo.security_monitor.app.governance.models import ExpansionStatus
from demo.security_monitor.app.governance.storage import GovernanceStorage

TARGET = "docs/notes.txt"  # MEDIUM: waits for a person


@pytest.fixture
def world(tmp_path: Path):
    ws = tmp_path / "ws"
    (ws / "docs").mkdir(parents=True)
    (ws / "docs" / "notes.txt").write_text("meeting notes v1\n")
    storage = GovernanceStorage(tmp_path / "gov.db")
    task, _ = TaskIntakeService(storage).submit_task("Summarise the meeting", "agent_once", str(ws))
    token = "tok_allow_once"
    storage.save_token(token, task.task_id, task.agent_id)
    service = ExpansionService(storage, provenance_enabled=False)
    return storage, service, task, token, ws


def _approve(storage: GovernanceStorage, service: ExpansionService, task, once: bool) -> str:
    req = service.evaluate_request(task_id=task.task_id, agent_id=task.agent_id, resource_type="file_read",
                                   resource_target=TARGET, justification="need the notes")
    assert req.status == ExpansionStatus.PENDING
    if once:
        storage.mark_expansion_single_use(req.request_id)
    service.approve_request(req.request_id, approved_by="operator:admin")
    return req.request_id


def test_allow_once_copy_is_gone_after_first_open(world):
    storage, service, task, _, ws = world
    rid = _approve(storage, service, task, once=True)
    assert storage.get_expansion_request(rid).single_use is True
    delivery = ExpansionDelivery(ws, storage)
    out = delivery.deliver(task.task_id, "file_read", TARGET, granted=True)
    copy = ws / "granted" / TARGET
    assert out["type"] == "file_copy" and copy.is_file()
    delivery.on_open(str(copy.resolve()))
    assert not copy.exists()
    rec = delivery.records[-1]
    assert rec["removed_reason"] == "single_use_consumed_after_first_observed_open"


def test_allow_once_second_read_is_refused(world):
    storage, service, task, token, _ = world
    _approve(storage, service, task, once=True)
    broker = ToolBroker(storage, expansion_service=service)
    assert "meeting notes v1" in broker.read_file(token, TARGET)
    with pytest.raises(PermissionError):
        broker.read_file(token, TARGET)


def test_allow_for_this_run_can_be_read_again(world):
    storage, service, task, token, ws = world
    rid = _approve(storage, service, task, once=False)
    assert storage.get_expansion_request(rid).single_use is False
    broker = ToolBroker(storage, expansion_service=service)
    assert "meeting notes v1" in broker.read_file(token, TARGET)
    assert "meeting notes v1" in broker.read_file(token, TARGET)
    delivery = ExpansionDelivery(ws, storage)
    delivery.deliver(task.task_id, "file_read", TARGET, granted=True)
    copy = ws / "granted" / TARGET
    delivery.on_open(str(copy.resolve()))
    assert copy.is_file()


def test_single_use_mark_only_applies_while_waiting(world):
    storage, service, task, _, _ = world
    rid = _approve(storage, service, task, once=False)
    storage.mark_expansion_single_use(rid)  # already approved: no change
    assert storage.get_expansion_request(rid).single_use is False
