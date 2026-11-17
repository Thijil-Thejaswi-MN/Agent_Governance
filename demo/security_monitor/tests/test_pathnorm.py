"""Audit finding A2: "./" handling must not change which file is delivered.

`lstrip("./")` strips characters, so a request for ".reference/target.csv" was shown to the
person under that name but "reference/target.csv" was copied into granted/.
"""
from __future__ import annotations

from pathlib import Path

from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.launcher import ExpansionDelivery
from demo.security_monitor.app.governance.pathnorm import strip_dot_slash
from demo.security_monitor.app.governance.storage import GovernanceStorage


def test_only_whole_dot_slash_segments_are_removed() -> None:
    assert strip_dot_slash("./input/a.csv") == "input/a.csv"
    assert strip_dot_slash("././input/a.csv") == "input/a.csv"
    assert strip_dot_slash(".reference/a.csv") == ".reference/a.csv"
    assert strip_dot_slash(".ssh/id_rsa") == ".ssh/id_rsa"
    assert strip_dot_slash("..hidden/x") == "..hidden/x"


def test_the_approved_name_is_the_delivered_file(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    for d in (".reference", "reference"):
        (ws / d).mkdir(parents=True)
    (ws / ".reference" / "target.csv").write_text("the approved file\n")
    (ws / "reference" / "target.csv").write_text("a different file\n")
    storage = GovernanceStorage(tmp_path / "g.db")
    task, _ = TaskIntakeService(storage).submit_task("Summarise the notes", "agent_p", str(ws))
    svc = ExpansionService(storage, provenance_enabled=False)
    req = svc.evaluate_request(task.task_id, task.agent_id, "file_read", ".reference/target.csv", "needed")
    svc.approve_request(req.request_id, approved_by="operator:admin")

    out = ExpansionDelivery(ws, storage).deliver(task.task_id, "file_read", ".reference/target.csv", granted=True)
    assert out["type"] == "file_copy", out
    assert out["delivered_path"] == "granted/.reference/target.csv"
    assert (ws / "granted" / ".reference" / "target.csv").read_text() == "the approved file\n"
    assert not (ws / "granted" / "reference").exists()
