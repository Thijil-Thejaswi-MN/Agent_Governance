"""Console runs: a bare allowed file name is that file, and a call with no path is not an attempt."""
from __future__ import annotations

from pathlib import Path

import pytest

from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.storage import GovernanceStorage


def _setup(tmp_path: Path):
    storage = GovernanceStorage(tmp_path / "g.db")
    ws = tmp_path / "ws"
    (ws / "input").mkdir(parents=True)
    (ws / "output").mkdir()
    (ws / "input" / "sales_1.csv").write_text("amount\n300\n")
    task, boundary = TaskIntakeService(storage).submit_task(
        "Read input/sales_1.csv and write output/summary.txt", "finance_bot", str(ws)
    )
    # The console derives v1.1 boundaries, which have no bare output alias.
    boundary.files_write = ["output/summary.txt"]
    storage.save_boundary(boundary)
    storage.save_token("tok", task.task_id, task.agent_id)
    return storage, task, ToolBroker(storage)


def test_bare_name_reads_the_allowed_file_in_console_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("GOVERNANCE_FRIENDLY_PATHS", "1")
    storage, task, broker = _setup(tmp_path)
    assert broker.read_file("tok", "sales_1.csv") == "amount\n300\n"
    broker.write_file("tok", "summary.txt", "Total amount: 300")
    assert (Path(storage.get_boundary(task.task_id).workspace_root) / "output" / "summary.txt").read_text() == "Total amount: 300"
    assert not [e for e in storage.get_events_for_task(task.task_id) if e.prevented]


def test_missing_path_is_an_error_not_a_blocked_attempt(tmp_path, monkeypatch):
    monkeypatch.setenv("GOVERNANCE_FRIENDLY_PATHS", "1")
    storage, task, broker = _setup(tmp_path)
    with pytest.raises(ValueError, match="needs a file path"):
        broker.read_file("tok", "")
    assert not [e for e in storage.get_events_for_task(task.task_id) if e.prevented]


def test_other_files_are_still_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("GOVERNANCE_FRIENDLY_PATHS", "1")
    _, _, broker = _setup(tmp_path)
    with pytest.raises(PermissionError):
        broker.read_file("tok", "~/projects/archive/q3_private_notes.txt")


def test_evaluation_behaviour_is_unchanged_without_the_flag(tmp_path, monkeypatch):
    monkeypatch.delenv("GOVERNANCE_FRIENDLY_PATHS", raising=False)
    _, _, broker = _setup(tmp_path)
    with pytest.raises(PermissionError):
        broker.read_file("tok", "sales_1.csv")
