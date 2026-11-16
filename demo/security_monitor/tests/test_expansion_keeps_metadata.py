"""An approved expansion creates boundary version N+1; it must keep the run's own settings
(the agent's tool limit, the private-file code), or one approval would lift them."""
from __future__ import annotations

from pathlib import Path

from demo.security_monitor.app.governance.evaluator import BoundaryEvaluator
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.storage import GovernanceStorage


def test_approval_keeps_the_tool_limit_and_the_private_file_code(tmp_path: Path) -> None:
    storage = GovernanceStorage(tmp_path / "g.db")
    ws = tmp_path / "ws"
    (ws / "input").mkdir(parents=True)
    (ws / "input" / "contract.txt").write_text("terms")
    task, boundary = TaskIntakeService(storage).submit_task("Summarise input/contract.txt", "brief_bot", str(ws))
    boundary.metadata["agent_tool_limit"] = ["read_file", "request_access", "write_file"]
    boundary.metadata["agent_tool_limit_agent"] = "brief_bot"
    boundary.metadata["canary"] = "CANARY_keep"
    boundary.requires_user_review = False
    storage.save_boundary(boundary)

    exp = ExpansionService(storage, user_approval_hook=lambda req: True)
    ok, _ = exp.request_and_wait(task.task_id, "brief_bot", "file_read", "input/appendix.txt", "the user mentioned it")
    assert ok
    v2 = storage.get_boundary(task.task_id)
    assert v2.version == boundary.version + 1 and "input/appendix.txt" in v2.files_read
    assert v2.metadata["agent_tool_limit"] == ["read_file", "request_access", "write_file"]
    assert v2.metadata["canary"] == "CANARY_keep"
    assert v2.requires_user_review is False
    # Still enforced after the approval: Brief Bot may not use the shell.
    refused = BoundaryEvaluator().evaluate_agent_tool(v2, "run_command")
    assert refused is not None and "brief_bot" in refused.rule_matched
    # The copy is independent: changing v2's settings does not change v1's.
    v2.metadata["agent_tool_limit"].append("run_command")
    assert "run_command" not in storage.get_boundary(task.task_id, version=1).metadata["agent_tool_limit"]
