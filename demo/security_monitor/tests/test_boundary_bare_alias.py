"""Documents current behaviour (not a change): the bare-basename alias in files_write.

For a request naming output/summary.txt, BoundaryDerivationV1 puts both
'output/summary.txt' and the bare 'summary.txt' in files_write (catalog.py: any output/
target, and the bare names summary.txt, summary.md, output.txt, research_notes.txt, are
added as 'output/<name>' plus '<name>').

What each layer then does with a write to <workspace>/summary.txt (the workspace root):
- Kernel layer: compile_landlock_rules skips the bare name as 'bare_alias_of_output_target',
  so there is no Landlock rule for <workspace>/summary.txt and a write to it from inside
  the sandbox (e.g. a shell command) is not permitted; output/summary.txt is (task-owned dir).
- Tool layer: BoundaryEvaluator matches the bare name in files_write, so the broker's
  write_file('summary.txt') is INSIDE and the broker (which runs outside the sandbox)
  writes <workspace>/summary.txt.

So the two layers disagree on this one path: the tool layer allows it, the kernel layer
would not. If the derivation changes, these assertions should change with it.
"""
from __future__ import annotations

import os
from pathlib import Path

from demo.security_monitor.app.governance import run_manager as rm
from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.catalog import BoundaryDerivationV1
from demo.security_monitor.app.governance.evaluator import BoundaryEvaluator
from demo.security_monitor.app.governance.models import EventVerdict
from demo.security_monitor.app.governance.os_layer.sandbox_spec import compile_landlock_rules, is_access_permitted
from demo.security_monitor.app.governance.storage import GovernanceStorage

PRESET_1_PROMPT = rm.PRESETS["summarise_csv"]["prompt"]  # "... write a summary to output/summary.txt."


def _boundary(workspace: Path):
    return BoundaryDerivationV1().derive(task_id="task_alias", request_text=PRESET_1_PROMPT, workspace_root=str(workspace))


def test_v1_derivation_adds_the_bare_basename(tmp_path: Path):
    b = _boundary(tmp_path)
    assert "output/summary.txt" in PRESET_1_PROMPT
    assert b.files_write == ["output/summary.txt", "summary.txt"]
    # The same happens for a bare name in the request.
    bare = BoundaryDerivationV1().derive(task_id="t", request_text="Analyse report.pdf and write summary.txt",
                                         workspace_root=str(tmp_path))
    assert bare.files_write == ["output/summary.txt", "summary.txt"]


def test_landlock_has_no_rule_for_the_bare_alias(tmp_path: Path):
    ws = tmp_path / "ws"
    (ws / "input").mkdir(parents=True)
    (ws / "input" / "sales_data.csv").write_text("quarter,revenue\n")
    spec = compile_landlock_rules(_boundary(ws), ws, proxy_port=None)
    root = Path(os.path.realpath(ws))

    skipped = spec["_compile_report"]["skipped"]
    assert {"pattern": "summary.txt", "reason": "bare_alias_of_output_target"} in skipped
    assert not (root / "summary.txt").exists(), "no placeholder is created for the bare alias"
    assert is_access_permitted(spec, str(root / "summary.txt"), ["write_file"]) is False
    assert is_access_permitted(spec, str(root / "output" / "summary.txt"), ["write_file"]) is True


def test_tool_layer_allows_writing_the_bare_alias_at_the_workspace_root(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    b = _boundary(ws)
    verdict = BoundaryEvaluator().evaluate_file_access(b, "summary.txt", is_write=True)
    assert verdict.verdict == EventVerdict.INSIDE
    assert Path(verdict.resolved_path) == Path(os.path.realpath(ws / "summary.txt"))

    # Through the real broker: the write lands at <workspace>/summary.txt.
    storage = GovernanceStorage(tmp_path / "gov.db")
    from demo.security_monitor.app.governance.intake import TaskIntakeService
    task, boundary = TaskIntakeService(storage).submit_task(PRESET_1_PROMPT, "agent_alias", str(ws))
    assert "summary.txt" in boundary.files_write
    storage.save_token("tok_alias", task.task_id, task.agent_id)
    res = ToolBroker(storage).write_file("tok_alias", "summary.txt", "hello")
    assert os.path.realpath(res["path"]) == os.path.realpath(ws / "summary.txt")
    assert (ws / "summary.txt").read_text() == "hello"
