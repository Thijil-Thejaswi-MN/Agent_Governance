"""M7 differential test: the broker and the kernel take the same decision on every probe.

For every v3 scenario boundary (derived and gold) and for randomised boundaries
(fixed seed), the broker's read and write decisions are compared with the same
read and write performed for real under the compiled Landlock ruleset. See
m7_differential.py for the probe set and the classification of probes.

Set M7_DIFF_PATH=old to run the agreement tests against the frozen M6 path
(BoundaryEvaluator + compile_landlock_rules); they then fail, starting with the
bare alias summary.txt. M7_DIFF_REPORT=<dir> writes each run's JSON report there.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from demo.security_monitor.app.governance import run_manager as rm
from demo.security_monitor.app.governance.catalog import BoundaryDerivationV1

from . import m7_differential as md

pytestmark = pytest.mark.os_layer

PATH = os.environ.get("M7_DIFF_PATH", "new")
RANDOM_SEED = 20261103
RANDOM_N = 200


def _report(rep: md.Report, name: str) -> None:
    print(f"\n[m7-differential] {name}: {json.dumps(rep.summary())}")
    out = os.environ.get("M7_DIFF_REPORT")
    if out:
        Path(out).mkdir(parents=True, exist_ok=True)
        Path(out, f"{name}_{rep.path}.json").write_text(json.dumps(
            {"summary": rep.summary(), "mismatches": rep.mismatches, "residuals": rep.residuals,
             "indeterminate": rep.indeterminates}, indent=1))


def _assert_agree(rep: md.Report) -> None:
    shown = "\n".join(f"  {m['case']}  {m['op']} {m['probe']!r}: broker={m['broker']} kernel={m['kernel']} "
                      f"({m['broker_rule']})" for m in rep.mismatches[:25])
    assert not rep.mismatches, f"{len(rep.mismatches)} of {rep.compared} compared probes disagree:\n{shown}"
    assert rep.compared > 0 and rep.agree == rep.compared


@pytest.mark.timeout(600)
def test_layers_agree_on_every_scenario_boundary(tmp_path: Path) -> None:
    cases = md.scenario_cases(PATH, tmp_path)
    assert len(cases) == 352  # 176 v3 scenarios x (derived, gold)
    rep = md.run_all(cases, tmp_path / "runs", PATH)
    _report(rep, "scenarios")
    _assert_agree(rep)


@pytest.mark.timeout(600)
def test_layers_agree_on_random_boundaries(tmp_path: Path) -> None:
    rep = md.run_all(md.random_cases(RANDOM_N, RANDOM_SEED), tmp_path / "runs", PATH)
    _report(rep, "random")
    _assert_agree(rep)
    # The only excluded disagreement is the declared residual: a sensitive name written
    # beneath a write-glob directory (broker refuses, Landlock cannot exclude one name).
    if PATH == "new":
        assert {(r["probe"], r["op"], r["broker"], r["kernel"]) for r in rep.residuals} <= {("src/.env", "write", "deny", "ok")}


def test_old_path_disagrees_on_the_bare_alias(tmp_path: Path) -> None:
    """The 30 Oct finding, reproduced by the differential harness on the frozen M6 path."""
    prompt = rm.PRESETS["summarise_csv"]["prompt"]
    b = BoundaryDerivationV1().derive(task_id="task_alias_old", request_text=prompt, workspace_root=str(tmp_path))
    case = md.Case("preset_summarise_csv:v1", b, {"input/sales_data.csv": "quarter,revenue\n"})
    old = md.run_all([case], tmp_path / "old", "old")
    rows = {(m["probe"], m["op"]): m for m in old.mismatches}
    assert ("summary.txt", "write") in rows, old.mismatches
    assert (rows["summary.txt", "write"]["broker"], rows["summary.txt", "write"]["kernel"]) == ("allow", "EACCES")
    _report(old, "bare_alias")

    # The same V1 boundary on the M7 path: the alias rule drops the bare name and both layers refuse it.
    b.workspace_root = str(tmp_path)
    case = md.Case("preset_summarise_csv:v1", b, {"input/sales_data.csv": "quarter,revenue\n"})
    new = md.run_all([case], tmp_path / "new", "new")
    _report(new, "bare_alias")
    _assert_agree(new)
