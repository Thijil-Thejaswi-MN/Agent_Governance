"""M7: one resolved boundary compiled into both enforcement layers.

Unit tests for resolve_boundary (alias rule, canonicalisation, globs, grants),
the resolved Landlock compiler, the derivation v1.1 switch, and which path each
entry point selects. The frozen M6 path stays the default (TaskSpec, harness).
"""
from __future__ import annotations

import datetime
import os
import subprocess
from pathlib import Path

import pytest

from demo.security_monitor.app.governance import run_manager as rm
from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.catalog import BoundaryDerivationV1, BoundaryDerivationV1_1
from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec
from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    EventVerdict,
    ExpansionRequest,
    ExpansionStatus,
    RiskTier,
    TaskBoundary,
)
from demo.security_monitor.app.governance.os_layer.sandbox_spec import (
    compile_landlock_rules_resolved,
    is_access_permitted,
    write_rules_file,
)
from demo.security_monitor.app.governance.resolved_boundary import (
    ResolvedBoundaryEvaluator,
    approved_file_grants,
    resolve_boundary,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage

ENFORCER = Path(__file__).resolve().parents[1] / "app/governance/os_layer/landlock_enforcer"
PRESET_PROMPT = rm.PRESETS["summarise_csv"]["prompt"]


def _ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    for d in ("input/sub", "output", "scratch", "granted", "tmp", "runtime", "src"):
        (ws / d).mkdir(parents=True, exist_ok=True)
    for rel in ("input/data.csv", "input/other.csv", "input/sub/deep.csv", "input/.env", "src/main.py"):
        (ws / rel).write_text("x\n")
    return Path(os.path.realpath(ws))


def _b(ws: Path, reads: list[str], writes: list[str], task_id: str = "task_m7") -> TaskBoundary:
    return TaskBoundary(task_id=task_id, workspace_root=str(ws), files_read=reads, files_write=writes)


def _paths(r) -> dict[str, tuple[str, list[str]]]:
    return {os.path.relpath(e.path, r.workspace): (e.kind, sorted(e.access)) for e in r.entries}


# --- derivation v1.1 -------------------------------------------------------

def test_v1_1_drops_only_the_bare_output_alias(tmp_path: Path) -> None:
    v1 = BoundaryDerivationV1().derive(task_id="t", request_text=PRESET_PROMPT, workspace_root=str(tmp_path))
    v11 = BoundaryDerivationV1_1().derive(task_id="t", request_text=PRESET_PROMPT, workspace_root=str(tmp_path))
    assert v1.files_write == ["output/summary.txt", "summary.txt"] and v1.derived_by == "template_v1"
    assert v11.files_write == ["output/summary.txt"] and v11.derived_by == "template_v1_1"
    assert v11.model_dump(exclude={"files_write", "derived_by"}) == v1.model_dump(exclude={"files_write", "derived_by"})
    for prompt in ("Analyse report.pdf and write summary.txt", "Research the web and take notes"):
        b = BoundaryDerivationV1_1().derive(task_id="t", request_text=prompt, workspace_root=str(tmp_path))
        assert all("/" in w for w in b.files_write), b.files_write
    # A bare write target without an output/ twin is not an alias and is kept.
    b = BoundaryDerivationV1_1().derive(task_id="t", request_text="Summarise input/a.csv", workspace_root=str(tmp_path),
                                        output_targets=["notes.md"])
    assert "notes.md" in b.files_write


def test_v1_1_narrows_code_write_globs_to_named_files(tmp_path: Path) -> None:
    prompt = "Fix the bug in src/app.py and write a summary to output/summary.txt"
    v1 = BoundaryDerivationV1().derive(task_id="t", request_text=prompt, workspace_root=str(tmp_path))
    v11 = BoundaryDerivationV1_1().derive(task_id="t", request_text=prompt, workspace_root=str(tmp_path))
    assert {"src/**", "tests/**"} <= set(v1.files_write)
    # src/ names a file, so its glob becomes that file; tests/ names none, so its glob stays.
    assert v11.files_write == ["output/summary.txt", "src/app.py", "tests/**"]
    assert v11.files_read == v1.files_read
    # The per-file rule closes the sensitive-name gap of the directory rule in both layers.
    ws = tmp_path / "ws"
    (ws / "src").mkdir(parents=True)
    (ws / "src/app.py").write_text("x = 1\n")
    v11.workspace_root = str(ws)
    r = resolve_boundary(v11, ws)
    assert not r.allows(str(ws / "src/.env"), "create")[0] and not r.allows(str(ws / "src/new.py"), "create")[0]
    assert r.allows(str(ws / "src/app.py"), "write")[0]
    spec = compile_landlock_rules_resolved(r, None)
    assert not any(x["path"].startswith(str(ws / "src")) for x in spec["_compile_report"]["kernel_cannot_express"])
    # With no file named, the glob is the only rule available and is kept.
    b = BoundaryDerivationV1_1().derive(task_id="t", request_text="Refactor the code", workspace_root=str(tmp_path))
    assert "src/**" in b.files_write


# --- resolve_boundary ------------------------------------------------------

def test_alias_rule_collapses_bare_names_into_the_scoped_entry(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    r = resolve_boundary(_b(ws, ["input/data.csv", "data.csv"], ["output/summary.txt", "summary.txt", "notes.md"]))
    p = _paths(r)
    assert "summary.txt" not in p and "data.csv" not in p
    assert p["output/summary.txt"] == ("file", ["create", "read", "write"])
    assert p["input/data.csv"] == ("file", ["read"])
    assert p["notes.md"] == ("file", ["create", "read", "write"])  # no output/notes.md twin: its own path
    assert ("summary.txt", "bare_alias_of:output/summary.txt") in r.skipped
    assert ("data.csv", "bare_alias_of:input/data.csv") in r.skipped
    assert p["output"] == ("dir", ["read"]) and p["granted"] == ("dir", ["read"])
    assert "scratch" not in p


def test_entries_must_be_canonical_paths_inside_the_workspace(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    os.symlink("../input/data.csv", ws / "output/link.csv")
    os.symlink(str(tmp_path), ws / "input/up")
    (tmp_path / "secret.txt").write_text("s")
    writes = ["../escape.txt", "/etc/passwd", str(ws / "output/abs.txt"), "./output/a.txt", "output//b.txt",
              "output/../input/data.csv", "tmp/x", "granted/x", "runtime/x", "broker.sock", "output/link.csv",
              "input/up/secret.txt", "input/data.csv/x", "*", "**", "output"]
    r = resolve_boundary(_b(ws, ["input/up/secret.txt", "input", "input/missing.csv"], writes))
    assert set(_paths(r)) == {"output", "granted"}
    reasons = dict(r.skipped)
    assert reasons["../escape.txt"] == "dotdot_component"
    assert reasons["/etc/passwd"] == "absolute_entry"
    assert reasons["./output/a.txt"] == "non_canonical_spelling"
    assert reasons["tmp/x"] == reasons["granted/x"] == reasons["broker.sock"] == "reserved_runtime_path"
    assert reasons["output/link.csv"] == "symlink_in_path"
    assert reasons["input/data.csv/x"] == "parent_not_a_directory"
    assert reasons["*"] == "glob_without_directory_prefix"
    assert reasons["output"] == "directory_named_in_files_write"
    assert reasons["input"] == "directory_named_in_files_read"
    assert reasons["input/missing.csv"] == "not_present_at_resolve"


def test_globs(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    os.symlink(str(tmp_path / "outside.txt"), ws / "input/link_out.txt")
    (tmp_path / "outside.txt").write_text("o")
    (ws / "output/a.txt").write_text("a")
    r = resolve_boundary(_b(ws, ["input/*"], ["src/**", "output/*.txt", "output/*.md"]))
    p = _paths(r)
    # Read globs: regular files present now, no sensitive names, no symlinks.
    assert {k for k in p if k.startswith("input/")} == {"input/data.csv", "input/other.csv", "input/sub/deep.csv"}
    assert p["src"] == ("dir", ["create", "read", "remove", "write"])
    assert p["output/a.txt"] == ("file", ["read", "write"])  # narrowed, no create
    assert ("output/*.md", "glob_matched_no_files_at_resolve") in r.skipped
    ok = lambda rel, a: r.allows(str(ws / rel), a)[0]  # noqa: E731
    assert ok("src/new/mod.py", "create") and ok("src/main.py", "remove")
    assert not ok("src/.env", "create") and ok("src/.env", "read")  # sensitive-name write exclusion (broker only)
    assert not ok("output/b.txt", "create")


def test_tool_layer_verdicts(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    r = resolve_boundary(_b(ws, ["input/data.csv"], ["output/summary.txt", "summary.txt"]))
    v = lambda p, w: r.evaluate(p, w).verdict  # noqa: E731
    assert v("output/summary.txt", True) == EventVerdict.INSIDE
    assert v(str(ws / "output/summary.txt"), True) == EventVerdict.INSIDE
    assert v("summary.txt", True) == EventVerdict.OUTSIDE
    assert v("OUTPUT/SUMMARY.TXT", True) == EventVerdict.OUTSIDE  # case-sensitive, like the kernel
    assert v("output/other.txt", True) == EventVerdict.OUTSIDE
    assert v("output/other.txt", False) == EventVerdict.INSIDE
    assert v("input/../input/data.csv", False) == EventVerdict.INSIDE
    assert v("scratch/x.txt", True) == EventVerdict.OUTSIDE
    assert r.evaluate("../x", False).risk_tier == RiskTier.HIGH
    assert r.evaluate("input/.env", False).risk_tier == RiskTier.HIGH
    assert r.evaluate("input/other.csv", False).risk_tier == RiskTier.MEDIUM


def _approve(storage: GovernanceStorage, task_id: str, rtype: str, target: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    storage.save_expansion_request(ExpansionRequest(
        request_id=f"exp_{rtype}_{abs(hash(target))}", task_id=task_id, agent_id="a", resource_type=rtype,
        resource_target=target, justification="j", baseline_risk_tier=RiskTier.LOW, effective_risk_tier=RiskTier.LOW,
        status=ExpansionStatus.APPROVED, created_at=now, resolved_at=now, resolved_by="human_user"))


def test_grants_resolve_to_the_delivered_copy(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws / "input/appendix.txt").write_text("a")
    (ws / "granted/input").mkdir()
    (ws / "granted/input/appendix.txt").write_text("a")
    storage = GovernanceStorage(tmp_path / "g.db")
    v1 = _b(ws, ["input/data.csv"], ["output/summary.txt"])
    storage.save_boundary(v1)
    v2 = v1.model_copy(deep=True)
    v2.version = 2
    v2.files_read += ["input/appendix.txt", "input/other.csv"]
    v2.files_write += ["output/extra.txt"]
    storage.save_boundary(v2)
    for rtype, t in (("file_read", "input/appendix.txt"), ("file_write", "output/extra.txt"), ("file_read", "input/data.csv")):
        _approve(storage, v1.task_id, rtype, t)
    # input/data.csv was already in v1: re-approving it is not a grant.
    assert approved_file_grants(storage, v1.task_id) == [("file_read", "input/appendix.txt"), ("file_write", "output/extra.txt")]
    ev = ResolvedBoundaryEvaluator(storage)
    r = ev.resolve(v2)
    assert ev.evaluate_file_access(v2, "input/appendix.txt", False).verdict == EventVerdict.OUTSIDE
    assert ev.evaluate_file_access(v2, "granted/input/appendix.txt", False).verdict == EventVerdict.INSIDE
    assert ev.evaluate_file_access(v2, "output/extra.txt", True).verdict == EventVerdict.OUTSIDE
    assert ev.evaluate_file_access(v2, "input/data.csv", False).verdict == EventVerdict.INSIDE
    assert ev.evaluate_file_access(v2, "input/other.csv", False).verdict == EventVerdict.INSIDE  # added, not approved-as-grant
    assert ("output/extra.txt", "write_grant_not_enforceable_in_kernel") in r.skipped


# --- resolved Landlock compiler -------------------------------------------

def test_resolved_compiler_rules(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    b = BoundaryDerivationV1().derive(task_id="t", request_text=PRESET_PROMPT, workspace_root=str(ws))
    spec = compile_landlock_rules_resolved(resolve_boundary(b), None, runtime_dir=ws / "runtime")
    rules = {r["path"]: sorted(r["access"]) for r in spec["rules"]}
    assert (ws / "output/summary.txt").is_file()  # pre-created write target
    assert rules[str(ws / "output/summary.txt")] == ["read_file", "truncate", "write_file"]
    assert rules[str(ws / "output")] == ["read_dir", "read_file"]
    assert str(ws / "summary.txt") not in rules and not (ws / "summary.txt").exists()
    assert str(ws / "scratch") not in rules
    assert is_access_permitted(spec, str(ws / "summary.txt"), ["write_file"]) is False
    assert is_access_permitted(spec, str(ws / "output/other.txt"), ["make_reg"]) is False
    assert is_access_permitted(spec, str(ws / "tmp/x"), ["write_file"]) is True  # kernel-only runtime support
    report = spec["_compile_report"]
    assert report["compiler"] == "resolved"
    assert {"pattern": "summary.txt", "reason": "bare_alias_of:output/summary.txt"} in report["skipped"]
    assert write_rules_file(spec, tmp_path / "rules.json").read_text().count("_compile_report") == 0


# --- path selection --------------------------------------------------------

def test_frozen_path_is_the_default_and_v1_1_is_opt_in(tmp_path: Path) -> None:
    from demo.security_monitor import evaluate_v3
    assert TaskSpec(prompt="p").boundary_model == "v1"
    src = Path(evaluate_v3.__file__).read_text()
    assert 'ap.add_argument("--boundary-model", choices=["v1", "v1.1"], default="v1"' in src
    launcher = TaskLauncher(GovernanceStorage(tmp_path / "g.db"), workspace_base=tmp_path)
    _, b1 = launcher.derive_boundary(TaskSpec(prompt=PRESET_PROMPT, task_id="task_a"), tmp_path / "ws", EnforcementMode.ENFORCE)
    _, b2 = launcher.derive_boundary(TaskSpec(prompt=PRESET_PROMPT, task_id="task_b", boundary_model="v1.1"),
                                     tmp_path / "ws", EnforcementMode.ENFORCE)
    assert b1.derived_by == "template_v1" and "summary.txt" in b1.files_write
    assert b2.derived_by == "template_v1_1" and "summary.txt" not in b2.files_write


def test_run_page_preview_shows_the_enforced_v1_1_boundary() -> None:
    data = rm.preview_run_boundary(PRESET_PROMPT)
    assert data["enforced_derivation"] == "template_v1_1"
    assert data["boundary_v1"]["files_write"] == ["output/summary.txt"]


def test_run_page_and_cli_select_v1_1() -> None:
    src = Path(rm.__file__).read_text()
    assert 'boundary_model="v1.1"' in src
    from demo.security_monitor.app.governance import launcher as ln
    assert 'spec.boundary_model = "v1.1"' in Path(ln.__file__).read_text()


# --- end to end on the M7 path (real broker, real Landlock) ----------------

@pytest.mark.os_layer
def test_bare_alias_refused_by_both_layers_on_the_m7_path(tmp_path: Path) -> None:
    from demo.security_monitor.app.governance.intake import TaskIntakeService
    ws = _ws(tmp_path)
    (ws / "input/sales_data.csv").write_text("quarter,revenue\n")
    storage = GovernanceStorage(tmp_path / "gov.db")
    # A V1 boundary (with the bare alias): the resolver alone must already make the layers agree.
    task, boundary = TaskIntakeService(storage).submit_task(PRESET_PROMPT, "agent_m7", str(ws))
    assert "summary.txt" in boundary.files_write
    ev = ResolvedBoundaryEvaluator(storage)
    spec = compile_landlock_rules_resolved(ev.resolve(boundary), None, runtime_dir=ws / "runtime")
    rules = write_rules_file(spec, tmp_path / "rules.json")

    storage.save_token("tok_m7", task.task_id, task.agent_id)
    broker = ToolBroker(storage, evaluator=ev)
    with pytest.raises(PermissionError):
        broker.write_file("tok_m7", "summary.txt", "hello")
    assert not (ws / "summary.txt").exists()
    assert broker.write_file("tok_m7", "output/summary.txt", "ok")["bytes_written"] == 2

    script = ("echo a > summary.txt 2>/dev/null && echo root_written || echo root_denied; "
              "echo b > output/summary.txt && echo output_written; "
              "echo c > output/other.txt 2>/dev/null && echo other_written || echo other_denied; "
              "echo d > scratch/x 2>/dev/null && echo scratch_written || echo scratch_denied")
    r = subprocess.run([str(ENFORCER), "--rules", str(rules), "--", "/bin/sh", "-c", script],
                       cwd=ws, capture_output=True, text=True, timeout=30)
    for marker in ("root_denied", "output_written", "other_denied", "scratch_denied"):
        assert marker in r.stdout, (marker, r.stdout, r.stderr)
    assert not (ws / "summary.txt").exists()
