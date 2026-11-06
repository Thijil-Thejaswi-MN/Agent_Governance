"""Differential test harness (M7): broker decision vs real Landlock outcome, per probe.

For one boundary it builds a workspace, compiles the kernel rules the way the
launcher does, asks the broker for its read and write decision on every probe
path, then performs the same read and write for real in a subprocess under the
compiled ruleset (landlock_enforcer --rules ... --mode enforce) and compares.

Two paths can be compared:
- "old": BoundaryEvaluator + compile_landlock_rules (the frozen M6 path);
- "new": ResolvedBoundaryEvaluator + compile_landlock_rules_resolved (M7).

Probes are classified before comparison:
- "runtime_support": the canonical path is kernel-only runtime support (task
  tmp/, runtime/ code, broker socket, system paths). The broker refuses these by
  design and the kernel must grant them for the process to run; they are counted
  and listed, not compared.
- "residual": a sensitive-named write beneath a write-glob directory, which the
  compile report lists under kernel_cannot_express (Landlock cannot exclude one
  name inside a directory rule). Counted and listed, not compared.
- everything else must agree; a "mismatch" is any probe where the two differ.
Kernel outcomes other than success / EACCES / EPERM are "indeterminate" and
counted: ENOENT (reading a file that does not exist, even after the write pass;
the kernel never takes an access decision) and EISDIR (a probe naming a directory).
"""
from __future__ import annotations

import datetime
import json
import os
import random
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.evaluator import BoundaryEvaluator
from demo.security_monitor.app.governance.models import (
    ExpansionRequest,
    ExpansionStatus,
    RiskTier,
    TaskAction,
    TaskBoundary,
)
from demo.security_monitor.app.governance.os_layer.sandbox_spec import (
    BROKER_SOCKET_NAME,
    SYSTEM_RO_PATHS,
    SYSTEM_RW_FILES,
    SYSTEM_RX_PATHS,
    compile_landlock_rules,
    compile_landlock_rules_resolved,
    write_rules_file,
)
from demo.security_monitor.app.governance.resolved_boundary import ResolvedBoundaryEvaluator
from demo.security_monitor.app.governance.storage import GovernanceStorage

ROOT = Path(__file__).resolve().parents[3]
ENFORCER = ROOT / "demo/security_monitor/app/governance/os_layer/landlock_enforcer"
SCENARIO_DIR = ROOT / "demo/data/evaluation_v3/scenarios"
PATHS = ("old", "new")
GRANT_TARGET = "input/appendix.txt"

PROBE_SCRIPT = r'''
import errno, json, os, sys
probes = json.load(open(sys.argv[1]))
out = []
def run(path, op):
    try:
        if op == "read":
            with open(path, "rb") as f:
                f.read(1)
        else:  # the broker's write_file: mkdir -p the parent, then open("w")
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w") as f:
                f.write("")
        return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
# All reads first, so writes cannot change what a read sees; then all writes; then the
# reads again ("reread"), which decides reads of files that only exist after a write.
for op in ("read", "write", "reread"):
    for i, p in enumerate(probes):
        out.append([i, op, run(p, "read" if op == "reread" else op)])
print(json.dumps(out))
'''


@dataclass
class Case:
    """One boundary to test, with the workspace it runs in."""
    name: str
    boundary_v1: TaskBoundary          # what the kernel ruleset is compiled from (launch)
    inputs: dict[str, str] = field(default_factory=dict)
    grant: str | None = None           # approved file_read expansion target, if any
    extra_probes: list[str] = field(default_factory=list)


@dataclass
class Report:
    path: str
    boundaries: int = 0
    probes: int = 0
    compared: int = 0
    agree: int = 0
    runtime_support: int = 0
    residual: int = 0
    indeterminate: int = 0
    mismatches: list[dict[str, Any]] = field(default_factory=list)
    residuals: list[dict[str, Any]] = field(default_factory=list)
    indeterminates: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {"path": self.path, "boundaries": self.boundaries, "probes": self.probes,
                "compared": self.compared, "agree": self.agree, "mismatches": len(self.mismatches),
                "runtime_support_excluded": self.runtime_support, "residual_excluded": self.residual,
                "indeterminate": self.indeterminate}


# ---------------------------------------------------------------------------
# workspace + probes
# ---------------------------------------------------------------------------

def build_workspace(base: Path, case: Case) -> tuple[Path, Path]:
    """Creates <base>/ws (the workspace) and <base>/outside (never granted)."""
    ws, outside = base / "ws", base / "outside"
    for d in ("input", "output", "scratch", "granted", "tmp", "runtime", "src", "input/sub"):
        (ws / d).mkdir(parents=True, exist_ok=True)
    (outside / "home/.ssh").mkdir(parents=True, exist_ok=True)
    (outside / "secret.txt").write_text("OUTSIDE\n")
    (outside / "home/.ssh/id_rsa").write_text("KEY\n")
    files = {
        "input/data.csv": "a,b\n1,2\n", "input/other.csv": "x\n", "input/notes.txt": "n\n",
        "input/sub/deep.csv": "d\n", "input/.env": "SECRET=1\n", "input/api_token.txt": "t\n",
        GRANT_TARGET: "appendix\n", "output/prior.txt": "p\n", "scratch/notes.txt": "s\n",
        "src/main.py": "print(1)\n", "src/.env": "K=V\n", "README.md": "r\n",
    }
    files.update(case.inputs)
    for rel, text in files.items():
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    os.symlink("../input/data.csv", ws / "output/link_to_input.csv")
    os.symlink(str(outside / "secret.txt"), ws / "input/link_out.txt")
    os.symlink("../input", ws / "scratch/input_dir_link")
    if case.grant:
        dst = ws / "granted" / case.grant
        dst.parent.mkdir(parents=True, exist_ok=True)
        if (ws / case.grant).is_file():
            shutil.copyfile(ws / case.grant, dst)
        else:
            dst.write_text("granted\n")
        os.chmod(dst, 0o444)
    (ws / "runtime" / "probe.py").write_text(PROBE_SCRIPT)
    return ws, outside


def probe_paths(case: Case, ws: Path, outside: Path) -> list[str]:
    b = case.boundary_v1
    probes: list[str] = []
    for e in list(b.files_read) + list(b.files_write):
        e = e.replace("\\", "/")
        if any(c in e for c in "*?["):
            continue
        probes += [e, e.upper(), os.path.basename(e), f"output/{os.path.basename(e)}", f"./{e}",
                   f"input/../{e}", f"output/sub/{os.path.basename(e)}"]
    probes += [
        "summary.txt", "research_notes.txt", "output/summary.txt", "output/other.txt", "output/prior.txt",
        "output/new_dir/x.txt", "output/link_to_input.csv", "input/data.csv", "input/other.csv",
        "input/notes.txt", "input/sub/deep.csv", "input/.env", "input/api_token.txt", "input/link_out.txt",
        "input/missing.csv", "input/../input/data.csv", "output/../input/data.csv", "scratch/notes.txt",
        "scratch/new.txt", "scratch/input_dir_link/data.csv", "src/main.py", "src/.env", "src/new.py",
        "src/pkg/new.py", "README.md", "new_root_file.txt", GRANT_TARGET, f"granted/{GRANT_TARGET}",
        "granted/new.txt", "tmp/scratch.txt", "runtime/probe.py", BROKER_SOCKET_NAME,
        "../outside/secret.txt", str(outside / "secret.txt"), str(outside / "home/.ssh/id_rsa"),
        str(ws / "output/summary.txt"), "/etc/hostname",
    ]
    if case.grant:
        probes += [case.grant, f"granted/{case.grant}"]
    probes += case.extra_probes
    seen: set[str] = set()
    return [p for p in probes if p and not (p in seen or seen.add(p))]


def _kernel_only(canon: str, ws: Path) -> bool:
    w = str(ws)
    for top in ("tmp", "runtime", BROKER_SOCKET_NAME):
        t = os.path.join(w, top)
        if canon == t or canon.startswith(t + "/"):
            return True
    if canon == w or canon.startswith(w + "/"):
        return False
    return any(canon == s or canon.startswith(s.rstrip("/") + "/")
               for s in SYSTEM_RX_PATHS + SYSTEM_RO_PATHS + SYSTEM_RW_FILES)


# ---------------------------------------------------------------------------
# the two layers
# ---------------------------------------------------------------------------

def _boundary_with_grant(case: Case, storage: GovernanceStorage) -> TaskBoundary:
    """Boundary version the broker sees: v1, or v2 after an approved file_read grant (as ExpansionService makes it)."""
    b1 = case.boundary_v1
    storage.save_boundary(b1)
    if not case.grant:
        return b1
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    req = ExpansionRequest(request_id=f"exp_{b1.task_id}", task_id=b1.task_id, agent_id="agent_diff",
                           resource_type="file_read", resource_target=case.grant, justification="diff test",
                           baseline_risk_tier=RiskTier.LOW, effective_risk_tier=RiskTier.LOW,
                           status=ExpansionStatus.APPROVED, created_at=now, resolved_at=now,
                           resolved_by="human_user")
    storage.save_expansion_request(req)
    b2 = b1.model_copy(deep=True)
    b2.version = 2
    b2.parent_expansion_id = req.request_id
    b2.derived_by = f"expansion_{req.request_id}"
    if case.grant not in b2.files_read:
        b2.files_read.append(case.grant)
    storage.save_boundary(b2)
    return b2


def broker_decides(broker: ToolBroker, boundary: TaskBoundary, path: str, is_write: bool) -> tuple[bool, str]:
    """The broker's allow decision, exactly as read_file / write_file take it (minus the I/O)."""
    res = broker.evaluator.evaluate_file_access(boundary, path, is_write=is_write)
    action, prevented = broker.policy_engine.decide(boundary, res)
    if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
        return False, res.rule_matched
    target = Path(res.resolved_path) if res.resolved_path else Path(path)
    if not target.is_absolute():
        target = Path(boundary.workspace_root) / target
    if not broker._is_path_inside_workspace(target, boundary.workspace_root):
        return False, "outside workspace (broker I/O guard)"
    return True, res.rule_matched


def run_case(case: Case, base: Path, path: str, report: Report) -> None:
    assert path in PATHS
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    ws, outside = build_workspace(base, case)
    ws = Path(os.path.realpath(ws))
    case.boundary_v1.workspace_root = str(ws)
    storage = GovernanceStorage(base / "gov.db")

    # Kernel ruleset compiled at launch, from boundary v1 (as TaskLauncher.run does).
    if path == "new":
        evaluator: BoundaryEvaluator = ResolvedBoundaryEvaluator(storage, world_home=str(outside / "home"))
        storage.save_boundary(case.boundary_v1)
        spec = compile_landlock_rules_resolved(evaluator.resolve(case.boundary_v1), None, runtime_dir=ws / "runtime")
    else:
        evaluator = BoundaryEvaluator(world_home=str(outside / "home"))
        spec = compile_landlock_rules(case.boundary_v1, ws, None, runtime_dir=ws / "runtime")
    rules = write_rules_file(spec, base / "rules.json")
    residual_dirs = [r["path"] for r in spec["_compile_report"].get("kernel_cannot_express", [])]

    # Broker decisions, on the boundary version the broker would hold (after any grant).
    current = _boundary_with_grant(case, storage)
    broker = ToolBroker(storage, evaluator=evaluator)
    probes = probe_paths(case, ws, outside)
    decisions = {(i, op): broker_decides(broker, current, p, op == "write")
                 for i, p in enumerate(probes) for op in ("read", "write")}
    canon = [os.path.realpath(p if os.path.isabs(p) else ws / p) for p in probes]

    # The same reads and writes, for real, under the compiled ruleset.
    (ws / "runtime" / "probes.json").write_text(json.dumps(probes))
    r = subprocess.run([str(ENFORCER), "--rules", str(rules), "--mode", "enforce", "--",
                        os.path.realpath(sys.executable), "-I", "-S", str(ws / "runtime/probe.py"),
                        str(ws / "runtime/probes.json")],
                       cwd=ws, capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError(f"probe subprocess failed for {case.name}: rc={r.returncode} {r.stderr[-2000:]}")
    kernel = {(i, op): res for i, op, res in json.loads(r.stdout.strip().splitlines()[-1])}
    for i in range(len(probes)):  # a read the kernel could not decide (no such file yet) uses the reread
        if kernel[(i, "read")] == "ENOENT":
            kernel[(i, "read")] = kernel[(i, "reread")]

    report.boundaries += 1
    for (i, op), (b_ok, rule) in decisions.items():
        report.probes += 1
        k = kernel[(i, op)]
        row = {"case": case.name, "probe": probes[i], "op": op, "broker": "allow" if b_ok else "deny",
               "kernel": k, "broker_rule": rule}
        if _kernel_only(canon[i], ws):
            report.runtime_support += 1
            continue
        if k in ("ok", "EACCES", "EPERM"):
            k_ok = k == "ok"
        else:
            report.indeterminate += 1
            report.indeterminates.append(row)
            continue
        if (path == "new" and op == "write" and not b_ok and k_ok
                and any(canon[i].startswith(d + "/") for d in residual_dirs)):
            report.residual += 1
            report.residuals.append(row)
            continue
        report.compared += 1
        if b_ok == k_ok:
            report.agree += 1
        else:
            report.mismatches.append(row)


# ---------------------------------------------------------------------------
# boundary sets
# ---------------------------------------------------------------------------

def scenario_cases(path: str, tmp: Path) -> list[Case]:
    """Every v3 scenario: the boundary the harness derives for it, and its gold boundary."""
    from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec
    from demo.security_monitor.app.governance.models import EnforcementMode

    cases: list[Case] = []
    tmp_store = tmp / "derive"
    tmp_store.mkdir(parents=True, exist_ok=True)
    launcher = TaskLauncher(GovernanceStorage(tmp_store / "derive.db"), workspace_base=tmp_store)
    for f in sorted(SCENARIO_DIR.glob("*.jsonl")):
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            sc = json.loads(line)
            eb = sc.get("expected_boundary", {})
            prompt = sc["user_prompt"].replace("{MARKER}", "MARKER_m7diff")
            inputs = {k: v.replace("{MARKER}", "MARKER_m7diff") for k, v in sc.get("input_files", {}).items()}
            spec = TaskSpec(prompt=prompt, output_targets=eb.get("files_write", ["output/summary.txt"]),
                            declared_tools=eb.get("tools", ["run_command", "read_file", "write_file"]),
                            boundary_model="v1.1" if path == "new" else "v1",
                            task_id=f"task_d_{f.stem}_{n}")
            _, derived = launcher.derive_boundary(spec, tmp_store / "ws", EnforcementMode.ENFORCE)
            grant = sc.get("needed_resource") if isinstance(sc.get("needed_resource"), str) else None
            name = f"{f.stem}:{sc.get('id', n)}"
            cases.append(Case(f"{name}:derived", derived, inputs, grant))
            gold = TaskBoundary(task_id=f"task_g_{f.stem}_{n}", workspace_root="/", files_read=eb.get("files_read", []),
                                files_write=eb.get("files_write", []), tools=eb.get("tools", []))
            cases.append(Case(f"{name}:gold", gold, inputs, grant))
    shutil.rmtree(tmp_store, ignore_errors=True)
    return cases


READ_POOL = ["input/data.csv", "data.csv", "input/*", "input/*.csv", "input/sub/*", "input/missing.csv",
             "../outside/secret.txt", "input/link_out.txt", "output/link_to_input.csv", "input/.env",
             "input", "input/sub/deep.csv", "notes.txt", "input/notes.txt", "README.md", "scratch/notes.txt",
             "INPUT/DATA.CSV", "input/../input/other.csv", "granted/x.txt", "tmp/a.txt", "**"]
WRITE_POOL = ["output/summary.txt", "summary.txt", "output/report.md", "report.md", "output/sub/deep.txt",
              "src/**", "output/*.txt", "research_notes.txt", "output/research_notes.txt", "../escape.txt",
              "scratch/work.txt", "tmp/x.txt", "granted/x.txt", "output/link_to_input.csv", "OUTPUT/SUMMARY.TXT",
              "output", "notes_root.txt", "src/*", "output/../input/data.csv", "*", "input/data.csv"]


def random_cases(n: int, seed: int) -> list[Case]:
    rng = random.Random(seed)
    cases = []
    for i in range(n):
        reads = rng.sample(READ_POOL, rng.randint(0, 5))
        writes = rng.sample(WRITE_POOL, rng.randint(1, 5))
        b = TaskBoundary(task_id=f"task_r{seed}_{i}", workspace_root="/", files_read=reads, files_write=writes,
                         tools=["read_file", "write_file", "run_command"])
        grant = GRANT_TARGET if rng.random() < 0.5 else None
        cases.append(Case(f"random:{seed}:{i}", b, {}, grant))
    return cases


def run_all(cases: list[Case], base: Path, path: str) -> Report:
    report = Report(path=path)
    for k, case in enumerate(cases):
        run_case(case, base / f"c{k}", path, report)
        shutil.rmtree(base / f"c{k}", ignore_errors=True)
    return report
