"""M7 frozen reproducibility check: re-derive recorded boundaries with V1 and diff them.

For a set of frozen trials it rebuilds the exact prompt the harness used
(evaluate_v3.py: scenario prompt, v3b-shell rewrite, the trial's recorded marker),
checks it against the receipt's prompt_sha256, derives the boundary through
TaskLauncher.derive_boundary with boundary_model="v1" (the path the frozen runs
took), and compares it byte for byte with the receipt's initial_boundary.

At the frozen commit (2d9cbda) the harness always set files_read to the
scenario's expected_boundary.files_read; today that is `--boundary-source gold`
(the default became "derived" afterwards). The check re-derives that way, and
also reports what today's default ("derived") would give, for contrast.

Reads results and receipts only; writes nothing under demo/data.

    python scripts/m7_frozen_boundary_check.py [--out report.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec  # noqa: E402
from demo.security_monitor.app.governance.models import EnforcementMode  # noqa: E402
from demo.security_monitor.app.governance.storage import GovernanceStorage  # noqa: E402
from demo.security_monitor.evaluate_v3 import SHELL_ONLY_TOOLS_SCHEMA  # noqa: E402

RESULTS = ROOT / "demo/data/evaluation_v3/results"
SCENARIOS = ROOT / "demo/data/evaluation_v3/scenarios"

# (results file, scenario_id, condition): injected, E1b shell-only, utility anticipated / unanticipated.
FROZEN_TRIALS = [
    ("injected_regression_v3d_C.jsonl", "injected_indirect_01", "C"),
    ("injected_regression_v3d_C.jsonl", "injected_indirect_09", "C"),
    ("e1b_regression_v3d_C.jsonl", "injected_indirect_04", "C"),
    ("utility_v3d_qwen2.5_7b.jsonl", "legit_anticipated_03", "C"),
    ("utility_v3d_qwen2.5_7b.jsonl", "legit_unanticipated_05", "C"),
]


def _prompt(sc: dict, variant: str, marker: str) -> str:
    """The prompt as evaluate_v3.py builds it."""
    tmpl = sc["user_prompt"]
    if variant == "v3b-shell":
        m = re.match(r"^First display (input/\S+) with the shell \(for example with cat\)\. Then (.*)", tmpl)
        if m:
            rest = m.group(2)
            tmpl = f"First run cat {m.group(1)} to view the file, then {rest[0].lower() + rest[1:]}"
    return tmpl.replace("{MARKER}", marker)


def _find_scenario(sid: str, variant: str, marker: str, prompt_sha: str, recorded_shas: set[str]) -> tuple[Path, dict]:
    hits = []
    for f in sorted(SCENARIOS.glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                sc = json.loads(line)
                if sc.get("id") == sid and \
                        hashlib.sha256(_prompt(sc, variant, marker).encode()).hexdigest() == prompt_sha:
                    hits.append((f, sc))
    if not hits:
        raise LookupError(f"no scenario reproduces the recorded prompt of {sid}")
    # Several scenario files can share a prompt; prefer one whose file hash the trial recorded.
    hits.sort(key=lambda h: hashlib.sha256(h[0].read_bytes()).hexdigest() not in recorded_shas)
    return hits[0]


def check(results_file: str, sid: str, cond: str, launcher: TaskLauncher, ws: Path) -> dict:
    rec = next(r for r in map(json.loads, (RESULTS / results_file).read_text(encoding="utf-8").splitlines())
               if r["scenario_id"] == sid and r["condition"] == cond)
    receipt_path = Path(rec["receipt_path"])
    receipt_path = receipt_path if receipt_path.is_absolute() else ROOT / receipt_path
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    recorded_shas = {v for k, v in rec.items() if k.endswith("sha256") and isinstance(v, str)}
    f, sc = _find_scenario(sid, rec["prompt_variant"], rec["marker"], receipt["prompt_sha256"], recorded_shas)
    eb = sc.get("expected_boundary", {})
    shell_only = rec.get("variant") == "e1b_shell_only"

    def derive(files_read: list[str] | None, tag: str) -> dict:
        spec = TaskSpec(
            prompt=_prompt(sc, rec["prompt_variant"], rec["marker"]),
            output_targets=eb.get("files_write", ["output/summary.txt"]),
            files_read=files_read,
            declared_tools=["run_command", "write_file"] if shell_only else eb.get("tools", ["run_command", "read_file", "write_file"]),
            tools_schema=SHELL_ONLY_TOOLS_SCHEMA if shell_only else None,
            enforcement_mode="ENFORCE" if cond in ("B", "B+F", "C", "D") else "OBSERVE",
            task_id=f"task_frozen_{tag}_{sid}_{cond}",
        )
        assert spec.boundary_model == "v1", "the frozen harness path is the TaskSpec default"
        _, b = launcher.derive_boundary(spec, ws, EnforcementMode(spec.enforcement_mode))
        return {"version": b.version, "files_read": b.files_read, "files_write": b.files_write,
                "network": b.network, "tools": b.tools, "peer_agents": b.peer_agents,
                "enforcement_mode": b.enforcement_mode.value, "derived_by": b.derived_by,
                "max_duration_sec": b.max_duration_sec}

    want = json.dumps(receipt["initial_boundary"], sort_keys=True)
    frozen_way = derive(eb.get("files_read"), "gold")
    today_default = derive(None, "derived")
    return {"results_file": results_file, "scenario_id": sid, "condition": cond, "scenario_file": f.name,
            "receipt": receipt_path.name, "prompt_sha256_matches": True,
            "identical": json.dumps(frozen_way, sort_keys=True) == want,
            "today_default_derived_identical": json.dumps(today_default, sort_keys=True) == want,
            "recorded": receipt["initial_boundary"], "rederived": frozen_way,
            "today_default_derived": today_default}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    with tempfile.TemporaryDirectory() as td:
        launcher = TaskLauncher(GovernanceStorage(Path(td) / "g.db"), workspace_base=Path(td))
        rows = [check(*t, launcher, Path(td) / "ws") for t in FROZEN_TRIALS]
    for r in rows:
        print(f"{'IDENTICAL' if r['identical'] else 'DIFFERENT'}  {r['results_file']}  {r['scenario_id']}  "
              f"cond={r['condition']}  scenario_file={r['scenario_file']}  receipt={r['receipt']}  "
              f"files_write={r['rederived']['files_write']}  "
              f"(today's default --boundary-source derived: {'identical' if r['today_default_derived_identical'] else 'differs, files_read=' + str(r['today_default_derived']['files_read'])})")
    if args.out:
        Path(args.out).write_text(json.dumps(rows, indent=1), encoding="utf-8")
    return 0 if all(r["identical"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
