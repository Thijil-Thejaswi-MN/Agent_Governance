"""Prompt-to-task attribution accuracy (roadmap item 3).

Runs scripted tasks under the real OS layer (sensor, Landlock, per-task scope) and checks
that every OS event is linked to the tool call that caused it. Each command the script
runs only touches files named tmp/m<N>_*, so the right call for those events is known
in advance (ground truth by construction):

  call_001  a plain foreground command
  call_002  a background job the shell does not wait for
  call_003  a double fork into a new session (re-parented away from the shell)
  call_004  a pipeline of several processes
  call_005  a wait so the detached jobs finish inside the run

Several tasks can run at the same time (--concurrent) to check that labels never cross
between tasks. The agent is a scripted MOCK (no model): this measures the attribution
mechanism, not model behaviour.

Usage (Linux/WSL2 with the OS layer built):
  python demo/security_monitor/measure_attribution.py --runs 5 --concurrent 3 \\
      --output demo/data/attribution/attribution_v1.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

MARKER = re.compile(r"/tmp/m(\d+)_")

ATTRIBUTION_STEPS: list[dict[str, Any]] = [
    {"tool": "run_command", "args": {"command": ": > tmp/m1_fg && cat tmp/m1_fg"}},
    {"tool": "run_command", "args": {"command": "( sleep 0.3; : > tmp/m2_bg ) >/dev/null 2>&1 & : > tmp/m2_fg"}},
    {"tool": "run_command", "args": {"command": "setsid sh -c 'sleep 0.3; : > tmp/m3_ds' >/dev/null 2>&1 < /dev/null &"}},
    {"tool": "run_command", "args": {"command": "printf 'x\\n' | tee tmp/m4_tee | wc -l > tmp/m4_wc"}},
    {"tool": "run_command", "args": {"command": "sleep 1; : > tmp/m5_wait"}},
    {"final": "done"},
]


def os_events(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    return [e for e in receipt.get("events", []) if e.get("syscall")]


def score_attribution(events: list[dict[str, Any]], task_id: str) -> dict[str, Any]:
    """Precision and recall of tool-call labels on the marker files (call N touches tmp/m<N>_*).

    precision: of the marker events given a call label, the share with the right one.
    recall:    of all marker events, the share given the right label.
    """
    tp = fp = fn = 0
    wrong: list[dict[str, Any]] = []
    for e in events:
        m = MARKER.search(str(e.get("target") or ""))
        if not m:
            continue
        truth = f"call_{int(m.group(1)):03d}"
        got = e.get("tool_call") if e.get("attributed_task_id") == task_id else None
        if got == truth:
            tp += 1
            continue
        fn += 1
        if got is not None:
            fp += 1
        wrong.append({"target": e.get("target"), "truth": truth, "got": got, "task": e.get("attributed_task_id")})
    return {
        "marker_events": tp + fn,
        "correct": tp,
        "precision": tp / (tp + fp) if tp + fp else 1.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "wrong": wrong,
    }


def run_task(storage: Any, receipts_dir: Path, name: str) -> Any:
    from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec

    launcher = TaskLauncher(storage, workspace_base=Path(os.environ["HOME"]) / "agent_workspaces",
                            receipts_dir=receipts_dir / name)
    spec = TaskSpec(prompt="Count the rows of input/sales.csv and write the count to output/summary.txt",
                    inputs={"input/sales.csv": "id,amount\n1,10\n"}, output_targets=["output/summary.txt"],
                    llm={"provider": "scripted", "steps": ATTRIBUTION_STEPS}, timeout_s=90, freeze_timeout_s=1.0)
    return launcher.run(spec)


def run_batch(storage: Any, receipts_dir: Path, tag: str, concurrent: int) -> list[Any]:
    out: dict[int, Any] = {}

    def go(i: int) -> None:
        out[i] = run_task(storage, receipts_dir, f"{tag}_{i}")

    threads = [threading.Thread(target=go, args=(i,)) for i in range(concurrent)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(300)
    return [out[i] for i in sorted(out)]


def summarise_task(res: Any) -> dict[str, Any]:
    r = res.receipt
    att = (r.get("extra") or {}).get("tool_call_attribution") or {}
    score = score_attribution(os_events(r), res.task_id)
    return {
        "task_id": res.task_id,
        "calls_placed": att.get("placed"),
        "calls_not_placed": att.get("not_placed"),
        "os_events_by_tool_call": att.get("os_events_by_tool_call"),
        "cross_attributions": (r.get("sensor") or {}).get("cross_attributions"),
        **score,
    }


def main(argv: list[str] | None = None) -> int:
    from demo.security_monitor.app.governance.storage import GovernanceStorage

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=3, help="batches to run")
    ap.add_argument("--concurrent", type=int, default=2, help="tasks running at the same time in each batch")
    ap.add_argument("--output", required=True)
    args = ap.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="attr_"))
    storage = GovernanceStorage(work / "gov.db")
    tasks: list[dict[str, Any]] = []
    try:
        for b in range(args.runs):
            for res in run_batch(storage, work / "receipts", f"b{b}", args.concurrent):
                tasks.append({"batch": b, **summarise_task(res)})
                shutil.rmtree(res.workspace, ignore_errors=True)
                shutil.rmtree(res.control_dir, ignore_errors=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    n = sum(t["marker_events"] for t in tasks)
    ok = sum(t["correct"] for t in tasks)
    labelled = sum(t["correct"] + sum(1 for w in t["wrong"] if w["got"] is not None) for t in tasks)
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_root).decode().strip()
    except Exception:
        commit = "unknown"
    summary = {
        "meta": {"runs": args.runs, "concurrent": args.concurrent, "agent": "scripted_mock",
                 "git_commit": commit, "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
        "tasks": len(tasks),
        "marker_events": n,
        "precision": ok / labelled if labelled else 1.0,
        "recall": ok / n if n else 0.0,
        "calls_not_placed": sum(t["calls_not_placed"] or 0 for t in tasks),
        "cross_attributions": sum(t["cross_attributions"] or 0 for t in tasks),
        "per_task": tasks,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != "per_task"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
