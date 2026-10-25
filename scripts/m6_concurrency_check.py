#!/usr/bin/env python3
"""M6.1 concurrency check: 2 tasks at the same time, N rounds.

Each round launches two launcher processes concurrently (shared governance DB,
scripted MOCK LLM issuing overlapping shell commands). Afterwards every sensor
event of both tasks is re-attributed purely from its cgroup path through the
shared task_os_identity table and compared with the sensor instance that
emitted it (tracer lineage):

  cross_attribution  cgroup maps to the *other* task      (expected 0)
  unattributed       cgroup maps to no task / unreadable  (reported)

All counts are computed from the raw sensor JSONL by this script.
Usage: python scripts/m6_concurrency_check.py [--rounds 20] [--out DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

STEPS = [
    {"tool": "run_command", "args": {"command": "for i in 1 2 3 4 5; do cat input/sales.csv >/dev/null; sleep 0.1; done; wc -l input/sales.csv"}},
    {"tool": "read_file", "args": {"file_path": "input/sales.csv"}},
    {"tool": "run_command", "args": {"command": "cat input/other.txt; ls /etc >/dev/null; python3 -c 'print(1)'"}},
    {"tool": "write_file", "args": {"file_path": "output/summary.txt", "content": "ok"}},
    {"final": "done"},
]


def task_file(out: Path, tag: str) -> Path:
    spec = {
        "prompt": "Count rows of input/sales.csv and write output/summary.txt",
        "inputs": {"input/sales.csv": "a,b\n1,2\n", "input/other.txt": "x\n"},
        "output_targets": ["output/summary.txt"],
        "llm": {"provider": "scripted", "steps": STEPS},
        "timeout_s": 120,
        "condition": f"concurrency_{tag}",
    }
    p = out / f"task_{tag}.json"
    p.write_text(json.dumps(spec))
    return p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--out", default=str(ROOT / "demo" / "data" / "evaluation_v3" / "checkpoint1" / "concurrency"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    base = Path(os.environ["HOME"]) / "agent_workspaces"
    db = base / ".control" / f"concurrency_{int(time.time())}.db"
    tf = {t: task_file(out, t) for t in ("A", "B")}
    rows = []
    log = open(out / "concurrency_log.jsonl", "w")
    for rnd in range(args.rounds):
        procs = {}
        for t in ("A", "B"):
            procs[t] = subprocess.Popen(
                [sys.executable, "-m", "demo.security_monitor.app.governance.launcher", "run",
                 "--task-file", str(tf[t]), "--db", str(db), "--receipts-dir", str(out / "receipts")],
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        res = {}
        for t, p in procs.items():
            so, se = p.communicate(timeout=300)
            res[t] = json.loads(so[so.index("{"):]) if "{" in so else {"error": se[-500:]}
        con = sqlite3.connect(db)
        table = dict(con.execute("SELECT cgroup_path, task_id FROM task_os_identity").fetchall())
        con.close()
        row = {"round": rnd, "tasks": {}, "cross_attributions": 0, "unattributed": 0, "events": 0, "overlap_s": None}
        spans = {}
        for t, r in res.items():
            tid = r.get("task_id")
            ev_path = base / ".control" / str(tid) / "sensor_events.jsonl"
            n = cross = unattr = 0
            ts = []
            for line in ev_path.read_text().splitlines() if ev_path.exists() else []:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("type") != "syscall":
                    continue
                n += 1
                ts.append(e["ts_ms"])
                cg = e.get("cgroup_id", "")
                owner = None
                if e.get("cgroup_status") == "ok":
                    owner = next((v for k, v in table.items() if cg == k or cg.startswith(k + "/")), None)
                if owner is None:
                    unattr += 1
                elif owner != tid:
                    cross += 1
            spans[t] = (min(ts), max(ts)) if ts else (0, 0)
            row["tasks"][t] = {"task_id": tid, "events": n, "cross": cross, "unattributed": unattr,
                               "shim_status": r.get("shim_status"), "freeze_events": r.get("freeze_events"),
                               "aborted": r.get("aborted")}
            row["events"] += n
            row["cross_attributions"] += cross
            row["unattributed"] += unattr
        a, b = spans.get("A", (0, 0)), spans.get("B", (0, 0))
        row["overlap_s"] = round(max(0, min(a[1], b[1]) - max(a[0], b[0])) / 1000.0, 3)
        rows.append(row)
        log.write(json.dumps(row) + "\n")
        log.flush()
        print(f"round {rnd:2d}: events={row['events']} cross={row['cross_attributions']} "
              f"unattributed={row['unattributed']} overlap={row['overlap_s']}s "
              f"status={[v['shim_status'] for v in row['tasks'].values()]}", flush=True)
    summary = {
        "rounds": len(rows),
        "tasks_run": 2 * len(rows),
        "total_events": sum(r["events"] for r in rows),
        "cross_attributions": sum(r["cross_attributions"] for r in rows),
        "unattributed": sum(r["unattributed"] for r in rows),
        "rounds_with_overlap": sum(1 for r in rows if r["overlap_s"] and r["overlap_s"] > 0),
        "min_overlap_s": min((r["overlap_s"] for r in rows), default=0),
        "tasks_not_completed": sum(1 for r in rows for v in r["tasks"].values() if v["shim_status"] != "completed"),
        "llm": "scripted_mock",
        "attribution_method": "cgroup (task_os_identity table); tracer lineage used only as the reference",
    }
    (out / "concurrency_summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))
    return 0 if summary["cross_attributions"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
