#!/usr/bin/env python3
"""M6.1b concurrency check v2: 2 simultaneous tasks x N rounds, ~10 s of
interleaved file + network work each, plus a background child that outlives
the step that started it (and the shim itself).

Per task (scripted MOCK LLM; the OS layer, broker, proxy, sensor are real):
  1. run_command: start a detached background loop (~10 s) that reads input/,
     appends to output/bg_marker_<TAG>.log and sleeps; returns immediately.
  2. run_command: ~3 s foreground loop: input reads, scratch/ writes, direct TCP
     connects (denied by Landlock).
  3. http_get x3 through the egress proxy to a local HTTP server (tool channel).
  4. read_file, then a ~2 s loop of connects to the broker's Unix socket.
  5. write_file, final.

All numbers are computed from the raw sensor JSONL by this script:
  cross_attributions  event's cgroup maps to the other task (expected 0)
  unattributed        event's cgroup maps to no task / unreadable
  background tree     pids that wrote bg_marker_<TAG> plus their children;
                      every one of their events must map to the emitting task.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTTP_PORT = 8000  # boundary derivation grants localhost:8000 / 127.0.0.1:8000 for "fetch" prompts

FG_TCP = "python3 -c \"import socket; s=socket.socket(); s.settimeout(0.2); print('tcp', s.connect_ex(('127.0.0.1', 8000)))\""
UDS = "python3 -c \"import socket; s=socket.socket(socket.AF_UNIX); print('uds', s.connect_ex('broker.sock')); s.close()\""


def steps(tag: str) -> list[dict]:
    bg = (f"nohup sh -c 'for i in $(seq 1 40); do cat input/sales.csv > /dev/null; "
          f"echo $i >> output/bg_marker_{tag}.log; sleep 0.25; done' > /dev/null 2>&1 & echo started")
    fg = f"for i in $(seq 1 6); do cat input/sales.csv > /dev/null; echo $i > scratch/fg_{tag}_$i.txt; {FG_TCP}; sleep 0.3; done"
    uds = f"for i in $(seq 1 6); do {UDS}; cat input/sales.csv > /dev/null; sleep 0.25; done"
    return [
        {"tool": "run_command", "args": {"command": bg}},
        {"tool": "run_command", "args": {"command": fg}},
        {"tool": "http_get", "args": {"url": f"http://127.0.0.1:{HTTP_PORT}/a"}},
        {"tool": "http_get", "args": {"url": f"http://127.0.0.1:{HTTP_PORT}/b"}},
        {"tool": "http_get", "args": {"url": f"http://127.0.0.1:{HTTP_PORT}/c"}},
        {"tool": "read_file", "args": {"file_path": "input/sales.csv"}},
        {"tool": "run_command", "args": {"command": uds}},
        {"tool": "write_file", "args": {"file_path": "output/summary.txt", "content": f"done {tag}"}},
        {"final": "done"},
    ]


class _H(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = f"local mock body for {self.path}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a) -> None:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--out", default=str(ROOT / "demo" / "data" / "evaluation_v3" / "checkpoint1" / "concurrency_v2"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    base = Path(os.environ["HOME"]) / "agent_workspaces"
    db = base / ".control" / f"concurrency_v2_{int(time.time())}.db"

    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", HTTP_PORT)) == 0:
            print(f"port {HTTP_PORT} already in use; aborting", file=sys.stderr)
            return 2
    httpd = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), _H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    tfiles = {}
    for t in ("A", "B"):
        spec = {
            "prompt": "Fetch the reference data over http and count the rows of input/sales.csv, write output/summary.txt",
            "inputs": {"input/sales.csv": "a,b\n1,2\n3,4\n"},
            "output_targets": ["output/summary.txt"],
            "llm": {"provider": "scripted", "steps": steps(t)},
            "timeout_s": 120,
            "condition": f"concurrency_v2_{t}",
        }
        tfiles[t] = out / f"task_{t}.json"
        tfiles[t].write_text(json.dumps(spec, indent=1))

    rows = []
    log = open(out / "concurrency_v2_log.jsonl", "w")
    for rnd in range(args.rounds):
        t0 = time.time()
        procs = {t: subprocess.Popen(
            [sys.executable, "-m", "demo.security_monitor.app.governance.launcher", "run", "--task-file", str(tfiles[t]),
             "--db", str(db), "--receipts-dir", str(out / "receipts")],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for t in ("A", "B")}
        res = {}
        for t, p in procs.items():
            so, se = p.communicate(timeout=300)
            res[t] = json.loads(so[so.index("{"):]) if "{" in so else {"error": se[-800:]}
        con = sqlite3.connect(db)
        table = dict(con.execute("SELECT cgroup_path, task_id FROM task_os_identity").fetchall())
        con.close()

        row = {"round": rnd, "wall_s": round(time.time() - t0, 2), "tasks": {}}
        spans = {}
        for t, r in res.items():
            tid = r.get("task_id")
            path = base / ".control" / str(tid) / "sensor_events.jsonl"
            lines = [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []
            start = next((e for e in lines if e.get("type") == "start"), {})
            evs = [e for e in lines if e.get("type") == "syscall"]
            n = cross = unattr = 0
            owner_of = {}
            for e in evs:
                n += 1
                cg = e.get("cgroup_id", "")
                owner = next((v for k, v in table.items() if cg == k or cg.startswith(k + "/")), None) \
                    if e.get("cgroup_status") == "ok" else None
                owner_of[e["seq"]] = owner
                if owner is None:
                    unattr += 1
                elif owner != tid:
                    cross += 1
            bg_pids = {e["pid"] for e in evs if f"bg_marker_{t}" in (e.get("abs_target") or "")}
            bg_tree = set(bg_pids) | {e["pid"] for e in evs if e.get("ppid") in bg_pids}
            bg = [e for e in evs if e["pid"] in bg_tree]
            root = start.get("child_pid")
            root_last = max((e["ts_ms"] for e in evs if e["pid"] == root), default=0)
            bg_wrong = sum(1 for e in bg if owner_of[e["seq"]] != tid)
            marker = Path(r.get("workspace", "")) / "output" / f"bg_marker_{t}.log"
            iterations = len(marker.read_text().splitlines()) if marker.exists() else 0
            ts = [e["ts_ms"] for e in evs]
            spans[t] = (min(ts), max(ts)) if ts else (0, 0)
            row["tasks"][t] = {
                "task_id": tid, "events": n, "cross": cross, "unattributed": unattr,
                "bg_tree_pids": len(bg_tree), "bg_events": len(bg), "bg_events_misattributed": bg_wrong,
                "bg_events_after_shim_last_event": sum(1 for e in bg if e["ts_ms"] > root_last),
                "bg_iterations_completed": iterations,
                "task_span_s": round((spans[t][1] - spans[t][0]) / 1000, 2),
                "outside_prevented_landlock": sum(1 for x in [None]),  # placeholder replaced below
                "shim_status": r.get("shim_status"), "freeze_events": r.get("freeze_events"), "aborted": r.get("aborted"),
            }
            rec_path = out / "receipts" / f"{tid}.json"
            if rec_path.exists():
                rec = json.loads(rec_path.read_text())
                row["tasks"][t]["outside_prevented_landlock"] = sum(1 for e in rec["outside_events"] if e["prevented_by"] == "landlock")
                row["tasks"][t]["proxy_events"] = sum(1 for e in rec["events"] if e["source"] == "EGRESS_PROXY")
                row["tasks"][t]["receipt_events"] = rec["hash_chain"]["count"]
        a, b = spans.get("A", (0, 0)), spans.get("B", (0, 0))
        row["overlap_s"] = round(max(0, min(a[1], b[1]) - max(a[0], b[0])) / 1000.0, 2)
        rows.append(row)
        log.write(json.dumps(row) + "\n")
        log.flush()
        ta, tb = row["tasks"]["A"], row["tasks"]["B"]
        print(f"round {rnd:2d}: overlap={row['overlap_s']}s events={ta['events']}+{tb['events']} "
              f"cross={ta['cross'] + tb['cross']} unattr={ta['unattributed'] + tb['unattributed']} "
              f"bg_events={ta['bg_events']}+{tb['bg_events']} bg_misattr={ta['bg_events_misattributed'] + tb['bg_events_misattributed']} "
              f"bg_after_shim={ta['bg_events_after_shim_last_event']}+{tb['bg_events_after_shim_last_event']} "
              f"status={ta['shim_status']},{tb['shim_status']}", flush=True)
    httpd.shutdown()

    tasks = [v for r in rows for v in r["tasks"].values()]
    summary = {
        "rounds": len(rows),
        "tasks_run": len(tasks),
        "llm": "scripted_mock",
        "total_events": sum(v["events"] for v in tasks),
        "cross_attributions": sum(v["cross"] for v in tasks),
        "unattributed": sum(v["unattributed"] for v in tasks),
        "background_events": sum(v["bg_events"] for v in tasks),
        "background_events_misattributed": sum(v["bg_events_misattributed"] for v in tasks),
        "background_events_after_shim_last_event": sum(v["bg_events_after_shim_last_event"] for v in tasks),
        "tasks_with_background_tree": sum(1 for v in tasks if v["bg_tree_pids"] > 0),
        "background_iterations_completed_min": min((v["bg_iterations_completed"] for v in tasks), default=0),
        "min_overlap_s": min((r["overlap_s"] for r in rows), default=0),
        "mean_overlap_s": round(sum(r["overlap_s"] for r in rows) / max(1, len(rows)), 2),
        "mean_task_span_s": round(sum(v["task_span_s"] for v in tasks) / max(1, len(tasks)), 2),
        "tasks_not_completed": sum(1 for v in tasks if v["shim_status"] != "completed"),
        "tasks_with_freeze": sum(1 for v in tasks if v["freeze_events"]),
        "proxy_events_total": sum(v.get("proxy_events", 0) for v in tasks),
        "landlock_prevented_outside_total": sum(v.get("outside_prevented_landlock", 0) for v in tasks),
        "attribution_method": "cgroup (task_os_identity table); tracer lineage used only as the reference",
    }
    (out / "concurrency_v2_summary.json").write_text(json.dumps(summary, indent=1))

    # Pack receipts: one tarball + per-task hash list (raw receipts are not committed individually).
    rdir = out / "receipts"
    if rdir.exists():
        with open(out / "receipts_sha256.txt", "w") as h:
            for p in sorted(rdir.glob("*.json")):
                h.write(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n")
        with tarfile.open(out / "receipts.tar.gz", "w:gz") as tar:
            tar.add(rdir, arcname="receipts")
    print(json.dumps(summary, indent=1))
    return 0 if summary["cross_attributions"] == 0 and summary["background_events_misattributed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
