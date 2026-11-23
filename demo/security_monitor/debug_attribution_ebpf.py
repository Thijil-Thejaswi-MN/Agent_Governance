"""Prints what one attribution run's OS events contain (for the eBPF tool-call label check).

Run: GOVERNANCE_SENSOR=ebpf python -m demo.security_monitor.debug_attribution_ebpf
"""
from __future__ import annotations

import json
import tempfile
from collections import Counter
from pathlib import Path

from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.measure_attribution import os_events, run_task, score_attribution


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="dbg_attr_"))
    storage = GovernanceStorage(tmp / "g.db")
    res = run_task(storage, tmp / "receipts", "one")
    r = res.receipt
    print("task:", res.task_id)
    print("sensor:", json.dumps(r.get("sensor") or r.get("extra", {}).get("sensor"), default=str)[:400])
    print("isolation:", json.dumps(r.get("isolation"), default=str)[:400])
    print("task cgroups:", storage.list_task_cgroups())
    att = r["extra"]["tool_call_attribution"]
    print("calls:", [(c["call_id"], c["cgroup"]) for c in att["calls"]])
    evs = os_events(r)
    print("os events:", len(evs))
    print("cgroup_path values:", Counter(str(e.get("cgroup_path")) for e in evs).most_common(8))
    print("tool_call values:", Counter(str(e.get("tool_call")) for e in evs).most_common(8))
    print("attributed_task_id values:", Counter(str(e.get("attributed_task_id")) for e in evs).most_common(4))
    score = score_attribution(evs, res.task_id)
    print("score:", {k: v for k, v in score.items() if k != "wrong"})
    for w in score["wrong"][:6]:
        print("  wrong:", w)
    markers = [e for e in evs if "/tmp/m" in str(e.get("target") or "")]
    for e in markers[:6]:
        print("  marker:", {k: e.get(k) for k in ("syscall", "target", "cgroup_path", "tool_call", "attributed_task_id", "phase")})


if __name__ == "__main__":
    main()
