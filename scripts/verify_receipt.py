#!/usr/bin/env python3
"""Recomputes the hash chain of Task Receipt v0 files.

Usage: python scripts/verify_receipt.py receipts/<task_id>.json [more.json ...]
Exit code 0 if every receipt verifies, 1 otherwise.

"Verified" means: each event entry's hash equals SHA-256 over its canonical
JSON (including the previous entry's hash), the final hash and entry count match
the receipt's hash_chain block, and the verdict counts match the event list.
The receipt is hash-chained, not signed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo.security_monitor.app.governance.receipt import verify_chain  # noqa: E402


def verify_file(path: Path) -> tuple[bool, str]:
    try:
        r = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return False, f"unreadable: {e}"
    events = r.get("events", [])
    ok, final, msg = verify_chain(events)
    if not ok:
        return False, msg
    hc = r.get("hash_chain", {})
    if hc.get("count") != len(events):
        return False, f"count mismatch: chain says {hc.get('count')}, list has {len(events)}"
    if hc.get("final_hash") != final:
        return False, "final_hash mismatch"
    counts: dict[str, int] = {}
    for e in events:
        counts[e["verdict"]] = counts.get(e["verdict"], 0) + 1
    declared = {k: v for k, v in r.get("event_counts", {}).get("by_verdict", {}).items() if v}
    if declared != counts:
        return False, f"verdict counts mismatch: declared {declared}, recomputed {counts}"
    return True, f"ok ({len(events)} entries, final {final[:16]}...)"


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    all_ok = True
    for a in argv:
        ok, msg = verify_file(Path(a))
        print(f"{'PASS' if ok else 'FAIL'} {a}: {msg}")
        all_ok &= ok
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
