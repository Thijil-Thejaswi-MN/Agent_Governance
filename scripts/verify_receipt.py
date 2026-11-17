#!/usr/bin/env python3
"""Checks Task Receipt files (v1, and older v0).

Usage: python scripts/verify_receipt.py receipts/<task_id>.json [more.json ...]
Exit code 0 if every receipt verifies, 1 otherwise.

"Verified" means: the required fields are present; each event entry's hash equals SHA-256
over its canonical JSON (including the previous entry's hash); the final hash, entry count
and verdict counts match; and, for v1 records, the SHA-256 over the whole record matches
hash_chain.document_sha256, so approvals, approvers, deliveries, the initial boundary and
termination are covered too. Older v0 records report "events only".
The receipt is hash-chained, not signed: someone who can rewrite the whole file and
recompute every hash is not detected.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo.security_monitor.app.governance.receipt import verify_receipt  # noqa: E402


def verify_file(path: Path) -> tuple[bool, str]:
    try:
        r = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return False, f"unreadable: {e}"
    res = verify_receipt(r)
    return res["ok"], res["message"]


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
