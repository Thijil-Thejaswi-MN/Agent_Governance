#!/usr/bin/env python3
"""Checks Task Receipt files (v2, v1, and older v0).

Usage: python scripts/verify_receipt.py receipts/<task_id>.json [more.json ...] [--pubkey <file>]
Exit code 0 if every receipt verifies, 1 otherwise.

"Verified" means: the required fields are present; each event entry's hash equals SHA-256
over its canonical JSON (including the previous entry's hash); the final hash, entry count
and verdict counts match; and, for v1/v2 records, the SHA-256 over the whole record matches
hash_chain.document_sha256, so approvals, approvers, deliveries, the initial boundary and
termination are covered too. For v2 records, the Ed25519 signature is verified against a known
public key or one passed via --pubkey. Older v0 records report "events only".
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo.security_monitor.app.governance.receipt import verify_receipt  # noqa: E402


def verify_file(path: Path, pubkey: str | Path | None = None) -> tuple[bool, str]:
    try:
        r = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return False, f"unreadable: {e}"
    res = verify_receipt(r, pubkey=pubkey)
    return res["ok"], res["message"]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Checks Task Receipt files (v2, v1, and older v0).")
    parser.add_argument("receipts", nargs="*", help="Receipt JSON file paths")
    parser.add_argument("--pubkey", help="Path to public key file (PEM, JSON or raw) for verification")
    args = parser.parse_args(argv)

    if not args.receipts:
        parser.print_help()
        return 2

    all_ok = True
    for a in args.receipts:
        ok, msg = verify_file(Path(a), pubkey=args.pubkey)
        print(f"{'PASS' if ok else 'FAIL'} {a}: {msg}")
        all_ok &= ok
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
