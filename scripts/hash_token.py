#!/usr/bin/env python3
"""CLI tool to hash an operator token for GOVERNANCE_USERS_FILE.

Usage:
    python scripts/hash_token.py <token>
    or run interactively to enter token securely:
    python scripts/hash_token.py
"""
from __future__ import annotations

import getpass
import hashlib
import sys


def hash_token(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def main() -> None:
    if len(sys.argv) > 1:
        token = sys.argv[1]
    else:
        try:
            token = getpass.getpass("Enter token to hash: ")
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.", file=sys.stderr)
            sys.exit(1)

    if not token.strip():
        print("Error: token cannot be empty.", file=sys.stderr)
        sys.exit(1)

    token_hash = hash_token(token)
    print(f"Token SHA-256: {token_hash}")


if __name__ == "__main__":
    main()
