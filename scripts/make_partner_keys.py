#!/usr/bin/env python3
"""Generate an outside A2A partner signing keypair (chmod 600) and print the public JWK to pin.

Usage:
    python scripts/make_partner_keys.py --out /path/outside/repo/partner_key.json > partner.jwk.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_partner_keypair(kid: str | None = None, alg: str = "EdDSA") -> dict:
    """Generates a signing keypair and returns {kid, alg, private_jwk, public_jwk}."""
    key_id = (kid or f"partner-{uuid.uuid4().hex[:12]}").strip()
    alg_norm = alg.strip()
    if alg_norm == "EdDSA":
        priv = Ed25519PrivateKey.generate()
        priv_jwk = jwt.algorithms.OKPAlgorithm.to_jwk(priv, as_dict=True)
        pub_jwk = jwt.algorithms.OKPAlgorithm.to_jwk(priv.public_key(), as_dict=True)
    elif alg_norm == "ES256":
        priv = ec.generate_private_key(ec.SECP256R1())
        priv_jwk = jwt.algorithms.ECAlgorithm.to_jwk(priv, as_dict=True)
        pub_jwk = jwt.algorithms.ECAlgorithm.to_jwk(priv.public_key(), as_dict=True)
    else:
        raise ValueError(f"Unsupported algorithm '{alg}'; choose EdDSA or ES256")

    priv_jwk["kid"] = key_id
    priv_jwk["alg"] = alg_norm
    priv_jwk["use"] = "sig"
    pub_jwk["kid"] = key_id
    pub_jwk["alg"] = alg_norm
    pub_jwk["use"] = "sig"
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return {
        "kid": key_id,
        "alg": alg_norm,
        "private_jwk": priv_jwk,
        "public_jwk": pub_jwk,
        "private_pem": pem,
    }


def write_private_keyfile(out_path: Path, bundle: dict) -> Path:
    resolved = out_path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(bundle, indent=2) + "\n").encode("utf-8")
    fd = os.open(str(resolved), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.chmod(str(resolved), 0o600)
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate an A2A partner keypair (written with chmod 600) and print public JWK to pin."
    )
    parser.add_argument("out_pos", nargs="?", help="Output file path for private+public key bundle (chmod 600)")
    parser.add_argument("-o", "--out", dest="out_flag", help="Output file path for private+public key bundle (chmod 600)")
    parser.add_argument("--kid", default=None, help="Optional key ID (kid) for JWK")
    parser.add_argument("--alg", default="EdDSA", choices=["EdDSA", "ES256"], help="Signing algorithm (default: EdDSA)")
    args = parser.parse_args(argv)

    target = args.out_flag or args.out_pos
    if not target:
        parser.error("Specify an output file path via --out PATH or positional argument")

    bundle = generate_partner_keypair(kid=args.kid, alg=args.alg)
    written = write_private_keyfile(Path(target), bundle)
    print(f"Wrote partner keypair (mode 600) to {written}", file=sys.stderr)
    print(json.dumps(bundle["public_jwk"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
