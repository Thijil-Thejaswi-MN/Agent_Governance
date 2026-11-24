"""Ed25519 cryptographic signing for task records (receipts).

Provides per-organisation Ed25519 signing and verification over whole-record hashes.
Private keys are kept in $GOVERNANCE_KEYS_DIR/<org_id>/signing_key.pem (mode 0600, folder 0700),
outside every workspace and repository boundary.

Public keys and key rotation history are recorded in public_keys.json.
Key id is the initial 16 hex characters of the SHA-256 of the raw public key bytes.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger(__name__)

DEFAULT_KEYS_DIR = Path.home() / ".agent_governance" / "keys"


def get_keys_dir() -> Path:
    """Returns the base keys directory from $GOVERNANCE_KEYS_DIR or default."""
    env_dir = os.environ.get("GOVERNANCE_KEYS_DIR")
    if env_dir and env_dir.strip():
        return Path(env_dir).expanduser().resolve()
    return DEFAULT_KEYS_DIR.resolve()


def get_org_keys_dir(org_id: str = "default") -> Path:
    """Returns the directory for a specific organisation, ensuring 0700 permissions."""
    base = get_keys_dir()
    clean_org = os.path.basename((org_id or "default").strip() or "default")
    org_dir = base / clean_org
    org_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        org_dir.chmod(0o700)
    except OSError:
        pass
    return org_dir


def compute_key_id(public_key: ed25519.Ed25519PublicKey) -> str:
    """Computes the key id: the initial 16 hex characters of SHA-256(raw public key)."""
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw_bytes).hexdigest()[:16]


def raw_public_key_b64(public_key: ed25519.Ed25519PublicKey) -> str:
    """Returns base64-encoded raw public key bytes."""
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw_bytes).decode("ascii")


def _save_public_keys_registry(org_dir: Path, registry: list[dict[str, Any]]) -> None:
    pub_file = org_dir / "public_keys.json"
    content = json.dumps(registry, indent=2, sort_keys=True)
    tmp = org_dir / "public_keys.json.tmp"
    tmp.write_text(content, encoding="utf-8")
    try:
        tmp.chmod(0o644)
    except OSError:
        pass
    tmp.replace(pub_file)


def load_public_keys(org_id: str = "default") -> list[dict[str, Any]]:
    """Loads the public key history for an organisation. Never includes private keys."""
    org_dir = get_org_keys_dir(org_id)
    pub_file = org_dir / "public_keys.json"
    if pub_file.is_file():
        try:
            data = json.loads(pub_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except Exception as e:
            logger.warning("Could not read public_keys.json for org %s: %s", org_id, e)
    key_path = org_dir / "signing_key.pem"
    if key_path.is_file():
        try:
            _, key_id = get_or_create_signing_key(org_id)
            if pub_file.is_file():
                return json.loads(pub_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def get_signing_enabled_since(org_id: str = "default") -> str | None:
    """Returns the ISO timestamp when signing was initial enabled for an organisation.
    Corresponds to the earliest created_at in public_keys.json.
    Returns None if no keys exist for the organisation.
    """
    keys = load_public_keys(org_id)
    if not keys:
        return None
    created_ats = [k.get("created_at") for k in keys if k.get("created_at")]
    return min(created_ats) if created_ats else None


def get_or_create_signing_key(org_id: str = "default") -> tuple[ed25519.Ed25519PrivateKey, str]:
    """Retrieves or generates the active Ed25519 signing key for an organisation.

    Creates signing_key.pem with file mode 0600 on initial use.
    Returns (private_key, key_id).
    """
    org_dir = get_org_keys_dir(org_id)
    key_path = org_dir / "signing_key.pem"
    pub_file = org_dir / "public_keys.json"

    registry: list[dict[str, Any]] = []
    if pub_file.is_file():
        try:
            loaded = json.loads(pub_file.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                registry = loaded
        except Exception:
            registry = []

    if key_path.is_file():
        pem_data = key_path.read_bytes()
        priv = serialization.load_pem_private_key(pem_data, password=None)
        if not isinstance(priv, ed25519.Ed25519PrivateKey):
            raise TypeError(f"Existing key at {key_path} is not Ed25519")
        key_id = compute_key_id(priv.public_key())
        if not any(k.get("key_id") == key_id for k in registry):
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            registry.append({
                "key_id": key_id,
                "public_key": raw_public_key_b64(priv.public_key()),
                "created_at": now_iso,
                "retired_at": None,
            })
            _save_public_keys_registry(org_dir, registry)
        return priv, key_id

    priv = ed25519.Ed25519PrivateKey.generate()
    pem_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(pem_bytes)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    try:
        os.chmod(str(key_path), 0o600)
    except OSError:
        pass

    key_id = compute_key_id(priv.public_key())
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    registry.append({
        "key_id": key_id,
        "public_key": raw_public_key_b64(priv.public_key()),
        "created_at": now_iso,
        "retired_at": None,
    })
    _save_public_keys_registry(org_dir, registry)
    return priv, key_id


def rotate_key(org_id: str = "default") -> dict[str, Any]:
    """Generates a new active key for an organisation and retires the old key.

    Old public keys are preserved in public_keys.json and are never deleted.
    Returns the new key metadata dict.
    """
    org_dir = get_org_keys_dir(org_id)
    key_path = org_dir / "signing_key.pem"
    pub_file = org_dir / "public_keys.json"

    registry: list[dict[str, Any]] = []
    if pub_file.is_file():
        try:
            loaded = json.loads(pub_file.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                registry = loaded
        except Exception:
            registry = []

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for entry in registry:
        if entry.get("retired_at") is None:
            entry["retired_at"] = now_iso

    priv = ed25519.Ed25519PrivateKey.generate()
    pem_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(pem_bytes)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    try:
        os.chmod(str(key_path), 0o600)
    except OSError:
        pass

    key_id = compute_key_id(priv.public_key())
    new_entry = {
        "key_id": key_id,
        "public_key": raw_public_key_b64(priv.public_key()),
        "created_at": now_iso,
        "retired_at": None,
    }
    registry.append(new_entry)
    _save_public_keys_registry(org_dir, registry)
    return new_entry


def sign_bytes(data: bytes, org_id: str = "default") -> tuple[bytes, str]:
    """Applies Ed25519 signature to arbitrary raw bytes using active organisation key.
    Returns (signature_bytes, key_id).
    """
    priv, key_id = get_or_create_signing_key(org_id)
    sig_bytes = priv.sign(data)
    return sig_bytes, key_id


def verify_bytes(public_key: ed25519.Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    """Validates raw signature against raw bytes under given public key."""
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False


def sign_document_sha256(document_sha256: str, org_id: str = "default") -> dict[str, Any]:
    """Signs the raw bytes of a document SHA-256 hash using the organisation's active key.

    Returns the signature dict structure for task receipts.
    """
    priv, key_id = get_or_create_signing_key(org_id)
    try:
        data_to_sign = bytes.fromhex(document_sha256)
    except ValueError:
        data_to_sign = document_sha256.encode("ascii")
    sig_bytes = priv.sign(data_to_sign)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {
        "alg": "Ed25519",
        "key_id": key_id,
        "org_id": org_id,
        "signed_at": now_iso,
        "value": base64.b64encode(sig_bytes).decode("ascii"),
    }


def parse_public_key(val: Any) -> ed25519.Ed25519PublicKey | None:
    """Parses an Ed25519 public key from PEM, raw bytes, or base64 string."""
    if isinstance(val, ed25519.Ed25519PublicKey):
        return val
    if isinstance(val, str):
        val_bytes = val.encode("utf-8")
        if b"BEGIN PUBLIC KEY" in val_bytes:
            try:
                pk = serialization.load_pem_public_key(val_bytes)
                if isinstance(pk, ed25519.Ed25519PublicKey):
                    return pk
            except Exception:
                pass
        try:
            raw = base64.b64decode(val.strip())
            if len(raw) == 32:
                return ed25519.Ed25519PublicKey.from_public_bytes(raw)
        except Exception:
            pass
    if isinstance(val, (bytes, bytearray)):
        if b"BEGIN PUBLIC KEY" in val:
            try:
                pk = serialization.load_pem_public_key(val)
                if isinstance(pk, ed25519.Ed25519PublicKey):
                    return pk
            except Exception:
                pass
        if len(val) == 32:
            try:
                return ed25519.Ed25519PublicKey.from_public_bytes(bytes(val))
            except Exception:
                pass
    return None


def load_public_key_from_source(source: str | Path | dict[str, Any] | ed25519.Ed25519PublicKey) -> dict[str, ed25519.Ed25519PublicKey]:
    """Loads one or more public keys from a file, dict, or key object.

    Returns a mapping of key_id -> Ed25519PublicKey.
    """
    out: dict[str, ed25519.Ed25519PublicKey] = {}
    if isinstance(source, ed25519.Ed25519PublicKey):
        out[compute_key_id(source)] = source
        return out

    if isinstance(source, (str, Path)):
        p = Path(source)
        if p.is_file():
            content = p.read_bytes()
            try:
                data = json.loads(content.decode("utf-8"))
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "public_key" in item:
                            pk = parse_public_key(item["public_key"])
                            if pk:
                                kid = item.get("key_id") or compute_key_id(pk)
                                out[kid] = pk
                    if out:
                        return out
                elif isinstance(data, dict):
                    if "public_key" in data:
                        pk = parse_public_key(data["public_key"])
                        if pk:
                            kid = data.get("key_id") or compute_key_id(pk)
                            out[kid] = pk
                            return out
                    elif "keys" in data and isinstance(data["keys"], list):
                        for item in data["keys"]:
                            if isinstance(item, dict) and "public_key" in item:
                                pk = parse_public_key(item["public_key"])
                                if pk:
                                    kid = item.get("key_id") or compute_key_id(pk)
                                    out[kid] = pk
                        if out:
                            return out
            except Exception:
                pass
            pk = parse_public_key(content)
            if pk:
                out[compute_key_id(pk)] = pk
                return out
            pk = parse_public_key(p.read_text(encoding="utf-8").strip())
            if pk:
                out[compute_key_id(pk)] = pk
                return out
        else:
            pk = parse_public_key(str(source))
            if pk:
                out[compute_key_id(pk)] = pk
                return out

    if isinstance(source, dict):
        if "public_key" in source:
            pk = parse_public_key(source["public_key"])
            if pk:
                kid = source.get("key_id") or compute_key_id(pk)
                out[kid] = pk
        elif "keys" in source and isinstance(source["keys"], list):
            for item in source["keys"]:
                if isinstance(item, dict) and "public_key" in item:
                    pk = parse_public_key(item["public_key"])
                    if pk:
                        kid = item.get("key_id") or compute_key_id(pk)
                        out[kid] = pk

    return out


def verify_signature(
    public_key: ed25519.Ed25519PublicKey,
    signature_b64: str,
    document_sha256: str,
) -> bool:
    """Verifies that signature_b64 matches document_sha256 under public_key."""
    try:
        sig_bytes = base64.b64decode(signature_b64)
    except Exception:
        return False

    try:
        raw_hash = bytes.fromhex(document_sha256)
        public_key.verify(sig_bytes, raw_hash)
        return True
    except Exception:
        pass

    try:
        public_key.verify(sig_bytes, document_sha256.encode("ascii"))
        return True
    except Exception:
        return False
