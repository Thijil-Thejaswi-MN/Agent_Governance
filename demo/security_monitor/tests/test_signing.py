"""Tests for Ed25519 signing and verification of task records."""
from __future__ import annotations

import copy

import base64
import datetime
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI
from fastapi.testclient import TestClient

from demo.security_monitor.app.governance.api import governance_router
from demo.security_monitor.app.governance.models import (
    EventSource,
    EventVerdict,
)
from demo.security_monitor.app.governance.receipt import (
    chain_entries,
    document_hash,
    seal,
    verify_receipt,
)
from demo.security_monitor.app.governance.signing import (
    compute_key_id,
    get_or_create_signing_key,
    get_org_keys_dir,
    load_public_keys,
    raw_public_key_b64,
    rotate_key,
    sign_document_sha256,
    verify_signature,
)
from scripts.verify_receipt import verify_file


def _make_dummy_receipt() -> dict:
    entries = [
        {
            "timestamp": "2026-11-21T10:00:00Z",
            "source": EventSource.TOOL_BROKER.value,
            "kind": "file_read",
            "target": "/workspace/input/data.txt",
            "verdict": EventVerdict.INSIDE.value,
            "risk_tier": "low",
            "action_taken": "allowed",
            "prevented": False,
            "prevented_by": "none",
            "observed_by": ["broker"],
            "channel": "tool",
            "rule_matched": "allowed input read",
            "boundary_version": 1,
            "details": {},
        }
    ]
    final_h = chain_entries(entries)
    return {
        "receipt_version": "v2",
        "task_id": "test-task-123",
        "events": entries,
        "hash_chain": {
            "algorithm": "sha256",
            "genesis": "0" * 64,
            "count": len(entries),
            "final_hash": final_h,
        },
        "event_counts": {"total": 1, "by_verdict": {EventVerdict.INSIDE.value: 1}},
        "initial_boundary": {"files_read": ["/workspace/input/data.txt"]},
        "expansions": [],
        "deliveries": [],
        "termination": {"status": "SUCCESS"},
        "isolation_level": "process",
        "requester": "developer",
    }


def test_sign_and_verify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))

    rec = _make_dummy_receipt()
    sealed = seal(rec, org_id="default")

    assert sealed["receipt_version"] == "v2"
    assert "signature" in sealed
    sig = sealed["signature"]
    assert sig["alg"] == "Ed25519"
    assert sig["org_id"] == "default"
    assert len(sig["key_id"]) == 16
    assert isinstance(sig["value"], str)

    # In-memory verification
    res = verify_receipt(sealed)
    assert res["ok"] is True
    assert res["scope"] == "signed"
    assert "signature verified" in res["message"]

    # File-based verification via scripts/verify_receipt.py
    rec_file = tmp_path / "receipt.json"
    rec_file.write_text(json.dumps(sealed), encoding="utf-8")

    ok, msg = verify_file(rec_file)
    assert ok is True
    assert "signature verified" in msg

    # Verification with explicit --pubkey passed
    pub_file = keys_dir / "default" / "public_keys.json"
    ok_pub, msg_pub = verify_file(rec_file, pubkey=pub_file)
    assert ok_pub is True
    assert "signature verified" in msg_pub


def test_tampered_field_signature_does_not_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))

    rec = _make_dummy_receipt()
    sealed = seal(rec, org_id="default")

    # If field is changed and document_sha256 is recomputed, signature fails
    tampered = dict(sealed)
    tampered["requester"] = "malicious_actor"
    tampered["hash_chain"] = dict(tampered["hash_chain"])
    tampered["hash_chain"]["document_sha256"] = document_hash(tampered)

    res = verify_receipt(tampered)
    assert res["ok"] is False
    assert res["message"] == "signature does not match"

    # If field is changed and document_sha256 is NOT recomputed, hash check fails
    tampered_raw = dict(sealed)
    tampered_raw["requester"] = "malicious_actor"
    res_raw = verify_receipt(tampered_raw)
    assert res_raw["ok"] is False
    assert "whole-record hash does not match" in res_raw["message"]


def test_tampered_signature_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))

    rec = _make_dummy_receipt()
    sealed = seal(rec, org_id="default")

    # Modify signature bytes to another 64 bytes of valid base64 that doesn't match
    raw_sig = base64.b64decode(sealed["signature"]["value"])
    corrupted_sig = bytes([(b ^ 0xFF) for b in raw_sig])
    sealed["signature"]["value"] = base64.b64encode(corrupted_sig).decode("ascii")

    res = verify_receipt(sealed)
    assert res["ok"] is False
    assert res["message"] == "signature does not match"


def test_unknown_key_gives_unknown_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))

    rec = _make_dummy_receipt()
    sealed = seal(rec, org_id="default")

    # Change key_id to an unknown id
    sealed["signature"]["key_id"] = "deadbeefcafebabe"

    res = verify_receipt(sealed)
    assert res["ok"] is False
    assert res["scope"] == "unknown_key"
    assert res["message"] == "unknown key: deadbeefcafebabe"


def test_rotation_verifies_old_records_with_retired_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))

    # Initial record under initial key
    rec1 = _make_dummy_receipt()
    rec1["task_id"] = "task-before-rotation"
    sealed1 = seal(rec1, org_id="default")
    key_id_1 = sealed1["signature"]["key_id"]

    res1 = verify_receipt(sealed1)
    assert res1["ok"] is True
    assert res1["scope"] == "signed"

    # Rotate key
    new_meta = rotate_key("default")
    key_id_2 = new_meta["key_id"]
    assert key_id_1 != key_id_2

    # Check public_keys.json retains initial key marked retired
    registered = load_public_keys("default")
    assert len(registered) == 2
    r1 = next(k for k in registered if k["key_id"] == key_id_1)
    r2 = next(k for k in registered if k["key_id"] == key_id_2)
    assert r1["retired_at"] is not None
    assert r2["retired_at"] is None

    # New record under new active key
    rec2 = _make_dummy_receipt()
    rec2["task_id"] = "task-after-rotation"
    sealed2 = seal(rec2, org_id="default")
    assert sealed2["signature"]["key_id"] == key_id_2

    # Both verify successfully
    v1 = verify_receipt(sealed1)
    assert v1["ok"] is True
    assert v1["scope"] == "signed"
    assert key_id_1 in v1["message"]

    v2 = verify_receipt(sealed2)
    assert v2["ok"] is True
    assert v2["scope"] == "signed"
    assert key_id_2 in v2["message"]


def test_existing_v1_and_v0_fixtures_verify_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(tmp_path / "empty_keys"))
    # 1. Existing v0 fixture from repository
    fixture_path = Path("demo/security_monitor/tests/fixtures/receipts/task_4793807674a4.json")
    if fixture_path.is_file():
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        res = verify_receipt(data)
        assert res["ok"] is True
        assert res["scope"] == "events_only"
        assert "only the event list is chained" in res["message"] or "events only" in res["message"]

    # 2. Existing v1 record (whole record checked, unsigned)
    rec_v1 = _make_dummy_receipt()
    rec_v1["receipt_version"] = "v1"
    sealed_v1 = seal(rec_v1, sign=False)
    assert "signature" not in sealed_v1
    assert sealed_v1["receipt_version"] == "v1"
    res_v1 = verify_receipt(sealed_v1)
    assert res_v1["ok"] is True
    assert res_v1["scope"] == "whole_record"
    assert "whole record checked" in res_v1["message"]


def test_file_mode_0600(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))

    priv, kid = get_or_create_signing_key("default")
    org_dir = keys_dir / "default"
    key_file = org_dir / "signing_key.pem"

    assert org_dir.is_dir()
    assert key_file.is_file()

    # Verify folder mode 0700
    dir_mode = stat.S_IMODE(org_dir.stat().st_mode)
    assert dir_mode == 0o700

    # Verify file mode 0600
    file_mode = stat.S_IMODE(key_file.stat().st_mode)
    assert file_mode == 0o600


def test_private_key_never_leaks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))

    priv, kid = get_or_create_signing_key("default")
    pem_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_str = pem_bytes.decode("ascii")
    priv_payload = pem_str.split("\n")[1].strip()

    # 1. load_public_keys
    pub_keys = load_public_keys("default")
    pub_dump = json.dumps(pub_keys)
    assert priv_payload not in pub_dump
    assert "PRIVATE KEY" not in pub_dump

    # 2. Receipt seal and verify
    rec = _make_dummy_receipt()
    sealed = seal(rec, org_id="default")
    sealed_dump = json.dumps(sealed)
    assert priv_payload not in sealed_dump
    assert "PRIVATE KEY" not in sealed_dump

    # 3. Check logs
    assert priv_payload not in caplog.text
    assert "PRIVATE KEY" not in caplog.text

    # 4. API endpoint GET /api/governance/records/public-keys
    app = FastAPI()
    app.include_router(governance_router, prefix="/api/governance")
    client = TestClient(app)
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "test-token-admin")
    resp = client.get("/api/governance/records/public-keys", headers={"Authorization": "Bearer test-token-admin"})
    assert resp.status_code == 200
    resp_text = resp.text
    assert priv_payload not in resp_text
    assert "PRIVATE KEY" not in resp_text
    body = resp.json()
    assert "keys" in body
    assert any(k["key_id"] == kid for k in body["keys"])


def test_landlock_condition_c_blocks_private_key(tmp_path: Path) -> None:
    from demo.security_monitor.app.governance.os_layer.sandbox_spec import compile_landlock_rules
    from demo.security_monitor.app.governance.models import TaskBoundary

    workspace = tmp_path / "workspace"
    workspace.mkdir()

    boundary = TaskBoundary(task_id="test_task", workspace_root=str(workspace))
    compiled = compile_landlock_rules(boundary, workspace, proxy_port=None)

    # Ensure $HOME keys directory is not in any allowed paths
    allowed_paths = [str(Path(r["path"]).resolve()) for r in compiled["rules"]]
    keys_path = str((Path.home() / ".agent_governance" / "keys").resolve())

    for ap in allowed_paths:
        assert not keys_path.startswith(ap) or ap == "/"


ROOT = Path(__file__).resolve().parents[3]


def test_downgraded_v2_to_v1_flagged_unsigned_after_signing_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))

    rec = _make_dummy_receipt()
    now_iso = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)).isoformat()
    rec["created_at"] = now_iso
    rec["started_at"] = now_iso
    sealed = seal(rec, org_id="default")
    assert sealed["receipt_version"] == "v2"
    assert "signature" in sealed

    # Downgrade: remove signature field and set receipt_version to v1
    forged = dict(sealed)
    forged.pop("signature", None)
    forged["receipt_version"] = "v1"
    forged["hash_chain"] = dict(forged["hash_chain"])
    forged["hash_chain"]["document_sha256"] = document_hash(forged)

    res = verify_receipt(forged)
    assert res["ok"] is False
    assert res["scope"] == "unsigned_after_signing_enabled"


def test_genuine_v1_record_before_initial_key_verifies_whole_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))

    # Initialize keys with current timestamp
    get_or_create_signing_key("default")

    # A genuine record from October 2026, before signing was enabled
    rec = _make_dummy_receipt()
    rec["created_at"] = "2026-10-15T12:00:00Z"
    rec["started_at"] = "2026-10-15T12:00:00Z"
    rec["receipt_version"] = "v1"
    sealed = seal(rec, sign=False)

    res = verify_receipt(sealed, trusted_started_at="2026-10-15T12:00:00Z", trusted_org_id="default")
    assert res["ok"] is True
    assert res["scope"] == "whole_record"
    assert "whole record checked" in res["message"]


def test_signing_unavailable_shows_signing_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))

    rec = _make_dummy_receipt()
    rec["extra"] = {"signing": "unavailable: permission denied on keys dir"}
    rec["receipt_version"] = "v1"
    sealed = seal(rec, sign=False)

    res = verify_receipt(sealed)
    assert res["scope"] == "signing_unavailable"
    assert res["ok"] is False
    assert res["message"] == "signing unavailable"
    assert res["signature_reason"] == "signing unavailable"


def test_all_existing_demo_data_records_verify_as_before(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(tmp_path / "empty_keys"))
    # Only verify committed files in demo/data; skip with clear reason if folder does not exist
    committed_dir = Path("demo/data/evaluation_v3/checkpoint1/receipts")
    if not committed_dir.is_dir():
        pytest.skip(f"Committed directory {committed_dir} does not exist")
    receipt_files = list(committed_dir.glob("*.json"))
    if not receipt_files:
        pytest.skip(f"No json files found in {committed_dir}")

    eval_dir = Path("demo/data/evaluation_v3/receipts")
    if eval_dir.is_dir():
        receipt_files.extend(list(eval_dir.glob("*.json")))

    for rf in receipt_files:
        data = json.loads(rf.read_text(encoding="utf-8"))
        res = verify_receipt(data)
        assert res["ok"] is True, f"Failed to verify {rf.name}: {res}"
        assert res["scope"] in ("whole_record", "events_only")


def test_scripts_verify_receipt_downgrade_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))
    priv, kid = get_or_create_signing_key("default")

    # Sealed record downgraded to v1
    rec = _make_dummy_receipt()
    now_iso = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1)).isoformat()
    rec["created_at"] = now_iso
    rec["started_at"] = now_iso
    sealed = seal(rec, org_id="default")
    downgraded = dict(sealed)
    downgraded.pop("signature", None)
    downgraded["receipt_version"] = "v1"
    downgraded["hash_chain"] = dict(downgraded["hash_chain"])
    downgraded["hash_chain"]["document_sha256"] = document_hash(downgraded)

    rec_file = tmp_path / "downgraded.json"
    rec_file.write_text(json.dumps(downgraded), encoding="utf-8")

    pub_file = keys_dir / "default" / "public_keys.json"

    # 1. The CLI's --pubkey mode must still run the downgrade check, using the public key's created_at, and fail
    out_skip = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_receipt.py"), str(rec_file), "--pubkey", str(pub_file)],
        capture_output=True,
        text=True,
    )
    assert out_skip.returncode == 1
    assert "FAIL" in out_skip.stdout

    # 2. With --signing-enabled-since, downgrade is detected and fails
    out_fail = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_receipt.py"),
            str(rec_file),
            "--pubkey",
            str(pub_file),
            "--signing-enabled-since",
            "2026-11-21T00:00:00Z",
        ],
        capture_output=True,
        text=True,
    )
    assert out_fail.returncode == 1
    assert "FAIL" in out_fail.stdout
    assert "No signature" in out_fail.stdout

    # 3. Signing unavailable record prints FAIL and exits with code 1
    unavail = dict(downgraded)
    unavail["extra"] = {"signing": "unavailable: test write failure"}
    unavail["hash_chain"] = dict(unavail["hash_chain"])
    unavail["hash_chain"]["document_sha256"] = document_hash(unavail)
    unavail_file = tmp_path / "unavail.json"
    unavail_file.write_text(json.dumps(unavail), encoding="utf-8")

    out_warn = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_receipt.py"), str(unavail_file)],
        capture_output=True,
        text=True,
    )
    assert out_warn.returncode == 1
    assert "FAIL" in out_warn.stdout
    assert "signing unavailable" in out_warn.stdout


def test_downgraded_record_backdated_created_at_flagged_using_stored_task_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))
    get_or_create_signing_key("default")

    # Stored task's created_at is after signing enabled
    after_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=5)
    trusted_created_at = after_dt.isoformat()

    # Tampered record forged to v1 with backdated created_at (before signing enabled)
    rec = _make_dummy_receipt()
    rec["created_at"] = "2026-10-01T12:00:00Z"
    rec["receipt_version"] = "v1"
    forged = seal(rec, sign=False)

    # Without trusted time, a v0/v1 record FAILS when signing is enabled
    res_untrusted = verify_receipt(forged)
    assert res_untrusted["ok"] is False
    assert res_untrusted["scope"] == "unsigned_after_signing_enabled"

    # With stored task time passed, the stored task's time wins and flags it
    res = verify_receipt(forged, trusted_started_at=trusted_created_at, trusted_org_id="default")
    assert res["ok"] is False
    assert res["scope"] == "unsigned_after_signing_enabled"
    assert "No signature, but signing was enabled when this record was made" in res["message"]


def test_record_org_id_changed_is_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))
    get_or_create_signing_key("default")

    rec = _make_dummy_receipt()
    rec["created_at"] = "2026-10-01T12:00:00Z"
    rec["receipt_version"] = "v1"
    sealed = seal(rec, sign=False)

    # Tamper org_id in record extra
    tampered_org = copy.deepcopy(sealed)
    tampered_org["extra"] = {"org_id": "rogue_org"}
    tampered_org["hash_chain"]["document_sha256"] = document_hash(tampered_org)

    res = verify_receipt(tampered_org, trusted_started_at="2026-10-01T12:00:00Z", trusted_org_id="default")
    assert res["ok"] is False
    assert res["scope"] == "record_fields_mismatch"
    assert "differs from stored task" in res["message"]

    # Tamper started_at in record
    tampered_time = copy.deepcopy(sealed)
    tampered_time["started_at"] = "2026-10-01T13:00:00Z"
    tampered_time["hash_chain"]["document_sha256"] = document_hash(tampered_time)

    res_time = verify_receipt(tampered_time, trusted_started_at="2026-10-01T12:00:00Z", trusted_org_id="default")
    assert res_time["ok"] is False
    assert res_time["scope"] == "record_fields_mismatch"
    assert "differs from stored task" in res_time["message"]


def test_imported_record_with_no_stored_task_shows_time_taken_from_record_itself(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))
    get_or_create_signing_key("default")

    # Record from before signing enabled, verified with no stored task
    rec = _make_dummy_receipt()
    rec["created_at"] = "2026-10-01T12:00:00Z"
    rec["receipt_version"] = "v1"
    sealed = seal(rec, sign=False)

    # When signing is enabled, a v0/v1 record without trusted time from storage FAILS
    res = verify_receipt(sealed, trusted_started_at=None, trusted_org_id=None)
    assert res["ok"] is False
    assert res["scope"] == "unsigned_after_signing_enabled"
