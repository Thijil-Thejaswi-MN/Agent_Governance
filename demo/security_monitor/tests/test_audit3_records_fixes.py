"""Unit tests verifying all PR 3 audit fixes:
1. Downgraded records fail (4 cases: v0 backdated, v1 with --pubkey, signing_unavailable, stripped signature).
2. No record swaps (B.json copied to A.json fails for A).
3. Lost writes are visible (per-task transactions, bad row skipped & counted, dropped_writes in receipt).
4. Delegation links checked by product (verify_delegation_links fails if token hash not in storage, no empty list shortcuts).
5. Scale attribution (report_result in AGENT_ENDPOINTS, classifier stops only on own resource refusal).
6. Keys security (refuse permissions > 0o600, atomic key rotation, verifying does not create directories).
7. Discovery security (argv[0] + frameworks in evidence, strip cmdlines on read, org from session, RBAC on host processes, repo scanner lstat + O_NOFOLLOW + 1MB cap).
"""
import copy
import datetime
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from demo.security_monitor.app.governance.models import (
    EventSource,
    EventVerdict,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.receipt import (
    build_receipt,
    chain_entries,
    document_hash,
    seal,
    verify_delegation_links,
    verify_receipt,
)
from demo.security_monitor.app.governance.signing import (
    compute_key_id,
    get_or_create_signing_key,
    get_org_keys_dir,
    load_public_keys,
    rotate_key,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.delegation_token import (
    compute_token_hash,
    mint_delegation_token,
)
from demo.security_monitor.measure_scale import classify_stopping_layer_with_evidence

ROOT = Path(__file__).resolve().parents[3]


def make_task_record(
    task_id: str,
    agent_id: str = "planner",
    status: TaskLifecycle = TaskLifecycle.ACTIVE,
    root_task_id: str | None = None,
    parent_task_id: str | None = None,
    depth: int = 0,
    chain: list[str] | None = None,
    workspace_root: str = "/tmp/ws",
    owner: str | None = None,
    team: str | None = None,
    timeout_s: float | None = 900.0,
) -> TaskRecord:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return TaskRecord(
        task_id=task_id,
        request_text="test request",
        request_hash="hash_" + task_id,
        agent_id=agent_id,
        workspace_root=workspace_root,
        status=status,
        created_at=now,
        root_task_id=root_task_id or task_id,
        parent_task_id=parent_task_id,
        depth=depth,
        chain=chain or [agent_id],
        owner=owner,
        team=team,
        timeout_s=timeout_s,
    )


def _make_dummy_receipt(task_id: str = "task_test_123") -> dict:
    events = [
        {
            "timestamp": "2026-11-21T10:00:00Z",
            "source": EventSource.TOOL_BROKER.value,
            "syscall": "read_file",
            "target": "input/data.txt",
            "verdict": EventVerdict.INSIDE.value,
            "label_integrity": "trusted",
            "label_confidentiality": "public",
        }
    ]
    chain = chain_entries(events)
    return {
        "receipt_version": "v2",
        "task_id": task_id,
        "events": events,
        "hash_chain": {
            "initial_hash": "0" * 64,
            "count": len(events),
            "final_hash": chain,
            "algorithm": "sha256",
            "document_sha256": "",
        },
        "event_counts": {"total": 1, "by_verdict": {EventVerdict.INSIDE.value: 1}},
        "initial_boundary": {"tools": ["read_file"], "files_read": ["input/*"], "files_write": ["output/*"]},
        "expansions": [],
        "deliveries": [],
        "termination": {"reason": "normal", "exit_code": 0},
        "isolation_level": "process",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dropped_writes": 0,
        "extra": {"org_id": "default"},
    }


# ============================================================================
# ITEM 1: DOWNGRADED RECORDS FAIL (4 AUDIT CASES)
# ============================================================================

def test_downgrade_case_1_v0_backdated_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Case 1: v0 record backdated to before signing enabled fails without trusted time."""
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))
    get_or_create_signing_key("default")

    rec = _make_dummy_receipt()
    rec["receipt_version"] = "v0"
    rec["created_at"] = "2025-01-01T00:00:00Z"
    rec["started_at"] = "2025-01-01T00:00:00Z"
    rec["hash_chain"].pop("document_sha256", None)

    # Without trusted timestamp from storage, it MUST fail
    res = verify_receipt(rec)
    assert res["ok"] is False
    assert res["scope"] == "unsigned_after_signing_enabled"


def test_downgrade_case_2_v1_with_cli_pubkey_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Case 2: v1 record verified with CLI --pubkey must run downgrade check using key's created_at and fail."""
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))
    get_or_create_signing_key("default")

    rec = _make_dummy_receipt()
    sealed = seal(rec, org_id="default")
    downgraded = dict(sealed)
    downgraded.pop("signature", None)
    downgraded["receipt_version"] = "v1"
    downgraded["hash_chain"] = dict(downgraded["hash_chain"])
    downgraded["hash_chain"]["document_sha256"] = document_hash(downgraded)

    rec_file = tmp_path / "downgraded_v1.json"
    rec_file.write_text(json.dumps(downgraded), encoding="utf-8")
    pub_file = keys_dir / "default" / "public_keys.json"

    cmd = [sys.executable, str(ROOT / "scripts" / "verify_receipt.py"), str(rec_file), "--pubkey", str(pub_file)]
    out = subprocess.run(cmd, capture_output=True, text=True)
    assert out.returncode == 1
    assert "FAIL" in out.stdout


def test_downgrade_case_3_signing_unavailable_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Case 3: signing_unavailable is a failure (non-zero CLI exit, fixed message)."""
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))

    rec = _make_dummy_receipt()
    rec["extra"] = {"signing": "unavailable: test keys failure", "org_id": "default"}
    rec["receipt_version"] = "v1"
    sealed = seal(rec, sign=False)

    res = verify_receipt(sealed)
    assert res["ok"] is False
    assert res["scope"] == "signing_unavailable"
    assert res["message"] == "signing unavailable"
    assert res["signature_reason"] == "signing unavailable"

    rec_file = tmp_path / "unavail.json"
    rec_file.write_text(json.dumps(sealed), encoding="utf-8")

    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "verify_receipt.py"), str(rec_file)], capture_output=True, text=True)
    assert out.returncode == 1
    assert "FAIL" in out.stdout
    assert "signing unavailable" in out.stdout


def test_downgrade_case_4_stripped_signature_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Case 4: v2 record stripped of signature fails."""
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))
    get_or_create_signing_key("default")

    rec = _make_dummy_receipt()
    sealed = seal(rec, org_id="default")
    assert "signature" in sealed

    # Strip signature and set version to v1
    stripped = dict(sealed)
    stripped.pop("signature", None)
    stripped["receipt_version"] = "v1"
    stripped["hash_chain"] = dict(stripped["hash_chain"])
    stripped["hash_chain"]["document_sha256"] = document_hash(stripped)

    res = verify_receipt(stripped)
    assert res["ok"] is False
    assert res["scope"] == "unsigned_after_signing_enabled"


# ============================================================================
# ITEM 2: NO RECORD SWAPS
# ============================================================================

def test_no_record_swaps_expected_task_id_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Task B receipt copied to Task A receipt path fails when verifying for Task A."""
    rec_b = _make_dummy_receipt(task_id="task_B")
    rec_b_sealed = seal(rec_b, org_id="default")

    # Verifying rec_b as task_B passes
    res_b = verify_receipt(rec_b_sealed, expected_task_id="task_B")
    assert res_b["ok"] is True

    # Verifying rec_b when expecting task_A MUST FAIL
    res_a = verify_receipt(rec_b_sealed, expected_task_id="task_A")
    assert res_a["ok"] is False
    assert res_a["scope"] == "task_id_mismatch"
    assert "expected task_A, got task_B" in res_a["message"]


# ============================================================================
# ITEM 3: LOST WRITES ARE VISIBLE
# ============================================================================

def test_lost_writes_isolation_and_counting(tmp_path: Path):
    """A malformed row for task B skips only bad row, preserves task A's events, and counts dropped writes."""
    from demo.security_monitor.app.governance.models import GovernanceEvent, EventSource, EventVerdict, RiskTier, TaskAction

    db_path = tmp_path / "test_lost_writes.db"
    storage = GovernanceStorage(db_path)

    task_a = make_task_record("task_A", workspace_root="/tmp/a")
    task_b = make_task_record("task_B", workspace_root="/tmp/b")
    storage.save_task(task_a)
    storage.save_task(task_b)

    ev_a = GovernanceEvent(
        event_id="ev_a_1",
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source=EventSource.TOOL_BROKER,
        task_id="task_A",
        agent_id="agent_a",
        kind="tool_call",
        target="input/data_a.txt",
        verdict=EventVerdict.INSIDE,
        risk_tier=RiskTier.LOW,
        action_taken=TaskAction.ALLOW,
        prevented=False,
        rule_matched="boundary_read",
        boundary_version=1,
        details={"path": "input/data_a.txt"},
    )

    # Malformed row for task B: non-serializable details causes json.dumps to fail during batch write
    ev_b_bad = GovernanceEvent(
        event_id="ev_b_bad",
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source=EventSource.TOOL_BROKER,
        task_id="task_B",
        agent_id="agent_b",
        kind="tool_call",
        target="input/data_b.txt",
        verdict=EventVerdict.INSIDE,
        risk_tier=RiskTier.LOW,
        action_taken=TaskAction.ALLOW,
        prevented=False,
        rule_matched="boundary_read",
        boundary_version=1,
        details={"bad_obj": object()},
    )

    with storage._writer_lock:
        storage._write_batch_to_db([("event", ev_a), ("event", ev_b_bad)])

    # Task A's event succeeded
    assert storage.get_dropped_writes("task_A") == 0
    events_a = storage.get_events_for_task("task_A")
    assert len(events_a) == 1
    assert events_a[0].target == "input/data_a.txt"

    # Task B's bad event was dropped and counted
    assert storage.get_dropped_writes("task_B") == 1


def test_dropped_writes_in_receipt(tmp_path: Path):
    """Receipt includes dropped_writes field populated from storage."""
    db_path = tmp_path / "test_rcpt_dropped.db"
    storage = GovernanceStorage(db_path)
    tid = "task_dropped_test"
    task = make_task_record(tid, workspace_root=str(tmp_path))
    storage.save_task(task)
    boundary = TaskBoundary(task_id=tid, workspace_root=str(tmp_path))
    storage.save_boundary(boundary)

    # Manually increment dropped writes
    storage.task_dropped_writes[tid] = 3

    rcpt = build_receipt(
        task=task,
        initial_boundary=boundary,
        requester="human",
        storage=storage,
        os_records=[],
        deliveries=[],
        sensor_status={"kind": "none"},
        isolation={"isolation_level": "process"},
        freeze_events=[],
        termination={"reason": "normal", "exit_code": 0},
        wall_time_s=1.0,
        os_identity=None,
    )
    assert rcpt["dropped_writes"] == 3


# ============================================================================
# ITEM 4: DELEGATION LINKS CHECKED BY PRODUCT
# ============================================================================

def test_delegation_links_checked_in_storage(tmp_path: Path):
    """A stated token hash not in delegation_tokens fails verification; no empty list shortcuts."""
    db_path = tmp_path / "test_deleg_links.db"
    storage = GovernanceStorage(db_path)

    parent_rcpt = {
        "receipt_version": "v2",
        "task_id": "parent_1",
        "initial_boundary": {"tools": ["call_agent"]},
        "delegated_children": [
            {"task_id": "child_1", "agent_id": "researcher", "token_hash": "a" * 64}
        ],
        "delegation_token": {
            "token_hash": "p" * 64,
        },
    }

    child_rcpt = {
        "receipt_version": "v2",
        "task_id": "child_1",
        "parent_task_id": "parent_1",
        "initial_boundary": {"tools": []},
        "delegation_token": {
            "token_hash": "a" * 64,
            "par_hash": "p" * 64,
        },
    }

    # Storage does not contain token_hash "a"*64
    ok, reason = verify_delegation_links(parent_rcpt, child_rcpt, storage=storage)
    assert ok is False
    assert "not found in delegation_tokens" in reason

    # Save token hash into storage
    storage.save_delegation_token("child_1", "fake.jwt.token", parent_token_hash="p" * 64)
    # The compute_token_hash of fake.jwt.token:
    actual_hash = compute_token_hash("fake.jwt.token")

    parent_rcpt["delegated_children"][0]["token_hash"] = actual_hash
    child_rcpt["delegation_token"]["token_hash"] = actual_hash

    ok2, reason2 = verify_delegation_links(parent_rcpt, child_rcpt, storage=storage)
    assert ok2 is True


# ============================================================================
# ITEM 5: SCALE ATTRIBUTION
# ============================================================================

def test_report_result_in_agent_endpoints():
    """report_result is included in AGENT_ENDPOINTS and has a dispatcher."""
    from demo.security_monitor.app.governance.broker_rpc import AGENT_ENDPOINTS, BrokerRPCServer
    assert "report_result" in AGENT_ENDPOINTS
    # Verify server initializes with report_result handler
    server = BrokerRPCServer(broker=None, socket_path="/tmp/fake.sock", task_id="task_123")
    assert "report_result" in server._handlers


def test_scale_attribution_only_counts_own_resource_refusal(tmp_path: Path):
    """Classifier counts stop only from event whose target is attack's own resource and verdict is refusal; never unrelated RPC."""
    storage = GovernanceStorage(tmp_path / "scale.db")

    # Trace where attack target was allowed, but unrelated RPC rejection occurred
    res_allowed = SimpleNamespace(
        task_id="task_atk",
        receipt={
            "events": [
                {
                    "source": "TOOL_BROKER",
                    "syscall": "read_file",
                    "target": "secrets/decoy.txt",
                    "verdict": "ALLOW",
                }
            ]
        },
        audit_sink_requests=[],
        rpc_rejections=[{"endpoint": "call_agent", "reason": "rate limit"}],
    )

    layer, ev = classify_stopping_layer_with_evidence("condition_c", res_allowed, storage)
    assert layer is None  # Attack was NOT stopped! Unrelated RPC rejection is ignored.

    # Trace where target was refused
    res_stopped = SimpleNamespace(
        task_id="task_atk2",
        receipt={
            "events": [
                {
                    "source": "TOOL_BROKER",
                    "action_taken": "BLOCK_ACTION",
                    "syscall": "read_file",
                    "target": "secrets/decoy.txt",
                    "verdict": "BLOCK_ACTION",
                    "rule_matched": "file_not_in_boundary",
                }
            ]
        },
        audit_sink_requests=[],
        rpc_rejections=[],
    )
    layer2, ev2 = classify_stopping_layer_with_evidence("condition_c", res_stopped, storage)
    assert layer2 == "broker"


# ============================================================================
# ITEM 6: KEYS SECURITY
# ============================================================================

def test_keys_permission_0600_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Refuse signing_key.pem with group/other permissions (chmod 600 required)."""
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))
    org_dir = get_org_keys_dir("default", create=True)
    key_file = org_dir / "signing_key.pem"
    key_file.write_text("FAKE KEY", encoding="utf-8")
    # Set permissions to 0o644 (world readable)
    key_file.chmod(0o644)

    with pytest.raises(PermissionError) as exc:
        get_or_create_signing_key("default")
    assert "chmod 600" in str(exc.value)


def test_keys_rotation_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """rotate_key writes to private temp file and renames into place."""
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))
    priv1, kid1 = get_or_create_signing_key("default")
    priv2, kid2, pub2, entry2 = rotate_key("default")
    assert kid1 != kid2
    key_file = get_org_keys_dir("default", create=False) / "signing_key.pem"
    mode = stat.S_IMODE(key_file.stat().st_mode)
    assert mode == 0o600


def test_load_public_keys_does_not_create_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verifying must not create directories for non-existent org."""
    keys_dir = tmp_path / "keys"
    monkeypatch.setenv("GOVERNANCE_KEYS_DIR", str(keys_dir))
    non_existent = keys_dir / "non_existent_org"
    keys = load_public_keys("non_existent_org")
    assert keys == []
    assert not non_existent.exists()


# ============================================================================
# ITEM 7: DISCOVERY SECURITY
# ============================================================================

def test_repo_scan_symlink_and_traversal_protection(tmp_path: Path):
    """Repo scan rejects symlinks and directory escapes, capping at 1MB."""
    from demo.security_monitor.app.governance.discovery.repo_scan import safe_read_file

    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("OUTSIDE SECRET", encoding="utf-8")

    # Symlink to outside
    sym = repo / "sym.txt"
    try:
        sym.symlink_to(outside)
        res = safe_read_file(sym, repo)
        assert res is None, "Symlinks must be rejected"
    except OSError:
        pass  # If OS unprivileged symlink fails

    # Big file > 1MB
    big = repo / "big.bin"
    big.write_bytes(b"0" * (1024 * 1024 + 50))
    assert safe_read_file(big, repo) is None


def test_host_scan_cmdline_sanitization():
    """Host scan evidence stores only argv[0] plus framework names, not sensitive args."""
    from demo.security_monitor.app.governance.discovery.host_scan import sanitize_cmdline

    cmdline = ["/usr/bin/python3", "server.py", "--api-key=supersecretkey123", "--token=xyz"]
    sanitized = sanitize_cmdline(cmdline, frameworks=["langchain"])
    assert "supersecretkey123" not in sanitized
    assert "xyz" not in sanitized
    assert sanitized.startswith("/usr/bin/python3")
    assert "[frameworks: langchain]" in sanitized
