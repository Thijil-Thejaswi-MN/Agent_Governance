import os, json, pytest
from pathlib import Path
from fastapi.testclient import TestClient
from demo.security_monitor.app.gateway.server import app
from demo.security_monitor.app.governance.roles import Role, hash_token
from demo.security_monitor.app.governance.receipt import chain_entries

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def users_env(monkeypatch, tmp_path):
    users_file = tmp_path / "users.json"
    users_data = [
        {"name": "Alex", "role": "developer", "team": "core", "token_sha256": hash_token("dev-token")},
        {"name": "Riley", "role": "auditor", "team": "audit", "token_sha256": hash_token("auditor-token")},
    ]
    users_file.write_text(json.dumps(users_data))
    monkeypatch.setenv("GOVERNANCE_USERS_FILE", str(users_file))
    return {
        "developer": {"Authorization": "Bearer dev-token"},
        "auditor": {"Authorization": "Bearer auditor-token"},
    }

def test_records_summary_empty(client, users_env, monkeypatch, tmp_path):
    rec_dir = tmp_path / "receipts"
    rec_dir.mkdir()
    monkeypatch.setenv("RECEIPTS_DIR", str(rec_dir))
    resp = client.get("/api/governance/records/summary", headers=users_env["auditor"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["verified"] == 0
    assert data["failed"] == 0
    assert data["failed_ids"] == []

def test_records_summary_all_verified(client, users_env, monkeypatch, tmp_path):
    rec_dir = tmp_path / "receipts"
    rec_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("RECEIPTS_DIR", str(rec_dir))
    ev1 = [{"verdict": "INSIDE", "target": "a"}]
    final1 = chain_entries(ev1)
    (rec_dir / "task_01.json").write_text(json.dumps({
        "task_id": "task_01",
        "events": ev1,
        "hash_chain": {"count": len(ev1), "final_hash": final1}
    }))

    ev2 = [{"verdict": "INSIDE", "target": "b"}]
    final2 = chain_entries(ev2)
    (rec_dir / "task_02.json").write_text(json.dumps({
        "task_id": "task_02",
        "events": ev2,
        "hash_chain": {"count": len(ev2), "final_hash": final2}
    }))

    resp = client.get("/api/governance/records/summary", headers=users_env["auditor"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert data["verified"] == 2
    assert data["failed"] == 0
    assert data["failed_ids"] == []

def test_records_summary_failed_check(client, users_env, monkeypatch, tmp_path):
    rec_dir = tmp_path / "receipts"
    rec_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("RECEIPTS_DIR", str(rec_dir))
    ev1 = [{"verdict": "INSIDE", "target": "a"}]
    final1 = chain_entries(ev1)
    (rec_dir / "task_good.json").write_text(json.dumps({
        "task_id": "task_good",
        "events": ev1,
        "hash_chain": {"count": len(ev1), "final_hash": final1}
    }))

    ev2 = [{"verdict": "INSIDE", "target": "b"}]
    final2 = chain_entries(ev2)
    # Alter entry without updating hash chain
    ev2[0]["target"] = "corrupted"
    (rec_dir / "task_altered.json").write_text(json.dumps({
        "task_id": "task_altered",
        "events": ev2,
        "hash_chain": {"count": len(ev2), "final_hash": final2}
    }))

    resp = client.get("/api/governance/records/summary", headers=users_env["auditor"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert data["verified"] == 1
    assert data["failed"] == 1
    assert "task_altered" in data["failed_ids"]

def test_records_summary_permissions(client, users_env, monkeypatch, tmp_path):
    rec_dir = tmp_path / "receipts"
    rec_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("RECEIPTS_DIR", str(rec_dir))
    resp_dev = client.get("/api/governance/records/summary", headers=users_env["developer"])
    assert resp_dev.status_code == 403
    resp_aud = client.get("/api/governance/records/summary", headers=users_env["auditor"])
    assert resp_aud.status_code == 200


def test_records_summary_lists_each_record_by_what_was_checked(client, users_env, monkeypatch, tmp_path):
    """The console labels each row from these lists: a whole-record (v1) check, an events-only
    (v0) check, or a failure. A run with no stored record is in none of them."""
    from demo.security_monitor.tests.test_receipt_whole_record import _v1

    rec_dir = tmp_path / "receipts"
    rec_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("RECEIPTS_DIR", str(rec_dir))
    from demo.security_monitor.app.governance.receipt import seal
    v1 = _v1()
    v1["task_id"] = "task_v1"
    v1["hash_chain"].pop("document_sha256", None)  # re-seal after changing the task id
    (rec_dir / "task_v1.json").write_text(json.dumps(seal(v1)))
    ev = [{"verdict": "INSIDE", "target": "a"}]
    (rec_dir / "task_v0.json").write_text(json.dumps(
        {"task_id": "task_v0", "events": ev, "hash_chain": {"count": 1, "final_hash": chain_entries(ev)}}))
    (rec_dir / "task_bad.json").write_text(json.dumps(
        {"task_id": "task_bad", "events": ev, "hash_chain": {"count": 1, "final_hash": "0" * 64}}))

    data = client.get("/api/governance/records/summary", headers=users_env["auditor"]).json()
    assert sorted(data["verified_ids"]) == ["task_v0", "task_v1"]
    assert data["events_only_ids"] == ["task_v0"]
    assert data["failed_ids"] == ["task_bad"]
    assert "task_none" not in data["verified_ids"] + data["failed_ids"]
