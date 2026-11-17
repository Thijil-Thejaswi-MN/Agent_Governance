"""Audit finding A3: the receipt's hash chain covered only `events`; approvals, approvers,
deliveries, the initial boundary, termination and isolation level could be edited and the
verifier still said PASS. v1 receipts add a SHA-256 over the whole record."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

from demo.security_monitor.app.governance.receipt import GENESIS_HASH, chain_entries, seal, verify_receipt

ROOT = Path(__file__).resolve().parents[3]


def _v1() -> dict:
    events = [
        {"timestamp": "t1", "source": "tool_broker", "kind": "file_read", "target": "input/a.csv", "verdict": "INSIDE"},
        {"timestamp": "t2", "source": "tool_broker", "kind": "request_access", "target": "docs/b.txt", "verdict": "OUTSIDE"},
    ]
    final = chain_entries(events)
    return seal({
        "receipt_version": "v1",
        "task_id": "task_x",
        "requester": "asha",
        "prompt_sha256": "abc",
        "initial_boundary": {"version": 1, "files_read": ["input/a.csv"]},
        "expansions": [{"request_id": "exp_1", "decision": "DENIED", "approver": "operator:asha", "risk_tier": "MEDIUM"}],
        "deliveries": [],
        "event_counts": {"total": 2, "by_verdict": {"INSIDE": 1, "OUTSIDE": 1}},
        "outside_events": [{"index": 1, "target": "docs/b.txt"}],
        "isolation_level": "landlock+seccomp+cgroup",
        "termination": {"reason": "completed"},
        "events": events,
        "hash_chain": {"algorithm": "sha256", "genesis": GENESIS_HASH, "count": 2, "final_hash": final},
    })


def test_a_sealed_record_verifies_after_a_file_round_trip(tmp_path: Path) -> None:
    r = _v1()
    assert verify_receipt(r) == {"ok": True, "scope": "whole_record", "message": "ok (2 entries; whole record checked)",
                                 "final_hash": r["hash_chain"]["final_hash"]}
    p = tmp_path / "task_x.json"
    p.write_text(json.dumps(r, indent=1))
    assert verify_receipt(json.loads(p.read_text()))["ok"] is True
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "verify_receipt.py"), str(p)], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.startswith("PASS"), out.stdout


def test_every_edit_the_audit_made_is_now_caught() -> None:
    edits = {
        "decision": lambda r: r["expansions"][0].update(decision="APPROVED"),
        "approver": lambda r: r["expansions"][0].update(approver="operator:someone_else"),
        "risk": lambda r: r["expansions"][0].update(risk_tier="LOW"),
        "outside_events": lambda r: r.update(outside_events=[]),
        "termination": lambda r: r.update(termination={"reason": "operator_stop"}),
        "isolation": lambda r: r.update(isolation_level="none"),
        "boundary": lambda r: r["initial_boundary"]["files_read"].append("input/payroll.csv"),
        "task_id": lambda r: r.update(task_id="task_y"),
        "requester": lambda r: r.update(requester="mallory"),
        "prompt": lambda r: r.update(prompt_sha256="def"),
    }
    for name, edit in edits.items():
        r = _v1()
        edit(r)
        res = verify_receipt(r)
        assert res["ok"] is False and "whole-record hash" in res["message"], (name, res)


def test_missing_parts_and_a_bare_record_fail() -> None:
    bare = {"events": [], "hash_chain": {"count": 0, "final_hash": "0" * 64}, "event_counts": {"by_verdict": {}}}
    assert verify_receipt(bare)["ok"] is False and "missing fields" in verify_receipt(bare)["message"]
    r = _v1()
    del r["hash_chain"]["document_sha256"]
    assert verify_receipt(r) == {"ok": False, "scope": None, "message": "whole-record hash missing",
                                 "final_hash": r["hash_chain"]["final_hash"]}
    r = _v1()
    del r["expansions"]
    assert "missing fields: expansions" in verify_receipt(r)["message"]
    assert verify_receipt([1, 2])["ok"] is False


def test_older_v0_records_still_check_but_say_events_only() -> None:
    r = _v1()
    r = copy.deepcopy(r)
    r.pop("receipt_version")
    del r["hash_chain"]["document_sha256"]
    res = verify_receipt(r)
    assert res["ok"] is True and res["scope"] == "events_only" and "only the event list" in res["message"]
    r["events"][0]["target"] = "input/other.csv"
    assert verify_receipt(r)["ok"] is False
