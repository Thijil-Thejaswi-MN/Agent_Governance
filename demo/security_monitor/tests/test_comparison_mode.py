"""Tests for Feature 3: Kernel-off comparison mode (admin only)."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from demo.security_monitor.app.gateway.server import create_app
from demo.security_monitor.app.governance import api as gov_api
from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec
from demo.security_monitor.app.governance.models import (
    EventSource,
    EventVerdict,
    GovernanceEvent,
    RiskTier,
    TaskAction,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.run_manager import PRESETS
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.inventory import AgentInventoryService

IS_LINUX = sys.platform == "linux"
linux_only = pytest.mark.skipif(not IS_LINUX, reason="Requires Linux (WSL2)")
needs_scope = pytest.mark.os_layer

ADMIN_TOKEN = "admin_tok_cmp"
ADMIN = {"X-Operator-Token": ADMIN_TOKEN}
DEV_TOKEN = "dev_tok_cmp"
DEV = {"X-Operator-Token": DEV_TOKEN}


@linux_only
@needs_scope
def test_sentinel_file_masked_in_condition_b(tmp_path: Path) -> None:
    """Proves that a Condition B run cannot read a sentinel file written to the real user home,
    because eval_world mounts tmpfs over real home."""
    sentinel_name = f".sentinel_test_{uuid.uuid4().hex[:8]}.txt"
    sentinel_path = Path.home() / sentinel_name
    sentinel_secret = f"REAL_HOME_SECRET_{uuid.uuid4().hex}"
    sentinel_path.write_text(sentinel_secret, encoding="utf-8")

    try:
        storage = GovernanceStorage(tmp_path / "gov.db")
        launcher = TaskLauncher(storage)

        steps = [
            {"tool": "run_command", "args": {"command": f"cat ~/{sentinel_name}"}},
            {"tool": "write_file", "args": {"file_path": "output/done.txt", "content": "done"}},
            {"final": "done"},
        ]

        spec = TaskSpec(
            prompt="check sentinel file in real home",
            condition="B",
            use_eval_world=True,
            inputs={"input/test.txt": "dummy"},
            llm={"provider": "scripted", "steps": steps},
            boundary_model="v1.1",
        )

        res = launcher.run(spec)
        assert res.aborted is None

        # Verify agent's output never contains the secret from the real home
        th = res.shim_result.get("tool_history", [])
        assert len(th) >= 1
        step0 = th[0]
        assert step0["tool"] == "run_command"
        assert sentinel_secret not in step0["output"].get("stdout", "")
        assert "No such file" in step0["output"].get("stderr", "") or step0["output"].get("exit_code") != 0
        assert res.receipt.get("condition") == "B"
    finally:
        if sentinel_path.exists():
            sentinel_path.unlink()


@linux_only
@needs_scope
def test_comparison_mode_condition_b_reads_decoy_vs_condition_c(tmp_path: Path) -> None:
    """Proves:
    - In Condition B (kernel lock off): decoy is read and canary appears in output.
    - In Condition C (kernel lock on): decoy read is blocked by Landlock (Permission denied)."""
    p = PRESETS["shell_injection"]
    storage = GovernanceStorage(tmp_path / "gov.db")

    # --- Condition B (kernel lock off) ---
    canary_b = f"CANARY_COND_B_{uuid.uuid4().hex[:12]}"
    launcher_b = TaskLauncher(storage)
    spec_b = TaskSpec(
        prompt=p["prompt"],
        condition="B",
        use_eval_world=True,
        inputs=p["files"],
        llm={"provider": "scripted", "steps": p["scripted_steps"]},
        decoys=p["decoys"],
        canary=canary_b,
        boundary_model="v1.1",
    )
    res_b = launcher_b.run(spec_b)
    assert res_b.aborted is None

    # Step 1: attempted decoy read via run_command -> succeeded in Condition B
    th_b = res_b.shim_result.get("tool_history", [])
    assert len(th_b) >= 2
    step1_b = th_b[1]
    assert step1_b["tool"] == "run_command"
    assert step1_b["output"]["exit_code"] == 0
    assert canary_b in step1_b["output"]["stdout"], "Canary must be read successfully in Condition B"

    # OS sensor detected outside access without freeze
    outside_b = [e for e in res_b.receipt.get("events", []) if e.get("verdict") == "OUTSIDE"]
    assert len(outside_b) > 0
    assert outside_b[0].get("prevented") is False

    # --- Condition C (kernel lock on) ---
    canary_c = f"CANARY_COND_C_{uuid.uuid4().hex[:12]}"
    launcher_c = TaskLauncher(storage)
    spec_c = TaskSpec(
        prompt=p["prompt"],
        condition="C",
        use_eval_world=True,
        inputs=p["files"],
        llm={"provider": "scripted", "steps": p["scripted_steps"]},
        decoys=p["decoys"],
        canary=canary_c,
        boundary_model="v1.1",
    )
    res_c = launcher_c.run(spec_c)
    assert res_c.aborted is None

    # Step 1: attempted decoy read via run_command -> Landlock EACCES denial in Condition C
    th_c = res_c.shim_result.get("tool_history", [])
    assert len(th_c) >= 2
    step1_c = th_c[1]
    assert step1_c["tool"] == "run_command"
    assert step1_c["output"]["exit_code"] != 0
    assert "Permission denied" in step1_c["output"]["stderr"]
    assert canary_c not in step1_c["output"]["stdout"], "Canary must never appear in Condition C"

    # OS sensor detected Landlock denial
    landlock_denials = [
        e for e in res_c.receipt.get("events", [])
        if e.get("prevented_by") == "landlock" or "Permission denied" in str(e)
    ]
    assert len(landlock_denials) > 0


def test_comparison_mode_server_security_checks(tmp_path: Path, monkeypatch) -> None:
    """Verifies server-side rejection of invalid comparison mode requests:
    - 403 Forbidden for non-admin roles
    - 422 for missing preset / custom requests
    - 422 for uploaded files
    - 422 for presets without decoys"""
    users = tmp_path / "users.json"
    users.write_text(
        json.dumps([
            {"name": "Dev", "role": "developer", "team": "core", "token_sha256": hashlib.sha256(DEV_TOKEN.encode()).hexdigest()},
            {"name": "Admin", "role": "admin", "team": "core", "token_sha256": hashlib.sha256(ADMIN_TOKEN.encode()).hexdigest()},
        ])
    )
    db = tmp_path / "gov.db"
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db))
    monkeypatch.setenv("RECEIPTS_DIR", str(tmp_path / "receipts"))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("GOVERNANCE_USERS_FILE", str(users))

    client = TestClient(create_app())

    # 1. Non-admin (developer) gets 403
    r1 = client.post(
        "/api/governance/run",
        headers=DEV,
        json={"prompt": "test", "preset": "shell_injection", "comparison_mode": True},
    )
    assert r1.status_code == 403
    assert "Comparison mode requires admin role" in r1.json()["detail"]

    # 2. Admin with custom request (no preset) gets 422
    r2 = client.post(
        "/api/governance/run",
        headers=ADMIN,
        json={"prompt": "custom attack", "preset": None, "comparison_mode": True},
    )
    assert r2.status_code == 422
    assert "Comparison mode requires a preset with decoys" in r2.json()["detail"]

    # 3. Admin with preset that has no decoys gets 422
    r3 = client.post(
        "/api/governance/run",
        headers=ADMIN,
        json={"prompt": "summarise", "preset": "summarise_csv", "comparison_mode": True},
    )
    assert r3.status_code == 422
    assert "Comparison mode requires a preset with decoys" in r3.json()["detail"]

    # 4. Admin with uploaded files gets 422
    r4 = client.post(
        "/api/governance/run",
        headers=ADMIN,
        json={
            "prompt": "attack",
            "preset": "shell_injection",
            "files": {"input/extra.txt": "extra"},
            "comparison_mode": True,
        },
    )
    assert r4.status_code == 422
    assert "Comparison mode does not allow uploaded files" in r4.json()["detail"]


def test_comparison_mode_excluded_from_fleet_and_overview(tmp_path: Path, monkeypatch) -> None:
    """Verifies that Condition B comparison tasks and their outside events:
    - Are excluded from /fleet/summary
    - Are excluded from inventory risk, violations and alerts
    - Are included in /incidents with label 'Comparison run: decoy was read (would be blocked by the kernel lock)'
    - Are included in /tasks/{task_id}/report with layer 'comparison_unlocked'"""
    users = tmp_path / "users.json"
    users.write_text(
        json.dumps([
            {"name": "Admin", "role": "admin", "team": "core", "token_sha256": hashlib.sha256(ADMIN_TOKEN.encode()).hexdigest()},
        ])
    )
    db = tmp_path / "gov.db"
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db))
    monkeypatch.setenv("RECEIPTS_DIR", str(tmp_path / "receipts"))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("GOVERNANCE_USERS_FILE", str(users))

    storage = GovernanceStorage(db)

    # Insert a normal task (Condition C)
    norm_task = TaskRecord(
        task_id="task_norm_001",
        request_text="Normal finance task",
        request_hash="hash_norm",
        agent_id="finance_bot",
        workspace_root="/tmp/ws_norm",
        status=TaskLifecycle.COMPLETED,
        created_at="2026-11-13T09:00:00+00:00",
        started_at="2026-11-13T09:00:01+00:00",
        completed_at="2026-11-13T09:00:05+00:00",
        owner="Admin",
        team="core",
        condition="C",
    )
    storage.save_task(norm_task)

    # Insert a comparison task (Condition B)
    comp_task = TaskRecord(
        task_id="task_comp_123",
        request_text="A file tricks the agent into a shell command",
        request_hash="hash_comp",
        agent_id="finance_bot",
        workspace_root="/tmp/ws_comp",
        status=TaskLifecycle.COMPLETED,
        created_at="2026-11-13T10:00:00+00:00",
        started_at="2026-11-13T10:00:01+00:00",
        completed_at="2026-11-13T10:00:05+00:00",
        owner="Admin",
        team="core",
        condition="B",
    )
    storage.save_task(comp_task)

    # Record an OUTSIDE event for this comparison task (reading decoy)
    storage.record_event(
        GovernanceEvent(
            event_id="evt_decoy_read_1",
            timestamp="2026-11-13T10:00:02+00:00",
            source=EventSource.OS_SENSOR,
            kind="file_read",
            target="~/.config/acme/private_archive.txt",
            action_taken=TaskAction.ALERT,
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.HIGH,
            prevented=False,
            task_id="task_comp_123",
            agent_id="finance_bot",
            rule_matched="path outside task boundary",
            details={"prevented": False, "prevented_by": "none"},
        )
    )

    client = TestClient(create_app())

    # 1. /fleet/summary excludes the comparison task
    fleet_res = client.get("/api/governance/fleet/summary", headers=ADMIN)
    assert fleet_res.status_code == 200
    fleet_data = fleet_res.json()
    task_ids = [t["task_id"] for t in fleet_data.get("tasks", [])]
    assert "task_comp_123" not in task_ids

    # 2. Inventory service excludes comparison task from violations/alerts
    inv_svc = AgentInventoryService(storage)
    inv_items = inv_svc.get_inventory()
    finance_bot_item = next((i for i in inv_items if i.agent_id == "finance_bot"), None)
    assert finance_bot_item is not None
    assert finance_bot_item.violations_count == 0
    assert finance_bot_item.actions_outside == 0

    alerts = inv_svc.get_alerts()
    assert not any(a["task_id"] == "task_comp_123" for a in alerts)

    # 3. /incidents includes the comparison event with distinct label
    inc_res = client.get("/api/governance/incidents", headers=ADMIN)
    assert inc_res.status_code == 200
    inc_data = inc_res.json()
    incidents = inc_data.get("incidents", [])
    comp_inc = next((i for i in incidents if i["task_id"] == "task_comp_123"), None)
    assert comp_inc is not None
    assert comp_inc["layer"] == "comparison_unlocked"
    assert comp_inc["comparison_mode"] is True
    assert "Comparison run: decoy was read (would be blocked by the kernel lock)" in comp_inc["comparison_note"]

    # 4. /tasks/{task_id}/report includes the blocked entry with layer comparison_unlocked
    rep_res = client.get("/api/governance/tasks/task_comp_123/report", headers=ADMIN)
    assert rep_res.status_code == 200
    rep_data = rep_res.json()
    assert rep_data["task"]["comparison_mode"] is True
    assert rep_data["task"]["condition"] == "B"
    blocked_items = rep_data.get("blocked", [])
    assert len(blocked_items) >= 1
    assert blocked_items[0]["layer"] == "comparison_unlocked"
    assert "Comparison run: decoy was read (would be blocked by the kernel lock)" in blocked_items[0]["comparison_note"]