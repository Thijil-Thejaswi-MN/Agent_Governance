import json
import os
import sys
import threading
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

repo_root = str(Path(__file__).resolve().parents[3])
sec_mon = str(Path(__file__).resolve().parents[1])
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
if sec_mon not in sys.path:
    sys.path.insert(0, sec_mon)

from app.gateway.server import create_app
from app.governance.catalog import BoundaryDerivationV1_1
from app.governance.intake import TaskIntakeService
from app.governance.launcher import TaskLauncher, TaskSpec
from app.governance.models import TaskLifecycle, TaskRecord
from app.governance.run_manager import (
    ActiveRunManager,
    get_configured_agents,
    load_agents_config,
)
from app.governance.storage import GovernanceStorage


@pytest.fixture
def env(tmp_path: Path):
    db_path = tmp_path / "test_agents.db"
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    os.environ["GOVERNANCE_DB_PATH"] = str(db_path)
    os.environ["RECEIPTS_DIR"] = str(receipts_dir)
    os.environ["GOVERNANCE_OPERATOR_TOKEN"] = "test_token"
    os.environ["GOVERNANCE_OPERATOR_NAME"] = "test_admin"
    os.environ["GOVERNANCE_OPERATOR_ROLE"] = "admin"

    storage = GovernanceStorage(db_path)
    client = TestClient(create_app())
    yield {
        "storage": storage,
        "client": client,
        "db_path": db_path,
        "receipts_dir": receipts_dir,
        "tmp_path": tmp_path,
    }


def test_boundary_invariance_across_agents(env):
    """Proves the exact same preset produces an identical resolved boundary for every agent.

    agent_id, owner, and team must NEVER affect the boundary or enforcement.
    """
    storage: GovernanceStorage = env["storage"]
    intake = TaskIntakeService(storage)
    ws_root = str(env["tmp_path"] / "ws")
    request_text = "Compare sales in input/sales_data.csv and write to output/report.txt"

    agents = ["finance_bot", "notes_bot", "brief_bot"]
    owners = ["Ana Dev", "Ravi K", "Meena R"]
    teams = ["finance", "core", "legal"]

    boundaries = []
    catalog_boundaries = []

    for agent_id, owner, team in zip(agents, owners, teams):
        # 1. Derivation catalog
        cat_b = BoundaryDerivationV1_1().derive(f"task_{agent_id}", request_text, ws_root)
        catalog_boundaries.append(cat_b.model_dump())

        # 2. Intake service
        task, boundary = intake.submit_task(
            request_text=request_text,
            agent_id=agent_id,
            workspace_root=ws_root,
            owner=owner,
            team=team,
        )
        boundaries.append(boundary.model_dump())

    # All derivations must be identical across agents, owners, and teams
    fields = ['files_read', 'files_write', 'network', 'tools', 'peer_agents', 'max_duration_sec', 'max_processes', 'enforcement_mode']
    for field in fields:
        assert catalog_boundaries[0][field] == catalog_boundaries[1][field] == catalog_boundaries[2][field]
        assert boundaries[0][field] == boundaries[1][field] == boundaries[2][field]


def test_concurrent_runs_named_agents_separate_cgroups_receipts_records(env, monkeypatch):
    """Starts 2 runs concurrently under different agents (finance_bot and notes_bot).

    Verifies:
    - 2 runs are active simultaneously
    - Separate cgroups in storage (agtask-{task_id_1} vs agtask-{task_id_2})
    - Separate task receipts written to receipts_dir
    - Separate SQLite task records and step chains
    """
    monkeypatch.setattr(TaskLauncher, "check_condition_c_support", staticmethod(lambda: []))
    storage: GovernanceStorage = env["storage"]
    receipts_dir: Path = env["receipts_dir"]
    tmp_path: Path = env["tmp_path"]

    barrier = threading.Barrier(2)
    captured_specs: list[TaskSpec] = []
    specs_lock = threading.Lock()

    def concurrent_run(launcher_self, spec: TaskSpec):
        with specs_lock:
            captured_specs.append(spec)

        task = TaskRecord(
            task_id=spec.task_id,
            request_text=spec.prompt,
            request_hash=f"hash_{spec.task_id}",
            agent_id=spec.agent_id,
            owner=spec.owner,
            team=spec.team,
            workspace_root=str(tmp_path / f"ws_{spec.task_id}"),
            status=TaskLifecycle.ACTIVE,
            created_at="2026-11-13T10:00:00Z",
        )
        storage.save_task(task)

        # Record cgroup for this task
        cg_path = f"/sys/fs/cgroup/agtask-{spec.task_id}"
        unit_name = f"agtask-{spec.task_id}.scope"
        storage.save_task_cgroup(spec.task_id, cg_path, unit_name, 10000 + len(captured_specs))

        storage.record_task_step(
            spec.task_id,
            kind="phase",
            layer="launcher",
            verdict="ALLOW",
            summary=f"Running agent {spec.agent_id} in {unit_name}",
            source_label="enforced",
        )

        # Synchronize both runs to be active at the same moment
        barrier.wait(timeout=5.0)

        # Write receipt for this task
        receipt_data = {
            "task_id": spec.task_id,
            "agent_id": spec.agent_id,
            "owner": spec.owner,
            "team": spec.team,
            "os_identity": {
                "cgroup_path": cg_path,
                "unit_name": unit_name,
            },
            "status": "COMPLETED",
        }
        receipt_file = receipts_dir / f"receipt_{spec.task_id}.json"
        receipt_file.write_text(json.dumps(receipt_data), encoding="utf-8")

        storage.record_task_step(
            spec.task_id,
            kind="receipt",
            layer="receipt",
            verdict="ALLOW",
            summary="Receipt verified",
            source_label="enforced",
        )

    monkeypatch.setattr(TaskLauncher, "run", concurrent_run)

    mgr = ActiveRunManager()

    tid_finance = mgr.start_run(
        prompt="Analyze finance figures",
        storage=storage,
        preset_id="summarise_csv",
        model="scripted",
        workspace_base=tmp_path / "ws",
        agent_id="finance_bot",
    )

    tid_notes = mgr.start_run(
        prompt="Summarize meeting notes",
        storage=storage,
        preset_id="summarise_csv",
        model="scripted",
        workspace_base=tmp_path / "ws",
        agent_id="notes_bot",
    )

    assert tid_finance != tid_notes

    # Wait for both worker threads to finish
    deadline = time.monotonic() + 5.0
    while mgr.is_active() and time.monotonic() < deadline:
        time.sleep(0.05)

    assert not mgr.is_active()

    # Verify captured specs
    assert len(captured_specs) == 2
    spec_map = {s.task_id: s for s in captured_specs}
    assert spec_map[tid_finance].agent_id == "finance_bot"
    assert spec_map[tid_finance].owner == "Ana Dev"
    assert spec_map[tid_finance].team == "finance"

    assert spec_map[tid_notes].agent_id == "notes_bot"
    assert spec_map[tid_notes].owner == "Ravi K"
    assert spec_map[tid_notes].team == "core"

    # Verify separate cgroups
    cg_finance = storage.get_task_cgroup(tid_finance)
    cg_notes = storage.get_task_cgroup(tid_notes)
    assert cg_finance is not None and cg_notes is not None
    assert cg_finance["cgroup_path"] != cg_notes["cgroup_path"]
    assert f"agtask-{tid_finance}" in cg_finance["cgroup_path"]
    assert f"agtask-{tid_notes}" in cg_notes["cgroup_path"]

    # Verify separate receipts
    rcpt_finance_file = receipts_dir / f"receipt_{tid_finance}.json"
    rcpt_notes_file = receipts_dir / f"receipt_{tid_notes}.json"
    assert rcpt_finance_file.exists()
    assert rcpt_notes_file.exists()

    rcpt_fin = json.loads(rcpt_finance_file.read_text())
    rcpt_not = json.loads(rcpt_notes_file.read_text())
    assert rcpt_fin["agent_id"] == "finance_bot"
    assert rcpt_not["agent_id"] == "notes_bot"
    assert rcpt_fin["os_identity"]["cgroup_path"] != rcpt_not["os_identity"]["cgroup_path"]

    # Verify separate records and steps in storage
    task_fin = storage.get_task(tid_finance)
    task_not = storage.get_task(tid_notes)
    assert task_fin is not None and task_not is not None
    assert task_fin.agent_id == "finance_bot"
    assert task_not.agent_id == "notes_bot"

    steps_fin = storage.get_task_steps(tid_finance)
    steps_not = storage.get_task_steps(tid_notes)
    assert any("finance_bot" in s["summary"] for s in steps_fin)
    assert any("notes_bot" in s["summary"] for s in steps_not)


def test_fourth_concurrent_run_refused(env, monkeypatch):
    """Verifies that up to 3 concurrent runs are permitted and the 4th is refused."""
    monkeypatch.setattr(TaskLauncher, "check_condition_c_support", staticmethod(lambda: []))
    storage: GovernanceStorage = env["storage"]
    tmp_path: Path = env["tmp_path"]

    mgr = ActiveRunManager()
    unblock_event = threading.Event()

    def blocking_run(launcher_self, spec: TaskSpec):
        unblock_event.wait(timeout=5.0)

    monkeypatch.setattr(TaskLauncher, "run", blocking_run)

    tids = []
    try:
        tids.append(mgr.start_run(prompt="Run 1", storage=storage, preset_id="summarise_csv", model="scripted", workspace_base=tmp_path / "ws", agent_id="finance_bot"))
        tids.append(mgr.start_run(prompt="Run 2", storage=storage, preset_id="summarise_csv", model="scripted", workspace_base=tmp_path / "ws", agent_id="notes_bot"))
        tids.append(mgr.start_run(prompt="Run 3", storage=storage, preset_id="summarise_csv", model="scripted", workspace_base=tmp_path / "ws", agent_id="brief_bot"))

        info = mgr.get_active_info()
        assert info["active_count"] == 3
        assert info["max_concurrent"] == 3

        with pytest.raises(RuntimeError, match="Maximum concurrent runs reached"):
            mgr.start_run(prompt="Run 4", storage=storage, preset_id="summarise_csv", model="scripted", workspace_base=tmp_path / "ws", agent_id="finance_bot")
    finally:
        unblock_event.set()
        deadline = time.monotonic() + 5.0
        while mgr.is_active() and time.monotonic() < deadline:
            time.sleep(0.05)


def test_api_agents_list_and_validation(env):
    """Tests GET /api/governance/run/agents and POST /api/governance/run agent validation."""
    client: TestClient = env["client"]
    headers = {"X-Operator-Token": "test_token"}

    # 1. Listing configured agents
    resp = client.get("/api/governance/run/agents", headers=headers)
    assert resp.status_code == 200
    agents = resp.json()
    assert len(agents) == 3
    ids = {a["id"] for a in agents}
    assert ids == {"finance_bot", "notes_bot", "brief_bot"}

    # 2. Validation: invalid agent_id returns 422
    resp_bad = client.post(
        "/api/governance/run",
        json={
            "prompt": "Test bad agent",
            "preset": "summarise_csv",
            "model": "scripted",
            "agent_id": "malicious_bot",
            "files": {},
        },
        headers=headers,
    )
    assert resp_bad.status_code == 422
    assert "Invalid agent_id 'malicious_bot'" in resp_bad.json()["detail"]
