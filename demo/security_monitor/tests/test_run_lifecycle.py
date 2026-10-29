"""Run page lifecycle: fail-closed start, visible failures, terminal SSE events, stop races.

- Prerequisites are checked synchronously in start_run: a host that cannot run the
  OS layer gets HTTP 503 with the problems, and no task id is created.
- A launcher that raises mid-run leaves a FAILED termination step, a FAILED task,
  a terminal 'finished' step, and a free run slot.
- The SSE stream always ends with an `end` event.
- Stop works during preparation (the agent never starts) and after the agent has
  started (the cgroup is killed); termination is operator_stop either way.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from demo.security_monitor.app.gateway.server import create_app
from demo.security_monitor.app.governance import run_manager as rm
from demo.security_monitor.app.governance.launcher import TaskLauncher
from demo.security_monitor.app.governance.models import TaskLifecycle, TaskRecord
from demo.security_monitor.app.governance.receipt import verify_chain
from demo.security_monitor.app.governance.storage import GovernanceStorage

TOKEN = "test_lifecycle_token"
HEADERS = {"X-Operator-Token": TOKEN}
RUN_BODY = {"prompt": rm.PRESETS["summarise_csv"]["prompt"], "preset": "summarise_csv", "model": "scripted", "files": {}}


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "gov.db"
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db_path))
    monkeypatch.setenv("RECEIPTS_DIR", str(tmp_path / "receipts"))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", TOKEN)
    monkeypatch.setenv("GOVERNANCE_OPERATOR_NAME", "lifecycle_operator")
    storage = GovernanceStorage(db_path)
    yield {"storage": storage, "client": TestClient(create_app()), "tmp_path": tmp_path}
    mgr = rm.get_run_manager()
    if mgr._active_thread is not None:
        mgr._active_thread.join(timeout=60)


def _join(mgr: rm.ActiveRunManager, timeout: float = 90.0) -> None:
    t = mgr._active_thread
    if t is not None:
        t.join(timeout=timeout)
        assert not t.is_alive(), "run worker did not finish"


def _steps(storage: GovernanceStorage, task_id: str) -> list[dict]:
    return storage.get_task_steps(task_id)


def _read_sse(client: TestClient, task_id: str) -> tuple[list[dict], dict | None]:
    steps, end = [], None
    with client.stream("GET", f"/api/governance/run/{task_id}/stream", headers=HEADERS) as resp:
        assert resp.status_code == 200
        event = "message"
        for line in resp.iter_lines():
            if line.startswith("event: "):
                event = line[7:]
            elif line.startswith("data: "):
                data = json.loads(line[6:])
                if event == "end":
                    end = data
                else:
                    steps.append(data)
                event = "message"
    return steps, end


# ---------------------------------------------------------------------------
# 1. Fail-closed start and visible failures
# ---------------------------------------------------------------------------

def test_start_refused_with_503_when_prerequisites_fail(env, monkeypatch):
    problems = ["launcher requires Linux (WSL2)"]
    monkeypatch.setattr(TaskLauncher, "check_prerequisites", staticmethod(lambda: list(problems)))

    resp = env["client"].post("/api/governance/run", json=RUN_BODY, headers=HEADERS)

    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert detail["message"] == rm.HOST_REQUIREMENT
    assert "systemd --user" in detail["message"] and "Landlock" in detail["message"]
    assert detail["problems"] == problems
    assert env["storage"].list_tasks() == []
    mgr = rm.get_run_manager()
    assert not mgr.is_active()
    assert mgr._active_task_id is None


def test_launcher_raising_mid_run_records_failed_terminal_step_and_frees_slot(env, monkeypatch):
    storage: GovernanceStorage = env["storage"]
    monkeypatch.setattr(TaskLauncher, "check_prerequisites", staticmethod(lambda: []))

    def exploding_run(self, spec):
        storage.record_task_step(spec.task_id, kind="phase", layer="intake", verdict="ALLOW",
                                 summary="Boundary derived", source_label="enforced")
        raise RuntimeError("sensor binary vanished mid-run")

    monkeypatch.setattr(TaskLauncher, "run", exploding_run)
    mgr = rm.ActiveRunManager()
    task_id = mgr.start_run(prompt="Analyse input/sales_data.csv", storage=storage, preset_id="summarise_csv",
                            model="scripted", workspace_base=env["tmp_path"] / "ws")
    _join(mgr)

    steps = _steps(storage, task_id)
    failed = [s for s in steps if s["kind"] == "termination" and s["verdict"] == "FAILED"]
    assert len(failed) == 1
    assert "sensor binary vanished mid-run" in failed[0]["summary"]
    assert steps[-1]["kind"] == "finished" and steps[-1]["verdict"] == "FAILED"
    task = storage.get_task(task_id)
    assert task is not None and task.status == TaskLifecycle.FAILED
    assert not mgr.is_active() and mgr._active_task_id is None and mgr._active_launcher is None

    # The slot is really free: another run is accepted.
    monkeypatch.setattr(TaskLauncher, "run", lambda self, spec: None)
    second = mgr.start_run(prompt="Analyse input/sales_data.csv", storage=storage, preset_id="summarise_csv",
                           model="scripted", workspace_base=env["tmp_path"] / "ws")
    _join(mgr)
    assert _steps(storage, second)[-1]["verdict"] == "COMPLETED"


def test_stream_of_failed_run_ends_with_failed_event(env, monkeypatch):
    monkeypatch.setattr(TaskLauncher, "check_prerequisites", staticmethod(lambda: []))
    started = threading.Event()

    def failing_run(self, spec):
        started.wait(5)
        raise OSError("systemd-run: Failed to connect to bus")

    monkeypatch.setattr(TaskLauncher, "run", failing_run)
    client: TestClient = env["client"]
    resp = client.post("/api/governance/run", json=RUN_BODY, headers=HEADERS)
    assert resp.status_code == 200
    task_id = resp.json()["task_id"]
    started.set()

    steps, end = _read_sse(client, task_id)
    assert end is not None and end["state"] == "failed"
    assert "Failed to connect to bus" in end["reason"]
    assert any(s["kind"] == "termination" and s["verdict"] == "FAILED" for s in steps)


def test_stream_for_task_not_run_here_ends_from_stored_status(env):
    storage: GovernanceStorage = env["storage"]
    storage.save_task(TaskRecord(task_id="task_cli_done", request_text="x", request_hash="h", agent_id="a",
                                 workspace_root="/tmp", status=TaskLifecycle.COMPLETED,
                                 created_at="2026-10-28T10:00:00Z"))
    storage.record_task_step("task_cli_done", kind="receipt", layer="receipt", verdict="ALLOW",
                             summary="Task receipt written", source_label="enforced")
    steps, end = _read_sse(env["client"], "task_cli_done")
    assert [s["kind"] for s in steps] == ["receipt"]
    assert end == {"task_id": "task_cli_done", "state": "completed", "reason": "task status COMPLETED"}


def test_stream_for_unknown_task_ends_instead_of_spinning(env):
    _, end = _read_sse(env["client"], "task_never_existed")
    assert end is not None and end["state"] == "failed"


def test_start_rejects_model_that_is_not_installed(env, monkeypatch):
    monkeypatch.setattr(rm, "list_installed_models", lambda: ["qwen2.5:7b", "llama3.1:8b"])
    monkeypatch.setattr(TaskLauncher, "check_prerequisites", staticmethod(lambda: []))
    monkeypatch.setattr(TaskLauncher, "run", lambda self, spec: None)
    client: TestClient = env["client"]

    resp = client.post("/api/governance/run", json=dict(RUN_BODY, model="gpt-imaginary:70b"), headers=HEADERS)
    assert resp.status_code == 422
    assert "gpt-imaginary:70b" in resp.json()["detail"] and "qwen2.5:7b" in resp.json()["detail"]
    assert env["storage"].list_tasks() == []

    for model in ("qwen2.5:7b", "scripted"):
        resp = client.post("/api/governance/run", json=dict(RUN_BODY, model=model), headers=HEADERS)
        assert resp.status_code == 200, (model, resp.text)
        _join(rm.get_run_manager())


def test_start_rejects_ollama_model_when_ollama_unreachable(env, monkeypatch):
    monkeypatch.setattr(rm, "list_installed_models", lambda: None)
    resp = env["client"].post("/api/governance/run", json=dict(RUN_BODY, model="qwen2.5:7b"), headers=HEADERS)
    assert resp.status_code == 422
    assert "Ollama unreachable" in resp.json()["detail"]
    models = env["client"].get("/api/governance/run/models", headers=HEADERS).json()
    assert models == {"models": [], "default": "scripted", "scripted_available": True, "ollama_reachable": False}


# ---------------------------------------------------------------------------
# 2. Stop races (real launcher, scripted MOCK LLM; OS layer, broker, sensor are real)
# ---------------------------------------------------------------------------

@pytest.fixture
def ws_base():
    # Not under /tmp: the evaluation world aborts if /tmp has content (pytest's tmp_path lives there).
    base = Path(os.environ["HOME"]) / "agent_workspaces" / f"pytest_lifecycle_{uuid.uuid4().hex[:8]}"
    yield base
    shutil.rmtree(base, ignore_errors=True)


def _start_real(storage: GovernanceStorage, ws_base: Path, preset: str = "summarise_csv", hooks=None):
    mgr = rm.ActiveRunManager()
    task_id = mgr.start_run(prompt=rm.PRESETS[preset]["prompt"], storage=storage, preset_id=preset,
                            model="scripted", workspace_base=ws_base, launcher_hooks=hooks)
    return mgr, task_id, mgr._active_launcher


def _assert_stopped_without_agent(storage, task_id, launcher):
    assert not launcher.live.get("agent_started"), "the agent must never have started"
    assert storage.get_task_cgroup(task_id) is None, "no task cgroup may have been created"
    assert launcher.termination["reason"] == "operator_stop"
    steps = _steps(storage, task_id)
    assert any(s["kind"] == "termination" and "operator_stop" in s["summary"] for s in steps)
    assert steps[-1]["kind"] == "finished" and steps[-1]["verdict"] == "STOPPED"
    assert not any("Agent process launched" in s["summary"] for s in steps)


@pytest.mark.os_layer
def test_stop_while_sandbox_is_being_prepared_never_starts_agent(env, ws_base):
    storage: GovernanceStorage = env["storage"]
    reached, release = threading.Event(), threading.Event()

    def hold_before_agent_start(launcher):
        reached.set()
        release.wait(30)

    mgr, task_id, launcher = _start_real(storage, ws_base, hooks={"before_agent_start": hold_before_agent_start})
    assert reached.wait(30), "launcher never reached sandbox preparation"
    assert mgr.stop_run(task_id) == {"killed": False, "cancelled_before_start": True}
    release.set()
    _join(mgr)

    _assert_stopped_without_agent(storage, task_id, launcher)
    assert "proc" not in launcher.live, "the sandbox process chain must not have been spawned"
    task = storage.get_task(task_id)
    assert task is not None and task.status == TaskLifecycle.TERMINATED
    receipt_path = ws_base / "receipts" / f"{task_id}.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["termination"]["reason"] == "operator_stop"
    assert receipt["termination"]["stage"] == "before_agent_start"
    ok, final, _ = verify_chain(receipt["events"])
    assert ok and final == receipt["hash_chain"]["final_hash"]
    assert any(s["kind"] == "receipt" for s in _steps(storage, task_id))


@pytest.mark.os_layer
def test_stop_immediately_after_start_run_returns_never_starts_agent(env, ws_base):
    storage: GovernanceStorage = env["storage"]
    mgr, task_id, launcher = _start_real(storage, ws_base)
    result = mgr.stop_run(task_id)
    assert result["cancelled_before_start"] is True
    _join(mgr)
    _assert_stopped_without_agent(storage, task_id, launcher)


@pytest.mark.os_layer
def test_stop_after_agent_started_kills_cgroup_and_writes_receipt(env, ws_base, monkeypatch):
    storage: GovernanceStorage = env["storage"]
    slow = dict(rm.PRESETS["summarise_csv"], id="slow_sleep",
                scripted_steps=[{"tool": "run_command", "args": {"command": "sleep 30"}}, {"final": "done"}])
    monkeypatch.setitem(rm.PRESETS, "slow_sleep", slow)

    t0 = time.monotonic()
    mgr, task_id, launcher = _start_real(storage, ws_base, preset="slow_sleep")
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        rpc = launcher.live.get("rpc")
        if launcher.live.get("agent_started") and rpc and rpc.call_counts.get("run_command_check"):
            break
        time.sleep(0.05)
    else:
        pytest.fail("agent never reached its sleep command")
    time.sleep(0.3)

    assert mgr.stop_run(task_id) == {"killed": True, "cancelled_before_start": False}
    _join(mgr)
    assert time.monotonic() - t0 < 30, "sleep must have been killed, not run to completion"

    assert storage.get_task_cgroup(task_id) is not None
    assert launcher.termination["reason"] == "operator_stop"
    assert launcher.termination["method"] != "no_cgroup"
    receipt_path = ws_base / "receipts" / f"{task_id}.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["termination"]["reason"] == "operator_stop"
    ok, final, _ = verify_chain(receipt["events"])
    assert ok and final == receipt["hash_chain"]["final_hash"]
    steps = _steps(storage, task_id)
    assert steps[-1]["kind"] == "finished" and steps[-1]["verdict"] == "STOPPED"
