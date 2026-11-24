"""The trip_planner example can be started from the Run page as the Planner (a multi-agent job)."""
from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request

import pytest

from demo.security_monitor.app.governance import run_manager
from demo.security_monitor.app.governance.launcher import TaskLauncher


def test_run_agents_offer_the_planner_but_inventory_is_unchanged():
    run_agents = {a["id"]: a for a in run_manager.get_run_agents()}
    planner = run_agents["planner"]
    assert planner["multi_agent"] is True
    assert {"call_agents", "read_file", "http_post"} <= set(planner["tools"])
    assert planner["model"] == "scripted"
    # Inventory agents stay as they are, and none of them may call another agent.
    inventory = {a["id"] for a in run_manager.get_configured_agents()}
    assert "planner" not in inventory
    assert inventory <= set(run_agents)
    # Only example starters are added, not every callable profile.
    assert "booking" not in run_agents and "payment" not in run_agents


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_practice_site_serves_the_example_page():
    port = _free_port()
    run_manager.ensure_practice_site({"host": "127.0.0.1", "port": port, "body": {"attractions": ["Kinkaku-ji"]}})
    run_manager.ensure_practice_site({"host": "127.0.0.1", "port": port, "body": {}})  # second call: no-op
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/kyoto_attractions", timeout=5) as r:
        assert json.loads(r.read()) == {"attractions": ["Kinkaku-ji"]}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api", data=b"x", method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        assert json.loads(r.read()) == {"status": "ok"}
    with pytest.raises(ValueError):
        run_manager.ensure_practice_site({"host": "example.com", "port": port})


def test_trip_planner_starts_as_the_planner_with_its_peers(monkeypatch, tmp_path):
    seen: dict = {}

    def fake_run(self, spec):
        seen["spec"] = spec

    monkeypatch.setattr(TaskLauncher, "check_condition_c_support", classmethod(lambda cls: []))
    monkeypatch.setattr(TaskLauncher, "run", fake_run)
    monkeypatch.setattr(run_manager, "ensure_practice_site", lambda site: seen.setdefault("site", site))
    monkeypatch.setattr(run_manager, "classify_run_outcome", lambda *a, **k: ("succeeded", ""))

    class _Storage:
        def record_task_step(self, *a, **k):
            return {}

    preset = run_manager.PRESETS["trip_planner"]
    mgr = run_manager.ActiveRunManager()
    task_id = mgr.start_run(preset["prompt"], storage=_Storage(), preset_id="trip_planner",
                            agent_id="planner", workspace_base=tmp_path)
    for _ in range(100):
        if "spec" in seen:
            break
        time.sleep(0.02)
    spec = seen["spec"]
    assert spec.task_id == task_id and spec.agent_id == "planner"
    assert spec.llm["provider"] == "scripted"
    assert any(s.get("tool") == "call_agents" for s in spec.llm["steps"])
    assert set(spec.peer_agents) == {"researcher", "budget", "booking"}
    assert "call_agents" in spec.agent_tools
    assert spec.owner == "Travel Desk"
    assert seen["site"]["port"] == 8765


def test_an_unknown_agent_is_still_refused():
    """A callable profile that starts no example (Payment) cannot be started from the Run page."""
    mgr = run_manager.ActiveRunManager()
    with pytest.raises(ValueError, match="Unknown agent 'payment'"):
        mgr.start_run("hi", storage=None, model="scripted", agent_id="payment")
