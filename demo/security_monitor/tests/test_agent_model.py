"""Each configured agent owns its model; a run may override it."""
from __future__ import annotations

import pytest

from demo.security_monitor.app.governance import run_manager


def test_configured_agents_carry_their_model():
    agents = {a["id"]: a for a in run_manager.get_configured_agents()}
    assert agents["finance_bot"]["model"] == "qwen2.5:7b"
    assert agents["notes_bot"]["model"] == "qwen2.5:7b"
    assert agents["brief_bot"]["model"] == "llama3.1:8b"
    assert agents["travel_bot"]["model"] == "qwen2.5:7b"


def test_missing_agent_model_names_the_agent(monkeypatch):
    monkeypatch.setattr(run_manager, "list_installed_models", lambda: [])
    with pytest.raises(ValueError, match="Finance Bot runs on 'qwen2.5:7b'"):
        mgr = object.__new__(run_manager.ActiveRunManager)
        mgr.start_run("Summarise input/x.csv", storage=None, agent_id="finance_bot")


def test_override_is_validated_as_given(monkeypatch):
    monkeypatch.setattr(run_manager, "list_installed_models", lambda: [])
    with pytest.raises(ValueError, match="Unknown model 'llama3.1:8b'"):
        mgr = object.__new__(run_manager.ActiveRunManager)
        mgr.start_run("Summarise input/x.csv", storage=None, model="llama3.1:8b", agent_id="finance_bot")


# --- Per-agent tool limits ---------------------------------------------------

from pathlib import Path  # noqa: E402

from demo.security_monitor.app.governance.broker import ToolBroker  # noqa: E402
from demo.security_monitor.app.governance.intake import TaskIntakeService  # noqa: E402
from demo.security_monitor.app.governance.launcher import TaskSpec, _offered_tools  # noqa: E402
from demo.security_monitor.app.governance.storage import GovernanceStorage  # noqa: E402


def test_configured_agents_have_different_tool_limits():
    agents = {a["id"]: a for a in run_manager.get_configured_agents()}
    # Least agency: each agent gets only what its jobs use. No agent may call another agent.
    assert agents["brief_bot"]["tools"] == ["read_file", "write_file", "request_access"]
    for a in ("finance_bot", "notes_bot", "travel_bot"):
        assert "run_command" in agents[a]["tools"]
    for a in agents.values():
        assert "call_agent" not in a["tools"] and "http_get" not in a["tools"]


def test_every_example_is_a_job_for_a_configured_agent():
    from demo.security_monitor.app.governance.agent_profiles import load_all_agent_profiles

    agents = {a["id"]: a for a in run_manager.get_configured_agents()}
    # Multi-agent examples (trip_planner) start from a callable agent profile in agents/,
    # whose admin-set ceiling is its tool limit. Inventory agents stay as configured above.
    profiles = {pid: {"tools": prof["ceiling"].get("tools", [])} for pid, prof in load_all_agent_profiles().items()}
    for pid, p in run_manager.PRESETS.items():
        if pid == "custom":
            continue
        agent = p.get("agent")
        limits = agents.get(agent) or profiles.get(agent)
        assert limits is not None, pid
        # The agent's own tool limit covers what its example needs.
        needed = {s["tool"] for s in p.get("scripted_steps", []) if s.get("tool")}
        assert needed <= set(limits["tools"]), pid
    assert run_manager.PRESETS["contract_review"]["agent"] == "brief_bot"
    assert run_manager.PRESETS["a2a_agent"]["agent"] == "travel_bot"
    assert run_manager.PRESETS["network_exfiltration"]["agent"] == "notes_bot"


def test_contract_example_hides_a_privileged_read():
    p = run_manager.PRESETS["contract_review"]
    assert "settlement_draft" in p["files"]["input/vendor_contract.txt"]
    assert "settlement_draft" not in p["prompt"]
    assert p["decoys"][0]["path"] == "~/legal/settlement_draft.txt"
    reads = [s["args"]["path"] for s in p["scripted_steps"] if s.get("tool") == "read_file"]
    assert reads == ["input/vendor_contract.txt", "~/legal/settlement_draft.txt"]


def test_model_is_offered_only_the_agents_tools():
    names = lambda ts: [t["function"]["name"] for t in ts]  # noqa: E731
    spec = TaskSpec(task_id="t", prompt="p", agent_tools=["read_file", "write_file", "request_access"])
    assert names(_offered_tools(spec)) == ["read_file", "write_file", "request_access"]
    shell = run_manager._shell_only_agent()["tools_schema"]
    spec_shell = TaskSpec(task_id="t", prompt="p", tools_schema=shell, agent_tools=["read_file", "write_file"])
    assert names(_offered_tools(spec_shell)) == ["write_file"]
    assert _offered_tools(TaskSpec(task_id="t", prompt="p")) is None


def test_broker_refuses_a_tool_outside_the_agent_limit(tmp_path: Path):
    storage = GovernanceStorage(tmp_path / "g.db")
    ws = tmp_path / "ws"
    (ws / "input").mkdir(parents=True)
    (ws / "output").mkdir()
    (ws / "input" / "notes.txt").write_text("hello")
    task, boundary = TaskIntakeService(storage).submit_task(
        "Read input/notes.txt and write output/summary.txt", "notes_bot", str(ws)
    )
    boundary.tools = sorted(set(boundary.tools) | {"read_file", "run_command"})
    boundary.metadata["agent_tool_limit"] = ["read_file", "request_access", "write_file"]
    boundary.metadata["agent_tool_limit_agent"] = "notes_bot"
    storage.save_boundary(boundary)
    storage.save_token("tok_limit", task.task_id, task.agent_id)
    broker = ToolBroker(storage)

    assert broker.read_file("tok_limit", "input/notes.txt") == "hello"
    with pytest.raises(PermissionError, match="run_command is not in the tool limit of notes_bot"):
        broker.run_command("tok_limit", "cat input/notes.txt", workspace_root=ws)
    with pytest.raises(PermissionError, match="http_get is not in the tool limit of notes_bot"):
        broker.http_get("tok_limit", "http://127.0.0.1:9/x")
    refused = [e for e in storage.get_events_for_task(task.task_id) if e.prevented and e.target in ("run_command", "http_get")]
    assert {e.target for e in refused} == {"run_command", "http_get"}


def test_travel_planner_is_run_as_a_program_not_called_as_an_agent():
    from demo.security_monitor.app.governance.launcher import _system_prompt

    preset = run_manager.PRESETS["a2a_agent"]
    assert "Verify system audit" not in preset["prompt"]
    tools = run_manager._preset_tools(preset)["tools_schema"]
    names = [t["function"]["name"] for t in tools]
    assert "call_agent" not in names and "run_command" in names
    prompt = _system_prompt(TaskSpec(task_id="t", prompt="p", tools_schema=tools))
    assert "call_agent" not in prompt and "4 governed tools" in prompt
