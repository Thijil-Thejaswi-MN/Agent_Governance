"""Each configured agent owns its model; a run may override it."""
from __future__ import annotations

import pytest

from demo.security_monitor.app.governance import run_manager


def test_configured_agents_carry_their_model():
    agents = {a["id"]: a for a in run_manager.get_configured_agents()}
    assert agents["finance_bot"]["model"] == "qwen2.5:7b"
    assert agents["notes_bot"]["model"] == "qwen2.5:7b"
    assert agents["brief_bot"]["model"] == "llama3.1:8b"


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
