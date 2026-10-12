from __future__ import annotations

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.core.models import SecuritySeverity, PolicyAction
from app.cards.normalizer import normalize_agent_card
from app.inventory.store import InMemoryAgentInventory
from app.policy.engine import PolicyEngine
from app.detection.capability_cloaking import (
    detect_runtime_capability_cloaking,
    detect_manifest_capability_cloaking,
    extract_declared_capabilities,
)
from app.gateway.server import create_app


def test_both_agents_normalize():
    """Verify both v1.0 (HelloWorld) and v0.3 (AgentAlice) schemas normalize correctly."""
    hw_raw = {
        "name": "Hello World Agent",
        "description": "Just a hello world agent",
        "version": "0.0.1",
        "supportedInterfaces": [
            {"url": "http://127.0.0.1:9999", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
        "skills": [{"id": "echo_bot", "name": "Echo Bot"}],
    }
    alice_raw = {
        "name": "AgentAlice",
        "description": "Hosts the number-guessing game",
        "version": "1.0.0",
        "protocolVersion": "0.3.0",
        "preferredTransport": "JSONRPC",
        "url": "http://localhost:8001/a2a/v1",
        "skills": [{"id": "number_guess_evaluator", "name": "Number Guess Evaluator"}],
    }

    norm_hw = normalize_agent_card(hw_raw)
    norm_alice = normalize_agent_card(alice_raw)

    assert norm_hw.name == "Hello World Agent"
    assert norm_hw.protocol_version == "1.0"
    assert norm_hw.endpoint_url == "http://127.0.0.1:9999"
    assert len(norm_hw.skills) == 1
    assert norm_hw.skills[0].id == "echo_bot"

    assert norm_alice.name == "AgentAlice"
    assert norm_alice.protocol_version == "0.3.0"
    assert norm_alice.endpoint_url == "http://localhost:8001/a2a/v1"
    assert len(norm_alice.skills) == 1
    assert norm_alice.skills[0].id == "number_guess_evaluator"


def test_capability_cloaking_allowed_methods():
    """Verify standard protocol methods and declared skills produce no violation."""
    inventory = InMemoryAgentInventory()
    hw_agent = inventory.get_trusted_agent("helloworld")
    alice_agent = inventory.get_trusted_agent("agentalice")

    # Standard protocol methods
    assert detect_runtime_capability_cloaking(hw_agent, "SendMessage") is None
    assert detect_runtime_capability_cloaking(hw_agent, "message/send") is None
    assert detect_runtime_capability_cloaking(alice_agent, "message/send") is None
    assert detect_runtime_capability_cloaking(alice_agent, "tasks/get") is None

    # Declared domain skills
    assert detect_runtime_capability_cloaking(hw_agent, "echo_bot") is None
    assert detect_runtime_capability_cloaking(alice_agent, "number_guess_evaluator") is None


def test_runtime_capability_cloaking_detected():
    """Verify unadvertised/cloaked methods trigger CC_UNDECLARED_CAPABILITY."""
    inventory = InMemoryAgentInventory()
    hw_agent = inventory.get_trusted_agent("helloworld")
    alice_agent = inventory.get_trusted_agent("agentalice")

    viol_hw = detect_runtime_capability_cloaking(hw_agent, "system_exec")
    assert viol_hw is not None
    assert viol_hw.violation_code == "CC_UNDECLARED_CAPABILITY"
    assert "system_exec" in viol_hw.description

    viol_alice = detect_runtime_capability_cloaking(alice_agent, "admin_shell")
    assert viol_alice is not None
    assert viol_alice.violation_code == "CC_UNDECLARED_CAPABILITY"
    assert "admin_shell" in viol_alice.description


def test_manifest_capability_cloaking_detected():
    """Verify static manifest set mismatch (A2ASecBench RulesComparator baseline)."""
    declared = ["echo_bot", "status_check"]
    actual = ["echo_bot", "status_check", "hidden_shell_exec"]

    viol = detect_manifest_capability_cloaking(declared, actual, agent_name="TestAgent")
    assert viol is not None
    assert viol.violation_code == "CC_UNDECLARED_CAPABILITY"
    assert "hidden_shell_exec" in viol.details["hidden_capabilities"]


def test_policy_engine_cc_mapping():
    """Verify PolicyEngine maps CC_UNDECLARED_CAPABILITY to HIGH severity and QUARANTINE."""
    engine = PolicyEngine()
    inventory = InMemoryAgentInventory()
    agent = inventory.get_trusted_agent("helloworld")

    viol = detect_runtime_capability_cloaking(agent, "eval_code")
    severity, action = engine.evaluate(viol)

    assert severity == SecuritySeverity.HIGH
    assert action == PolicyAction.QUARANTINE


def test_gateway_runtime_cc_blocking():
    """Verify gateway intercepts unmanifested method and blocks with 403 Forbidden."""
    app = create_app()
    client = TestClient(app)

    # 1. Calling declared skill on HelloWorld returns successful upstream (or mock)
    # 2. Calling undeclared capability triggers CC defense
    resp = client.post(
        "/proxy/helloworld",
        json={"jsonrpc": "2.0", "id": "test-cc", "method": "system_exec", "params": {"cmd": "dir"}},
        headers={"x-agent-id": "adversarial_client_01"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["error"]["code"] == -32004
    assert data["error"]["action"] == "QUARANTINE"
    assert data["error"]["violation"]["violation_code"] == "CC_UNDECLARED_CAPABILITY"

    # Verify that the caller was quarantined
    resp_quarantined = client.post(
        "/proxy/helloworld",
        json={"jsonrpc": "2.0", "id": "test-cc-2", "method": "echo_bot"},
        headers={"x-agent-id": "adversarial_client_01"},
    )
    assert resp_quarantined.status_code == 403
    assert "QUARANTINED" in resp_quarantined.text
