import pytest
from app.cards.normalizer import normalize_agent_card
from app.detection.squatting import detect_spoofing
from app.policy.engine import PolicyEngine
from app.core.models import SecuritySeverity, PolicyAction


@pytest.fixture
def trusted_helloworld_card():
    raw = {
        "name": "Hello World Agent",
        "supportedInterfaces": [
            {
                "url": "http://127.0.0.1:9999",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            }
        ],
        "version": "0.0.1",
        "skills": [{"id": "echo_bot", "name": "Echo Bot"}],
    }
    return normalize_agent_card(raw)


def test_trusted_card_no_violation(trusted_helloworld_card):
    # Evaluating a legitimate candidate identical to trusted inventory
    cand = normalize_agent_card({
        "name": "Hello World Agent",
        "supportedInterfaces": [{"url": "http://127.0.0.1:9999"}],
    })
    violation = detect_spoofing(cand, [trusted_helloworld_card])
    assert violation is None

    engine = PolicyEngine()
    severity, action = engine.evaluate(violation)
    assert severity is None
    assert action == PolicyAction.ALLOW


def test_homoglyph_spoof_detected(trusted_helloworld_card):
    # Candidate with Cyrillic 'о' (U+043E) in "Hellо World Agent" pointing to port 8002
    cand = normalize_agent_card({
        "name": "Hell\u043e World Agent",
        "url": "http://127.0.0.1:8002",
    })
    violation = detect_spoofing(cand, [trusted_helloworld_card])
    assert violation is not None
    assert violation.violation_code == "AS_HOMOGLYPH_SPOOF"
    assert violation.candidate_endpoint == "http://127.0.0.1:8002"

    engine = PolicyEngine()
    severity, action = engine.evaluate(violation)
    assert severity == SecuritySeverity.HIGH
    assert action == PolicyAction.QUARANTINE


def test_provenance_conflict_detected(trusted_helloworld_card):
    # Candidate with identical ASCII name but conflicting endpoint
    cand = normalize_agent_card({
        "name": "Hello World Agent",
        "url": "http://127.0.0.1:8003",
    })
    violation = detect_spoofing(cand, [trusted_helloworld_card])
    assert violation is not None
    assert violation.violation_code == "AS_PROVENANCE_CONFLICT"
    assert violation.candidate_endpoint == "http://127.0.0.1:8003"

    engine = PolicyEngine()
    severity, action = engine.evaluate(violation)
    assert severity == SecuritySeverity.HIGH
    assert action == PolicyAction.QUARANTINE


def test_typosquatting_detected(trusted_helloworld_card):
    # Candidate with slight typo: "Hello Wrld Agent"
    cand = normalize_agent_card({
        "name": "Hello Wrld Agent",
        "url": "http://127.0.0.1:8004",
    })
    violation = detect_spoofing(cand, [trusted_helloworld_card])
    assert violation is not None
    assert violation.violation_code == "AS_TYPOSQUATTING_CLONE"

    engine = PolicyEngine()
    severity, action = engine.evaluate(violation)
    assert severity == SecuritySeverity.HIGH
    assert action == PolicyAction.QUARANTINE


def test_normalization_formats():
    # v0.3 legacy format
    v03_raw = {
        "name": "AgentAlice",
        "url": "http://localhost:8001/a2a/v1",
        "protocolVersion": "0.3.0",
        "preferredTransport": "JSONRPC",
    }
    norm03 = normalize_agent_card(v03_raw)
    assert norm03.name == "AgentAlice"
    assert norm03.endpoint_url == "http://localhost:8001/a2a/v1"
    assert norm03.protocol_version == "0.3.0"
    assert norm03.protocol_binding == "JSONRPC"

    # v1.0 standard format
    v10_raw = {
        "name": "ModernAgent",
        "supportedInterfaces": [
            {
                "url": "https://agent.example.com",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            }
        ],
    }
    norm10 = normalize_agent_card(v10_raw)
    assert norm10.name == "ModernAgent"
    assert norm10.endpoint_url == "https://agent.example.com"
    assert norm10.protocol_version == "1.0"
