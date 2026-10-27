import pytest
from fastapi.testclient import TestClient

from app.gateway.server import create_app
from app.inventory.store import InMemoryAgentInventory
from app.policy.engine import PolicyEngine
from app.core.models import SecurityViolation, PolicyAction
from app.telemetry.metrics import EventStore
from app.policy.rate_limiter import RateLimiter


@pytest.fixture
def client():
    inventory = InMemoryAgentInventory()
    policy_engine = PolicyEngine()
    event_store = EventStore()
    rate_limiter = RateLimiter(max_requests=25, window_seconds=1.0)
    app = create_app(inventory, policy_engine, event_store, rate_limiter)
    return TestClient(app)


def test_dashboard_static_page(client):
    """Verify /dashboard serves the HTML single-page dashboard."""
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    assert "A2A Security Operations" in resp.text


def test_root_redirect(client):
    """Verify GET / redirects to /dashboard."""
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "/dashboard"


def test_api_overview(client):
    """Verify GET /api/v1/overview returns live topology, counts, and action distribution."""
    resp = client.get("/api/v1/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert data["gateway_status"] == "ONLINE"
    assert "counts" in data
    assert "action_distribution" in data
    assert "severity_distribution" in data
    assert "topology" in data
    assert "nodes" in data["topology"]
    assert len(data["topology"]["nodes"]) >= 2  # client + at least helloworld


def test_api_agents(client):
    """Verify GET /api/v1/agents returns catalog and entity states."""
    resp = client.get("/api/v1/agents")
    assert resp.status_code == 200
    data = resp.json()
    assert "agents" in data
    assert len(data["agents"]) >= 1
    assert data["agents"][0]["agent_id"] == "helloworld"
    assert "quarantined_entities" in data
    assert "restricted_entities" in data


def test_api_events_filtering_and_search(client):
    """Verify GET /api/v1/events with search, severity, and action filters."""
    # Seed events via register endpoint
    # 1. Benign registration -> ALLOW
    client.post("/api/v1/cards/register", json={
        "candidate_id": "legit_agent_99",
        "card": {
            "name": "Legitimate Agent 99",
            "url": "http://127.0.0.1:8999",
        }
    })
    # 2. Spoofed registration -> QUARANTINE
    client.post("/api/v1/cards/register", json={
        "candidate_id": "spoofed_hw_99",
        "card": {
            "name": "Hell\u043e World Agent",  # Cyrillic 'о'
            "url": "http://127.0.0.1:8998",
        }
    })

    # Search all
    resp = client.get("/api/v1/events")
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) >= 2

    # Filter by severity HIGH
    resp_high = client.get("/api/v1/events?severity=HIGH")
    assert resp_high.status_code == 200
    high_events = resp_high.json()
    assert len(high_events) >= 1
    assert all(e["severity"] == "HIGH" for e in high_events)

    # Filter by action QUARANTINE
    resp_quarantine = client.get("/api/v1/events?action=QUARANTINE")
    assert resp_quarantine.status_code == 200
    q_events = resp_quarantine.json()
    assert len(q_events) >= 1
    assert all(e["action_taken"] == "QUARANTINE" for e in q_events)

    # Search term matching spoofed
    resp_search = client.get("/api/v1/events?search=spoofed")
    assert resp_search.status_code == 200
    s_events = resp_search.json()
    assert len(s_events) >= 1
    assert "spoofed" in s_events[0]["candidate_id"].lower()


def test_api_evaluations_endpoints(client):
    """Verify research evaluation endpoints."""
    # List evaluations
    resp = client.get("/api/v1/evaluations")
    assert resp.status_code == 200
    evals = resp.json()
    assert isinstance(evals, list)
    if evals:
        eval_id = evals[0]["evaluation_id"]
        # Detail
        resp_detail = client.get(f"/api/v1/evaluations/{eval_id}")
        assert resp_detail.status_code == 200
        detail = resp_detail.json()
        assert "evaluation_id" in detail
        assert "categories" in detail

        # Trials
        resp_trials = client.get(f"/api/v1/evaluations/{eval_id}/trials?category=AS&limit=5")
        assert resp_trials.status_code in (200, 404)  # 200 if file exists, 404 if not run yet


def test_api_performance(client):
    """Verify GET /api/v1/performance returns disaggregated stats."""
    resp = client.get("/api/v1/performance")
    assert resp.status_code == 200
    data = resp.json()
    assert "pipeline_comparison" in data
    assert "intrinsic_security_pipeline_ms" in data["pipeline_comparison"]
    assert "proxy_forwarding_overhead_ms" in data["pipeline_comparison"]
    assert "interpretation_note" in data


def test_operator_controls_lifecycle(client):
    """Verify operator enforcement controls: apply restriction, release restriction, release quarantine."""
    agent_id = "test_agent_alpha"

    # 1. Apply restriction
    resp = client.post("/api/v1/restriction/apply", json={
        "identity": agent_id,
        "reason": "Test audit restriction",
        "allowed_operations": ["agent/inspect", "health"]
    })
    assert resp.status_code == 200
    assert resp.json()["restricted"] is True

    # Check via agents endpoint
    agents_resp = client.get("/api/v1/agents")
    restricted_identities = [r["identity"] for r in agents_resp.json()["restricted_entities"]]
    assert agent_id in restricted_identities

    # 2. Release restriction
    resp_rel = client.post("/api/v1/restriction/release", json={"identity": agent_id})
    assert resp_rel.status_code == 200
    assert resp_rel.json()["released"] is True

    # 3. Quarantine agent via spoof registration then release quarantine
    client.post("/api/v1/cards/register", json={
        "candidate_id": "spoof_target_01",
        "card": {
            "name": "Hell\u043e World Agent",  # Cyrillic 'о'
            "url": "http://127.0.0.1:8997",
        }
    })
    agents_after_q = client.get("/api/v1/agents").json()
    quarantined_ids = [q["identity"] for q in agents_after_q["quarantined_entities"]]
    assert "spoof_target_01" in quarantined_ids

    # Release quarantine
    rel_q_resp = client.post("/api/v1/quarantine/release", json={"identity": "spoof_target_01"})
    assert rel_q_resp.status_code == 200
    assert rel_q_resp.json()["released"] is True
    assert rel_q_resp.json()["quarantined"] is False


def test_agent_detail_and_ping_endpoints(client):
    """Verify GET /api/v1/agents/{agent_id} and ping endpoints."""
    # 1. Fetch details for helloworld
    resp = client.get("/api/v1/agents/helloworld")
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "helloworld"
    assert data["name"] == "Hello World Agent"
    assert "skills" in data
    assert data["status"] == "TRUSTED"

    # 2. 404 for unknown agent
    resp_404 = client.get("/api/v1/agents/non_existent_agent")
    assert resp_404.status_code == 404

    # 3. Ping endpoint (agent not running in test -> handles offline gracefully)
    ping_resp = client.get("/api/v1/agents/helloworld/ping")
    assert ping_resp.status_code == 200
    ping_data = ping_resp.json()
    assert ping_data["agent_id"] == "helloworld"
    assert "latency_ms" in ping_data
    assert "online" in ping_data


def test_public_cards_endpoint(client):
    """Verify GET /api/v1/registry/public-cards returns the real-world dataset."""
    resp = client.get("/api/v1/registry/public-cards?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_inventory" in data
    assert data["total_inventory"] == 203
    assert "cards" in data
    assert len(data["cards"]) <= 10
    if len(data["cards"]) > 0:
        first = data["cards"][0]
        assert "name" in first
        assert "skills_count" in first or "skills" in first

    # Test search filter
    search_resp = client.get("/api/v1/registry/public-cards?search=nodcheck")
    assert search_resp.status_code == 200
    s_data = search_resp.json()
    assert s_data["matched_count"] >= 1
    assert any("nodcheck" in c["name"].lower() for c in s_data["cards"])


def test_dispatch_task_interactive_workflow(client):
    """
    Verify the Interactive Agent Workspace task dispatcher endpoint:
    - Benign task passes all 6 mediation pipeline steps and returns agent output.
    - Undeclared method (CC exploit attempt) is intercepted and blocked with HTTP 403.
    - Quarantined agent blocks task execution.
    """
    # 1. Benign task dispatch
    benign_payload = {
        "task_prompt": "Hello HelloWorld agent, please process this test task.",
        "method": "echo_bot",
        "caller_id": "operator_console",
    }
    resp = client.post("/api/v1/agents/helloworld/dispatch-task", json=benign_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["agent_id"] == "helloworld"
    assert data["status"] == "COMPLETED"
    assert "steps" in data
    assert len(data["steps"]) == 6
    assert all(s["status"] == "PASS" for s in data["steps"])
    assert data["agent_output"]["result"]["status"] == "COMPLETED"

    # 2. Exploitative task: undeclared capability (Capability Cloaking attack)
    exploit_payload = {
        "task_prompt": "Exploit: execute shell command",
        "method": "system_exec",
        "caller_id": "test_adversary_01",
    }
    resp_exploit = client.post("/api/v1/agents/helloworld/dispatch-task", json=exploit_payload)
    assert resp_exploit.status_code == 403
    data_exploit = resp_exploit.json()
    assert data_exploit["success"] is False
    assert data_exploit["action"] == "QUARANTINE"
    assert data_exploit["violation"]["violation_code"] == "CC_UNDECLARED_CAPABILITY"
    assert any(s["status"] == "BLOCKED" and s["phase"] == "THREAT_DETECTION" for s in data_exploit["steps"])

    # 3. Quarantined target blocks all task dispatch
    client.post("/api/v1/quarantine/apply", json={"identity": "helloworld", "reason": "Test quarantine lock"})
    resp_q = client.post("/api/v1/agents/helloworld/dispatch-task", json=benign_payload)
    assert resp_q.status_code == 403
    data_q = resp_q.json()
    assert data_q["status"] == "QUARANTINED"
    assert any(s["status"] == "BLOCKED" and s["phase"] == "GATEWAY_STATUS_CHECK" for s in data_q["steps"])

    # Release quarantine for clean state
    client.post("/api/v1/quarantine/release", json={"identity": "helloworld"})


def test_governed_vs_discovered_catalog_distinction(client):
    """
    Verify:
    1. Discovered catalog contains 203 offline reference cards.
    2. Governed agents contains only local testbed agents (HelloWorld, AgentAlice).
    3. Public catalog cards are explicitly marked as OFFLINE REFERENCE with no live execution.
    """
    # 1. Overview counts
    ov_resp = client.get("/api/v1/overview")
    assert ov_resp.status_code == 200
    ov_data = ov_resp.json()
    assert ov_data["discovered_agents"] == 203
    assert ov_data["governed_agents"] == 2
    assert "active_session" in ov_data
    assert "research_snapshot" in ov_data

    # 2. Governed agents list
    agents_resp = client.get("/api/v1/agents")
    assert agents_resp.status_code == 200
    agents_data = agents_resp.json()
    assert "governed_agents" in agents_data
    gov_ids = [a["id"] for a in agents_data["governed_agents"]]
    assert "helloworld" in gov_ids
    assert "agentalice" in gov_ids
    for a in agents_data["governed_agents"]:
        assert a["is_governed"] is True
        assert a["status"] in ("TRUSTED", "HEALTHY", "RESTRICTED", "QUARANTINED")
        assert a["health"] in ("HEALTHY", "RESTRICTED", "QUARANTINED")
        assert "declared_capabilities" in a
        assert "supported_task_methods" in a

    # 3. Catalog endpoint (offline reference)
    cat_resp = client.get("/api/v1/catalog?limit=5")
    assert cat_resp.status_code == 200
    cat_data = cat_resp.json()
    assert cat_data["total_discovered"] == 203
    assert cat_data["status"] == "OFFLINE REFERENCE"
    assert len(cat_data["cards"]) <= 5
    for c in cat_data["cards"]:
        assert c["status"] == "OFFLINE REFERENCE"
        assert c["live_interaction"] is False

    # Catalog single agent detail
    c0_id = cat_data["cards"][0]["id"]
    detail_resp = client.get(f"/api/v1/catalog/{c0_id}")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()
    assert detail_data["status"] == "OFFLINE REFERENCE"
    assert detail_data["live_interaction"] is False


def test_agent_activation_deactivation_lifecycle(client):
    """Verify activating and deactivating active session on governed agents."""
    # Activate HelloWorld
    act_resp = client.post("/api/v1/agents/helloworld/activate")
    assert act_resp.status_code == 200
    assert act_resp.json()["active_session"] == "helloworld"

    # State reflects active
    state_resp = client.get("/api/v1/agents/helloworld/state")
    assert state_resp.status_code == 200
    st = state_resp.json()
    assert st["agent_id"] == "helloworld"
    assert st["lifecycle_state"] == "ACTIVE"
    assert st["is_active_session"] is True
    assert st["is_governed"] is True

    # Activate AgentAlice
    act_alice = client.post("/api/v1/agents/agentalice/activate")
    assert act_alice.status_code == 200
    assert act_alice.json()["active_session"] == "agentalice"

    # Deactivate
    deact_resp = client.post("/api/v1/agents/agentalice/deactivate")
    assert deact_resp.status_code == 200
    assert deact_resp.json()["active_session"] is None


def test_safety_boundary_blocks_public_catalog_task_execution(client):
    """
    Safety boundary:
    Public catalog cards are offline references. Calling /task or /dispatch-task
    on external/un-governed agents MUST return HTTP 400.
    """
    resp = client.post("/api/v1/agents/external_public_agent_99/task", json={
        "task_prompt": "Run external code",
        "method": "echo_bot",
    })
    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False
    assert data["status"] == "BLOCKED_SAFETY_BOUNDARY"
    assert data["upstream_contacted"] is False


def test_decision_inspector_and_execution_trace(client):
    """Verify that dispatching a task returns the 7 visual stages and Decision Inspector."""
    payload = {
        "task_prompt": "Hello world from operator console",
        "method": "echo_bot",
        "caller_id": "operator_console",
    }
    resp = client.post("/api/v1/agents/helloworld/task", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True

    # 7-stage visual execution trace
    assert "execution_trace" in data
    trace = data["execution_trace"]
    assert len(trace) == 7
    stage_names = [s["stage"] for s in trace]
    assert stage_names == [
        "REQUEST_RECEIVED",
        "IDENTITY_CHECK",
        "CAPABILITY_CHECK",
        "THREAT_CHECK",
        "POLICY_EVALUATION",
        "UPSTREAM_AGENT",
        "RESPONSE",
    ]

    # Decision Inspector
    assert "decision_inspector" in data
    di = data["decision_inspector"]
    assert di["identity"]["trusted_identity"] == "PASS"
    assert di["identity"]["endpoint_provenance"] == "PASS"
    assert di["capability"]["status"] == "PASS"
    assert di["security_signals"]["agent_spoofing"]["status"] == "PASS"
    assert di["security_signals"]["capability_cloaking"]["status"] == "PASS"
    assert di["security_signals"]["cycle_overflow"]["status"] == "PASS"
    assert di["security_signals"]["rate_limit_state"]["status"] == "NORMAL"
    assert di["policy"]["decision"] == "ALLOW"
    assert di["policy"]["severity"] == "NONE"
    assert "latencies" in di
    assert "detection_ms" in di["latencies"]
    assert "decision_ms" in di["latencies"]


def test_controlled_security_demo_scenarios(client):
    """
    Verify POST /api/v1/demo/scenario for all 5 controlled local scenarios:
    - normal: 200 ALLOW
    - burst: 429 RATE_LIMIT (LOW severity)
    - cloaking: 403 QUARANTINE (HIGH severity, Upstream Contacted: NO)
    - spoof: 403 QUARANTINE (HIGH severity, Upstream Contacted: NO)
    - cycle: 403 QUARANTINE (HIGH severity, Upstream Contacted: NO)
    """
    # 1. Normal task
    r_norm = client.post("/api/v1/demo/scenario", json={"scenario": "normal", "agent_id": "helloworld"})
    assert r_norm.status_code == 200
    d_norm = r_norm.json()
    assert d_norm["action"] == "ALLOW"
    assert d_norm["decision_inspector"]["policy"]["decision"] == "ALLOW"

    # 2. Request burst -> 429 RATE_LIMIT
    r_burst = client.post("/api/v1/demo/scenario", json={"scenario": "burst", "agent_id": "helloworld"})
    assert r_burst.status_code == 429
    d_burst = r_burst.json()
    assert d_burst["status_code"] == 429
    assert d_burst["severity"] == "LOW"
    assert d_burst["action"] == "RATE_LIMIT"

    # 3. Undeclared capability (Capability Cloaking) -> 403 QUARANTINE
    r_cc = client.post("/api/v1/demo/scenario", json={"scenario": "cloaking", "agent_id": "helloworld"})
    assert r_cc.status_code == 403
    d_cc = r_cc.json()
    assert d_cc["status_code"] == 403
    assert d_cc["severity"] == "HIGH"
    assert d_cc["action"] == "QUARANTINE"
    assert d_cc["upstream_contacted"] is False

    # 4. Agent Spoof -> 403 QUARANTINE
    r_spoof = client.post("/api/v1/demo/scenario", json={"scenario": "spoof", "agent_id": "helloworld"})
    assert r_spoof.status_code == 403
    d_spoof = r_spoof.json()
    assert d_spoof["status_code"] == 403
    assert d_spoof["severity"] == "HIGH"
    assert d_spoof["action"] == "QUARANTINE"
    assert d_spoof["upstream_contacted"] is False

    # 5. Delegation Cycle -> 403 QUARANTINE
    r_cyc = client.post("/api/v1/demo/scenario", json={"scenario": "cycle", "agent_id": "helloworld"})
    assert r_cyc.status_code == 403
    d_cyc = r_cyc.json()
    assert d_cyc["status_code"] == 403
    assert d_cyc["severity"] == "HIGH"
    assert d_cyc["action"] == "QUARANTINE"
    assert d_cyc["upstream_contacted"] is False

    # Cleanup any quarantine applied
    client.post("/api/v1/quarantine/release", json={"identity": "demo_spoof_attacker"})
    client.post("/api/v1/quarantine/release", json={"identity": "demo_cycle_initiator"})


def test_human_readable_security_events_enrichment(client):
    """Verify GET /api/v1/events returns enriched human-readable explanations."""
    resp = client.get("/api/v1/events?limit=5")
    assert resp.status_code == 200
    events = resp.json()
    assert isinstance(events, list)
    if events:
        e = events[0]
        assert "human_summary" in e
        assert "what_happened" in e["human_summary"]
        assert "detector_name" in e["human_summary"]
        assert "upstream_contacted" in e["human_summary"]
        assert "enforcement_code" in e["human_summary"]


def test_agent_monitoring_and_policy_mode_controls(client):
    """Verify operator toggles monitoring and policy mode per governed agent."""
    # 1. Toggle monitoring
    m_resp = client.post("/api/v1/agents/helloworld/monitoring", json={"enabled": False})
    assert m_resp.status_code == 200
    assert m_resp.json()["monitoring_enabled"] is False

    # Verify via state
    st1 = client.get("/api/v1/agents/helloworld/state").json()
    assert st1["monitoring_enabled"] is False

    # Re-enable monitoring
    m_resp2 = client.post("/api/v1/agents/helloworld/monitoring", json={"enabled": True})
    assert m_resp2.status_code == 200
    assert m_resp2.json()["monitoring_enabled"] is True

    # 2. Change policy mode
    p_resp = client.post("/api/v1/agents/helloworld/policy", json={"mode": "PERMISSIVE"})
    assert p_resp.status_code == 200
    assert p_resp.json()["policy_mode"] == "PERMISSIVE"

    # Reset to GRADUATED
    p_resp2 = client.post("/api/v1/agents/helloworld/policy", json={"mode": "GRADUATED"})
    assert p_resp2.status_code == 200
    assert p_resp2.json()["policy_mode"] == "GRADUATED"






def test_governance_system_status(client):
    """Tests GET /api/governance/system/status reports Landlock, seccomp, cgroups and sensor."""
    resp = client.get("/api/governance/system/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "landlock_abi" in data
    assert "seccomp_available" in data
    assert "cgroup_v2" in data
    assert "sensor_mode" in data
    assert isinstance(data["landlock_abi"], int)
    assert isinstance(data["seccomp_available"], bool)
