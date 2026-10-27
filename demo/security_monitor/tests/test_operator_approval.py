import sys
from pathlib import Path

# Add repo root and demo/security_monitor to sys.path
repo_root = str(Path(__file__).resolve().parents[3])
sec_mon = str(Path(__file__).resolve().parents[1])
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
if sec_mon not in sys.path:
    sys.path.insert(0, sec_mon)
import os
import time
import json
import tempfile
import threading
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.gateway.server import create_app
from app.governance.models import (
    ExpansionRequest,
    ExpansionStatus,
    GovernanceEvent,
    ProvenanceRecord,
    RiskTier,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from app.governance.storage import GovernanceStorage
from app.governance.expansion import ExpansionService
from app.governance.broker import ToolBroker
from app.governance.launcher import (
    ExpansionDelivery,
    TaskLauncher,
    TaskSpec,
)


@pytest.fixture
def test_env(tmp_path: Path):
    db_path = tmp_path / "test_gov.db"
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    os.environ["GOVERNANCE_DB_PATH"] = str(db_path)
    os.environ["RECEIPTS_DIR"] = str(receipts_dir)
    os.environ["GOVERNANCE_OPERATOR_TOKEN"] = "test_secret_token"
    os.environ["GOVERNANCE_OPERATOR_NAME"] = "secops_lead"

    storage = GovernanceStorage(db_path)
    client = TestClient(create_app())

    yield {
        "storage": storage,
        "client": client,
        "db_path": db_path,
        "receipts_dir": receipts_dir,
        "tmp_path": tmp_path,
    }


def test_approver_recorded_by_server_and_deny_requires_reason(test_env):
    storage: GovernanceStorage = test_env["storage"]
    client: TestClient = test_env["client"]

    # Create task
    task = TaskRecord(
        task_id="task_test_op_1",
        request_text="Process financials",
        request_hash="hash1",
        agent_id="test_agent",
        workspace_root="/tmp/ws1",
        status=TaskLifecycle.ACTIVE,
        created_at="2026-10-27T10:00:00Z",
    )
    storage.save_task(task)
    boundary = TaskBoundary(
        task_id="task_test_op_1",
        workspace_root="/tmp/ws1",
        files_read=["input/notes.txt"],
        files_write=["output/res.txt"],
        network_hosts=[],
        peer_agents=[],
    )
    storage.save_boundary(boundary)

    expansion = ExpansionService(storage, provenance_enabled=True, user_approval_hook=None, simulated_user_policy="operator")
    # Record untrusted read to taint agent
    expansion.record_untrusted_read("task_test_op_1", "file_read", "input/notes.txt", "Read notes mentioning input/target.csv")

    # Evaluate request for input/target.csv (baseline LOW -> effective MEDIUM, status PENDING)
    req = expansion.evaluate_request(
        task_id="task_test_op_1",
        agent_id="test_agent",
        resource_type="file_read",
        resource_target="input/target.csv",
        justification="Need target.csv",
        timeout_seconds=10.0,
    )
    assert req.status == ExpansionStatus.PENDING
    assert req.escalated_by_provenance is True
    assert req.effective_risk_tier == RiskTier.MEDIUM

    # 1. Deny without reason -> 422
    resp_deny_no_reason = client.post(
        f"/api/governance/expansions/{req.request_id}/deny",
        headers={"Authorization": "Bearer test_secret_token"},
        json={"decided_by": "attacker", "reason": ""},
    )
    assert resp_deny_no_reason.status_code == 422

    # 2. Approve: client tries to supply fake decided_by "fake_user", server must record "operator:secops_lead"
    resp_approve = client.post(
        f"/api/governance/expansions/{req.request_id}/approve",
        headers={"Authorization": "Bearer test_secret_token"},
        json={"decided_by": "fake_user", "reason": "Authorized by secops"},
    )
    assert resp_approve.status_code == 200
    data = resp_approve.json()
    assert data["status"] == "APPROVED"
    assert data["request"]["resolved_by"] == "operator:secops_lead"

    # Verify directly in storage
    updated_req = storage.get_expansion_request(req.request_id)
    assert updated_req.status == ExpansionStatus.APPROVED
    assert updated_req.resolved_by == "operator:secops_lead"

    # Now create another request to test deny with reason
    req2 = expansion.evaluate_request(
        task_id="task_test_op_1",
        agent_id="test_agent",
        resource_type="file_read",
        resource_target="input/other.csv",
        justification="Need other.csv",
        timeout_seconds=10.0,
    )
    resp_deny = client.post(
        f"/api/governance/expansions/{req2.request_id}/deny",
        headers={"Authorization": "Bearer test_secret_token"},
        json={"decided_by": "fake_user", "reason": "Not permitted for this phase"},
    )
    assert resp_deny.status_code == 200
    assert resp_deny.json()["status"] == "DENIED"
    updated_req2 = storage.get_expansion_request(req2.request_id)
    assert updated_req2.status == ExpansionStatus.DENIED
    assert updated_req2.resolved_by == "operator:secops_lead"
    assert updated_req2.reason == "Not permitted for this phase"


def test_high_request_under_operator_policy_is_denied_never_pending(test_env):
    storage: GovernanceStorage = test_env["storage"]
    task = TaskRecord(
        task_id="task_test_op_high",
        request_text="Process files",
        request_hash="hash_h",
        agent_id="test_agent",
        workspace_root="/tmp/ws_h",
        status=TaskLifecycle.ACTIVE,
        created_at="2026-10-27T10:00:00Z",
    )
    storage.save_task(task)
    expansion = ExpansionService(storage, provenance_enabled=True, user_approval_hook=None, simulated_user_policy="operator")

    # Outside workspace is HIGH baseline risk
    req = expansion.evaluate_request(
        task_id="task_test_op_high",
        agent_id="test_agent",
        resource_type="file_read",
        resource_target="/etc/passwd",
        justification="Check system passwd",
        timeout_seconds=5.0,
    )
    assert req.status == ExpansionStatus.DENIED
    assert req.status != ExpansionStatus.PENDING
    assert req.effective_risk_tier == RiskTier.HIGH


def test_operator_policy_timeout_fail_closed(test_env):
    storage: GovernanceStorage = test_env["storage"]
    task = TaskRecord(
        task_id="task_timeout_test",
        request_text="Process files",
        request_hash="hash_to",
        agent_id="test_agent",
        workspace_root="/tmp/ws_to",
        status=TaskLifecycle.ACTIVE,
        created_at="2026-10-27T10:00:00Z",
    )
    storage.save_task(task)
    boundary = TaskBoundary(
        task_id="task_timeout_test",
        workspace_root="/tmp/ws_to",
        files_read=["input/notes.txt"],
        files_write=["output/res.txt"],
        network_hosts=[],
        peer_agents=[],
    )
    storage.save_boundary(boundary)

    expansion = ExpansionService(storage, provenance_enabled=True, user_approval_hook=None, simulated_user_policy="operator")
    expansion.record_untrusted_read("task_timeout_test", "file_read", "input/notes.txt", "Mentions input/target.csv")

    t0 = time.time()
    # Wait for 0.3s timeout
    granted, msg = expansion.request_and_wait(
        task_id="task_timeout_test",
        agent_id="test_agent",
        resource_type="file_read",
        resource_target="input/target.csv",
        justification="Need target.csv",
        timeout_seconds=0.3,
    )
    elapsed = time.time() - t0
    assert elapsed >= 0.25
    assert granted is False
    assert "denied" in msg.lower() or "timed out" in msg.lower()

    # Verify request record in storage
    reqs = storage.list_expansion_requests(task_id="task_timeout_test")
    assert len(reqs) == 1
    assert reqs[0].status == ExpansionStatus.DENIED
    assert reqs[0].resolved_by == "timeout_fail_closed"


def test_operator_policy_api_approval_within_timeout_delivers_file(test_env):
    storage: GovernanceStorage = test_env["storage"]
    client: TestClient = test_env["client"]
    tmp_path: Path = test_env["tmp_path"]

    # Setup simulated workspace
    ws = tmp_path / "ws_delivery"
    ws.mkdir(parents=True)
    input_dir = ws / "input"
    input_dir.mkdir()
    target_file = input_dir / "target.csv"
    target_file.write_text("id,val\n1,100\n", encoding="utf-8")

    task = TaskRecord(
        task_id="task_deliv_test",
        request_text="Process files",
        request_hash="hash_d",
        agent_id="test_agent",
        workspace_root=str(ws),
        status=TaskLifecycle.ACTIVE,
        created_at="2026-10-27T10:00:00Z",
    )
    storage.save_task(task)
    boundary = TaskBoundary(
        task_id="task_deliv_test",
        workspace_root=str(ws),
        files_read=["input/notes.txt"],
        files_write=["output/res.txt"],
        network_hosts=[],
        peer_agents=[],
    )
    storage.save_boundary(boundary)

    expansion = ExpansionService(storage, provenance_enabled=True, user_approval_hook=None, simulated_user_policy="operator")
    expansion.record_untrusted_read("task_deliv_test", "file_read", "input/notes.txt", "Mentions input/target.csv")

    broker = ToolBroker(storage, expansion_service=expansion)
    broker.default_approval_timeout = 5.0
    storage.save_token("tok_test", "task_deliv_test", "test_agent")

    delivery = ExpansionDelivery(ws, storage)

    # Launch background approval after 0.2s
    def delayed_approve():
        time.sleep(0.2)
        # Find pending request
        reqs = storage.list_expansion_requests(task_id="task_deliv_test")
        assert len(reqs) == 1
        rid = reqs[0].request_id
        res = client.post(
            f"/api/governance/expansions/{rid}/approve",
            headers={"Authorization": "Bearer test_secret_token"},
            json={"reason": "Approved by human operator"},
        )
        assert res.status_code == 200

    th = threading.Thread(target=delayed_approve)
    th.start()

    res = broker.request_access(
        token="tok_test",
        resource_type="file_read",
        resource_target="input/target.csv",
        justification="Need target.csv",
        timeout_seconds=4.0,
    )
    th.join()

    assert res["granted"] is True
    # Perform delivery check
    deliv_info = delivery.deliver("task_deliv_test", "file_read", "input/target.csv", True)
    assert deliv_info["type"] == "file_copy"
    assert (ws / "granted" / "input" / "target.csv").is_file()
    assert (ws / "granted" / "input" / "target.csv").read_text() == "id,val\n1,100\n"


def test_provenance_reads_exposed_in_expansions_api(test_env):
    storage: GovernanceStorage = test_env["storage"]
    client: TestClient = test_env["client"]

    task = TaskRecord(
        task_id="task_prov_api",
        request_text="Analyze raw transaction log",
        request_hash="hash_p",
        agent_id="test_agent",
        workspace_root="/tmp/ws_p",
        status=TaskLifecycle.ACTIVE,
        created_at="2026-10-27T10:00:00Z",
    )
    storage.save_task(task)

    expansion = ExpansionService(storage, provenance_enabled=True, user_approval_hook=None, simulated_user_policy="operator")
    expansion.record_untrusted_read("task_prov_api", "file_read", "input/notes.txt", "Malicious notes content")

    req = expansion.evaluate_request(
        task_id="task_prov_api",
        agent_id="test_agent",
        resource_type="file_read",
        resource_target="input/target.csv",
        justification="Need target.csv",
        timeout_seconds=5.0,
    )

    # 1. Test GET /api/governance/expansions
    resp = client.get("/api/governance/expansions?task_id=task_prov_api")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    item = items[0]
    assert item["request_id"] == req.request_id
    assert item["task_request_text"] == "Analyze raw transaction log"
    assert len(item["prior_untrusted_reads"]) == 1
    assert item["prior_untrusted_reads"][0]["source_target"] == "input/notes.txt"
    assert "Malicious notes" in item["prior_untrusted_reads"][0]["content_snippet"]

    # 2. Test GET /api/governance/expansions/{id}
    resp_single = client.get(f"/api/governance/expansions/{req.request_id}")
    assert resp_single.status_code == 200
    single_data = resp_single.json()
    assert single_data["request_id"] == req.request_id
    assert single_data["task_request_text"] == "Analyze raw transaction log"
    assert len(single_data["prior_untrusted_reads"]) == 1
    assert single_data["prior_untrusted_reads"][0]["source_target"] == "input/notes.txt"


def test_receipt_raw_download_byte_for_byte(test_env):
    storage: GovernanceStorage = test_env["storage"]
    client: TestClient = test_env["client"]
    receipts_dir: Path = test_env["receipts_dir"]

    task_id = "task_receipt_raw_test"
    task = TaskRecord(
        task_id=task_id,
        request_text="Receipt download test",
        request_hash="hash_r",
        agent_id="test_agent",
        workspace_root="/tmp/ws_r",
        status=TaskLifecycle.COMPLETED,
        created_at="2026-10-27T10:00:00Z",
    )
    storage.save_task(task)

    receipt_content = {
        "task_id": task_id,
        "events": [],
        "hash_chain": {"count": 0, "final_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    }
    raw_bytes = json.dumps(receipt_content, indent=2).encode("utf-8")
    receipt_file = receipts_dir / f"{task_id}.json"
    receipt_file.write_bytes(raw_bytes)

    # Test GET /api/governance/tasks/{id}/receipt metadata
    resp_meta = client.get(f"/api/governance/tasks/{task_id}/receipt")
    assert resp_meta.status_code == 200
    meta = resp_meta.json()
    assert meta["available"] is True
    assert meta["file_sha256"] is not None
    assert meta["final_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Test GET /api/governance/tasks/{id}/receipt/raw
    resp_raw = client.get(f"/api/governance/tasks/{task_id}/receipt/raw")
    assert resp_raw.status_code == 200
    assert resp_raw.headers.get("content-disposition") == f'attachment; filename="{task_id}_receipt.json"'
    # Byte-for-byte exact comparison
    assert resp_raw.content == raw_bytes


def test_events_stream_cursor_newest_first_and_limits(test_env):
    storage: GovernanceStorage = test_env["storage"]
    client: TestClient = test_env["client"]

    # Seed two tasks
    task1 = TaskRecord(
        task_id="task_evt_1",
        request_text="Older task",
        request_hash="hash1",
        agent_id="agent1",
        workspace_root="/tmp/ws1",
        status=TaskLifecycle.COMPLETED,
        created_at="2026-10-27T10:00:00Z",
    )
    task2 = TaskRecord(
        task_id="task_evt_2",
        request_text="Newer task",
        request_hash="hash2",
        agent_id="agent2",
        workspace_root="/tmp/ws2",
        status=TaskLifecycle.COMPLETED,
        created_at="2026-10-27T10:10:00Z",
    )
    storage.save_task(task1)
    storage.save_task(task2)

    # Seed events for task1 (older) and task2 (newer)
    for i in range(1, 4):
        storage.record_event(GovernanceEvent(
            event_id=f"evt_task1_{i:03d}",
            timestamp=f"2026-10-27T10:0{i}:00Z",
            source="TOOL_BROKER",
            task_id="task_evt_1",
            agent_id="agent1",
            kind="file_read",
            target=f"input/file_{i}.txt",
            verdict="INSIDE",
            risk_tier=RiskTier.LOW,
            action_taken="ALLOW",
            prevented=False,
            rule_matched="allowed",
        ))

    for i in range(1, 4):
        storage.record_event(GovernanceEvent(
            event_id=f"evt_task2_{i:03d}",
            timestamp=f"2026-10-27T10:1{i}:00Z",
            source="TOOL_BROKER",
            task_id="task_evt_2",
            agent_id="agent2",
            kind="file_read",
            target=f"input/newer_file_{i}.txt",
            verdict="INSIDE",
            risk_tier=RiskTier.LOW,
            action_taken="ALLOW",
            prevented=False,
            rule_matched="allowed",
        ))

    # 1. Fetch with limit=3: newest events (from task2) must appear first
    resp = client.get("/api/governance/events?limit=3")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 3
    assert data["events"][0]["task_id"] == "task_evt_2"
    assert data["events"][0]["event_id"] == "evt_task2_003"
    assert data["events"][1]["event_id"] == "evt_task2_002"
    assert data["events"][2]["event_id"] == "evt_task2_001"
    assert data["cursor"] != ""

    # 2. Poll with cursor of the newest event: should return 0 new events
    cursor = data["cursor"]
    resp_poll = client.get(f"/api/governance/events?since={cursor}")
    assert resp_poll.status_code == 200
    assert len(resp_poll.json()["events"]) == 0

    # 3. Add a brand new event to task2
    brand_new = GovernanceEvent(
        event_id="evt_task2_004",
        timestamp="2026-10-27T10:20:00Z",
        source="TOOL_BROKER",
        task_id="task_evt_2",
        agent_id="agent2",
        kind="file_write",
        target="output/result.txt",
        verdict="INSIDE",
        risk_tier=RiskTier.LOW,
        action_taken="ALLOW",
        prevented=False,
        rule_matched="allowed",
    )
    storage.record_event(brand_new)

    # 4. Poll again with cursor: should return only the brand new event
    resp_poll2 = client.get(f"/api/governance/events?since={cursor}")
    assert resp_poll2.status_code == 200
    poll2_data = resp_poll2.json()
    assert len(poll2_data["events"]) == 1
    assert poll2_data["events"][0]["event_id"] == "evt_task2_004"
    assert poll2_data["cursor"] != cursor

    # 5. Limit respected
    resp_all = client.get("/api/governance/events?limit=100")
    assert resp_all.status_code == 200
    assert len(resp_all.json()["events"]) == 7  # 3 from task1 + 4 from task2


def test_provenance_reads_filtered_by_timestamp_and_linked_marking(test_env):
    storage: GovernanceStorage = test_env["storage"]
    client: TestClient = test_env["client"]

    task_id = "task_prov_time_filter"
    req_id = "exp_prov_time_filter"

    task = TaskRecord(
        task_id=task_id,
        request_text="Process secret records",
        request_hash="hash_prov_time",
        agent_id="agent_prov",
        workspace_root="/tmp/ws_prov_time",
        status=TaskLifecycle.ACTIVE,
        created_at="2026-10-27T10:00:00Z",
    )
    storage.save_task(task)

    # 1. Read before request that mentions target.csv -> must be included with linked=True
    pr_before_linked = ProvenanceRecord(
        task_id=task_id,
        timestamp="2026-10-27T10:01:00Z",
        source_type="file_read",
        source_target="input/notes.txt",
        content_hash="h1",
        content_len=50,
        content_snippet="Notice: Please inspect target.csv in input directory",
    )
    storage.record_provenance(pr_before_linked)

    # 2. Read before request that does NOT mention target.csv -> must be included with linked=False
    pr_before_unlinked = ProvenanceRecord(
        task_id=task_id,
        timestamp="2026-10-27T10:02:00Z",
        source_type="file_read",
        source_target="input/guidelines.txt",
        content_hash="h2",
        content_len=40,
        content_snippet="General guidelines without target mention",
    )
    storage.record_provenance(pr_before_unlinked)

    # 3. Expansion request created at 10:05:00Z
    req = ExpansionRequest(
        request_id=req_id,
        task_id=task_id,
        agent_id="agent_prov",
        resource_type="file_read",
        resource_target="input/target.csv",
        justification="Need target.csv",
        baseline_risk_tier=RiskTier.LOW,
        effective_risk_tier=RiskTier.MEDIUM,
        escalated_by_provenance=True,
        status=ExpansionStatus.PENDING,
        created_at="2026-10-27T10:05:00Z",
    )
    storage.save_expansion_request(req)

    # 4. Read after request created at 10:08:00Z -> must be EXCLUDED from prior_untrusted_reads
    pr_after = ProvenanceRecord(
        task_id=task_id,
        timestamp="2026-10-27T10:08:00Z",
        source_type="file_read",
        source_target="input/later_note.txt",
        content_hash="h3",
        content_len=60,
        content_snippet="Mentioning target.csv but read after request creation",
    )
    storage.record_provenance(pr_after)

    # Fetch enriched expansion
    resp = client.get(f"/api/governance/expansions/{req_id}")
    assert resp.status_code == 200
    data = resp.json()

    prior_reads = data["prior_untrusted_reads"]
    # Must only contain the 2 reads before the request
    assert len(prior_reads) == 2, f"Expected 2 reads, got {len(prior_reads)}"

    targets = [p["source_target"] for p in prior_reads]
    assert "input/notes.txt" in targets
    assert "input/guidelines.txt" in targets
    assert "input/later_note.txt" not in targets

    # Check linked flag
    read_linked = next(p for p in prior_reads if p["source_target"] == "input/notes.txt")
    assert read_linked["linked"] is True

    read_unlinked = next(p for p in prior_reads if p["source_target"] == "input/guidelines.txt")
    assert read_unlinked["linked"] is False


def test_events_cursor_ascending_pagination_over_multiple_polls(test_env):
    storage: GovernanceStorage = test_env["storage"]
    client: TestClient = test_env["client"]

    task_id = "task_pagination_test"
    task = TaskRecord(
        task_id=task_id,
        request_text="Pagination test task",
        request_hash="hash_pag",
        agent_id="agent_pag",
        workspace_root="/tmp/ws_pag",
        status=TaskLifecycle.ACTIVE,
        created_at="2026-10-27T11:00:00Z",
    )
    storage.save_task(task)

    # Seed baseline event so initial cursor is established
    storage.record_event(GovernanceEvent(
        event_id="evt_baseline_0",
        timestamp="2026-10-27T11:00:00Z",
        source="TOOL_BROKER",
        task_id=task_id,
        agent_id="agent_pag",
        kind="file_read",
        target="input/init.txt",
        verdict="INSIDE",
        risk_tier=RiskTier.LOW,
        action_taken="ALLOW",
        prevented=False,
        rule_matched="allowed",
    ))

    # Get baseline cursor before adding our 5 test events
    init_resp = client.get("/api/governance/events?limit=100")
    assert init_resp.status_code == 200
    baseline_cursor = init_resp.json()["cursor"]
    assert "evt_baseline_0" in baseline_cursor

    # Seed 5 new events with chronological timestamps
    event_ids = [f"evt_poll_{i}" for i in range(1, 6)]
    for i, eid in enumerate(event_ids, 1):
        storage.record_event(GovernanceEvent(
            event_id=eid,
            timestamp=f"2026-10-27T11:0{i}:00Z",
            source="TOOL_BROKER",
            task_id=task_id,
            agent_id="agent_pag",
            kind="file_read",
            target=f"input/doc_{i}.txt",
            verdict="INSIDE",
            risk_tier=RiskTier.LOW,
            action_taken="ALLOW",
            prevented=False,
            rule_matched="allowed",
        ))

    # Poll 1 with limit=2: should return oldest 2 events (evt_poll_1, evt_poll_2)
    resp1 = client.get(f"/api/governance/events?since={baseline_cursor}&limit=2")
    assert resp1.status_code == 200
    d1 = resp1.json()
    assert len(d1["events"]) == 2
    assert d1["events"][0]["event_id"] == "evt_poll_1"
    assert d1["events"][1]["event_id"] == "evt_poll_2"
    cursor1 = d1["cursor"]
    assert "evt_poll_2" in cursor1

    # Poll 2 with limit=2: should return next 2 oldest events (evt_poll_3, evt_poll_4)
    resp2 = client.get(f"/api/governance/events?since={cursor1}&limit=2")
    assert resp2.status_code == 200
    d2 = resp2.json()
    assert len(d2["events"]) == 2
    assert d2["events"][0]["event_id"] == "evt_poll_3"
    assert d2["events"][1]["event_id"] == "evt_poll_4"
    cursor2 = d2["cursor"]
    assert "evt_poll_4" in cursor2

    # Poll 3 with limit=2: should return remaining 1 event (evt_poll_5)
    resp3 = client.get(f"/api/governance/events?since={cursor2}&limit=2")
    assert resp3.status_code == 200
    d3 = resp3.json()
    assert len(d3["events"]) == 1
    assert d3["events"][0]["event_id"] == "evt_poll_5"
    cursor3 = d3["cursor"]
    assert "evt_poll_5" in cursor3

    # Poll 4 with limit=2: no new events, cursor unchanged
    resp4 = client.get(f"/api/governance/events?since={cursor3}&limit=2")
    assert resp4.status_code == 200
    d4 = resp4.json()
    assert len(d4["events"]) == 0
    assert d4["cursor"] == cursor3
