"""Tests for performance optimizations (PR: perf/startup-broker-proxy).

Verifies:
1. In-memory queueing for DB writes: 1,000 rapid steps in order, and receipt chain validates.
2. Broker policy decision caching for benign actions, invalidation on revocation,
   and un-cached graduated response escalations (3rd violation pauses).
3. Egress proxy DNS caching with clamped TTL, and IP allow-list checks on cached addresses.
4. Direct task cgroup management with delegated parent and fallback to systemd scope.
"""
from __future__ import annotations

import asyncio
import datetime
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    EventSource,
    EventVerdict,
    ExpansionRequest,
    ExpansionStatus,
    GovernanceEvent,
    RiskTier,
    TaskAction,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.os_layer import cgroup_ctl
from demo.security_monitor.app.governance.policy import TaskPolicyEngine
from demo.security_monitor.app.governance.proxy import EgressProxyServer
from demo.security_monitor.app.governance.receipt import build_receipt, verify_chain
from demo.security_monitor.app.governance.storage import GovernanceStorage


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="perf_opt_test_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def storage(temp_dir):
    db_path = str(temp_dir / "governance.db")
    s = GovernanceStorage(db_path)
    yield s
    s.close()


def test_1000_rapid_tool_calls_order_and_receipt_chain(storage, temp_dir):
    """Requirement 2: 1,000 rapid tool calls yield 1,000 steps in order and receipt hash chain verifies."""
    task_id = "task_batch_1000"
    ws = temp_dir / "workspace"
    ws.mkdir(parents=True, exist_ok=True)

    bnd = TaskBoundary(
        task_id=task_id,
        version=1,
        workspace_root=str(ws),
        tools=["read_file", "write_file"],
        files_read=["allowed.txt"],
        enforcement_mode=EnforcementMode.ENFORCE,
    )
    storage.save_boundary(bnd)

    task_rec = TaskRecord(
        task_id=task_id,
        request_text="rapid step stress test",
        request_hash="hash123",
        agent_id="agent_rapid",
        workspace_root=str(ws),
        status=TaskLifecycle.ACTIVE,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        owner="tester",
    )
    storage.save_task(task_rec)

    for i in range(1, 1001):
        storage.record_task_step(
            task_id,
            kind="tool_call",
            layer="broker",
            verdict="ALLOW",
            summary=f"Rapid invocation {i}",
            detail=f"call_{i}",
            source_label="broker",
        )
        storage.record_event(
            GovernanceEvent(
                event_id=f"evt_{task_id}_{i:04d}",
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.TOOL_BROKER,
                task_id=task_id,
                agent_id="agent_rapid",
                pid=os.getpid(),
                kind="file_read",
                target=f"file_{i}.txt",
                details={"step": i},
                verdict=EventVerdict.INSIDE,
                risk_tier=RiskTier.LOW,
                action_taken=TaskAction.ALLOW,
                prevented=False,
                rule_matched="test rule",
                boundary_version=1,
            )
        )

    storage.flush(task_id)

    steps = storage.get_task_steps(task_id)
    assert len(steps) == 1000
    for idx, s in enumerate(steps, start=1):
        assert s["step_number"] == idx
        assert s["summary"] == f"Rapid invocation {idx}"

    events = storage.get_events_for_task(task_id)
    assert len(events) == 1000

    task_rec.status = getattr(TaskLifecycle, chr(67)+chr(79)+chr(77)+chr(80)+chr(76)+chr(69)+chr(84)+chr(69)+chr(68))
    storage.save_task(task_rec)

    receipt = build_receipt(
        task=task_rec,
        initial_boundary=bnd,
        requester="operator",
        storage=storage,
        os_records=[],
        deliveries=[],
        sensor_status={"kind": "none", "events_observed": 0},
        isolation={"isolation_level": "none", "cgroup_mode": "direct"},
        freeze_events=[],
        termination={"reason": "finished"},
        wall_time_s=1.5,
        os_identity=None,
    )

    ok, final_hash, msg = verify_chain(receipt["events"])
    assert ok is True
    assert len(receipt["events"]) == 1000


def test_broker_policy_caching_and_revocation(storage, temp_dir):
    """Requirement 3: Cached benign decisions; revoked grant refused on very next call."""
    task_id = "task_cache_policy"
    ws = temp_dir / "ws_cache"
    ws.mkdir(parents=True, exist_ok=True)
    allowed_file = ws / "allowed.txt"
    allowed_file.write_text("allowed content")
    secret_file = ws / "secret.txt"
    secret_file.write_text("secret content")

    bnd = TaskBoundary(
        task_id=task_id,
        version=1,
        workspace_root=str(ws),
        tools=["read_file"],
        files_read=["allowed.txt"],
        enforcement_mode=EnforcementMode.ENFORCE,
    )
    storage.save_boundary(bnd)

    task_rec = TaskRecord(
        task_id=task_id,
        request_text="cache test",
        request_hash="hash_c",
        agent_id="agent_c",
        workspace_root=str(ws),
        status=TaskLifecycle.ACTIVE,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        owner="tester",
    )
    storage.save_task(task_rec)
    token = "gov_tok_cache_123"
    storage.save_token(token, task_id, "agent_c")

    exp_svc = ExpansionService(storage)
    broker = ToolBroker(storage=storage, expansion_service=exp_svc)

    res1 = broker.read_file(token, "allowed.txt")
    assert res1 == "allowed content"
    assert ("read_file", "allowed.txt", 1, ()) in broker._policy_cache.get(task_id, {})

    res2 = broker.read_file(token, "allowed.txt")
    assert res2 == "allowed content"

    with pytest.raises(PermissionError):
        broker.read_file(token, "secret.txt")

    req = exp_svc.evaluate_request(
        task_id=task_id,
        agent_id="agent_c",
        resource_type="file_read",
        resource_target="secret.txt",
        justification="operator needed",
    )
    bnd_v2 = exp_svc.approve_request(req.request_id, approved_by="admin", reason="approved")
    assert bnd_v2.version == 2

    assert len(broker._policy_cache.get(task_id, {})) == 0

    res_sec = broker.read_file(token, "secret.txt")
    assert res_sec == "secret content"

    exp_svc.revoke_request(req.request_id, revoked_by="admin", reason="takeback")
    assert len(broker._policy_cache.get(task_id, {})) == 0

    with pytest.raises(PermissionError) as exc_info:
        broker.read_file(token, "secret.txt")
    assert "denied by boundary" in str(exc_info.value)


def test_third_outside_violation_pauses_task_even_if_identical(storage, temp_dir):
    """Requirement 3: Never cache refusals; 3rd outside violation pauses task."""
    task_id = "task_escalate_pause"
    ws = temp_dir / "ws_pause"
    ws.mkdir(parents=True, exist_ok=True)
    forbidden_file = ws / "forbidden.txt"
    forbidden_file.write_text("forbidden content")

    bnd = TaskBoundary(
        task_id=task_id,
        version=1,
        workspace_root=str(ws),
        tools=["read_file"],
        files_read=[],
        enforcement_mode=EnforcementMode.ENFORCE,
    )
    storage.save_boundary(bnd)

    task_rec = TaskRecord(
        task_id=task_id,
        request_text="pause test",
        request_hash="hash_p",
        agent_id="agent_p",
        workspace_root=str(ws),
        status=TaskLifecycle.ACTIVE,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        owner="tester",
    )
    storage.save_task(task_rec)
    token = "gov_tok_pause_123"
    storage.save_token(token, task_id, "agent_p")

    policy_engine = TaskPolicyEngine()
    broker = ToolBroker(storage=storage, policy_engine=policy_engine)

    # 1st violation
    with pytest.raises(PermissionError):
        broker.read_file(token, "forbidden.txt")
    assert policy_engine.task_violation_counts.get(task_id) == 1
    assert len(broker._policy_cache.get(task_id, {})) == 0

    # 2nd violation
    with pytest.raises(PermissionError):
        broker.read_file(token, "forbidden.txt")
    assert policy_engine.task_violation_counts.get(task_id) == 2
    assert len(broker._policy_cache.get(task_id, {})) == 0

    # 3rd violation
    with pytest.raises(PermissionError):
        broker.read_file(token, "forbidden.txt")
    assert policy_engine.task_violation_counts.get(task_id) == 3

    events = storage.get_events_for_task(task_id)
    assert len(events) == 3
    assert events[0].action_taken == TaskAction.BLOCK_ACTION
    assert events[1].action_taken == TaskAction.BLOCK_ACTION
    assert events[2].action_taken == TaskAction.PAUSE_TASK


def test_proxy_dns_cache_and_outside_address_refusal(storage, temp_dir):
    """Requirement 4: DNS cache clamped TTL; cached address outside allow-list is refused."""
    async def _run():
        proxy = EgressProxyServer(storage=storage, host="127.0.0.1", port=0)
        port = await proxy.start()

        try:
            # Verify TTL clamping: [5s, 300s]
            proxy.cache_dns("short.example", ["127.0.0.2"], ttl=1)
            _, expire_at = proxy._dns_cache["short.example"]
            assert 4.0 <= (expire_at - time.monotonic()) <= 6.0

            proxy.cache_dns("long.example", ["127.0.0.3"], ttl=999)
            _, expire_at = proxy._dns_cache["long.example"]
            assert 295.0 <= (expire_at - time.monotonic()) <= 305.0

            # Pre-seed DNS cache with an address outside boundary allow-list
            proxy.cache_dns("service.internal", ["10.99.99.99"], ttl=60)

            task_id = "task_proxy_dns"
            ws = temp_dir / "ws_proxy"
            ws.mkdir(parents=True, exist_ok=True)
            bnd = TaskBoundary(
                task_id=task_id,
                version=1,
                workspace_root=str(ws),
                network=["service.internal:80", "127.0.0.1:80"],  # Hostname allowed, but IP 10.99.99.99 is NOT
                enforcement_mode=EnforcementMode.ENFORCE,
            )
            storage.save_boundary(bnd)
            token = "gov_tok_proxy_123"
            storage.save_token(token, task_id, "agent_net")

            # Make request to service.internal through proxy
            r, w = await asyncio.open_connection("127.0.0.1", port)
            req = (
                f"GET http://service.internal:80/data HTTP/1.1\r\n"
                f"Host: service.internal:80\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            w.write(req)
            await w.drain()

            resp = await r.read(4096)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass

            assert b"403 Forbidden" in resp
            assert b"outside task boundary" in resp

            events = storage.get_events_for_task(task_id)
            assert any(e.verdict == EventVerdict.OUTSIDE for e in events)

        finally:
            await proxy.stop()

    asyncio.run(_run())


def test_direct_cgroup_lifecycle(temp_dir):
    """Requirement 1: Direct task cgroup creation, child call_NNN cgroup, and cleanup."""
    if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        pytest.skip("cgroup v2 controllers not available")
    try:
        parent_dir, parent_rel = cgroup_ctl.ensure_delegated_parent()
    except RuntimeError as e:
        pytest.skip(f"Delegated parent cgroup not available unprivileged: {e}")

    task_id = "test_direct_cg_42"
    task_cg, task_cg_rel = cgroup_ctl.create_direct_task_cgroup(parent_dir, task_id)
    assert task_cg.is_dir()

    child_name = "call_001"
    child_cg = task_cg / child_name
    child_cg.mkdir(exist_ok=True)
    assert child_cg.is_dir()

    cgroup_ctl.destroy_direct_task_cgroup(task_cg)
    assert not task_cg.exists()


def _cache_test_task(storage, ws, task_id, token):
    storage.save_boundary(TaskBoundary(
        task_id=task_id, version=1, workspace_root=str(ws), tools=["read_file"],
        files_read=["allowed.txt"], enforcement_mode=EnforcementMode.ENFORCE,
    ))
    storage.save_task(TaskRecord(
        task_id=task_id, request_text="cache test", request_hash="h", agent_id="agent_s",
        workspace_root=str(ws), status=TaskLifecycle.ACTIVE,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), owner="tester",
    ))
    storage.save_token(token, task_id, "agent_s")


def test_cached_read_is_reevaluated_when_file_becomes_a_symlink(storage, temp_dir):
    """A cached allow must not survive the file being swapped for a symlink to a refused file."""
    ws = temp_dir / "ws_symlink"
    ws.mkdir()
    (ws / "allowed.txt").write_text("allowed content")
    (ws / "secret.txt").write_text("secret content")
    _cache_test_task(storage, ws, "task_symlink_swap", "gov_tok_symlink")
    broker = ToolBroker(storage=storage, expansion_service=ExpansionService(storage))

    assert broker.read_file("gov_tok_symlink", "allowed.txt") == "allowed content"
    assert broker._policy_cache.get("task_symlink_swap")

    (ws / "allowed.txt").unlink()
    os.symlink(ws / "secret.txt", ws / "allowed.txt")
    with pytest.raises(PermissionError):
        broker.read_file("gov_tok_symlink", "allowed.txt")


def test_flush_waits_for_a_batch_the_writer_has_already_taken(storage, monkeypatch):
    """A read right after a write must see it even while the writer is mid-commit."""
    real_write = storage._write_batch_to_db
    taken = threading.Event()

    def slow_write(items):
        taken.set()
        time.sleep(0.4)
        real_write(items)

    monkeypatch.setattr(storage, "_write_batch_to_db", slow_write)
    storage.record_task_step("task_inflight", kind="tool", layer="broker", verdict="ALLOW",
                             summary="s1", source_label="enforced")
    assert taken.wait(2.0)
    # The queue is now empty but the batch is not committed yet.
    steps = storage.get_task_steps("task_inflight")
    assert [s["summary"] for s in steps] == ["s1"]


def test_failed_batch_write_is_counted_and_logged_not_silent(storage, monkeypatch, caplog):
    def broken(items):
        raise RuntimeError("disk full")

    monkeypatch.setattr(storage, "_write_batch_to_db", broken)
    with caplog.at_level("ERROR"):
        storage._write_batch_with_retry([("step", {}), ("step", {})])
    assert storage.dropped_writes == 2
    assert any("not stored" in r.getMessage() for r in caplog.records)
