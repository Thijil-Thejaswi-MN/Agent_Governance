"""Portable unit test for demo receipt denial counting and provider extraction.

Tests that:
1. Blocked demo task (task_ff51172b7f73) reports exactly the distinct denied actions in its receipt.
2. Expansion demo task (task_4793807674a4) reports 0 OS denials, with its broker denial counted once.
3. Provider extraction returns 'scripted_mock' for demo receipts and 'unknown' when missing.
4. Operates against fixtures/receipts and a seeded temporary SQLite database (clean clone portability).
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import pytest

# Portable sys.path resolution relative to test file
REPO_ROOT = Path(__file__).resolve().parents[3]
APP_DIR = REPO_ROOT / "demo" / "security_monitor"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from app.governance.models import (
    EventSource,
    EventVerdict,
    GovernanceEvent,
    RiskTier,
    TaskAction,
    TaskLifecycle,
    TaskRecord,
)
from app.governance.storage import GovernanceStorage
from app.governance.api import (
    list_tasks,
    get_task_detail,
    get_task_events,
    _extract_os_receipt_events,
)


@pytest.fixture
def seeded_demo_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Configures RECEIPTS_DIR to test fixtures and GOVERNANCE_DB_PATH to a freshly seeded temp database."""
    fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "receipts"
    assert (fixtures_dir / "task_ff51172b7f73.json").exists(), "Missing fixture task_ff51172b7f73.json"
    assert (fixtures_dir / "task_4793807674a4.json").exists(), "Missing fixture task_4793807674a4.json"

    monkeypatch.setenv("RECEIPTS_DIR", str(fixtures_dir))

    db_path = tmp_path / "test_governance.db"
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db_path))

    storage = GovernanceStorage(db_path)

    # 1. Seed Blocked Demo Task (task_ff51172b7f73)
    t_blocked = TaskRecord(
        task_id="task_ff51172b7f73",
        request_text="Analyze input/sales.csv and summarize into output/summary.txt",
        request_hash="3a5e8222f4b9187e4fe6dc4fe71ce44720356d28215cd5526775a45b26c9e405",
        agent_id="m6_demo_blocked_agent",
        workspace_root=str(tmp_path / "ws_blocked"),
        status=TaskLifecycle.COMPLETED,
        created_at="2026-10-27T13:01:22.347321+00:00",
        completed_at="2026-10-27T13:01:23.140565+00:00",
    )
    storage.save_task(t_blocked)

    # Seed 1 denied OS Landlock event in storage
    storage.record_event(
        GovernanceEvent(
            event_id="evt_os_task_ff51172b7f73_000170",
            timestamp="2026-10-27T13:01:22.607000+00:00",
            source=EventSource.OS_SENSOR,
            task_id="task_ff51172b7f73",
            agent_id="os_process",
            kind="file_read",
            target="/home/thiji/agent_workspaces/ws_b7352f04780c/input/private_notes.txt",
            details={"syscall": "openat", "result": "EACCES", "prevented_by": "landlock", "observed_by": ["os_sensor"]},
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.MEDIUM,
            action_taken=TaskAction.LOG,
            prevented=True,
            rule_matched="os_sensor: unlisted file path inside workspace: input/private_notes.txt",
            boundary_version=1,
        )
    )

    # Seed 184 allowed inside events for blocked task (unique event_ids)
    for i in range(1, 185):
        storage.record_event(
            GovernanceEvent(
                event_id=f"evt_inside_allowed_{i:04d}",
                timestamp="2026-10-27T13:01:22.400000+00:00",
                source=EventSource.OS_SENSOR,
                task_id="task_ff51172b7f73",
                agent_id="os_process",
                kind="file_read",
                target=f"/tmp/file_{i}.txt",
                details={"syscall": "read", "result": 0},
                verdict=EventVerdict.INSIDE,
                risk_tier=RiskTier.LOW,
                action_taken=TaskAction.ALLOW,
                prevented=False,
                rule_matched="inside_workspace",
                boundary_version=1,
            )
        )

    # 2. Seed Expansion Demo Task (task_4793807674a4)
    t_expansion = TaskRecord(
        task_id="task_4793807674a4",
        request_text="Read input/data.csv, request expansion for reference/guidelines.txt, then read the granted reference file and write output/summary.txt.",
        request_hash="a92be845bbbc7e678b74aff1b5842a206489daca923fe1617de77a0da9a8e219",
        agent_id="m6_demo_expansion_agent",
        workspace_root=str(tmp_path / "ws_expansion"),
        status=TaskLifecycle.COMPLETED,
        created_at="2026-10-27T13:01:36.275975+00:00",
        completed_at="2026-10-27T13:01:37.049532+00:00",
    )
    storage.save_task(t_expansion)

    # Seed 1 denied broker expansion event in storage
    storage.record_event(
        GovernanceEvent(
            event_id="evt_broker_0004_857a9f",
            timestamp="2026-10-27T13:01:36.493188+00:00",
            source=EventSource.TOOL_BROKER,
            task_id="task_4793807674a4",
            agent_id="m6_demo_expansion_agent",
            kind="request_access",
            target="reference/guidelines.txt",
            details={"resource_type": "file_read", "granted": False},
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.HIGH,
            action_taken=TaskAction.BLOCK_ACTION,
            prevented=True,
            rule_matched="Denied by policy: agent-initiated expansion to HIGH-risk resource 'reference/guidelines.txt' is prohibited",
            boundary_version=1,
        )
    )

    # Seed 150 allowed inside events for expansion task
    for i in range(1, 151):
        storage.record_event(
            GovernanceEvent(
                event_id=f"evt_exp_inside_{i:04d}",
                timestamp="2026-10-27T13:01:36.300000+00:00",
                source=EventSource.TOOL_BROKER,
                task_id="task_4793807674a4",
                agent_id="m6_demo_expansion_agent",
                kind="file_read",
                target=f"/tmp/data_{i}.txt",
                details={},
                verdict=EventVerdict.INSIDE,
                risk_tier=RiskTier.LOW,
                action_taken=TaskAction.ALLOW,
                prevented=False,
                rule_matched="inside_workspace",
                boundary_version=1,
            )
        )

    # 3. Seed an unscripted task with no receipt to verify "unknown" fallback
    t_unknown = TaskRecord(
        task_id="task_unscripted_999",
        request_text="Ad-hoc user query without recorded provider",
        request_hash="deadbeef",
        agent_id="agent_generic",
        workspace_root=str(tmp_path / "ws_generic"),
        status=TaskLifecycle.COMPLETED,
        created_at="2026-10-27T14:00:00Z",
    )
    storage.save_task(t_unknown)

    return storage


def test_blocked_and_expansion_demo_receipt_denials(seeded_demo_env):
    async def run():
        # 1. Blocked demo task assertions
        blocked_tid = "task_ff51172b7f73"
        receipt_os_events = _extract_os_receipt_events(blocked_tid)
        distinct_receipt_denials = [e for e in receipt_os_events if e.get("prevented")]

        # Assert exactly the number of distinct denied actions in its receipt (1 Landlock denial)
        assert len(distinct_receipt_denials) == 1, f"Expected 1 denied action in receipt, found {len(distinct_receipt_denials)}"
        assert distinct_receipt_denials[0]["prevented_by"] == "landlock"

        # Verify get_task_detail
        detail = await get_task_detail(blocked_tid)
        assert detail["summary"]["prevented_count"] == len(distinct_receipt_denials)
        assert detail["summary"]["os_denials_count"] == len(distinct_receipt_denials)
        assert detail["summary"]["total_actions"] == 185
        assert detail["llm_provider"] in ("scripted", "scripted_mock")

        # Verify list_tasks
        all_tasks = await list_tasks()
        t_map = {t["task_id"]: t for t in all_tasks}
        blocked_t = t_map[blocked_tid]
        assert blocked_t["prevented_count"] == len(distinct_receipt_denials)
        assert blocked_t["os_denials_count"] == len(distinct_receipt_denials)
        assert blocked_t["llm_provider"] in ("scripted", "scripted_mock")

        # 2. Expansion demo task assertions
        expansion_tid = "task_4793807674a4"
        exp_receipt_os = _extract_os_receipt_events(expansion_tid)
        exp_distinct_os_denials = [e for e in exp_receipt_os if e.get("prevented")]

        # Expansion demo task receipt shows 0 OS denials
        assert len(exp_distinct_os_denials) == 0, f"Expected 0 OS denials in expansion receipt, found {len(exp_distinct_os_denials)}"

        exp_detail = await get_task_detail(expansion_tid)
        assert exp_detail["summary"]["os_denials_count"] == 0
        # Exactly 1 broker denial from storage (not double counted)
        assert exp_detail["summary"]["prevented_count"] == 1
        assert exp_detail["summary"]["total_actions"] == 151
        assert exp_detail["llm_provider"] in ("scripted", "scripted_mock")

        exp_t = t_map[expansion_tid]
        assert exp_t["os_denials_count"] == 0
        assert exp_t["prevented_count"] == 1
        assert exp_t["llm_provider"] in ("scripted", "scripted_mock")

        # 3. Verify deduplication in get_task_events
        events = await get_task_events(blocked_tid)
        denied_events = [e for e in events if e.get("prevented")]
        assert len(denied_events) == 1

        # 4. Verify unscripted task returns "unknown" for llm_provider
        unknown_t = t_map["task_unscripted_999"]
        assert unknown_t["llm_provider"] == "unknown"
        unknown_detail = await get_task_detail("task_unscripted_999")
        assert unknown_detail["llm_provider"] == "unknown"

    asyncio.run(run())
