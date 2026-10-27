import asyncio
from pathlib import Path
import sys

sys.path.insert(0, '/home/thiji/Agent_Governance')
sys.path.insert(0, '/home/thiji/Agent_Governance/demo/security_monitor')

from app.governance.api import list_tasks, get_task_detail, get_task_events, _extract_os_receipt_events


def test_blocked_and_expansion_demo_receipt_denials():
    async def run():
        # 1. Blocked demo task
        blocked_tid = "task_ff51172b7f73"
        receipt_os_events = _extract_os_receipt_events(blocked_tid)
        distinct_receipt_denials = [e for e in receipt_os_events if e.get("prevented")]

        # Receipt for blocked demo task has exactly 1 denied action (Landlock openat EACCES on private_notes.txt)
        assert len(distinct_receipt_denials) == 1, f"Expected 1 denied action in receipt, found {len(distinct_receipt_denials)}"
        assert distinct_receipt_denials[0]["prevented_by"] == "landlock"

        # Verify get_task_detail reports exactly the distinct denied actions from receipt
        detail = await get_task_detail(blocked_tid)
        assert detail["summary"]["prevented_count"] == len(distinct_receipt_denials)
        assert detail["summary"]["os_denials_count"] == len(distinct_receipt_denials)
        assert detail["llm_provider"] in ("scripted", "scripted_mock")

        # Verify list_tasks reports exactly the distinct denied actions from receipt
        all_tasks = await list_tasks()
        t_map = {t["task_id"]: t for t in all_tasks}
        blocked_t = t_map[blocked_tid]
        assert blocked_t["prevented_count"] == len(distinct_receipt_denials)
        assert blocked_t["os_denials_count"] == len(distinct_receipt_denials)
        assert blocked_t["llm_provider"] in ("scripted", "scripted_mock")

        # 2. Expansion demo task
        expansion_tid = "task_4793807674a4"
        exp_receipt_os = _extract_os_receipt_events(expansion_tid)
        exp_distinct_os_denials = [e for e in exp_receipt_os if e.get("prevented")]

        # Expansion demo task receipt shows 0 OS denials
        assert len(exp_distinct_os_denials) == 0, f"Expected 0 OS denials in expansion receipt, found {len(exp_distinct_os_denials)}"

        exp_detail = await get_task_detail(expansion_tid)
        assert exp_detail["summary"]["os_denials_count"] == 0
        # Its 1 broker denial is counted from storage, not double counted
        assert exp_detail["summary"]["prevented_count"] == 1
        assert exp_detail["llm_provider"] in ("scripted", "scripted_mock")

        exp_t = t_map[expansion_tid]
        assert exp_t["os_denials_count"] == 0
        assert exp_t["prevented_count"] == 1
        assert exp_t["llm_provider"] in ("scripted", "scripted_mock")

        # Verify get_task_events has no duplicate entries
        events = await get_task_events(blocked_tid)
        denied_events = [e for e in events if e.get("prevented")]
        assert len(denied_events) == 1

    asyncio.run(run())
