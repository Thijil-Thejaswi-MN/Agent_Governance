import ast
from datetime import datetime, timezone, timedelta
from pathlib import Path

from demo.security_monitor.app.governance.storage import GovernanceStorage, TaskRecord, TaskLifecycle, TaskBoundary
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.standing_rules import StandingRule
from demo.security_monitor.app.governance.api import _standing_rules, _standing_rules_lock


def test_evaluation_and_expansion_never_import_standing_rules():
    repo_root = Path(__file__).parent.parent.parent
    target_files = [
        repo_root / "demo/security_monitor/app/governance/expansion.py",
        repo_root / "demo/security_monitor/evaluate_v3.py",
        repo_root / "demo/security_monitor/evaluate_llm_agent_injection.py",
        repo_root / "demo/security_monitor/evaluate_derivation.py",
        repo_root / "demo/security_monitor/run_evaluation_v2.py",
        repo_root / "run_all_evaluations.py",
    ]
    for eval_dir in [
        repo_root / "demo/security_monitor/evaluation",
        repo_root / "demo/data/evaluation_v2",
        repo_root / "demo/data/evaluation_v3",
    ]:
        if eval_dir.exists():
            target_files.extend(eval_dir.rglob("*.py"))

    illegal_imports = []
    for file_path in target_files:
        if not file_path.is_file():
            continue
        tree = ast.parse(file_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    if "standing_rules" in n.name:
                        illegal_imports.append((str(file_path), n.name))
            elif isinstance(node, ast.ImportFrom):
                if node.module and "standing_rules" in node.module:
                    illegal_imports.append((str(file_path), node.module))

    assert len(illegal_imports ) == 0, f"Illegal standing_rules imports found: {illegal_imports}"


def test_oracle_expansion_ignores_standing_rules(tmp_path, monkeypatch):
    monkeypatch.setenv("GOVERNANCE_STANDING_RULES", "1")
    db_path = str(tmp_path / "test.db")
    storage = GovernanceStorage(db_path)
    storage.save_task(TaskRecord(
        task_id="task-1",
        request_text="test task",
        request_hash="hash1",
        agent_id="agent-1",
        workspace_root="/workspace",
        status=TaskLifecycle.ACTIVE,
        created_at="2026-11-02T00:00:00Z",
        team="secops",
    ))
    storage.save_boundary(TaskBoundary(
        task_id="task-1",
        version=1,
        workspace_root="/workspace",
    ))
    storage.save_task(TaskRecord(
        task_id="task-2",
        request_text="test task 2",
        request_hash="hash2",
        agent_id="agent-1",
        workspace_root="/workspace",
        status=TaskLifecycle.ACTIVE,
        created_at="2026-11-02T00:00:00Z",
        team="secops",
    ))
    storage.save_boundary(TaskBoundary(
        task_id="task-2",
        version=1,
        workspace_root="/workspace",
    ))

    now = datetime.now(timezone.utc)
    rule = StandingRule(
        rule_id="sr-test-1",
        agent_or_profile="*",
        action="file_read",
        target="data/allowed/file.txt",
        owner="reviewer_1",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
        team="secops",
        is_active=True,
    )
    with _standing_rules_lock:
        _standing_rules.clear()
        _standing_rules.append(rule)

    try:
        def oracle_hook(req):
            oracle_allowed = ["different/path.txt"]
            return req.resource_target in oracle_allowed

        expansion = ExpansionService(
            storage=storage,
            provenance_enabled=False,
            user_approval_hook=oracle_hook,
            simulated_user_policy="oracle",
        )

        assert expansion.simulated_user_policy == "oracle"
        approved, reason = expansion.request_and_wait(
            task_id="task-1",
            agent_id="agent-1",
            resource_type="file_read",
            resource_target="data/allowed/file.txt",
            justification="Need data file",
            timeout_seconds=0.5,
        )

        assert approved is False
        assert "oracle" in reason.lower()
        assert "standing_rule" not in reason.lower()

        def oracle_hook_allow(req):
            return True

        expansion_allow = ExpansionService(
            storage=storage,
            provenance_enabled=False,
            user_approval_hook=oracle_hook_allow,
            simulated_user_policy="oracle",
        )

        assert expansion_allow.simulated_user_policy == "oracle"
        approved2, reason2 = expansion_allow.request_and_wait(
            task_id="task-2",
            agent_id="agent-1",
            resource_type="file_read",
            resource_target="data/allowed/file.txt",
            justification="Need data file",
            timeout_seconds=0.5,
        )

        assert approved2 is True
        assert "Approved by simulated user (oracle)" in reason2
        assert "standing_rule" not in reason2
    finally:
        with _standing_rules_lock:
            _standing_rules.clear()
