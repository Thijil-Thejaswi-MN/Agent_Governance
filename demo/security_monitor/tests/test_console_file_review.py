"""The Run page's file check: the agent's model chooses the files, rules check them, the
requester unticks any before Start, and only files from the check can be enforced."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from demo.security_monitor.app.governance import run_manager as rm
from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec
from demo.security_monitor.app.governance.models import EnforcementMode
from demo.security_monitor.app.governance.storage import GovernanceStorage

FILES = {"input/sales_q3.csv": "a,b\n", "input/sales_q2.csv": "a,b\n", "input/payroll.csv": "x\n"}
PROMPT = "Total last quarter's sales into output/summary.txt"


def _model(reads: list[str]):
    return lambda _p: json.dumps({"files_read": reads, "files_write": ["output/summary.txt"],
                                  "network": [], "peer_agents": []})


def test_review_marks_named_and_chosen_files_and_drops_the_rest() -> None:
    res = rm.derive_files_for_review(PROMPT, files=FILES, agent_id="finance_bot",
                                     llm_client=_model(["input/sales_q3.csv", "~/.ssh/id_rsa"]))
    assert res["fallback"] is False and res["model"] == "qwen2.5:7b"
    assert res["reads"] == [{"path": "input/sales_q3.csv", "named": False}]
    assert res["writes"] == [{"path": "output/summary.txt", "named": True}]
    assert res["dropped"] == [{"field": "files_read", "entry": "~/.ssh/id_rsa", "reason": "outside_workspace"}]
    assert res["inputs"] == sorted(FILES)


def test_start_can_untick_but_never_add_files() -> None:
    res = rm.derive_files_for_review(PROMPT, files=FILES, llm_client=_model(["input/sales_q3.csv", "input/sales_q2.csv"]))
    rid, inputs = res["review_id"], sorted(FILES)
    kept = rm.take_file_review(rid, PROMPT, inputs, ["input/sales_q3.csv"])
    assert kept["files_read"] == ["input/sales_q3.csv"]
    assert kept["metadata"]["removed_by_reviewer"] == ["input/sales_q2.csv"]
    assert kept["metadata"]["reviewed_in_console"] is True
    assert rm.take_file_review(rid, PROMPT, inputs, None)["files_read"] == ["input/sales_q2.csv", "input/sales_q3.csv"]
    with pytest.raises(ValueError, match="Only files from the check"):
        rm.take_file_review(rid, PROMPT, inputs, ["input/payroll.csv"])
    with pytest.raises(ValueError, match="changed after the file check"):
        rm.take_file_review(rid, PROMPT + " and payroll", inputs, None)
    with pytest.raises(ValueError, match="changed after the file check"):
        rm.take_file_review(rid, PROMPT, inputs + ["input/extra.csv"], None)
    with pytest.raises(ValueError, match="expired"):
        rm.take_file_review("review_nope", PROMPT, inputs, None)


def test_a_model_that_cannot_be_reached_falls_back_and_says_so() -> None:
    def down(_p: str) -> str:
        raise ConnectionRefusedError("connection refused")

    res = rm.derive_files_for_review("Summarise input/sales_q3.csv", files=FILES, llm_client=down)
    assert res["fallback"] is True and "refused" in res["fallback_reason"]
    assert res["dropped"] == [] and res["reads"] == [{"path": "input/sales_q3.csv", "named": True}]
    with pytest.raises(ValueError, match="Write what the agent should do"):
        rm.derive_files_for_review("  ", files=FILES, llm_client=down)


def test_start_refuses_a_stale_check_before_anything_starts() -> None:
    mgr = object.__new__(rm.ActiveRunManager)
    with pytest.raises(ValueError, match="expired"):
        mgr.start_run(PROMPT, storage=None, files=FILES, review_id="review_gone")


def test_the_launcher_enforces_the_reviewed_files(tmp_path: Path) -> None:
    res = rm.derive_files_for_review(PROMPT, files=FILES, llm_client=_model(["input/sales_q3.csv", "input/sales_q2.csv"]))
    reviewed = rm.take_file_review(res["review_id"], PROMPT, sorted(FILES), ["input/sales_q3.csv"])
    storage = GovernanceStorage(tmp_path / "g.db")
    ws = tmp_path / "ws"
    spec = TaskSpec(prompt=PROMPT, inputs=FILES, output_targets=["output/summary.txt"], boundary_model="v1.1",
                    reviewed_boundary=reviewed)
    _, b = TaskLauncher(storage, workspace_base=tmp_path).derive_boundary(spec, ws, EnforcementMode.ENFORCE)
    assert b.files_read == ["input/sales_q3.csv"] and b.derived_by == "grounded_llm_v1_reviewed"
    assert "output/summary.txt" in b.files_write
    assert b.metadata["removed_by_reviewer"] == ["input/sales_q2.csv"]
    stored = storage.get_boundary(b.task_id)
    assert stored.files_read == ["input/sales_q3.csv"]


def test_derive_endpoint(tmp_path: Path, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from demo.security_monitor.app.gateway.server import create_app
    from demo.security_monitor.app.governance import api as gov_api

    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(tmp_path / "g.db"))
    monkeypatch.setenv("RECEIPTS_DIR", str(tmp_path / "r"))
    monkeypatch.setenv("GOVERNANCE_OPERATOR_TOKEN", "tok_review")
    monkeypatch.setenv("GOVERNANCE_OPERATOR_ROLE", "admin")
    seen = []

    def fake(prompt, preset, files, agent_id, model):
        seen.append((prompt, preset, sorted(files), agent_id, model))
        return rm.derive_files_for_review(prompt, preset, files, agent_id, model,
                                          llm_client=_model(["input/sales_q3.csv"]))

    monkeypatch.setattr(gov_api, "derive_files_for_review", fake)
    c = TestClient(create_app())
    h = {"X-Operator-Token": "tok_review"}
    body = {"prompt": PROMPT, "files": FILES, "agent_id": "finance_bot"}
    r = c.post("/api/governance/run/derive", json=body, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["reads"] == [{"path": "input/sales_q3.csv", "named": False}]
    assert seen == [(PROMPT, None, sorted(FILES), "finance_bot", None)]
    assert c.post("/api/governance/run/derive", json=body).status_code == 401
    assert c.post("/api/governance/run/derive", json={**body, "agent_id": "nobody"}, headers=h).status_code == 422
    bad = {**body, "files": {"../escape.txt": "x"}}
    assert c.post("/api/governance/run/derive", json=bad, headers=h).status_code == 422


def test_an_unreachable_or_missing_model_falls_back_at_once(monkeypatch) -> None:
    """Without this check the page waited for the full derivation timeout when Ollama
    could not be reached (seen on WSL with Ollama on the Windows side switched off)."""
    def never(*_a, **_k):
        raise AssertionError("the model must not be called")

    monkeypatch.setattr(rm, "ollama_client", never)
    monkeypatch.setattr(rm, "list_installed_models", lambda: None)
    res = rm.derive_files_for_review("Summarise input/sales_q3.csv", files=FILES, agent_id="finance_bot")
    assert res["fallback"] is True and "not running" in res["fallback_reason"]
    assert [r["path"] for r in res["reads"]] == ["input/sales_q3.csv"]

    monkeypatch.setattr(rm, "list_installed_models", lambda: ["llama3.1:8b"])
    res = rm.derive_files_for_review("Summarise input/sales_q3.csv", files=FILES, agent_id="finance_bot",
                                     model="qwen2.5:7b")
    assert res["fallback"] is True and "not installed" in res["fallback_reason"]
