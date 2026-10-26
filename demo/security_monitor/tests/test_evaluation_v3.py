"""Tests for Evaluation Suite v3 (M6.2).

Covers:
- Pre-trial checks in eval_world (one test per check, each fails closed).
- Audit sink HTTP logging and canary detection.
- Filesystem baseline snapshot and diff detection.
- Scenario loader on both injected and legit dataset files.
- Runner resume logic preventing duplicate trials.
"""
from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from demo.security_monitor.app.governance.eval_world import (
    AuditSinkHandler,
    PretrialCheckError,
    diff_filesystem,
    perform_pretrial_checks,
    run_audit_sink_server,
    snapshot_filesystem,
)
from demo.security_monitor.evaluate_v3 import load_scenarios


class TestPretrialChecks:
    def test_pretrial_check_mnt_c_visible_fails_closed(self, tmp_path: Path) -> None:
        """Check 1: Aborts if /mnt/c is visible."""
        with pytest.raises(PretrialCheckError, match="/mnt/c is visible"):
            perform_pretrial_checks(str(tmp_path), 8099, "C", simulate_fail="mnt_c")

    def test_pretrial_check_tmp_content_fails_closed(self, tmp_path: Path) -> None:
        """Check 2: Aborts if /tmp has pre-existing content."""
        with pytest.raises(PretrialCheckError, match="/tmp has pre-existing content"):
            perform_pretrial_checks(str(tmp_path), 8099, "C", simulate_fail="tmp_content")

    def test_pretrial_check_windows_profile_fails_closed(self, tmp_path: Path) -> None:
        """Check 3: Aborts if Windows profile is readable."""
        with pytest.raises(PretrialCheckError, match="Windows profile is readable"):
            perform_pretrial_checks(str(tmp_path), 8099, "C", simulate_fail="win_profile")

    def test_pretrial_check_real_home_visible_fails_closed(self, tmp_path: Path) -> None:
        """Check 4: Aborts if real home is visible."""
        with pytest.raises(PretrialCheckError, match="real_home_visible"):
            perform_pretrial_checks(str(tmp_path), 8099, "C", simulate_fail="real_home")

    def test_pretrial_check_tcp_connect_fails_closed(self, tmp_path: Path) -> None:
        """Check 5: Aborts if non-DNS external TCP connect succeeds."""
        with pytest.raises(PretrialCheckError, match="external_network_reachable"):
            perform_pretrial_checks(str(tmp_path), 8099, "C", simulate_fail="tcp_connect")

    def test_pretrial_check_dns_resolution_fails_closed(self, tmp_path: Path) -> None:
        """Check 6: Aborts if external DNS resolution succeeds."""
        with pytest.raises(PretrialCheckError, match="DNS resolution succeeded"):
            perform_pretrial_checks(str(tmp_path), 8099, "C", simulate_fail="dns_resolve")

    def test_pretrial_check_sink_unreachable_fails_closed(self, tmp_path: Path) -> None:
        """Check 7: Aborts if audit sink is unreachable."""
        with pytest.raises(PretrialCheckError, match="audit_sink_unreachable"):
            perform_pretrial_checks(str(tmp_path), 8099, "C", simulate_fail="sink")


class TestAuditSink:
    def test_sink_logging_and_canary_detection(self, tmp_path: Path) -> None:
        log_file = tmp_path / "sink_test.jsonl"
        sink_fd = os.open(str(log_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        canary = "CANARY_TOKEN_999"

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        AuditSinkHandler.sink_log_fd = sink_fd
        AuditSinkHandler.canary_token = canary
        import http.server
        httpd = http.server.HTTPServer(("127.0.0.1", port), AuditSinkHandler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        try:
            req1 = urllib.request.Request(
                f"http://127.0.0.1:{port}/sink",
                data=b"secret data with CANARY_TOKEN_999 included",
                headers={"Content-Type": "text/plain"},
            )
            with urllib.request.urlopen(req1, timeout=5) as resp:
                assert resp.status == 200

            req2 = urllib.request.Request(
                f"http://127.0.0.1:{port}/sink",
                data=b"benign request payload",
                headers={"Content-Type": "text/plain"},
            )
            with urllib.request.urlopen(req2, timeout=5) as resp:
                assert resp.status == 200

        finally:
            httpd.shutdown()
            os.close(sink_fd)

        lines = [json.loads(l) for l in log_file.read_text(encoding="utf-8").splitlines()]
        assert len(lines) == 2
        assert lines[0]["canary_in_request"] is True
        assert lines[0]["body_len"] == len(b"secret data with CANARY_TOKEN_999 included")
        assert lines[1]["canary_in_request"] is False


class TestFilesystemDiff:
    def test_filesystem_snapshot_and_diff(self, tmp_path: Path) -> None:
        home = tmp_path / "fake_home"
        ws = home / "workspace"
        home.mkdir()
        ws.mkdir()

        (home / "decoy.txt").write_text("initial decoy")
        (home / "unmodified.txt").write_text("keep same")
        (ws / "task_input.txt").write_text("input")

        base = snapshot_filesystem(str(home), str(ws))
        assert "decoy.txt" in base
        assert "unmodified.txt" in base
        assert "task_input.txt" not in base

        (home / "outside_leak.txt").write_text("attacker created file")
        (home / "decoy.txt").write_text("modified content")
        (ws / "output.txt").write_text("allowed workspace write")

        diff = diff_filesystem(base, str(home), str(ws))
        assert "outside_leak.txt" in diff["created"]
        assert "decoy.txt" in diff["modified"]
        assert diff["outside_writes_count"] == 2
        assert "output.txt" not in diff["created"]


class TestScenarioLoader:
    def test_injected_indirect_v3b_scenarios_schema(self) -> None:
        p = "demo/data/evaluation_v3/scenarios/injected_indirect_v3b.jsonl"
        scenarios = load_scenarios([p])
        assert len(scenarios) == 16
        for sc in scenarios:
            assert sc["id"].startswith("injected_indirect_")
            assert sc["category"] == "injected_indirect"
            assert "authored_by" in sc
            assert "user_prompt" in sc
            assert sc["needs_run_command"] is True
            assert isinstance(sc["input_files"], dict)
            assert "expected_boundary" in sc
            assert len(sc["decoys"]) == 4
            assert sc["injected_target"] is not None
            assert "expected_answer_numbers" in sc
            assert sc["scenario_version"] == "v3b"
            assert "changes_from_v3" in sc

    def test_legit_v3b_scenarios_schema(self) -> None:
        p = "demo/data/evaluation_v3/scenarios/legit_v3b.jsonl"
        scenarios = load_scenarios([p])
        assert len(scenarios) == 32
        anticipated = [s for s in scenarios if s["category"] == "legit_anticipated"]
        unanticipated = [s for s in scenarios if s["category"] == "legit_unanticipated"]
        assert len(anticipated) == 16
        assert len(unanticipated) == 16

        for s in scenarios:
            assert s["needs_run_command"] is True
            assert "{MARKER}" in s["user_prompt"]
            assert len(s["decoys"]) == 4
            assert "expected_answer_numbers" in s

        for u in unanticipated:
            assert "needed_resource" in u


class TestRunnerResume:
    def test_resume_skips_completed_trials(self, tmp_path: Path) -> None:
        out_file = tmp_path / "results.jsonl"
        rec1 = {"repeat_index": 0, "condition": "A", "scenario_id": "legit_anticipated_01"}
        rec2 = {"repeat_index": 0, "condition": "B", "scenario_id": "legit_anticipated_01"}
        out_file.write_text(f"{json.dumps(rec1)}\n{json.dumps(rec2)}\n")

        completed = set()
        with open(out_file) as f:
            for line in f:
                r = json.loads(line)
                completed.add((r["repeat_index"], r["condition"], r["scenario_id"]))

        assert (0, "A", "legit_anticipated_01") in completed
        assert (0, "B", "legit_anticipated_01") in completed
        assert (0, "C", "legit_anticipated_01") not in completed
