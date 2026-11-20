"""Test for measure_scale.py runner.

Runs a small 2-task scale evaluation (--rounds 2 --repeats 1 --real 0)
under the real OS layer to check output JSON schema and governance invariants.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
import pytest

repo_root = Path(__file__).resolve().parents[3]
sec_mon = Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))
if str(sec_mon) not in sys.path:
    sys.path.insert(0, str(sec_mon))


@pytest.mark.os_layer
def test_measure_scale_smoke(tmp_path: Path):
    script_path = repo_root / "demo" / "security_monitor" / "measure_scale.py"
    out_json = tmp_path / "scale_out.json"
    out_md = tmp_path / "scale_out.md"
    cmd = [
        sys.executable,
        str(script_path),
        "--rounds", "2",
        "--repeats", "1",
        "--real", "0",
        "--output", str(out_json),
        "--summary", str(out_md),
    ]

    res = subprocess.run(cmd, cwd=str(repo_root), capture_output=True, text=True, timeout=180)
    assert res.returncode == 0, f"measure_scale.py failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"

    assert out_json.is_file(), "JSON output file was not created"
    assert out_md.is_file(), "Markdown summary file was not created"

    data = json.loads(out_json.read_text(encoding="utf-8"))

    # Validate host section
    assert "host" in data
    assert "cpu_count" in data["host"]
    assert "ram_mb" in data["host"]
    assert "kernel" in data["host"]
    assert "wsl_version" in data["host"]

    # Validate meta section
    assert data["meta"]["rounds"] == [2]
    assert data["meta"]["repeats"] == 1
    assert data["meta"]["real_n"] == 0

    # Validate baseline section
    assert "baseline" in data
    assert "scripted_p50" in data["baseline"]
    assert "scripted_p95" in data["baseline"]
    assert len(data["baseline"]["runs"]) > 0

    # Validate rounds section
    assert len(data["rounds"]) == 1
    r0 = data["rounds"][0]
    assert r0["round_size"] == 2
    assert r0["repeat_index"] == 0
    assert r0["total_runs"] == 2
    assert r0["enforcement"]["all_attacks_stopped"] is True
    assert r0["enforcement"]["canary_leaks"] == 0
    assert r0["enforcement"]["boundary_violations_allowed"] == 0
    assert r0["records"]["all_verified"] is True
    assert r0["cleanup"]["all_clean"] is True

    # Validate overall section
    ov = data["overall"]
    assert ov["verdict"] == "PASS"
    assert ov["total_runs"] == 2
    assert ov["attacks_total"] == ov["attacks_stopped"]
    assert ov["canary_leaks"] == 0
    assert ov["boundary_violations_allowed"] == 0
    assert ov["receipts_verified_whole_record"] == 2
    assert ov["processes_left_alive"] == 0
    assert ov["cgroups_left_behind"] == 0
    assert ov["failures_count"] == 0

    # Validate Markdown summary content
    md_content = out_md.read_text(encoding="utf-8")
    assert "# Scale Governance Evaluation Summary" in md_content
    assert "Overall Verdict: **PASS**" in md_content
    assert "Forbidden Attack Actions Stopped" in md_content
