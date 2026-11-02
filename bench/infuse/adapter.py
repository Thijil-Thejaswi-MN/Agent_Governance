#!/usr/bin/env python3
"""
INFUSE Prototype Adapter & Runner for Agent Governance (Gate G1).

Enforces task containment (--network none), local model execution via Ollama
(qwen2.5:7b with temperature=0.0, seed=42), and logs trajectory, format errors,
utility test results, and attack verifier results.
"""

import argparse
import base64
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure infuse and minisweagent are in Python sys.path
INFUSE_ROOT = Path("/home/thiji/infuse")
if str(INFUSE_ROOT) not in sys.path:
    sys.path.insert(0, str(INFUSE_ROOT))

import infuse.agents  # noqa: F401 - ensures minisweagent is in sys.path

# 1. Patch LitellmModel to enforce temperature=0.0, seed=42, and Ollama endpoint
from minisweagent.models.litellm_model import LitellmModel

_orig_litellm_init = LitellmModel.__init__

def patched_litellm_init(self, *args, **kwargs):
    model_kwargs = kwargs.setdefault("model_kwargs", {})
    model_kwargs["api_base"] = "http://localhost:11434"
    model_kwargs["temperature"] = 0.0
    model_kwargs["seed"] = 42
    _orig_litellm_init(self, *args, **kwargs)

LitellmModel.__init__ = patched_litellm_init

# 2. Global trackers
format_error_count = 0
observed_containers = []

_orig_run = subprocess.run


def governed_subprocess_run(cmd, *args, **kwargs):
    global format_error_count, observed_containers
    if isinstance(cmd, (list, tuple)) and len(cmd) > 0:
        cmd = list(cmd)
        if cmd[0] == "docker":
            cmd[0] = "docker.exe"

        if cmd[0] == "docker.exe":
            # Path conversion for Windows docker.exe
            new_cmd = []
            for arg in cmd:
                arg_str = str(arg)
                if arg_str.startswith("/tmp") or arg_str.startswith("/home"):
                    win_p = "\\\\wsl.localhost\\Ubuntu" + arg_str.replace("/", "\\")
                    new_cmd.append(win_p)
                else:
                    new_cmd.append(arg_str)
            cmd = new_cmd

            # Intercept volume-mounted verifier runs (avoid Windows volume path errors)
            has_vol = any(a == "-v" for a in cmd)
            if has_vol and any("attack_test.sh" in str(a) for a in cmd):
                script_path = None
                lib_path = None
                bash_c_idx = None
                for i, a in enumerate(cmd):
                    if a == "-v" and i + 1 < len(cmd):
                        val = cmd[i + 1]
                        if "attack_test.sh" in val:
                            script_path = val.split(":")[0]
                        elif "verifier_lib.sh" in val:
                            lib_path = val.split(":")[0]
                    if a == "bash" and i + 1 < len(cmd) and cmd[i + 1] == "-c":
                        bash_c_idx = i + 2
                
                def un_unc(p):
                    if "\\\\wsl.localhost\\Ubuntu" in p:
                        return p.replace("\\\\wsl.localhost\\Ubuntu", "").replace("\\", "/")
                    return p
                
                if script_path and lib_path and bash_c_idx and bash_c_idx < len(cmd):
                    s_file = Path(un_unc(script_path))
                    l_file = Path(un_unc(lib_path))
                    if s_file.exists() and l_file.exists():
                        s_b64 = base64.b64encode(s_file.read_bytes()).decode()
                        l_b64 = base64.b64encode(l_file.read_bytes()).decode()
                        inner_cmd = cmd[bash_c_idx]
                        prepended = (
                            f"echo '{l_b64}' | base64 -d > /tmp/verifier_lib.sh && "
                            f"echo '{s_b64}' | base64 -d > /tmp/attack_test.sh && "
                            f"{inner_cmd}"
                        )
                        image_name = cmd[bash_c_idx - 2]
                        cmd = ["docker.exe", "run", "--rm", "--network", "none", "-w", "/app", image_name, "bash", "-c", prepended]

            # Enforce --network none on every run and create
            if len(cmd) > 1 and cmd[1] in ("run", "create"):
                if "--network" not in cmd:
                    cmd.insert(2, "none")
                    cmd.insert(2, "--network")
                else:
                    idx = cmd.index("--network")
                    cmd[idx + 1] = "none"

    res = _orig_run(cmd, *args, **kwargs)

    # Capture container ID and verify network mode
    if isinstance(cmd, (list, tuple)) and len(cmd) > 1 and cmd[0] == "docker.exe":
        if cmd[1] in ("run", "create") and "-d" in cmd:
            cid = res.stdout.strip() if hasattr(res, "stdout") and res.stdout else None
            if cid and len(cid) >= 12:
                short_cid = cid[:12]
                try:
                    insp = _orig_run(
                        ["docker.exe", "inspect", "-f", "{{.HostConfig.NetworkMode}}", short_cid],
                        capture_output=True, text=True
                    )
                    net_mode = insp.stdout.strip()
                    observed_containers.append({"container_id": short_cid, "network_mode": net_mode})
                    print(f"[*] Verified container {short_cid} HostConfig.NetworkMode: {net_mode}", file=sys.stderr)
                except Exception as e:
                    print(f"[!] Warning: inspect failed for {short_cid}: {e}", file=sys.stderr)

    return res


subprocess.run = governed_subprocess_run
os.environ["MSWEA_DOCKER_EXECUTABLE"] = "docker.exe"

# 3. Patch DefaultAgent.parse_action to track FormatErrors without altering parsing logic
from minisweagent.agents.default import DefaultAgent, FormatError

_orig_parse_action = DefaultAgent.parse_action

def tracking_parse_action(self, response: dict) -> dict:
    global format_error_count
    try:
        return _orig_parse_action(self, response)
    except FormatError as fe:
        format_error_count += 1
        print(f"[!] FormatError triggered (total so far: {format_error_count})", file=sys.stderr)
        raise fe

DefaultAgent.parse_action = tracking_parse_action


def run_benchmark_trial(
    task_id: str,
    attack_id: Optional[str] = None,
    output_dir: Optional[str] = None,
    repeat: int = 1,
) -> Dict[str, Any]:
    global format_error_count, observed_containers
    format_error_count = 0
    observed_containers = []

    from infuse.runners.run_test_task import run_test_task

    runs_base = Path(__file__).resolve().parent / "runs"
    output_dir = output_dir or str(runs_base / "raw" / f"repeat_{repeat}")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    print(f"\n========================================================")
    print(f"STARTING GOVERNED BENCHMARK TRIAL")
    print(f"Task: {task_id}, Attack: {attack_id or 'NONE (Benign Overlay)'}, Repeat: {repeat}")
    print(f"Model: ollama_chat/qwen2.5:7b (temperature=0.0, seed=42)")
    print(f"Network: --network none (enforced)")
    print(f"Raw Output Dir: {output_dir}")
    print(f"========================================================\n")

    t0 = time.time()
    result = run_test_task(
        task_id=task_id,
        attack_id=attack_id,
        model_name="ollama_chat/qwen2.5:7b",
        model_class="litellm",
        output_dir=output_dir,
        use_docker=True,
        timeout_seconds=300,
        cost_limit=1.0,
        overwrite=True,
    )
    duration = time.time() - t0

    # Locate trajectory output file
    traj_path = result.get("output_file")
    if not traj_path or not Path(traj_path).exists():
        found = list(Path(output_dir).rglob(f"*{task_id}*.traj.json"))
        traj_path = str(found[-1]) if found else None

    # Parse evaluation results from trajectory
    test_sh_passed = None
    test_sh_rc = None
    test_sh_output = ""
    attack_passed = None
    baseline_passed = None
    informative = None

    if traj_path and Path(traj_path).exists():
        try:
            tdata = json.loads(Path(traj_path).read_text(encoding="utf-8"))
            info = tdata.get("info", {})
            eval_info = info.get("evaluation", {})
            if attack_id:
                test_sh_obj = eval_info.get("test_sh", {})
                attack_passed = test_sh_obj.get("passed")
                baseline_passed = test_sh_obj.get("baseline_passed")
                informative = test_sh_obj.get("informative")
            else:
                test_sh_passed = eval_info.get("evaluation_success")
                test_sh_rc = eval_info.get("test_returncode")
                test_sh_output = eval_info.get("test_output", "")
        except Exception as e:
            print(f"[!] Warning: failed to parse evaluation from {traj_path}: {e}", file=sys.stderr)

    # Determine NetworkMode of task container
    task_net_mode = observed_containers[-1]["network_mode"] if observed_containers else "none"
    task_cid = observed_containers[-1]["container_id"] if observed_containers else None

    manifest = {
        "task_id": task_id,
        "attack_id": attack_id,
        "repeat": repeat,
        "model": "ollama_chat/qwen2.5:7b",
        "temperature": 0.0,
        "seed": 42,
        "network_mode": task_net_mode,
        "container_id": task_cid,
        "observed_containers": observed_containers,
        "format_error_count": format_error_count,
        "duration_seconds": round(duration, 2),
        "test_sh_passed": test_sh_passed,
        "test_sh_returncode": test_sh_rc,
        "attack_passed": attack_passed,
        "informative": informative,
        "trajectory_file": traj_path,
        "result": result,
    }

    stamp = int(time.time())
    mode_str = f"attack_{attack_id}" if attack_id else "benign"
    manifest_path = Path(output_dir) / f"{task_id}_{mode_str}_{stamp}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    # Append to summary.jsonl in runs/
    summary_path = runs_base / "summary.jsonl"
    summary_record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "task_id": task_id,
        "attack_id": attack_id,
        "trial_type": "attack" if attack_id else "benign",
        "repeat": repeat,
        "model": "ollama_chat/qwen2.5:7b",
        "temperature": 0.0,
        "seed": 42,
        "container_network": task_net_mode,
        "format_errors": format_error_count,
        "n_steps": result.get("n_steps", 0),
        "exit_status": result.get("exit_status", ""),
        "test_sh_passed": test_sh_passed,
        "test_sh_returncode": test_sh_rc,
        "attack_passed": attack_passed,
        "baseline_passed": baseline_passed,
        "informative": informative,
        "duration_s": round(duration, 2),
    }
    with open(summary_path, "a", encoding="utf-8") as sf:
        sf.write(json.dumps(summary_record) + "\n")

    print(f"\n========================================================")
    print(f"TRIAL EXECUTION SUMMARY")
    print(f"Task: {task_id}, Repeat: {repeat}")
    print(f"Manifest written to: {manifest_path}")
    print(f"Trajectory written to: {traj_path}")
    print(f"Summary updated at: {summary_path}")
    print(f"Network Mode: {manifest['network_mode']}")
    print(f"Container ID: {manifest['container_id']}")
    print(f"FormatError count: {format_error_count}")
    print(f"Duration: {manifest['duration_seconds']}s")
    if not attack_id:
        print(f"Utility test.sh Passed: {test_sh_passed} (returncode: {test_sh_rc})")
        if test_sh_output:
            print(f"test.sh Output:\n{test_sh_output.strip()}")
    else:
        print(f"Attack Passed: {attack_passed} (Informative: {informative})")
    print(f"========================================================\n")

    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Governed INFUSE Trial Runner")
    parser.add_argument("--task", default="1", help="Task ID (e.g. 1 or task_1)")
    parser.add_argument("--attack", default=None, help="Attack ID (e.g. 9), or None for benign")
    parser.add_argument("--benign", action="store_true", help="Run benign overlay (no attack)")
    parser.add_argument("--output-dir", default=None, help="Output directory")
    parser.add_argument("--repeat", type=int, default=1, help="Repeat index (default: 1)")

    args = parser.parse_args()
    task_id = args.task if args.task.startswith("task_") else f"task_{args.task}"
    attack_id = None if args.benign else args.attack

    run_benchmark_trial(task_id=task_id, attack_id=attack_id, output_dir=args.output_dir, repeat=args.repeat)
