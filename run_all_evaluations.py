"""
Master benchmark runner for Milestone 5 (F13.2) empirical evaluation.
Runs all 4 benchmarks in sequence, logging progress and automatically scoring results at the end.
Fully resumable: re-running this script skips already completed trials.
"""

import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
LOG_FILE = REPO_ROOT / "demo" / "data" / "full_evaluation_run.log"


def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run_command(cmd: list[str], desc: str):
    log(f"=== Starting: {desc} ===")
    log(f"Command: {' '.join(cmd)}")
    start_time = time.time()
    proc = subprocess.Popen(
        cmd,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    if proc.stdout:
        for out_line in iter(proc.stdout.readline, ""):
            print(out_line, end="", flush=True)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(out_line)

    proc.wait()
    duration = time.time() - start_time
    if proc.returncode != 0:
        log(f"!!! Error in {desc} (exit code {proc.returncode}) after {duration:.1f}s")
        sys.exit(proc.returncode)
    else:
        log(f"=== Completed: {desc} in {duration:.1f}s ===\n")


def main():
    log("Starting Milestone 5 Empirical Evaluation Run")
    log(f"Repo root: {REPO_ROOT}")
    log(f"Log file: {LOG_FILE}")

    benchmarks = [
        # 1. Boundary Derivation - llama3.1:8b
        (
            [
                sys.executable,
                "demo/security_monitor/evaluate_derivation.py",
                "--provider",
                "ollama",
                "--model",
                "llama3.1:8b",
                "--repeats",
                "3",
                "--resume",
            ],
            "Boundary Derivation (llama3.1:8b, 3 repeats)",
        ),
        # 2. Boundary Derivation - qwen2.5:7b
        (
            [
                sys.executable,
                "demo/security_monitor/evaluate_derivation.py",
                "--provider",
                "ollama",
                "--model",
                "qwen2.5:7b",
                "--repeats",
                "3",
                "--resume",
            ],
            "Boundary Derivation (qwen2.5:7b, 3 repeats)",
        ),
        # 3. LLM Agent Injection - llama3.1:8b
        (
            [
                sys.executable,
                "demo/security_monitor/evaluate_llm_agent_injection.py",
                "--provider",
                "ollama",
                "--model",
                "llama3.1:8b",
                "--repeats",
                "3",
                "--resume",
            ],
            "Agent Injection (llama3.1:8b, 80 scenarios x 3 repeats x 2 conditions)",
        ),
        # 4. LLM Agent Injection - qwen2.5:7b
        (
            [
                sys.executable,
                "demo/security_monitor/evaluate_llm_agent_injection.py",
                "--provider",
                "ollama",
                "--model",
                "qwen2.5:7b",
                "--repeats",
                "3",
                "--resume",
            ],
            "Agent Injection (qwen2.5:7b, 80 scenarios x 3 repeats x 2 conditions)",
        ),
    ]

    for cmd, desc in benchmarks:
        run_command(cmd, desc)

    # 5. Final Scoring
    log("=== Running Final Scoring on All Output Files ===")
    run_command(
        [sys.executable, "demo/security_monitor/score_results.py", "--input-dir", "demo/data/"],
        "Score All Results",
    )
    log("All benchmark runs and scoring completed successfully!")


if __name__ == "__main__":
    main()
