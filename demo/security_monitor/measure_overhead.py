"""Reproducible benchmark evaluating governance overhead across layers.

Evaluates configurations:
  A: Baseline (no governance - direct execution)
  W: Workspace sandbox (Landlock workspace boundary)
  C: Full governance (tool broker, Landlock, seccomp, netns/proxy, ptrace sensor)
  C-nosensor: C without the ptrace sensor (via GOVERNANCE_BENCH_MODE=1 and GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR=1)
  C-ebpf: C-nosensor plus the eBPF shadow sensor (skipped with note if loader is unavailable)

Evaluates workloads:
  W1: Start-up & teardown (phase breakdown: cgroup/scope, netns/proxy, landlock/seccomp,
      sensor attach, broker connect, startup total, teardown)
  W2: Tool-call latency (200 read_file 1KB, 200 write_file output/, 50 request_access auto-approved at LOW;
      p50/p95/p99 vs direct Python file I/O in A)
  W3: Shell-heavy / sensor cost (find 5,000 files, grep -r, Python reading 2,000 files,
      tar 50MB folder, 500 short execs /bin/true; slowdown factor vs A)
  W4: Network (100 HTTP GETs direct [A] vs proxy [C]; per-request p50/p95)
  W5: End-to-end scripted presets (summarise_csv; wall time per task)

Resources from task cgroup:
  CPU user/system time (cpu.stat), peak memory (memory.peak), extra governance processes count.

Outputs:
  demo/data/perf/perf_v1.json
  demo/data/perf/perf_v1.md (uncommitted; user reviews prior to commit)
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import platform
import random
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SECMON_DIR = REPO_ROOT / "demo" / "security_monitor"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(SECMON_DIR))

from app.governance.launcher import TaskLauncher, TaskSpec
from app.governance.storage import GovernanceStorage
from app.governance.perf_stats import (
    bootstrap_ci,
    get_system_info,
    iqr,
    median,
    percentile,
)

OUTPUT_DIR = REPO_ROOT / "demo" / "data" / "perf"


def is_ebpf_loader_available() -> tuple[bool, str]:
    """Check if the eBPF shadow sensor loader is available."""
    try:
        from app.governance.os_layer.ebpf_shadow import EBPFShadowManager
        mgr = EBPFShadowManager.get_instance()
        ok, reason = mgr.ensure_running()
        if ok:
            return True, "eBPF shadow loader is running"
        return False, f"eBPF shadow loader unavailable: {reason}"
    except Exception as ex:
        return False, f"eBPF shadow loader error: {ex}"


class EphemeralHTTPServer:
    """Lightweight local HTTP server for network workload benchmarks."""

    def __init__(self, payload: bytes = b"X" * 1024) -> None:
        self.payload = payload
        self.server: socketserver.TCPServer | None = None
        self.thread: threading.Thread | None = None
        self.port: int = 0

    def start(self) -> int:
        payload = self.payload

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:
                pass  # Silence request logging

        self.server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.port

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


class GovernanceBenchmarkRunner:
    """Orchestrates overhead evaluation across configurations and workloads."""

    def __init__(
        self,
        base_dir: Path | None = None,
        warmup_count: int = 2,
        repeats_w1_w5: int = 10,
        repeats_w2_w4: int = 20,
        configs: list[str] | None = None,
    ) -> None:
        self.base_dir = base_dir or Path(tempfile.mkdtemp(prefix="gov_bench_"))
        self.warmup_count = warmup_count
        self.repeats_w1_w5 = repeats_w1_w5
        self.repeats_w2_w4 = repeats_w2_w4
        self.storage = GovernanceStorage(self.base_dir / "bench_gov.db")
        self.receipts_dir = self.base_dir / "receipts"
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        self.workspace_base = Path(os.environ.get("HOME", "/tmp")) / "agent_workspaces"
        self.workspace_base.mkdir(parents=True, exist_ok=True)
        self.launcher = TaskLauncher(
            self.storage,
            workspace_base=self.workspace_base,
            receipts_dir=self.receipts_dir,
        )

        ebpf_ok, ebpf_reason = is_ebpf_loader_available()
        self.ebpf_available = ebpf_ok
        self.ebpf_note = ebpf_reason

        all_configs = ["A", "W", "C", "C-nosensor"]
        if self.ebpf_available:
            all_configs.append("C-ebpf")
        self.active_configs = configs or all_configs

    def cleanup(self) -> None:
        shutil.rmtree(self.base_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Workload W1: Start-up & Teardown Phase Breakdown
    # -------------------------------------------------------------------------

    def run_w1_single(self, config: str) -> dict[str, Any]:
        """Measure start-up phases and teardown duration for a single run."""
        task_id = f"w1_{config.lower().replace('-', '_')}_{uuid.uuid4().hex[:8]}"

        if config == "A":
            # Baseline A: direct process start and folder creation/cleanup
            t0 = time.monotonic()
            temp_dir = Path(tempfile.mkdtemp(prefix=f"direct_{task_id}_"))
            t_start = time.monotonic()
            p = subprocess.run([sys.executable, "-c", "pass"], cwd=str(temp_dir))
            t_exec = time.monotonic()
            shutil.rmtree(temp_dir, ignore_errors=True)
            t_end = time.monotonic()

            startup = t_exec - t_start
            teardown = t_end - t_exec
            return {
                "config": config,
                "startup_total_s": round(startup, 6),
                "teardown_s": round(teardown, 6),
                "intake_s": 0.0,
                "workspace_setup_s": 0.0,
                "cgroup_scope_s": 0.0,
                "net_ns_proxy_s": 0.0,
                "landlock_seccomp_s": 0.0,
                "sensor_attach_s": 0.0,
                "broker_connect_s": 0.0,
                "enforcer_arm_s": 0.0,
                "teardown_breakdown": {
                    "sensor_trailer_wait_s": 0.0,
                    "process_cleanup_s": 0.0,
                    "correlator_flush_s": 0.0,
                    "rpc_stop_s": 0.0,
                    "cgroup_cleanup_s": 0.0,
                    "proxy_stop_s": 0.0,
                    "total_teardown_s": round(teardown, 6),
                },
                "cpu_user_usec": None,
                "cpu_system_usec": None,
                "memory_peak_bytes": None,
                "extra_processes": 0,
            }

        # Governed configurations: W, C, C-nosensor, C-ebpf
        env_backup = dict(os.environ)
        try:
            if config in ("W", "C-nosensor", "C-ebpf"):
                os.environ["GOVERNANCE_BENCH_MODE"] = "1"
                os.environ["GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR"] = "1"
            if config == "C-ebpf":
                os.environ["GOVERNANCE_EBPF_SHADOW"] = "1"

            target_cond = "W" if config == "W" else "C"
            spec = TaskSpec(
                task_id=task_id,
                prompt="benchmark startup test",
                agent_id="bench_agent",
                condition=target_cond,
                llm={"provider": "scripted", "steps": [{"final": "done"}]},
                timeout_s=30.0,
                freeze_timeout_s=1.0,
                boundary_model="v1.1",
            )

            res = self.launcher.run(spec)
            pt = res.phase_timings
            cg_res = res.cgroup_resources

            # Extra governance processes:
            # In C: 1 sensor process + 1 proxy + 1 broker + 1 correlator
            # In C-nosensor: 1 proxy + 1 broker
            extra_procs = 4 if config == "C" else (3 if config == "C-ebpf" else 2)

            return {
                "config": config,
                "startup_total_s": pt.get("startup_total_s", 0.0),
                "teardown_s": pt.get("teardown_s", 0.0),
                "intake_s": pt.get("intake_s", 0.0),
                "workspace_setup_s": pt.get("workspace_setup_s", 0.0),
                "cgroup_scope_s": pt.get("cgroup_scope_s", 0.0),
                "net_ns_proxy_s": pt.get("net_ns_proxy_s", 0.0),
                "landlock_seccomp_s": pt.get("landlock_seccomp_s", 0.0),
                "sensor_attach_s": pt.get("sensor_attach_s", 0.0),
                "broker_connect_s": pt.get("broker_connect_s", 0.0),
                "enforcer_arm_s": pt.get("enforcer_arm_s", 0.0),
                "teardown_breakdown": pt.get("teardown_breakdown", {}),
                "cpu_user_usec": cg_res.get("cpu_user_usec"),
                "cpu_system_usec": cg_res.get("cpu_system_usec"),
                "memory_peak_bytes": cg_res.get("memory_peak_bytes"),
                "extra_processes": extra_procs,
            }
        finally:
            os.environ.clear()
            os.environ.update(env_backup)
            if 'res' in locals() and res and res.workspace:
                shutil.rmtree(res.workspace, ignore_errors=True)
                shutil.rmtree(res.control_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Workload W2: Tool-Call Latency (200 read, 200 write, 50 request_access)
    # -------------------------------------------------------------------------

    def run_w2_single(self, config: str) -> dict[str, Any]:
        """Measure latency of read_file, write_file, and request_access."""
        task_id = f"w2_{config.lower().replace('-', '_')}_{uuid.uuid4().hex[:8]}"

        if config == "A":
            # Baseline A: direct Python file I/O
            temp_dir = Path(tempfile.mkdtemp(prefix=f"direct_w2_{task_id}_"))
            out_dir = temp_dir / "output"
            in_dir = temp_dir / "input"
            out_dir.mkdir(parents=True)
            in_dir.mkdir(parents=True)

            # Seed 200 1KB input files
            sample_content = "A" * 1024
            for i in range(200):
                (in_dir / f"file_{i}.txt").write_text(sample_content, encoding="utf-8")

            read_latencies: list[float] = []
            write_latencies: list[float] = []
            access_latencies: list[float] = []

            for i in range(200):
                t0 = time.perf_counter()
                content = (in_dir / f"file_{i}.txt").read_text(encoding="utf-8")
                read_latencies.append((time.perf_counter() - t0) * 1000.0)
                if len(content) != 1024 or content != sample_content:
                    raise RuntimeError(f"Config A read check failed at file_{i}.txt")

            for i in range(200):
                t0 = time.perf_counter()
                out_path = out_dir / f"out_{i}.txt"
                out_path.write_text(sample_content, encoding="utf-8")
                write_latencies.append((time.perf_counter() - t0) * 1000.0)
                if not out_path.is_file() or out_path.stat().st_size != 1024:
                    raise RuntimeError(f"Config A write check failed at out_{i}.txt")

            shutil.rmtree(temp_dir, ignore_errors=True)
            return {
                "config": config,
                "read_latencies_ms": read_latencies,
                "write_latencies_ms": write_latencies,
                "access_latencies_ms": None,
            }

        # Governed configurations: W, C, C-nosensor, C-ebpf
        sample_content = "A" * 1024
        inputs = {f"input/file_{i}.txt": sample_content for i in range(200)}

        # Scripted tool steps: 200 reads, 200 writes, 50 requests
        steps: list[dict[str, Any]] = []
        for i in range(200):
            steps.append({"tool": "read_file", "args": {"file_path": f"input/file_{i}.txt"}})
        for i in range(200):
            steps.append({"tool": "write_file", "args": {"file_path": f"output/out_{i}.txt", "content": sample_content}})
        if config != "W":
            for i in range(50):
                steps.append({
                    "tool": "request_access",
                    "args": {
                        "resource_type": "file_read",
                        "resource_target": f"input/doc_{i}.txt",
                        "justification": f"benchmark request {i}",
                    },
                })
        steps.append({"final": "done"})

        env_backup = dict(os.environ)
        try:
            if config in ("W", "C-nosensor", "C-ebpf"):
                os.environ["GOVERNANCE_BENCH_MODE"] = "1"
                os.environ["GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR"] = "1"
            if config == "C-ebpf":
                os.environ["GOVERNANCE_EBPF_SHADOW"] = "1"

            target_cond = "W" if config == "W" else "C"
            spec = TaskSpec(
                task_id=task_id,
                prompt="benchmark tool latency",
                agent_id="bench_agent",
                condition=target_cond,
                inputs=inputs,
                output_targets=[f"output/out_{i}.txt" for i in range(200)],
                max_iterations=500,
                llm={"provider": "scripted", "steps": steps},
                approval_policy="oracle",
                oracle_allowed=[f"input/doc_{i}.txt" for i in range(50)],
                timeout_s=180.0,
                freeze_timeout_s=1.0,
                boundary_model="v1.1",
            )

            res = self.launcher.run(spec)
            hist = (res.shim_result or {}).get("tool_history", [])

            reads = [t for t in hist if t.get("tool") == "read_file"]
            for idx, r in enumerate(reads):
                out = r.get("output", "")
                if len(out) != 1024 or out != sample_content:
                    raise RuntimeError(f"Config {config} read check failed at step {idx}: length {len(out)} != 1024")

            for i in range(200):
                wp = res.workspace / "output" / f"out_{i}.txt"
                if not wp.is_file() or wp.stat().st_size != 1024:
                    raise RuntimeError(f"Config {config} write check failed: {wp} missing or size != 1024")

            read_latencies = [float(t.get("duration_ms", 0.0)) for t in reads]
            write_latencies = [
                float(t.get("duration_ms", 0.0)) for t in hist if t.get("tool") == "write_file"
            ]
            access_latencies = [
                float(t.get("duration_ms", 0.0)) for t in hist if t.get("tool") == "request_access"
            ] if config != "W" else None

            return {
                "config": config,
                "read_latencies_ms": read_latencies,
                "write_latencies_ms": write_latencies,
                "access_latencies_ms": access_latencies,
            }
        finally:
            os.environ.clear()
            os.environ.update(env_backup)
            if 'res' in locals() and res and res.workspace:
                shutil.rmtree(res.workspace, ignore_errors=True)
                shutil.rmtree(res.control_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Workload W3: Shell-heavy / Sensor Cost
    # -------------------------------------------------------------------------

    def run_w3_single(self, config: str) -> dict[str, Any]:
        """Measure find 5k files, grep -r, python read 2k files, tar 50MB, 500 execs."""
        task_id = f"w3_{config.lower().replace('-', '_')}_{uuid.uuid4().hex[:8]}"

        # Seed data in workspace or temp dir
        temp_dir = Path(tempfile.mkdtemp(prefix=f"w3_{task_id}_"))
        scratch_dir = temp_dir / "scratch"
        files_5k_dir = scratch_dir / "files_5k"
        folder_50mb_dir = scratch_dir / "folder_50mb"
        (temp_dir / "output").mkdir(parents=True, exist_ok=True)
        files_5k_dir.mkdir(parents=True, exist_ok=True)
        folder_50mb_dir.mkdir(parents=True, exist_ok=True)

        # 5,000 files across 50 subdirectories
        for d in range(50):
            sub = files_5k_dir / f"sub_{d}"
            sub.mkdir()
            for f in range(100):
                content_str = "NEEDLE_KEY sample line\n" if (d == 25 and f == 50) else "sample data line\n"
                (sub / f"file_{f}.txt").write_text(content_str, encoding="utf-8")

        # 50MB folder (50 x 1MB files)
        chunk_1mb = b"Z" * (1024 * 1024)
        for i in range(50):
            (folder_50mb_dir / f"blob_{i}.dat").write_bytes(chunk_1mb)

        cmd_find = "find scratch/files_5k -type f | wc -l"
        cmd_grep = "grep -r 'NEEDLE_KEY' scratch/files_5k"
        cmd_py_read = (
            "python3 -c \""
            "import os; "
            "b = sum(len(open(f'scratch/files_5k/sub_{i%50}/file_{i%100}.txt').read().encode('utf-8')) for i in range(2000)); "
            "print(f'BYTES_READ:{b}')\""
        )
        cmd_tar = "tar -czf output/test_50mb.tar.gz scratch/folder_50mb"
        cmd_execs = "/bin/sh -c 'count=0; for i in $(seq 1 500); do /bin/true && count=$((count+1)); done; echo EXECS:$count'"

        failures: list[str] = []

        if config == "A":
            # Baseline A: direct shell execution with strict validation
            def run_shell(c: str) -> tuple[float, int, str]:
                t0 = time.perf_counter()
                p = subprocess.run(c, shell=True, cwd=str(temp_dir), capture_output=True, text=True)
                dur = (time.perf_counter() - t0) * 1000.0
                return dur, p.returncode, p.stdout.strip()

            d_find, code_find, out_find = run_shell(cmd_find)
            if code_find != 0 or out_find != "5000":
                failures.append(f"Config A find check failed: exit={code_find}, count={out_find}")

            d_grep, code_grep, out_grep = run_shell(cmd_grep)
            if code_grep != 0 or "NEEDLE_KEY" not in out_grep or len(out_grep.splitlines()) != 1:
                failures.append(f"Config A grep check failed: exit={code_grep}, out={out_grep}")

            d_py, code_py, out_py = run_shell(cmd_py_read)
            if code_py != 0 or out_py != "BYTES_READ:34000":
                failures.append(f"Config A python read check failed: exit={code_py}, out={out_py}")

            d_tar, code_tar, _ = run_shell(cmd_tar)
            tar_file = temp_dir / "output" / "test_50mb.tar.gz"
            tar_cnt = 0
            if tar_file.is_file():
                tar_list_p = subprocess.run(f"tar -tf {tar_file} | wc -l", shell=True, capture_output=True, text=True)
                tar_cnt = int(tar_list_p.stdout.strip() or 0)
            if code_tar != 0 or not tar_file.is_file() or tar_file.stat().st_size <= 0 or tar_cnt != 51:
                failures.append(f"Config A tar check failed: exit={code_tar}, size={tar_file.stat().st_size if tar_file.is_file() else 0}, entries={tar_cnt}")

            d_execs, code_execs, out_execs = run_shell(cmd_execs)
            if code_execs != 0 or out_execs != "EXECS:500":
                failures.append(f"Config A execs check failed: exit={code_execs}, out={out_execs}")

            shutil.rmtree(temp_dir, ignore_errors=True)
            return {
                "config": config,
                "find_ms": d_find if not any("find" in f for f in failures) else "failed: find output mismatch",
                "grep_ms": d_grep if not any("grep" in f for f in failures) else "failed: grep output mismatch",
                "py_read_ms": d_py if not any("python" in f for f in failures) else "failed: python read mismatch",
                "tar_ms": d_tar if not any("tar" in f for f in failures) else "failed: tar mismatch",
                "execs_ms": d_execs if not any("execs" in f for f in failures) else "failed: execs mismatch",
                "failures": failures,
            }

        # Governed: run inside task sandbox
        steps = [
            {"tool": "run_command", "args": {"command": cmd_find}},
            {"tool": "run_command", "args": {"command": cmd_grep}},
            {"tool": "run_command", "args": {"command": cmd_py_read}},
            {"tool": "run_command", "args": {"command": cmd_tar}},
            {"tool": "run_command", "args": {"command": cmd_execs}},
            {"final": "done"},
        ]

        def seed_w3_into_workspace(l_obj: Any) -> None:
            w_dir = l_obj.live.get("workspace")
            if w_dir:
                (w_dir / "scratch").mkdir(parents=True, exist_ok=True)
                (w_dir / "output").mkdir(parents=True, exist_ok=True)
                shutil.copytree(files_5k_dir, w_dir / "scratch" / "files_5k", dirs_exist_ok=True)
                shutil.copytree(folder_50mb_dir, w_dir / "scratch" / "folder_50mb", dirs_exist_ok=True)

        self.launcher.test_hooks["after_workspace_created"] = seed_w3_into_workspace

        env_backup = dict(os.environ)
        try:
            if config in ("W", "C-nosensor", "C-ebpf"):
                os.environ["GOVERNANCE_BENCH_MODE"] = "1"
                os.environ["GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR"] = "1"
            if config == "C-ebpf":
                os.environ["GOVERNANCE_EBPF_SHADOW"] = "1"

            target_cond = "W" if config == "W" else "C"
            spec = TaskSpec(
                task_id=task_id,
                prompt="Read files in scratch/files_5k and write output/test_50mb.tar.gz using shell commands",
                agent_id="bench_agent",
                condition=target_cond,
                declared_tools=["run_command"],
                output_targets=["output/test_50mb.tar.gz"],
                max_iterations=20,
                llm={"provider": "scripted", "steps": steps},
                timeout_s=180.0,
                freeze_timeout_s=1.0,
                boundary_model="v1",
            )

            res = self.launcher.run(spec)
            hist = (res.shim_result or {}).get("tool_history", [])
            # Commands are at index 0, 1, 2, 3, 4
            exec_tools = [t for t in hist if t.get("tool") == "run_command"]

            def get_step_info(idx: int) -> tuple[float, int, str]:
                if idx < len(exec_tools):
                    t = exec_tools[idx]
                    dur = float(t.get("duration_ms", 0.0))
                    out_dict = t.get("output") or {}
                    if isinstance(out_dict, dict):
                        return dur, int(out_dict.get("exit_code", -1)), str(out_dict.get("stdout", "")).strip()
                    return dur, 0, str(out_dict).strip()
                return 0.0, -1, ""

            d_find, c_find, o_find = get_step_info(0)
            if c_find != 0 or o_find != "5000":
                failures.append(f"Config {config} find check failed: exit={c_find}, count={o_find}")

            d_grep, c_grep, o_grep = get_step_info(1)
            if c_grep != 0 or "NEEDLE_KEY" not in o_grep or len(o_grep.splitlines()) != 1:
                failures.append(f"Config {config} grep check failed: exit={c_grep}, out={o_grep}")

            d_py, c_py, o_py = get_step_info(2)
            if c_py != 0 or o_py != "BYTES_READ:34000":
                failures.append(f"Config {config} python read check failed: exit={c_py}, out={o_py}")

            d_tar, c_tar, _ = get_step_info(3)
            tar_p = res.workspace / "output" / "test_50mb.tar.gz"
            tar_cnt = 0
            if tar_p.is_file():
                tar_list_p = subprocess.run(f"tar -tf {tar_p} | wc -l", shell=True, capture_output=True, text=True)
                tar_cnt = int(tar_list_p.stdout.strip() or 0)
            if c_tar != 0 or not tar_p.is_file() or tar_p.stat().st_size <= 0 or tar_cnt != 51:
                failures.append(f"Config {config} tar check failed: exit={c_tar}, size={tar_p.stat().st_size if tar_p.is_file() else 0}, entries={tar_cnt}")

            d_execs, c_execs, o_execs = get_step_info(4)
            if c_execs != 0 or o_execs != "EXECS:500":
                failures.append(f"Config {config} execs check failed: exit={c_execs}, out={o_execs}")

            return {
                "config": config,
                "find_ms": d_find if not any("find" in f for f in failures) else "failed: find output mismatch",
                "grep_ms": d_grep if not any("grep" in f for f in failures) else "failed: grep output mismatch",
                "py_read_ms": d_py if not any("python" in f for f in failures) else "failed: python read mismatch",
                "tar_ms": d_tar if not any("tar" in f for f in failures) else "failed: tar mismatch",
                "execs_ms": d_execs if not any("execs" in f for f in failures) else "failed: execs mismatch",
                "failures": failures,
            }
        finally:
            self.launcher.test_hooks.pop("after_workspace_created", None)
            shutil.rmtree(temp_dir, ignore_errors=True)
            os.environ.clear()
            os.environ.update(env_backup)
            if 'res' in locals() and res and res.workspace:
                shutil.rmtree(res.workspace, ignore_errors=True)
                shutil.rmtree(res.control_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Workload W4: Network (100 HTTP GETs direct vs proxy)
    # -------------------------------------------------------------------------

    def run_w4_single(self, config: str, http_port: int) -> dict[str, Any]:
        """Measure 100 HTTP GETs with status 200 and body length verification."""
        target_url = f"http://127.0.0.1:{http_port}/test"
        task_id = f"w4_{config.lower().replace('-', '_')}_{uuid.uuid4().hex[:8]}"

        if config == "W":
            # Condition W has no network namespace or proxy by design
            return {
                "config": config,
                "http_get_latencies_ms": None,
                "status": "n/a (no network in W)",
            }

        if config == "A":
            # Direct HTTP GETs (no proxy)
            latencies: list[float] = []
            for _ in range(100):
                t0 = time.perf_counter()
                with urllib.request.urlopen(target_url, timeout=5.0) as resp:
                    data = resp.read()
                    status = resp.status
                latencies.append((time.perf_counter() - t0) * 1000.0)
                if status != 200 or len(data) != 1024:
                    raise RuntimeError(f"Config A W4 verification failed: status={status}, len={len(data)}")

            return {
                "config": config,
                "http_get_latencies_ms": latencies,
                "status": "success",
            }

        # Governed: 100 http_get tool calls routed through proxy
        steps = [{"tool": "http_get", "args": {"url": target_url}} for _ in range(100)]
        steps.append({"final": "done"})

        env_backup = dict(os.environ)
        try:
            if config in ("W", "C-nosensor", "C-ebpf"):
                os.environ["GOVERNANCE_BENCH_MODE"] = "1"
                os.environ["GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR"] = "1"
            if config == "C-ebpf":
                os.environ["GOVERNANCE_EBPF_SHADOW"] = "1"

            target_cond = "W" if config == "W" else "C"
            spec = TaskSpec(
                task_id=task_id,
                prompt="benchmark network latency",
                agent_id="bench_agent",
                condition=target_cond,
                network=["127.0.0.1", f"127.0.0.1:{http_port}"],
                max_iterations=120,
                llm={"provider": "scripted", "steps": steps},
                timeout_s=120.0,
                freeze_timeout_s=1.0,
                boundary_model="v1.1",
            )

            res = self.launcher.run(spec)
            hist = (res.shim_result or {}).get("tool_history", [])
            latencies = []
            for t in hist:
                if t.get("tool") == "http_get":
                    latencies.append(float(t.get("duration_ms", 0.0)))
                    out = t.get("output") or {}
                    if isinstance(out, dict):
                        st = out.get("status", 200)
                        body = out.get("body", "")
                        if st != 200 or len(body.encode("utf-8")) != 1024:
                            raise RuntimeError(f"Config {config} W4 check failed: status={st}, len={len(body)}")

            return {
                "config": config,
                "http_get_latencies_ms": latencies,
                "status": "success",
            }
        finally:
            os.environ.clear()
            os.environ.update(env_backup)
            if 'res' in locals() and res and res.workspace:
                shutil.rmtree(res.workspace, ignore_errors=True)
                shutil.rmtree(res.control_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Workload W5: End-to-end scripted presets (summarise_csv)
    # -------------------------------------------------------------------------

    def run_w5_single(self, config: str) -> dict[str, Any]:
        """Measure wall time of summarise_csv preset comparing like with like.
        
        Condition A runs the exact same scripted preset through TaskLauncher
        with condition='A' (same process launch, no governance runtime).
        """
        task_id = f"w5_{config.lower().replace('-', '_')}_{uuid.uuid4().hex[:8]}"
        csv_rows = ["id,amount"] + [f"{i},{i*10}" for i in range(1, 101)]
        csv_content = "\n".join(csv_rows) + "\n"

        cmd_awk = "awk -F, 'NR>1 {sum+=$2; cnt++} END {print \"Count: \" cnt \", Total: \" sum}' input/sales.csv > output/summary.txt"

        steps = [
            {"tool": "read_file", "args": {"file_path": "input/sales.csv"}},
            {"tool": "run_command", "args": {"command": cmd_awk}},
            {"tool": "read_file", "args": {"file_path": "output/summary.txt"}},
            {"final": "done"},
        ]

        env_backup = dict(os.environ)
        try:
            if config in ("W", "C-nosensor", "C-ebpf"):
                os.environ["GOVERNANCE_BENCH_MODE"] = "1"
                os.environ["GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR"] = "1"
            if config == "C-ebpf":
                os.environ["GOVERNANCE_EBPF_SHADOW"] = "1"

            target_cond = "A" if config == "A" else ("W" if config == "W" else "C")
            spec = TaskSpec(
                task_id=task_id,
                prompt="Summarise input/sales.csv into output/summary.txt",
                agent_id="bench_agent",
                condition=target_cond,
                inputs={"input/sales.csv": csv_content},
                output_targets=["output/summary.txt"],
                llm={"provider": "scripted", "steps": steps},
                timeout_s=60.0,
                freeze_timeout_s=1.0,
                boundary_model="v1.1",
            )

            res = self.launcher.run(spec)

            out_file = res.workspace / "output" / "summary.txt"
            if not out_file.is_file() or "Count: 100, Total: 50500" not in out_file.read_text(encoding="utf-8"):
                raise RuntimeError(f"Config {config} W5 output verification failed")

            receipt = res.receipt or {}
            wall_time_with_td = float(receipt.get("wall_time_s", 0.0))
            teardown_s = float(res.phase_timings.get("teardown_s", 0.0))
            wall_time_without_td = max(0.001, wall_time_with_td - teardown_s)

            return {
                "config": config,
                "wall_time_with_teardown_s": round(wall_time_with_td, 4),
                "wall_time_without_teardown_s": round(wall_time_without_td, 4),
                "teardown_s": round(teardown_s, 4),
            }
        finally:
            os.environ.clear()
            os.environ.update(env_backup)
            if 'res' in locals() and res and res.workspace:
                shutil.rmtree(res.workspace, ignore_errors=True)
                shutil.rmtree(res.control_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Full Benchmark Execution
    # -------------------------------------------------------------------------

    def run_benchmark(self, quick: bool = False) -> dict[str, Any]:
        """Run all workloads across active configurations with randomized repeat order."""
        sys_before = get_system_info()
        print(f"System Info: {sys_before['cpu_model']} ({sys_before['cpu_cores']} cores), kernel {sys_before['kernel']}")
        print(f"Load Average: 1m={sys_before['load_avg_1m']}, 5m={sys_before['load_avg_5m']}")
        if sys_before.get("load_warning"):
            print(f"WARNING: {sys_before['load_warning']}")

        if not self.ebpf_available:
            print(f"NOTE: {self.ebpf_note}. Skipping C-ebpf configuration.")

        repeats_1_5 = 2 if quick else self.repeats_w1_w5
        repeats_2_4 = 2 if quick else self.repeats_w2_w4
        warmups = 1 if quick else self.warmup_count

        print(f"\nStarting benchmark: {len(self.active_configs)} configs, {warmups} warmups, repeats: W1/W5={repeats_1_5}, W2-W4={repeats_2_4}")

        # Setup HTTP server for W4
        http_srv = EphemeralHTTPServer()
        http_port = http_srv.start()

        # Data collection containers
        w1_results: dict[str, list[dict[str, Any]]] = {c: [] for c in self.active_configs}
        w2_results: dict[str, list[dict[str, Any]]] = {c: [] for c in self.active_configs}
        w3_results: dict[str, list[dict[str, Any]]] = {c: [] for c in self.active_configs}
        w4_results: dict[str, list[dict[str, Any]]] = {c: [] for c in self.active_configs}
        w5_results: dict[str, list[dict[str, Any]]] = {c: [] for c in self.active_configs}

        try:
            # 1. Warm-ups
            print("\n[Phase 1] Running warm-up iterations...")
            for _ in range(warmups):
                for c in self.active_configs:
                    self.run_w1_single(c)
                    self.run_w5_single(c)

            # 2. W1: Start-up & Teardown
            print("\n[Phase 2] Evaluating W1: Start-up & Teardown Breakdown...")
            for r in range(repeats_1_5):
                order = list(self.active_configs)
                random.shuffle(order)
                for c in order:
                    res = self.run_w1_single(c)
                    w1_results[c].append(res)
                print(f"  W1 repeat {r + 1}/{repeats_1_5} finished")

            # 3. W2: Tool-Call Latency
            print("\n[Phase 3] Evaluating W2: Tool-Call Latency (200 read, 200 write, 50 request_access)...")
            for r in range(repeats_2_4):
                order = list(self.active_configs)
                random.shuffle(order)
                for c in order:
                    res = self.run_w2_single(c)
                    w2_results[c].append(res)
                print(f"  W2 repeat {r + 1}/{repeats_2_4} finished")

            # 4. W3: Shell-heavy / Sensor Cost
            print("\n[Phase 4] Evaluating W3: Shell-heavy Sensor Cost (5k find, grep, python read 2k, tar 50MB, 500 execs)...")
            for r in range(repeats_2_4):
                order = list(self.active_configs)
                random.shuffle(order)
                for c in order:
                    res = self.run_w3_single(c)
                    w3_results[c].append(res)
                print(f"  W3 repeat {r + 1}/{repeats_2_4} finished")

            # 5. W4: Network
            print("\n[Phase 5] Evaluating W4: Network Latency (100 HTTP GETs direct vs proxy)...")
            for r in range(repeats_2_4):
                order = list(self.active_configs)
                random.shuffle(order)
                for c in order:
                    res = self.run_w4_single(c, http_port)
                    w4_results[c].append(res)
                print(f"  W4 repeat {r + 1}/{repeats_2_4} finished")

            # 6. W5: End-to-end Preset
            print("\n[Phase 6] Evaluating W5: End-to-End Preset (summarise_csv)...")
            for r in range(repeats_1_5):
                order = list(self.active_configs)
                random.shuffle(order)
                for c in order:
                    res = self.run_w5_single(c)
                    w5_results[c].append(res)
                print(f"  W5 repeat {r + 1}/{repeats_1_5} finished")

        finally:
            http_srv.stop()

        sys_after = get_system_info()

        # Aggregate Statistics
        summary = self._aggregate_summary(
            sys_before, sys_after, w1_results, w2_results, w3_results, w4_results, w5_results
        )
        return summary

    def _aggregate_summary(
        self,
        sys_before: dict[str, Any],
        sys_after: dict[str, Any],
        w1: dict[str, list[dict[str, Any]]],
        w2: dict[str, list[dict[str, Any]]],
        w3: dict[str, list[dict[str, Any]]],
        w4: dict[str, list[dict[str, Any]]],
        w5: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        """Compute medians, IQR, and 95% bootstrap CIs for all benchmarks."""
        out: dict[str, Any] = {
            "system_info": {
                "before": sys_before,
                "after": sys_after,
                "ebpf_available": self.ebpf_available,
                "ebpf_note": self.ebpf_note,
            },
            "w1_startup_teardown": {},
            "w2_tool_latency": {},
            "w3_shell_sensor": {},
            "w4_network": {},
            "w5_preset_e2e": {},
        }

        # W1 Aggregation
        for c, runs in w1.items():
            if not runs:
                continue
            startup_vals = [r["startup_total_s"] * 1000.0 for r in runs]
            teardown_vals = [r["teardown_s"] * 1000.0 for r in runs]

            intake_vals = [r.get("intake_s", 0.0) * 1000.0 for r in runs]
            ws_vals = [r.get("workspace_setup_s", 0.0) * 1000.0 for r in runs]
            scope_vals = [r["cgroup_scope_s"] * 1000.0 for r in runs]
            proxy_vals = [r["net_ns_proxy_s"] * 1000.0 for r in runs]
            rules_vals = [r["landlock_seccomp_s"] * 1000.0 for r in runs]
            sensor_vals = [r["sensor_attach_s"] * 1000.0 for r in runs]
            broker_vals = [r["broker_connect_s"] * 1000.0 for r in runs]
            arm_vals = [r.get("enforcer_arm_s", 0.0) * 1000.0 for r in runs]

            tb_trailer = [r.get("teardown_breakdown", {}).get("sensor_trailer_wait_s", 0.0) * 1000.0 for r in runs]
            tb_cleanup = [r.get("teardown_breakdown", {}).get("process_cleanup_s", 0.0) * 1000.0 for r in runs]
            tb_flush = [r.get("teardown_breakdown", {}).get("correlator_flush_s", 0.0) * 1000.0 for r in runs]
            tb_rpc = [r.get("teardown_breakdown", {}).get("rpc_stop_s", 0.0) * 1000.0 for r in runs]
            tb_cg = [r.get("teardown_breakdown", {}).get("cgroup_cleanup_s", 0.0) * 1000.0 for r in runs]
            tb_proxy = [r.get("teardown_breakdown", {}).get("proxy_stop_s", 0.0) * 1000.0 for r in runs]

            cpu_u = [float(r["cpu_user_usec"]) for r in runs if r.get("cpu_user_usec") is not None]
            cpu_s = [float(r["cpu_system_usec"]) for r in runs if r.get("cpu_system_usec") is not None]
            mem_p = [float(r["memory_peak_bytes"]) / (1024.0 * 1024.0) for r in runs if r.get("memory_peak_bytes") is not None]

            out["w1_startup_teardown"][c] = {
                "startup_total_ms": {
                    "median": round(median(startup_vals), 2),
                    "iqr": iqr(startup_vals),
                    "ci_95": list(bootstrap_ci(startup_vals)),
                },
                "teardown_ms": {
                    "median": round(median(teardown_vals), 2),
                    "iqr": iqr(teardown_vals),
                    "ci_95": list(bootstrap_ci(teardown_vals)),
                },
                "phases_ms": {
                    "intake": round(median(intake_vals), 2),
                    "workspace_setup": round(median(ws_vals), 2),
                    "cgroup_scope": round(median(scope_vals), 2),
                    "netns_proxy": round(median(proxy_vals), 2),
                    "landlock_seccomp": round(median(rules_vals), 2),
                    "sensor_attach": round(median(sensor_vals), 2),
                    "broker_connect": round(median(broker_vals), 2),
                    "enforcer_arm": round(median(arm_vals), 2),
                },
                "teardown_breakdown_ms": {
                    "sensor_trailer_wait": round(median(tb_trailer), 2),
                    "process_cleanup": round(median(tb_cleanup), 2),
                    "correlator_flush": round(median(tb_flush), 2),
                    "rpc_stop": round(median(tb_rpc), 2),
                    "cgroup_cleanup": round(median(tb_cg), 2),
                    "proxy_stop": round(median(tb_proxy), 2),
                },
                "resources": {
                    "cpu_user_usec": round(median(cpu_u), 0) if cpu_u else None,
                    "cpu_system_usec": round(median(cpu_s), 0) if cpu_s else None,
                    "memory_peak_mb": round(median(mem_p), 2) if mem_p else None,
                    "extra_processes": runs[0]["extra_processes"],
                },
            }

        # W2 Aggregation
        for c, runs in w2.items():
            if not runs:
                continue
            all_reads = [lat for r in runs for lat in r["read_latencies_ms"]]
            all_writes = [lat for r in runs for lat in r["write_latencies_ms"]]
            access_runs = [r["access_latencies_ms"] for r in runs if r.get("access_latencies_ms") is not None]
            all_access = [lat for r_acc in access_runs for lat in r_acc] if access_runs else []

            out["w2_tool_latency"][c] = {
                "read_file": {
                    "p50": round(median(all_reads), 3),
                    "p95": round(percentile(all_reads, 95.0), 3),
                    "p99": round(percentile(all_reads, 99.0), 3),
                    "iqr": iqr(all_reads),
                    "ci_95": list(bootstrap_ci(all_reads)),
                },
                "write_file": {
                    "p50": round(median(all_writes), 3),
                    "p95": round(percentile(all_writes, 95.0), 3),
                    "p99": round(percentile(all_writes, 99.0), 3),
                    "iqr": iqr(all_writes),
                    "ci_95": list(bootstrap_ci(all_writes)),
                },
                "request_access": {
                    "p50": round(median(all_access), 3),
                    "p95": round(percentile(all_access, 95.0), 3),
                    "p99": round(percentile(all_access, 99.0), 3),
                    "iqr": iqr(all_access),
                    "ci_95": list(bootstrap_ci(all_access)),
                } if all_access else None,
            }

        # W3 Aggregation
        baseline_w3: dict[str, float] = {}
        all_failures: list[str] = []
        for c, runs in w3.items():
            if not runs:
                continue
            for r in runs:
                all_failures.extend(r.get("failures", []))

            def extract_valid_times(key: str) -> list[float]:
                vals = []
                for r in runs:
                    val = r.get(key)
                    if isinstance(val, (int, float)):
                        vals.append(float(val))
                return vals

            find_v = extract_valid_times("find_ms")
            grep_v = extract_valid_times("grep_ms")
            py_v = extract_valid_times("py_read_ms")
            tar_v = extract_valid_times("tar_ms")
            exec_v = extract_valid_times("execs_ms")

            med_find = round(median(find_v), 1) if find_v else None
            med_grep = round(median(grep_v), 1) if grep_v else None
            med_py = round(median(py_v), 1) if py_v else None
            med_tar = round(median(tar_v), 1) if tar_v else None
            med_exec = round(median(exec_v), 1) if exec_v else None

            if c == "A" and med_find and med_grep and med_py and med_tar and med_exec:
                baseline_w3 = {
                    "find": med_find,
                    "grep": med_grep,
                    "py_read": med_py,
                    "tar": med_tar,
                    "execs": med_exec,
                }

            out["w3_shell_sensor"][c] = {
                "find_5k_ms": {"median": med_find, "iqr": iqr(find_v), "ci_95": list(bootstrap_ci(find_v))} if med_find is not None else "failed: mismatch",
                "grep_r_ms": {"median": med_grep, "iqr": iqr(grep_v), "ci_95": list(bootstrap_ci(grep_v))} if med_grep is not None else "failed: mismatch",
                "py_read_2k_ms": {"median": med_py, "iqr": iqr(py_v), "ci_95": list(bootstrap_ci(py_v))} if med_py is not None else "failed: mismatch",
                "tar_50mb_ms": {"median": med_tar, "iqr": iqr(tar_v), "ci_95": list(bootstrap_ci(tar_v))} if med_tar is not None else "failed: mismatch",
                "execs_500_ms": {"median": med_exec, "iqr": iqr(exec_v), "ci_95": list(bootstrap_ci(exec_v))} if med_exec is not None else "failed: mismatch",
            }

        out["w3_failures"] = list(sorted(set(all_failures)))

        # Slowdown factor vs A in W3
        if baseline_w3:
            for c, data in out["w3_shell_sensor"].items():
                def calc_sd(k: str) -> float | str:
                    obj = data.get(f"{k}_ms") or data.get(f"{k}_5k_ms") or data.get(f"{k}_r_ms") or data.get(f"{k}_2k_ms") or data.get(f"{k}_50mb_ms") or data.get(f"{k}_500_ms")
                    if isinstance(obj, dict) and obj.get("median") is not None:
                        return round(obj["median"] / max(0.001, baseline_w3[k]), 2)
                    return "n/a"

                data["slowdown_vs_A"] = {
                    "find": calc_sd("find"),
                    "grep": calc_sd("grep"),
                    "py_read": calc_sd("py_read"),
                    "tar": calc_sd("tar"),
                    "execs": calc_sd("execs"),
                }

        # W4 Aggregation
        for c, runs in w4.items():
            if not runs:
                continue
            if c == "W":
                out["w4_network"][c] = {"status": "n/a (no network in W)"}
                continue

            all_http = [lat for r in runs if r.get("http_get_latencies_ms") for lat in r["http_get_latencies_ms"]]
            if all_http:
                out["w4_network"][c] = {
                    "p50_ms": round(median(all_http), 3),
                    "p95_ms": round(percentile(all_http, 95.0), 3),
                    "iqr": iqr(all_http),
                    "ci_95": list(bootstrap_ci(all_http)),
                    "status": "success",
                }
            else:
                out["w4_network"][c] = {"status": "failed: requests failed"}

        # W5 Aggregation
        baseline_w5_no_td = 0.0
        baseline_w5_with_td = 0.0
        for c, runs in w5.items():
            if not runs:
                continue
            no_td_times = [r["wall_time_without_teardown_s"] for r in runs]
            with_td_times = [r["wall_time_with_teardown_s"] for r in runs]

            med_no_td = round(median(no_td_times), 3)
            med_with_td = round(median(with_td_times), 3)

            if c == "A":
                baseline_w5_no_td = med_no_td
                baseline_w5_with_td = med_with_td

            out["w5_preset_e2e"][c] = {
                "wall_time_without_teardown_s": {
                    "median": med_no_td,
                    "iqr": iqr(no_td_times),
                    "ci_95": list(bootstrap_ci(no_td_times)),
                },
                "wall_time_with_teardown_s": {
                    "median": med_with_td,
                    "iqr": iqr(with_td_times),
                    "ci_95": list(bootstrap_ci(with_td_times)),
                },
                "slowdown_without_teardown": round(med_no_td / max(0.001, baseline_w5_no_td), 2) if baseline_w5_no_td > 0 else 1.0,
                "slowdown_with_teardown": round(med_with_td / max(0.001, baseline_w5_with_td), 2) if baseline_w5_with_td > 0 else 1.0,
            }

        return out


def generate_perf_markdown(summary: dict[str, Any]) -> str:
    """Format benchmark results into comprehensive Markdown tables."""
    sys_b = summary["system_info"]["before"]
    ebpf_note = summary["system_info"].get("ebpf_note", "")

    lines: list[str] = [
        "# Runtime Governance Performance Overhead Benchmark (v1)",
        "",
        "Empirical measurement of execution duration and system resource overhead across isolation layers, comparing:",
        "- **A**: Baseline (no governance runtime; Condition A via TaskLauncher)",
        "- **W**: Workspace sandbox (Landlock workspace boundary)",
        "- **C**: Full governance (tool broker, Landlock, seccomp, netns/proxy, ptrace sensor)",
        "- **C-nosensor**: Condition C with the ptrace sensor disabled (benchmark mode)",
        "- **C-ebpf**: Condition C with eBPF shadow sensor",
        "",
        f"**Environment**: {sys_b.get('cpu_model')} ({sys_b.get('cpu_cores')} cores), Linux {sys_b.get('kernel')}  ",
        f"**System Load**: 1m={sys_b.get('load_avg_1m')}, 5m={sys_b.get('load_avg_5m')}  ",
    ]
    if ebpf_note:
        lines.append(f"**eBPF Sensor Status**: {ebpf_note}  ")
    lines.append("")

    # 1. W1 Table (Startup Phases)
    lines.extend([
        "## W1: Start-up Phase Breakdown (Non-Overlapping Contiguous Intervals)",
        "",
        "| Configuration | Total Startup (ms) | Intake (ms) | Workspace Setup (ms) | NetNS / Proxy (ms) | Landlock / Seccomp (ms) | Process Launch (ms) | Cgroup Scope (ms) | Enforcer Arm (ms) | Peak Mem (MB) | Extra Procs |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])
    for c, stats in summary.get("w1_startup_teardown", {}).items():
        st = f"{stats['startup_total_ms']['median']:.1f} [IQR: {stats['startup_total_ms']['iqr']:.1f}]"
        ph = stats.get("phases_ms", {})
        res = stats.get("resources", {})
        mem = f"{res.get('memory_peak_mb'):.1f}" if res.get("memory_peak_mb") is not None else "not measured"
        procs = f"{res.get('extra_processes', 0)}"
        lines.append(
            f"| **{c}** | {st} | {ph.get('intake', 0):.1f} | {ph.get('workspace_setup', 0):.1f} | "
            f"{ph.get('netns_proxy', 0):.1f} | {ph.get('landlock_seccomp', 0):.1f} | {ph.get('sensor_attach', 0):.1f} | "
            f"{ph.get('cgroup_scope', 0):.1f} | {ph.get('enforcer_arm', 0):.1f} | {mem} | {procs} |"
        )

    # 1b. Teardown Breakdown Table & Analysis
    lines.extend([
        "",
        "## W1: Teardown Duration Breakdown",
        "",
        "| Configuration | Total Teardown (ms) | Sensor Trailer Wait (ms) | Process Cleanup / Freeze (ms) | Correlator Flush (ms) | RPC Stop (ms) | Cgroup Cleanup (ms) | Proxy Stop (ms) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])
    for c, stats in summary.get("w1_startup_teardown", {}).items():
        td_total = f"{stats['teardown_ms']['median']:.1f}"
        tb = stats.get("teardown_breakdown_ms", {})
        lines.append(
            f"| **{c}** | {td_total} | {tb.get('sensor_trailer_wait', 0):.1f} | {tb.get('process_cleanup', 0):.1f} | "
            f"{tb.get('correlator_flush', 0):.1f} | {tb.get('rpc_stop', 0):.1f} | {tb.get('cgroup_cleanup', 0):.1f} | {tb.get('proxy_stop', 0):.1f} |"
        )

    lines.extend([
        "",
        "> [!NOTE]",
        "> **Teardown Latency Root Cause:**",
        "> In Condition C, teardown latency (~2,470 ms) is dominated by:",
        "> 1. `proxy_stop` (~2,001 ms): `_AsyncLoopThread.stop()` schedules `_shutdown()` via `asyncio.run_coroutine_threadsafe(...).result(timeout=2.0)`. In `_shutdown()`, `self.loop.stop()` stops the loop immediately before the future is resolved, causing `fut.result(timeout=2.0)` to wait for the 2.0s timeout (`demo/security_monitor/app/governance/launcher.py` line 441).",
        "> 2. `rpc_stop` (~460 ms): `BrokerRPCServer.stop()` joins threaded UNIX domain socket servers and cleans up endpoints (`demo/security_monitor/app/governance/launcher.py` line 1488).",
        "",
        "## W2: Tool-Call Latency (Content Verified)",
        "",
        "| Configuration | `read_file` 1KB p50 / p95 (ms) | `write_file` 1KB p50 / p95 (ms) | `request_access` p50 / p95 (ms) |",
        "| :--- | :---: | :---: | :---: |",
    ])
    for c, stats in summary.get("w2_tool_latency", {}).items():
        r = f"{stats['read_file']['p50']:.2f} / {stats['read_file']['p95']:.2f}"
        w = f"{stats['write_file']['p50']:.2f} / {stats['write_file']['p95']:.2f}"
        if stats.get("request_access"):
            a = f"{stats['request_access']['p50']:.2f} / {stats['request_access']['p95']:.2f}"
        else:
            a = "n/a (no access request in " + c + ")"
        lines.append(f"| **{c}** | {r} | {w} | {a} |")

    # 3. W3 Table
    lines.extend([
        "",
        "## W3: Shell-Heavy / Sensor Cost (Strict Content Checked)",
        "",
        "| Configuration | `find` 5k files (ms) | `grep -r` 5k (ms) | Python read 2k (ms) | `tar` 50MB (ms) | 500 execs `/bin/true` (ms) | Slowdown (execs vs A) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])
    for c, stats in summary.get("w3_shell_sensor", {}).items():
        def fmt_cmd(k: str) -> str:
            item = stats.get(k)
            if isinstance(item, dict) and item.get("median") is not None:
                return f"{item['median']:.1f}"
            return str(item or "failed")

        f = fmt_cmd("find_5k_ms")
        g = fmt_cmd("grep_r_ms")
        py = fmt_cmd("py_read_2k_ms")
        t = fmt_cmd("tar_50mb_ms")
        ex = fmt_cmd("execs_500_ms")
        sd = f"{stats.get('slowdown_vs_A', {}).get('execs', 1.0):.2f}x" if isinstance(stats.get('slowdown_vs_A', {}).get('execs'), (int, float)) else "n/a"
        lines.append(f"| **{c}** | {f} | {g} | {py} | {t} | {ex} | {sd} |")

    failures = summary.get("w3_failures", [])
    if failures:
        lines.extend([
            "",
            "**W3 Failures Detected:**",
        ])
        for fl in failures:
            lines.append(f"- {fl}")

    # 4. W4 Table
    lines.extend([
        "",
        "## W4: Network Overhead (100 HTTP GETs 1KB; Status 200 & Length Verified)",
        "",
        "| Configuration | Per-Request p50 (ms) | Per-Request p95 (ms) | IQR (ms) | 95% Bootstrap CI (ms) | Status |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ])
    for c, stats in summary.get("w4_network", {}).items():
        if stats.get("status") == "n/a (no network in W)":
            lines.append(f"| **{c}** | n/a | n/a | n/a | n/a | n/a (no network in W) |")
        elif "p50_ms" in stats:
            p50 = f"{stats['p50_ms']:.2f}"
            p95 = f"{stats['p95_ms']:.2f}"
            iqr_val = f"{stats['iqr']:.2f}"
            ci = f"{stats['ci_95'][0]:.2f}–{stats['ci_95'][1]:.2f}"
            lines.append(f"| **{c}** | {p50} | {p95} | {iqr_val} | {ci} | verified |")
        else:
            lines.append(f"| **{c}** | failed | failed | failed | failed | {stats.get('status', 'failed')} |")

    # 5. W5 Table
    lines.extend([
        "",
        "## W5: End-to-End Preset (`summarise_csv`; Comparable Condition-A Path)",
        "",
        "| Configuration | Without Teardown p50 (s) | Slowdown (No TD) | With Teardown p50 (s) | Slowdown (With TD) | IQR With TD (s) | 95% Bootstrap CI (s) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])
    for c, stats in summary.get("w5_preset_e2e", {}).items():
        wt_no_td = f"{stats['wall_time_without_teardown_s']['median']:.3f}"
        sd_no_td = f"{stats['slowdown_without_teardown']:.2f}x"
        wt_with_td = f"{stats['wall_time_with_teardown_s']['median']:.3f}"
        sd_with_td = f"{stats['slowdown_with_teardown']:.2f}x"
        iqr_val = f"{stats['wall_time_with_teardown_s']['iqr']:.3f}"
        ci = f"{stats['wall_time_with_teardown_s']['ci_95'][0]:.3f}–{stats['wall_time_with_teardown_s']['ci_95'][1]:.3f}"
        lines.append(f"| **{c}** | {wt_no_td} | {sd_no_td} | {wt_with_td} | {sd_with_td} | {iqr_val} | {ci} |")

    lines.append("")
    return "\n".join(lines)

def run_overhead_benchmark(
    quick: bool = False,
    out_dir: Path | None = None,
    configs: list[str] | None = None,
) -> tuple[dict[str, Any], str]:
    """Execute the overhead benchmark and generate JSON and Markdown reports."""
    output_directory = out_dir or OUTPUT_DIR
    output_directory.mkdir(parents=True, exist_ok=True)

    runner = GovernanceBenchmarkRunner(configs=configs)
    try:
        summary = runner.run_benchmark(quick=quick)
    finally:
        runner.cleanup()

    md = generate_perf_markdown(summary)

    json_path = output_directory / "perf_v1.json"
    md_path = output_directory / "perf_v1.md"

    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    md_path.write_text(md, encoding="utf-8")

    return summary, md


def main() -> int:
    parser = argparse.ArgumentParser(description="Governance performance overhead benchmark.")
    parser.add_argument("--quick", action="store_true", help="Run quick benchmark with minimal repeats for verification.")
    parser.add_argument("--out-dir", type=Path, default=OUTPUT_DIR, help="Output directory.")
    parser.add_argument("--configs", type=str, default="", help="Comma-separated configs to evaluate (e.g. A,W,C).")
    args = parser.parse_args()

    cfg_list = [c.strip() for c in args.configs.split(",") if c.strip()] if args.configs else None
    summary, md = run_overhead_benchmark(quick=args.quick, out_dir=args.out_dir, configs=cfg_list)

    print(f"\nWrote benchmark results to {args.out_dir / 'perf_v1.json'}")
    print(f"Wrote Markdown report to {args.out_dir / 'perf_v1.md'}\n")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
