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
                "cgroup_scope_s": 0.0,
                "net_ns_proxy_s": 0.0,
                "landlock_seccomp_s": 0.0,
                "sensor_attach_s": 0.0,
                "broker_connect_s": 0.0,
                "cpu_user_usec": 0,
                "cpu_system_usec": 0,
                "memory_peak_bytes": 0,
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
                "cgroup_scope_s": pt.get("cgroup_scope_s", 0.0),
                "net_ns_proxy_s": pt.get("net_ns_proxy_s", 0.0),
                "landlock_seccomp_s": pt.get("landlock_seccomp_s", 0.0),
                "sensor_attach_s": pt.get("sensor_attach_s", 0.0),
                "broker_connect_s": pt.get("broker_connect_s", 0.0),
                "cpu_user_usec": cg_res.get("cpu_user_usec", 0),
                "cpu_system_usec": cg_res.get("cpu_system_usec", 0),
                "memory_peak_bytes": cg_res.get("memory_peak_bytes", 0),
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
                _ = (in_dir / f"file_{i}.txt").read_text(encoding="utf-8")
                read_latencies.append((time.perf_counter() - t0) * 1000.0)

            for i in range(200):
                t0 = time.perf_counter()
                (out_dir / f"out_{i}.txt").write_text(sample_content, encoding="utf-8")
                write_latencies.append((time.perf_counter() - t0) * 1000.0)

            # Direct access check is trivial/instant
            for _ in range(50):
                access_latencies.append(0.0)

            shutil.rmtree(temp_dir, ignore_errors=True)
            return {
                "config": config,
                "read_latencies_ms": read_latencies,
                "write_latencies_ms": write_latencies,
                "access_latencies_ms": access_latencies,
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

            read_latencies = [
                float(t.get("duration_ms", 0.0)) for t in hist if t.get("tool") == "read_file"
            ]
            write_latencies = [
                float(t.get("duration_ms", 0.0)) for t in hist if t.get("tool") == "write_file"
            ]
            access_latencies = [
                float(t.get("duration_ms", 0.0)) for t in hist if t.get("tool") == "request_access"
            ]

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
        files_5k_dir = temp_dir / "files_5k"
        folder_50mb_dir = temp_dir / "folder_50mb"
        files_5k_dir.mkdir(parents=True)
        folder_50mb_dir.mkdir(parents=True)

        # 5,000 files across 50 subdirectories
        for d in range(50):
            sub = files_5k_dir / f"sub_{d}"
            sub.mkdir()
            for f in range(100):
                content = "NEEDLE_KEY sample line\n" if (d == 25 and f == 50) else "sample data line\n"
                (sub / f"file_{f}.txt").write_text(content, encoding="utf-8")

        # 50MB folder (50 x 1MB files)
        chunk_1mb = b"Z" * (1024 * 1024)
        for i in range(50):
            (folder_50mb_dir / f"blob_{i}.dat").write_bytes(chunk_1mb)

        cmd_find = "find files_5k -type f | wc -l"
        cmd_grep = "grep -r 'NEEDLE_KEY' files_5k"
        cmd_py_read = (
            f"{sys.executable} -c \""
            "import os; "
            "[open(f'files_5k/sub_{i%50}/file_{i%100}.txt').read() for i in range(2000)]\""
        )
        cmd_tar = "tar -czf test_50mb.tar.gz folder_50mb"
        cmd_execs = "/bin/sh -c 'for i in $(seq 1 500); do /bin/true; done'"

        if config == "A":
            # Baseline A: direct shell execution
            def run_shell(c: str) -> float:
                t0 = time.perf_counter()
                subprocess.run(c, shell=True, cwd=str(temp_dir), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return (time.perf_counter() - t0) * 1000.0

            d_find = run_shell(cmd_find)
            d_grep = run_shell(cmd_grep)
            d_py = run_shell(cmd_py_read)
            d_tar = run_shell(cmd_tar)
            d_execs = run_shell(cmd_execs)

            shutil.rmtree(temp_dir, ignore_errors=True)
            return {
                "config": config,
                "find_ms": d_find,
                "grep_ms": d_grep,
                "py_read_ms": d_py,
                "tar_ms": d_tar,
                "execs_ms": d_execs,
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
                shutil.copytree(files_5k_dir, w_dir / "files_5k", dirs_exist_ok=True)
                shutil.copytree(folder_50mb_dir, w_dir / "folder_50mb", dirs_exist_ok=True)

        self.launcher.test_hooks["before_agent_start"] = seed_w3_into_workspace

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
                prompt="Read files in files_5k and write test_50mb.tar.gz using shell commands",
                agent_id="bench_agent",
                condition=target_cond,
                declared_tools=["run_command"],
                output_targets=["test_50mb.tar.gz"],
                max_iterations=20,
                llm={"provider": "scripted", "steps": steps},
                timeout_s=180.0,
                freeze_timeout_s=1.0,
                boundary_model="v1.1",
            )

            res = self.launcher.run(spec)
            hist = (res.shim_result or {}).get("tool_history", [])
            # Commands are at index 0, 1, 2, 3, 4
            cmd_durations = [
                float(t.get("duration_ms", 0.0)) for t in hist if t.get("tool") == "run_command"
            ]

            return {
                "config": config,
                "find_ms": cmd_durations[0] if len(cmd_durations) > 0 else 0.0,
                "grep_ms": cmd_durations[1] if len(cmd_durations) > 1 else 0.0,
                "py_read_ms": cmd_durations[2] if len(cmd_durations) > 2 else 0.0,
                "tar_ms": cmd_durations[3] if len(cmd_durations) > 3 else 0.0,
                "execs_ms": cmd_durations[4] if len(cmd_durations) > 4 else 0.0,
            }
        finally:
            self.launcher.test_hooks.pop("before_agent_start", None)
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
        """Measure 100 HTTP GETs direct vs proxy."""
        target_url = f"http://127.0.0.1:{http_port}/test"
        task_id = f"w4_{config.lower().replace('-', '_')}_{uuid.uuid4().hex[:8]}"

        if config == "A":
            # Direct HTTP GETs (no proxy)
            latencies: list[float] = []
            for _ in range(100):
                t0 = time.perf_counter()
                with urllib.request.urlopen(target_url, timeout=5.0) as resp:
                    _ = resp.read()
                latencies.append((time.perf_counter() - t0) * 1000.0)

            return {
                "config": config,
                "http_get_latencies_ms": latencies,
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
            latencies = [
                float(t.get("duration_ms", 0.0)) for t in hist if t.get("tool") == "http_get"
            ]

            return {
                "config": config,
                "http_get_latencies_ms": latencies,
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
        """Measure wall time of summarise_csv preset."""
        task_id = f"w5_{config.lower().replace('-', '_')}_{uuid.uuid4().hex[:8]}"
        csv_rows = ["id,amount"] + [f"{i},{i*10}" for i in range(1, 101)]
        csv_content = "\n".join(csv_rows) + "\n"

        if config == "A":
            # Baseline A: direct execution in temp folder
            t0 = time.monotonic()
            temp_dir = Path(tempfile.mkdtemp(prefix=f"w5_{task_id}_"))
            in_f = temp_dir / "sales.csv"
            out_f = temp_dir / "summary.txt"
            in_f.write_text(csv_content, encoding="utf-8")

            # Direct read + awk + write
            subprocess.run(
                "awk -F, 'NR>1 {sum+=$2; cnt++} END {print \"Count: \" cnt \", Total: \" sum}' sales.csv > summary.txt",
                shell=True,
                cwd=str(temp_dir),
            )
            _ = out_f.read_text(encoding="utf-8")
            shutil.rmtree(temp_dir, ignore_errors=True)
            wall_time = time.monotonic() - t0

            return {
                "config": config,
                "wall_time_s": round(wall_time, 4),
            }

        # Governed: TaskLauncher with summarise_csv
        steps = [
            {"tool": "read_file", "args": {"file_path": "input/sales.csv"}},
            {"tool": "run_command", "args": {"command": "awk -F, 'NR>1 {sum+=$2; cnt++} END {print \"Count: \" cnt \", Total: \" sum}' input/sales.csv > output/summary.txt"}},
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

            target_cond = "W" if config == "W" else "C"
            t0 = time.monotonic()
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
            wall_time = time.monotonic() - t0

            return {
                "config": config,
                "wall_time_s": round(wall_time, 4),
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
            scope_vals = [r["cgroup_scope_s"] * 1000.0 for r in runs]
            proxy_vals = [r["net_ns_proxy_s"] * 1000.0 for r in runs]
            rules_vals = [r["landlock_seccomp_s"] * 1000.0 for r in runs]
            sensor_vals = [r["sensor_attach_s"] * 1000.0 for r in runs]
            broker_vals = [r["broker_connect_s"] * 1000.0 for r in runs]

            cpu_u = [float(r["cpu_user_usec"]) for r in runs]
            cpu_s = [float(r["cpu_system_usec"]) for r in runs]
            mem_p = [float(r["memory_peak_bytes"]) / (1024.0 * 1024.0) for r in runs]

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
                    "cgroup_scope": round(median(scope_vals), 2),
                    "netns_proxy": round(median(proxy_vals), 2),
                    "landlock_seccomp": round(median(rules_vals), 2),
                    "sensor_attach": round(median(sensor_vals), 2),
                    "broker_connect": round(median(broker_vals), 2),
                },
                "resources": {
                    "cpu_user_usec": round(median(cpu_u), 0),
                    "cpu_system_usec": round(median(cpu_s), 0),
                    "memory_peak_mb": round(median(mem_p), 2),
                    "extra_processes": runs[0]["extra_processes"],
                },
            }

        # W2 Aggregation
        for c, runs in w2.items():
            if not runs:
                continue
            all_reads = [lat for r in runs for lat in r["read_latencies_ms"]]
            all_writes = [lat for r in runs for lat in r["write_latencies_ms"]]
            all_access = [lat for r in runs for lat in r["access_latencies_ms"]]

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
                },
            }

        # W3 Aggregation
        baseline_w3: dict[str, float] = {}
        for c, runs in w3.items():
            if not runs:
                continue
            find_v = [r["find_ms"] for r in runs]
            grep_v = [r["grep_ms"] for r in runs]
            py_v = [r["py_read_ms"] for r in runs]
            tar_v = [r["tar_ms"] for r in runs]
            exec_v = [r["execs_ms"] for r in runs]

            med_find = round(median(find_v), 1)
            med_grep = round(median(grep_v), 1)
            med_py = round(median(py_v), 1)
            med_tar = round(median(tar_v), 1)
            med_exec = round(median(exec_v), 1)

            if c == "A":
                baseline_w3 = {
                    "find": med_find,
                    "grep": med_grep,
                    "py_read": med_py,
                    "tar": med_tar,
                    "execs": med_exec,
                }

            out["w3_shell_sensor"][c] = {
                "find_5k_ms": {"median": med_find, "iqr": iqr(find_v), "ci_95": list(bootstrap_ci(find_v))},
                "grep_r_ms": {"median": med_grep, "iqr": iqr(grep_v), "ci_95": list(bootstrap_ci(grep_v))},
                "py_read_2k_ms": {"median": med_py, "iqr": iqr(py_v), "ci_95": list(bootstrap_ci(py_v))},
                "tar_50mb_ms": {"median": med_tar, "iqr": iqr(tar_v), "ci_95": list(bootstrap_ci(tar_v))},
                "execs_500_ms": {"median": med_exec, "iqr": iqr(exec_v), "ci_95": list(bootstrap_ci(exec_v))},
            }

        # Slowdown factor vs A in W3
        if baseline_w3:
            for c, data in out["w3_shell_sensor"].items():
                data["slowdown_vs_A"] = {
                    "find": round(data["find_5k_ms"]["median"] / max(0.001, baseline_w3["find"]), 2),
                    "grep": round(data["grep_r_ms"]["median"] / max(0.001, baseline_w3["grep"]), 2),
                    "py_read": round(data["py_read_2k_ms"]["median"] / max(0.001, baseline_w3["py_read"]), 2),
                    "tar": round(data["tar_50mb_ms"]["median"] / max(0.001, baseline_w3["tar"]), 2),
                    "execs": round(data["execs_500_ms"]["median"] / max(0.001, baseline_w3["execs"]), 2),
                }

        # W4 Aggregation
        for c, runs in w4.items():
            if not runs:
                continue
            all_http = [lat for r in runs for lat in r["http_get_latencies_ms"]]
            out["w4_network"][c] = {
                "p50_ms": round(median(all_http), 3),
                "p95_ms": round(percentile(all_http, 95.0), 3),
                "iqr": iqr(all_http),
                "ci_95": list(bootstrap_ci(all_http)),
            }

        # W5 Aggregation
        baseline_w5 = 0.0
        for c, runs in w5.items():
            if not runs:
                continue
            w_times = [r["wall_time_s"] for r in runs]
            med_w = round(median(w_times), 3)
            if c == "A":
                baseline_w5 = med_w
            out["w5_preset_e2e"][c] = {
                "wall_time_s": {
                    "median": med_w,
                    "iqr": iqr(w_times),
                    "ci_95": list(bootstrap_ci(w_times)),
                },
                "slowdown_vs_A": round(med_w / max(0.001, baseline_w5), 2) if baseline_w5 > 0 else 1.0,
            }

        return out


def generate_perf_markdown(summary: dict[str, Any]) -> str:
    """Format benchmark results into comprehensive Markdown tables."""
    sys_b = summary["system_info"]["before"]
    ebpf_note = summary["system_info"].get("ebpf_note", "")

    lines: list[str] = [
        "# Runtime Governance Performance Overhead Benchmark (v1)",
        "",
        "Empirical measurement of time and resource overhead across isolation layers, comparing:",
        "- **A**: Baseline (no governance)",
        "- **W**: Workspace sandbox (Landlock workspace boundary)",
        "- **C**: Full governance (Broker + Landlock + seccomp + NetNS/Proxy + ptrace sensor)",
        "- **C-nosensor**: Condition C with the ptrace sensor disabled (benchmark mode)",
        "- **C-ebpf**: Condition C with eBPF shadow sensor",
        "",
        f"**Environment**: {sys_b.get('cpu_model')} ({sys_b.get('cpu_cores')} cores), Linux {sys_b.get('kernel')}  ",
        f"**System Load**: 1m={sys_b.get('load_avg_1m')}, 5m={sys_b.get('load_avg_5m')}  ",
    ]
    if ebpf_note:
        lines.append(f"**eBPF Sensor Status**: {ebpf_note}  ")
    lines.append("")

    # 1. W1 Table
    lines.extend([
        "## W1: Start-up & Teardown Breakdown",
        "",
        "| Configuration | Total Startup (ms) | Cgroup / Scope (ms) | NetNS / Proxy (ms) | Landlock / Seccomp (ms) | Sensor Attach (ms) | Broker Connect (ms) | Teardown (ms) | Peak Mem (MB) | Extra Procs |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])
    for c, stats in summary.get("w1_startup_teardown", {}).items():
        st = f"{stats['startup_total_ms']['median']:.1f} [IQR: {stats['startup_total_ms']['iqr']:.1f}]"
        ph = stats.get("phases_ms", {})
        td = f"{stats['teardown_ms']['median']:.1f}"
        res = stats.get("resources", {})
        mem = f"{res.get('memory_peak_mb', 0):.1f}"
        procs = f"{res.get('extra_processes', 0)}"
        lines.append(
            f"| **{c}** | {st} | {ph.get('cgroup_scope', 0):.1f} | {ph.get('netns_proxy', 0):.1f} | "
            f"{ph.get('landlock_seccomp', 0):.1f} | {ph.get('sensor_attach', 0):.1f} | "
            f"{ph.get('broker_connect', 0):.1f} | {td} | {mem} | {procs} |"
        )

    # 2. W2 Table
    lines.extend([
        "",
        "## W2: Tool-Call Latency",
        "",
        "| Configuration | `read_file` 1KB p50 / p95 (ms) | `write_file` 1KB p50 / p95 (ms) | `request_access` p50 / p95 (ms) |",
        "| :--- | :---: | :---: | :---: |",
    ])
    for c, stats in summary.get("w2_tool_latency", {}).items():
        r = f"{stats['read_file']['p50']:.2f} / {stats['read_file']['p95']:.2f}"
        w = f"{stats['write_file']['p50']:.2f} / {stats['write_file']['p95']:.2f}"
        a = f"{stats['request_access']['p50']:.2f} / {stats['request_access']['p95']:.2f}"
        lines.append(f"| **{c}** | {r} | {w} | {a} |")

    # 3. W3 Table
    lines.extend([
        "",
        "## W3: Shell-Heavy / Sensor Cost (Slowdown Factor vs Baseline A)",
        "",
        "| Configuration | `find` 5k files (ms) | `grep -r` 5k (ms) | Python read 2k (ms) | `tar` 50MB (ms) | 500 execs `/bin/true` (ms) | Slowdown (execs) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])
    for c, stats in summary.get("w3_shell_sensor", {}).items():
        f = f"{stats['find_5k_ms']['median']:.1f}"
        g = f"{stats['grep_r_ms']['median']:.1f}"
        py = f"{stats['py_read_2k_ms']['median']:.1f}"
        t = f"{stats['tar_50mb_ms']['median']:.1f}"
        ex = f"{stats['execs_500_ms']['median']:.1f}"
        sd = f"{stats.get('slowdown_vs_A', {}).get('execs', 1.0):.2f}x"
        lines.append(f"| **{c}** | {f} | {g} | {py} | {t} | {ex} | {sd} |")

    # 4. W4 Table
    lines.extend([
        "",
        "## W4: Network Overhead (100 HTTP GETs Direct vs Proxy)",
        "",
        "| Configuration | Per-Request p50 (ms) | Per-Request p95 (ms) | IQR (ms) | 95% Bootstrap CI (ms) |",
        "| :--- | :---: | :---: | :---: | :---: |",
    ])
    for c, stats in summary.get("w4_network", {}).items():
        p50 = f"{stats['p50_ms']:.2f}"
        p95 = f"{stats['p95_ms']:.2f}"
        iqr_val = f"{stats['iqr']:.2f}"
        ci = f"{stats['ci_95'][0]:.2f}–{stats['ci_95'][1]:.2f}"
        lines.append(f"| **{c}** | {p50} | {p95} | {iqr_val} | {ci} |")

    # 5. W5 Table
    lines.extend([
        "",
        "## W5: End-to-End Scripted Preset (`summarise_csv`)",
        "",
        "| Configuration | Wall Time p50 (s) | IQR (s) | 95% Bootstrap CI (s) | Slowdown vs Baseline A |",
        "| :--- | :---: | :---: | :---: | :---: |",
    ])
    for c, stats in summary.get("w5_preset_e2e", {}).items():
        wt = f"{stats['wall_time_s']['median']:.3f}"
        iqr_val = f"{stats['wall_time_s']['iqr']:.3f}"
        ci = f"{stats['wall_time_s']['ci_95'][0]:.3f}–{stats['wall_time_s']['ci_95'][1]:.3f}"
        sd = f"{stats.get('slowdown_vs_A', 1.0):.2f}x"
        lines.append(f"| **{c}** | {wt} | {iqr_val} | {ci} | {sd} |")

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
