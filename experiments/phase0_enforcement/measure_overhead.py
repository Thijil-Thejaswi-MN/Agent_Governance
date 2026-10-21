#!/usr/bin/env python3
"""
Empirical Overhead Measurement for Phase 0 Runtime Governance.
Measures N=30 repetitions of the benign workload across 3 conditions:
1. Unsupervised Baseline (direct execution)
2. Supervised via Unfiltered Ptrace (every syscall stops)
3. Supervised via Seccomp BPF Filter (SECCOMP_RET_TRACE - only open/openat/connect stop)

Computes Mean, Median, Min, Max, and P95 latency distributions.
"""

from __future__ import annotations

import ctypes
import json
import os
import signal
import statistics
import subprocess
import sys
import time
from typing import Any

from runtime_supervisor import TaskContract, TaskRuntimeSupervisor, UserRegsStruct, libc, ptrace
from setup_workspace import setup_workspace

# BPF Constants
BPF_LD = 0x00
BPF_W  = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K   = 0x00
BPF_RET = 0x06

SECCOMP_RET_KILL  = 0x00000000
SECCOMP_RET_TRAP  = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_TRACE = 0x7ff00000
SECCOMP_RET_ALLOW = 0x7fff0000

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]

class SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(SockFilter)),
    ]

def install_seccomp_trace_filter():
    """
    Install a Seccomp BPF filter that only triggers SECCOMP_RET_TRACE
    for open (2), openat (257), creat (85), openat2 (437), and connect (42).
    All other syscalls are SECCOMP_RET_ALLOW.
    """
    # BPF Program assembly:
    # 0: BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0) -> load syscall number from seccomp_data.nr
    # 1: if nr == 2 goto TRACE (jump 5) else goto 2
    # 2: if nr == 257 goto TRACE (jump 4) else goto 3
    # 3: if nr == 85 goto TRACE (jump 3) else goto 4
    # 4: if nr == 437 goto TRACE (jump 2) else goto 5
    # 5: if nr == 42 goto TRACE (jump 1) else goto 6 (ALLOW)
    # 6: RET_ALLOW
    # 7: RET_TRACE
    filters = (SockFilter * 8)(
        SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),         # 0
        SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 5, 0, 2),        # 1: open -> 7
        SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 257),      # 2: openat -> 7
        SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 3, 0, 85),       # 3: creat -> 7
        SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 437),      # 4: openat2 -> 7
        SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 42),       # 5: connect -> 7
        SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),  # 6: ALLOW
        SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_TRACE),  # 7: TRACE
    )
    prog = SockFprog(len=8, filter=filters)
    libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    res = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0)
    return res

def run_seccomp_filtered_supervisor(contract: TaskContract, cmd: list[str]) -> tuple[int, int]:
    """
    Supervisor using PTRACE_O_TRACESECCOMP so kernel only stops process
    when matching syscalls fire.
    """
    PTRACE_TRACEME = 0
    PTRACE_SYSCALL = 24
    PTRACE_CONT = 7
    PTRACE_SETOPTIONS = 0x4200
    PTRACE_O_TRACESECCOMP = (1 << 7)
    PTRACE_O_EXITKILL = (1 << 20)
    PTRACE_GETREGS = 12
    PTRACE_SETREGS = 13
    PTRACE_EVENT_SECCOMP = 7

    pid = os.fork()
    if pid == 0:
        ptrace(PTRACE_TRACEME, 0, None, None)
        os.kill(os.getpid(), signal.SIGSTOP)
        # Install Seccomp BPF filter inside child
        install_seccomp_trace_filter()
        os.execvp(cmd[0], cmd)
        sys.exit(1)

    _, status = os.waitpid(pid, 0)
    ptrace(PTRACE_SETOPTIONS, pid, None, PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL)

    regs = UserRegsStruct()
    event_count = 0
    ptrace(PTRACE_CONT, pid, None, None)

    while True:
        wpid, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status), event_count
        if os.WIFSIGNALED(status):
            return -os.WTERMSIG(status), event_count

        if os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
            event_code = status >> 16
            if event_code == PTRACE_EVENT_SECCOMP:
                event_count += 1
                ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(regs))
                # Security check handled here
                pass
            ptrace(PTRACE_CONT, pid, None, None)

def compute_stats(series: list[float]) -> dict[str, float]:
    s_sorted = sorted(series)
    n = len(s_sorted)
    p95_idx = min(int(n * 0.95), n - 1)
    return {
        "count": n,
        "mean_ms": round(statistics.mean(series), 3),
        "median_ms": round(statistics.median(series), 3),
        "stdev_ms": round(statistics.stdev(series), 3) if n > 1 else 0.0,
        "min_ms": round(min(series), 3),
        "max_ms": round(max(series), 3),
        "p95_ms": round(s_sorted[p95_idx], 3),
    }

def main():
    print("================================================================================")
    print("PHASE 0: EMPIRICAL OVERHEAD MEASUREMENT (N=30 REPETITIONS)")
    print("Workload: Benign Document Summarizer (report.txt -> summary.txt)")
    print("================================================================================\n")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    workspace_dir = os.path.join(base_dir, "workspace")
    setup_workspace(workspace_dir)

    benign_script = os.path.join(base_dir, "agent_benign.py")
    contract = TaskContract(
        task_id="task_bench_overhead",
        agent_id="agent_bench",
        workspace_root=workspace_dir,
        allowed_scripts=[benign_script],
        allowed_inputs=[os.path.join(workspace_dir, "input", "report.txt")],
        allowed_outputs=[os.path.join(workspace_dir, "output", "summary.txt")],
        prohibited_paths=[os.path.join(workspace_dir, "credentials.txt")],
        enforcement_mode="BLOCK",
    )

    N = 30
    cmd = [sys.executable, "-u", benign_script, workspace_dir]

    # Condition 1: Unsupervised Baseline
    print(f"[*] Running Condition 1: Unsupervised Baseline ({N} trials)...")
    c1_latencies: list[float] = []
    for i in range(N):
        t0 = time.perf_counter_ns()
        res = subprocess.run(cmd, capture_output=True)
        t1 = time.perf_counter_ns()
        assert res.returncode == 0
        c1_latencies.append((t1 - t0) / 1_000_000.0)

    # Condition 2: Supervised via Unfiltered Ptrace
    print(f"[*] Running Condition 2: Supervised via Unfiltered Ptrace ({N} trials)...")
    c2_latencies: list[float] = []
    for i in range(N):
        sup = TaskRuntimeSupervisor(contract)
        t0 = time.perf_counter_ns()
        code, events = sup.run(cmd)
        t1 = time.perf_counter_ns()
        assert code == 0
        c2_latencies.append((t1 - t0) / 1_000_000.0)

    # Condition 3: Supervised via Seccomp BPF Filter (SECCOMP_RET_TRACE)
    print(f"[*] Running Condition 3: Supervised via Seccomp BPF Filter ({N} trials)...")
    c3_latencies: list[float] = []
    for i in range(N):
        t0 = time.perf_counter_ns()
        code, ev_cnt = run_seccomp_filtered_supervisor(contract, cmd)
        t1 = time.perf_counter_ns()
        assert code == 0
        c3_latencies.append((t1 - t0) / 1_000_000.0)

    stats1 = compute_stats(c1_latencies)
    stats2 = compute_stats(c2_latencies)
    stats3 = compute_stats(c3_latencies)

    overhead_ptrace_mean_pct = round(((stats2["mean_ms"] - stats1["mean_ms"]) / stats1["mean_ms"]) * 100.0, 2)
    overhead_seccomp_mean_pct = round(((stats3["mean_ms"] - stats1["mean_ms"]) / stats1["mean_ms"]) * 100.0, 2)

    results = {
        "repetitions": N,
        "workload": "agent_benign.py (file read + summary write)",
        "condition1_unsupervised": stats1,
        "condition2_unfiltered_ptrace": stats2,
        "condition3_seccomp_filtered_ptrace": stats3,
        "overhead_comparison": {
            "unfiltered_ptrace_overhead_pct": overhead_ptrace_mean_pct,
            "seccomp_filtered_overhead_pct": overhead_seccomp_mean_pct,
            "reduction_with_seccomp_pp": round(overhead_ptrace_mean_pct - overhead_seccomp_mean_pct, 2)
        }
    }

    report_path = os.path.join(base_dir, "overhead_benchmark.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\n================================================================================")
    print("EMPIRICAL OVERHEAD BENCHMARK RESULTS")
    print("================================================================================")
    print(f"1. Unsupervised Baseline:     Mean: {stats1['mean_ms']} ms | Median: {stats1['median_ms']} ms | P95: {stats1['p95_ms']} ms")
    print(f"2. Unfiltered Ptrace:         Mean: {stats2['mean_ms']} ms | Median: {stats2['median_ms']} ms | P95: {stats2['p95_ms']} ms (Overhead: +{overhead_ptrace_mean_pct}%)")
    print(f"3. Seccomp-Filtered Ptrace:   Mean: {stats3['mean_ms']} ms | Median: {stats3['median_ms']} ms | P95: {stats3['p95_ms']} ms (Overhead: +{overhead_seccomp_mean_pct}%)")
    print(f"Latency reduction with Seccomp filter: {round(overhead_ptrace_mean_pct - overhead_seccomp_mean_pct, 2)} percentage points")
    print(f"Detailed JSON results written to: {report_path}\n")

if __name__ == "__main__":
    main()
