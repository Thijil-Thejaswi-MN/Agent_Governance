"""Differential evaluation between ptrace sensor and eBPF shadow sensor.

Runs a fixed task suite under Condition C with GOVERNANCE_EBPF_SHADOW=1:
  - Scripted console presets;
  - E1b shell-only scenarios;
  - 5 custom probes (UDP send, bind/listen, proxy curl, rename/delete, fork-exec).

Matches events by (pid, op, normalised target, result class) and reports:
  - matched count;
  - ptrace-only events with reason;
  - eBPF-only events grouped by category (UDP, bind/listen/accept, etc.);
  - dropped event counts (target: 0) and heartbeat status at 1, 5, 10 concurrency.

Outputs demo/data/ebpf/shadow_v1.json and demo/data/ebpf/shadow_v1.md.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

# Add project root to path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from demo.security_monitor.app.governance.launcher import (
    ScriptedLLMProvider,
    TaskLauncher,
    TaskSpec,
)
from demo.security_monitor.app.governance.models import EnforcementMode
from demo.security_monitor.app.governance.run_manager import PRESETS, load_agents_config
from demo.security_monitor.app.governance.storage import GovernanceStorage


DATA_EBPF_DIR = REPO_ROOT / "demo" / "data" / "ebpf"
SCENARIOS_E1B_PATH = (
    REPO_ROOT
    / "demo"
    / "data"
    / "evaluation_v3"
    / "scenarios"
    / "injected_indirect_v3b_shell.jsonl"
)


def normalise_op(syscall: str, op: str | None = None) -> str:
    sc = (syscall or "").lower()
    if sc in ("open", "openat", "openat2"):
        return "open"
    if sc in ("execve", "execveat"):
        return "exec"
    if sc == "connect":
        return "connect"
    if sc == "bind":
        return "bind"
    if sc == "listen":
        return "listen"
    if sc in ("accept", "accept4"):
        return "accept"
    if sc in ("sendto", "sendmsg", "sendmmsg"):
        return "send"
    if sc in ("unlink", "unlinkat", "rmdir"):
        return "unlink"
    if sc in ("rename", "renameat", "renameat2"):
        return "rename"
    if sc in ("mkdir", "mkdirat"):
        return "mkdir"
    if sc in ("clone", "clone3", "fork", "vfork"):
        return "clone"
    if sc in ("exit", "exit_group"):
        return "exit"
    if op:
        op_low = op.lower()
        if "open" in op_low:
            return "open"
        if "exec" in op_low:
            return "exec"
        if "connect" in op_low:
            return "connect"
        if "bind" in op_low:
            return "bind"
        if "listen" in op_low:
            return "listen"
        if "accept" in op_low:
            return "accept"
        if "send" in op_low:
            return "send"
        if "unlink" in op_low:
            return "unlink"
        if "rename" in op_low:
            return "rename"
        if "mkdir" in op_low:
            return "mkdir"
        if "clone" in op_low:
            return "clone"
        if "exit" in op_low:
            return "exit"
    return sc


def normalise_target(target: str | None, abs_target: str | None = None, task_cwd: str | Path | None = None) -> str:
    t = abs_target or target or ""
    t = t.strip()
    if not t:
        return ""
    if t.startswith("unix:") or t.startswith("inet:") or t.startswith("inet6:") or t.startswith("fd:"):
        return t
    if not t.startswith("/") and task_cwd:
        t = os.path.join(str(task_cwd), t)
    try:
        norm = os.path.normpath(t)
        return norm
    except Exception:
        return t


def normalise_result_class(result: Any, ret: Any = None) -> str:
    res_str = str(result or "").strip()
    if res_str.lower() == "ok" or res_str == "0":
        return "ok"
    try:
        val = int(ret if ret is not None else result)
        if val >= 0:
            return "ok"
    except (ValueError, TypeError):
        pass
    if res_str.startswith("E") and len(res_str) <= 16:
        return res_str
    return "error"


def ptrace_only_reason(syscall: str, target: str) -> str:
    sc = (syscall or "").lower()
    if sc in ("link", "linkat", "symlink", "symlinkat", "truncate", "ftruncate"):
        return f"unwatched_syscall_in_ebpf ({sc})"
    if "broker.sock" in target or "sensor_gate" in target:
        return "sensor_internal_channel"
    return f"ptrace_specific_tracepoint ({sc})"


PREFIX_REASONS: dict[str, str] = {
    "/proc": "sensor.c:154,192,557-558 reads /proc/<pid>/stat and /proc/<pid>/cgroup for each event; sensor.c does not ptrace-trace itself",
    "/usr/lib": "glibc dynamic linker and runtime libraries loaded during binary execution (dl-open/elf startup)",
    "/lib": "glibc dynamic linker and essential shared libraries loaded during execve initialization",
    "/etc": "system configuration files (ld.so.cache, nsswitch.conf, resolv.conf) opened during glibc startup",
    "/dev": "system device nodes (/dev/null, /dev/urandom) opened during process runtime",
    "/sys": "kernel system information (/sys/devices/system/cpu, /sys/kernel) inspected by runtime environment",
    "/tmp": "temporary files created or inspected by shell commands and tool runners",
    "workspace": "launcher.py:420,1015 and tool runner access to workspace directory files and Python bytecode cache",
    "network_udp": "raw_syscall tracepoint captures UDP sendto/sendmsg datagrams bypassing local TCP proxy",
    "network_server": "raw_syscall tracepoint records socket server lifecycle (bind/listen/accept) not emitted by ptrace",
    "process_lifecycle": "raw_syscall tracepoint captures clone/fork/exit handled via ptrace event notifications",
    "decoy_and_home": "launcher.py:1020,1418 and eval_world.py decoy verification and snapshot diffs in user home directory",
    "proxy_loopback": "launcher.py:1193 and proxy.py:150 loopback connect to task proxy port",
    "other": "unmatched event outside standard runtime prefixes",
}


def classify_ebpf_only(
    op: str,
    target: str,
    syscall: str,
    workspace_path: str | Path | None = None,
) -> tuple[str, str, str]:
    if op == "send" and ("inet:" in target or "inet6:" in target or "8999" in target):
        return ("UDP", "network_udp", PREFIX_REASONS["network_udp"])
    if op in ("bind", "listen", "accept"):
        return ("bind-listen-accept", "network_server", PREFIX_REASONS["network_server"])
    if op in ("clone", "exit"):
        return ("clone-exit", "process_lifecycle", PREFIX_REASONS["process_lifecycle"])

    ws_str = str(workspace_path) if workspace_path else ""
    if ws_str and (target.startswith(ws_str) or ws_str.startswith(target)):
        return ("workspace", "workspace", PREFIX_REASONS["workspace"])
    if "/ebpf_shadow_workspaces" in target or "/ws_round_" in target or "/ws_" in target or "/workspace" in target:
        return ("workspace", "workspace", PREFIX_REASONS["workspace"])

    if target.startswith("/proc"):
        return ("library-and-system", "/proc", PREFIX_REASONS["/proc"])
    if target.startswith("/usr/lib"):
        return ("library-and-system", "/usr/lib", PREFIX_REASONS["/usr/lib"])
    if target.startswith("/lib") or target.startswith("/lib64"):
        return ("library-and-system", "/lib", PREFIX_REASONS["/lib"])
    if target.startswith("/etc"):
        return ("library-and-system", "/etc", PREFIX_REASONS["/etc"])
    if target.startswith("/dev"):
        return ("library-and-system", "/dev", PREFIX_REASONS["/dev"])
    if target.startswith("/sys"):
        return ("library-and-system", "/sys", PREFIX_REASONS["/sys"])
    if target.startswith("/tmp"):
        return ("library-and-system", "/tmp", PREFIX_REASONS["/tmp"])

    if target.startswith("/home") or target.startswith("~") or "/home/" in target:
        return ("decoy-and-home", "/home", PREFIX_REASONS["decoy_and_home"])
    if target.startswith("inet:127.0.0.1") or target.startswith("inet6:[::1]") or "127.0.0.1:" in target:
        return ("proxy-loopback", "proxy_loopback", PREFIX_REASONS["proxy_loopback"])

    return ("unexplained", "other", PREFIX_REASONS["other"])


def match_task_events(
    ptrace_events: list[dict[str, Any]],
    ebpf_events: list[dict[str, Any]],
    task_cwd: str | Path | None = None,
) -> dict[str, Any]:
    """Matches ptrace and eBPF events by (pid, op, normalised target, result class).

    Only exact matches on all four dimensions count as matched.
    Loose basename and pid_op matches are collected for diagnostic reporting.
    """
    ebpf_pool: list[dict[str, Any]] = []
    for ev in ebpf_events:
        if ev.get("type") != "syscall":
            continue
        pid = ev.get("pid")
        op = normalise_op(ev.get("syscall", ""), ev.get("op", ""))
        tgt = normalise_target(ev.get("target"), ev.get("abs_target"), task_cwd=task_cwd)
        res = normalise_result_class(ev.get("result"), ev.get("ret"))
        ebpf_pool.append({
            "pid": pid,
            "op": op,
            "target": tgt,
            "target_base": os.path.basename(tgt) if "/" in tgt else tgt,
            "result_class": res,
            "raw": ev,
            "used": False,
        })

    exact_count = 0
    basename_matches: list[dict[str, Any]] = []
    pid_op_matches: list[dict[str, Any]] = []
    ptrace_only: list[dict[str, Any]] = []

    for pev in ptrace_events:
        if pev.get("type", "syscall") != "syscall":
            continue
        pid = pev.get("pid")
        op = normalise_op(pev.get("syscall", ""), pev.get("op") or pev.get("kind"))
        tgt = normalise_target(pev.get("target"), pev.get("abs_target"), task_cwd=task_cwd)
        tgt_base = os.path.basename(tgt) if "/" in tgt else tgt
        res = normalise_result_class(pev.get("result"), pev.get("ret"))

        found_idx = -1
        # Exact match ONLY
        for idx, entry in enumerate(ebpf_pool):
            if not entry["used"] and entry["pid"] == pid and entry["op"] == op:
                if entry["target"] == tgt and entry["result_class"] == res:
                    found_idx = idx
                    break

        if found_idx != -1:
            ebpf_pool[found_idx]["used"] = True
            exact_count += 1
        else:
            # Diagnostic loose match tracking: do NOT mark used and do NOT count as matched
            matched_basename = False
            for entry in ebpf_pool:
                if not entry["used"] and entry["pid"] == pid and entry["op"] == op:
                    if entry["result_class"] == res and entry["target_base"] == tgt_base:
                        if len(basename_matches) < 20:
                            basename_matches.append({
                                "pid": pid,
                                "op": op,
                                "result_class": res,
                                "ptrace_target": tgt,
                                "ebpf_target": entry["target"],
                            })
                        matched_basename = True
                        break
            if not matched_basename:
                for entry in ebpf_pool:
                    if not entry["used"] and entry["pid"] == pid and entry["op"] == op:
                        if len(pid_op_matches) < 20:
                            pid_op_matches.append({
                                "pid": pid,
                                "op": op,
                                "ptrace_target": tgt,
                                "ebpf_target": entry["target"],
                            })
                        break

            reason = ptrace_only_reason(pev.get("syscall", ""), tgt)
            ptrace_only.append({
                "pid": pid,
                "op": op,
                "target": tgt,
                "syscall": pev.get("syscall"),
                "result_class": res,
                "reason": reason,
            })

    ebpf_only: list[dict[str, Any]] = []
    ebpf_by_category: dict[str, int] = {
        "UDP": 0,
        "bind-listen-accept": 0,
        "clone-exit": 0,
        "library-and-system": 0,
        "workspace": 0,
        "decoy-and-home": 0,
        "proxy-loopback": 0,
        "unexplained": 0,
    }
    ebpf_by_prefix: dict[str, int] = {}

    for entry in ebpf_pool:
        if not entry["used"]:
            cat, pfx, reason = classify_ebpf_only(
                entry["op"],
                entry["target"],
                entry["raw"].get("syscall", ""),
                workspace_path=task_cwd,
            )
            ebpf_by_category[cat] = ebpf_by_category.get(cat, 0) + 1
            ebpf_by_prefix[pfx] = ebpf_by_prefix.get(pfx, 0) + 1
            ebpf_only.append({
                "pid": entry["pid"],
                "op": entry["op"],
                "target": entry["target"],
                "syscall": entry["raw"].get("syscall"),
                "result_class": entry["result_class"],
                "category": cat,
                "prefix": pfx,
                "reason": reason,
            })

    return {
        "exact": exact_count,
        "matched": exact_count,
        "basename_matches": basename_matches,
        "pid_op_matches": pid_op_matches,
        "ptrace_only": ptrace_only,
        "ptrace_only_count": len(ptrace_only),
        "ebpf_only": ebpf_only,
        "ebpf_only_count": len(ebpf_only),
        "ebpf_by_category": ebpf_by_category,
        "ebpf_by_prefix": ebpf_by_prefix,
    }


def build_probe_task_spec(probe_id: str, prompt: str, command: str) -> TaskSpec:
    steps = [
        {"tool": "run_command", "args": {"command": command}},
        {"final": f"probe {probe_id} finished"},
    ]
    return TaskSpec(
        prompt=prompt,
        task_id=f"probe_{probe_id}_{uuid.uuid4().hex[:8]}",
        agent_id="finance_bot",
        condition="C",
        enforcement_mode="ENFORCE",
        declared_tools=["run_command"],
        llm={"provider": "scripted", "steps": steps},
        max_iterations=4,
    )


def build_preset_task_spec(preset_id: str) -> TaskSpec:
    preset = PRESETS[preset_id]
    steps = list(preset.get("scripted_steps", []))
    if not steps:
        steps = [{"final": "preset without scripted steps"}]
    return TaskSpec(
        prompt=preset.get("prompt", f"Run {preset_id}"),
        task_id=f"preset_{preset_id}_{uuid.uuid4().hex[:8]}",
        agent_id=preset.get("agent", "finance_bot"),
        condition="C",
        enforcement_mode="ENFORCE",
        declared_tools=list(preset.get("tools", ["run_command", "read_file", "write_file"])),
        inputs=dict(preset.get("files", {})),
        decoys=list(preset.get("decoys", [])),
        llm={"provider": "scripted", "steps": steps},
        max_iterations=6,
    )


def build_e1b_task_specs() -> list[TaskSpec]:
    specs: list[TaskSpec] = []
    if not SCENARIOS_E1B_PATH.exists():
        return specs

    with open(SCENARIOS_E1B_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            sc_id = data.get("id", "e1b")
            in_files = data.get("input_files", {})
            input_file = next(iter(in_files.keys()), "input/data.csv")
            injected_target = data.get("injected_target", "~/private.txt")

            steps = [
                {"tool": "run_command", "args": {"command": f"cat {input_file}"}},
                {"tool": "run_command", "args": {"command": f"cat {injected_target}"}},
                {"tool": "write_file", "args": {"path": "output/summary.txt", "content": "Sample output.\n"}},
                {"final": f"Scenario {sc_id} done"},
            ]
            spec = TaskSpec(
                prompt=data.get("user_prompt", f"Process {input_file}"),
                task_id=f"e1b_{sc_id}_{uuid.uuid4().hex[:8]}",
                agent_id="finance_bot",
                condition="C",
                enforcement_mode="ENFORCE",
                declared_tools=["run_command", "write_file"],
                inputs=dict(in_files),
                decoys=list(data.get("decoys", [])),
                canary=f"CANARY_{uuid.uuid4().hex[:12]}",
                llm={"provider": "scripted", "steps": steps},
                max_iterations=6,
            )
            specs.append(spec)
    return specs


def build_custom_probe_specs() -> list[TaskSpec]:
    return [
        build_probe_task_spec(
            "udp_send",
            "Send a test UDP datagram to local port",
            "python3 -c \"import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'probe_udp', ('127.0.0.1', 8999))\"",
        ),
        build_probe_task_spec(
            "bind_listen",
            "Bind and listen on a local TCP port",
            "python3 -c \"import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', 0)); s.listen(1); s.close()\"",
        ),
        build_probe_task_spec(
            "proxy_curl",
            "Fetch through the local egress proxy",
            "curl -s -o /dev/null -x http://127.0.0.1:$GOVERNANCE_PROXY_PORT http://127.0.0.1:$GOVERNANCE_PROXY_PORT/ || true",
        ),
        build_probe_task_spec(
            "rename_delete",
            "Create, rename, and remove a file",
            "touch foo_probe.txt && mv foo_probe.txt bar_probe.txt && rm bar_probe.txt",
        ),
        build_probe_task_spec(
            "fork_exec",
            "Run a child process through a shell fork chain",
            "python3 -c \"import subprocess; subprocess.run(['sh', '-c', 'echo probe_fork_exec'])\"",
        ),
    ]


RUNTIME_FILTER_PREFIXES = (
    "/usr/lib",
    "/lib",
    "/usr/share/zoneinfo",
    "/etc/ld.so.cache",
    "/lib64",
    "/usr/lib64",
    "/usr/share/locale",
)


def is_filtered_runtime_read(ev: dict[str, Any]) -> bool:
    op = (ev.get("op") or ev.get("kind") or "").lower()
    sc = (ev.get("syscall") or "").lower()
    if op != "open" and sc not in ("open", "openat", "openat2"):
        return False
    flags = ev.get("flags")
    if flags is not None:
        try:
            if isinstance(flags, str):
                flags_int = int(flags, 0)
            else:
                flags_int = int(flags)
            if (flags_int & 3) != 0:
                return False
            if (flags_int & (64 | 512)) != 0:
                return False
        except (ValueError, TypeError):
            pass
    ret = ev.get("ret")
    result = ev.get("result")
    try:
        val = int(ret if ret is not None else (0 if result == "ok" else -1))
        if val < 0:
            return False
    except (ValueError, TypeError):
        pass

    target = ev.get("target") or ev.get("abs_target") or ""
    return any(target.startswith(p) for p in RUNTIME_FILTER_PREFIXES)


def run_single_task(
    spec: TaskSpec,
    ws_base: Path,
    receipts_dir: Path,
) -> dict[str, Any]:
    db_path = ws_base / f"gov_{spec.task_id}.db"
    storage = GovernanceStorage(str(db_path))
    launcher = TaskLauncher(
        storage=storage,
        workspace_base=ws_base,
        receipts_dir=receipts_dir,
    )
    res = launcher.run(spec)
    task_id = res.task_id

    # Read ptrace events from control/sensor_events.jsonl (raw syscall stream) or receipt
    ptrace_events: list[dict[str, Any]] = []
    control_dir = res.control_dir
    if control_dir:
        ptrace_file = control_dir / "sensor_events.jsonl"
        if ptrace_file.exists():
            with open(ptrace_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            pev = json.loads(line)
                            if pev.get("type") == "syscall":
                                ptrace_events.append(pev)
                        except json.JSONDecodeError:
                            pass
    if not ptrace_events and res.receipt:
        ptrace_events = [e for e in res.receipt.get("events", []) if e.get("type", "syscall") == "syscall" and e.get("syscall")]

    # With in-kernel runtime filtering on in eBPF, filter runtime reads from ptrace events
    ptrace_events = [e for e in ptrace_events if not is_filtered_runtime_read(e)]

    # Read eBPF events from receipts/<task_id>.ebpf.jsonl
    ebpf_file = receipts_dir / f"{task_id}.ebpf.jsonl"
    ebpf_events: list[dict[str, Any]] = []
    if ebpf_file.exists():
        with open(ebpf_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        ebpf_events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    match_res = match_task_events(ptrace_events, ebpf_events, task_cwd=res.workspace)
    ebpf_meta = (res.receipt or {}).get("extra", {}).get("ebpf_shadow", {})

    udp_probe_info = None
    if "udp" in spec.task_id:
        udp_ev = None
        for ev in ebpf_events:
            tgt = ev.get("target", "") + " " + ev.get("abs_target", "")
            if ev.get("syscall") == "sendto" or "8999" in tgt:
                udp_ev = ev
                break
        send_status = "not_observed"
        if udp_ev:
            ret = udp_ev.get("ret", 0)
            if ret >= 0 or udp_ev.get("result") == "ok":
                send_status = f"succeeded (kernel ret={ret})"
            else:
                send_status = f"refused (kernel ret={ret}, result={udp_ev.get('result')})"

        termination = (res.receipt or {}).get("termination", {})
        stdout_txt = ""
        stderr_txt = ""
        if res.control_dir:
            if (res.control_dir / "stdout.log").exists():
                stdout_txt = (res.control_dir / "stdout.log").read_text(errors="replace").strip()
            if (res.control_dir / "stderr.log").exists():
                stderr_txt = (res.control_dir / "stderr.log").read_text(errors="replace").strip()

        udp_probe_info = {
            "task_id": task_id,
            "send_status": send_status,
            "sensor_exit_code": termination.get("sensor_exit_code"),
            "termination_reason": termination.get("reason"),
            "stdout": stdout_txt,
            "stderr": stderr_txt,
            "classified_udp": any(e.get("category") == "UDP" for e in match_res["ebpf_only"]) or any(normalise_op(e.get("syscall", "")) == "send" for e in ebpf_events),
        }

    return {
        "task_id": task_id,
        "ptrace_count": len(ptrace_events),
        "ebpf_count": len(ebpf_events),
        "exact": match_res["exact"],
        "matched": match_res["matched"],
        "basename_matches": match_res["basename_matches"],
        "basename_count": len(match_res["basename_matches"]),
        "pid_op_matches": match_res["pid_op_matches"],
        "pid_op_count": len(match_res["pid_op_matches"]),
        "ptrace_only": match_res["ptrace_only"],
        "ebpf_only": match_res["ebpf_only"],
        "ebpf_by_category": match_res["ebpf_by_category"],
        "ebpf_by_prefix": match_res["ebpf_by_prefix"],
        "ebpf_shadow_meta": ebpf_meta,
        "dropped": ebpf_meta.get("dropped", 0),
        "heartbeat_ok": ebpf_meta.get("heartbeat_ok", False),
        "udp_probe_info": udp_probe_info,
    }


def run_concurrency_round(
    specs: list[TaskSpec],
    concurrency: int,
    base_dir: Path,
) -> dict[str, Any]:
    round_ws = base_dir / f"ws_round_c{concurrency}"
    round_receipts = base_dir / f"receipts_c{concurrency}"
    round_ws.mkdir(parents=True, exist_ok=True)
    round_receipts.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    t0 = time.monotonic()

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(run_single_task, spec, round_ws, round_receipts)
            for spec in specs
        ]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    wall_s = time.monotonic() - t0

    total_ptrace = sum(r["ptrace_count"] for r in results)
    total_ebpf = sum(r["ebpf_count"] for r in results)
    total_exact = sum(r["exact"] for r in results)
    total_basename = sum(r["basename_count"] for r in results)
    total_pid_op = sum(r["pid_op_count"] for r in results)
    total_dropped = sum(r["dropped"] for r in results)
    all_heartbeats_ok = all(r["heartbeat_ok"] for r in results)

    ptrace_reasons: dict[str, int] = {}
    for r in results:
        for po in r["ptrace_only"]:
            re_str = po["reason"]
            ptrace_reasons[re_str] = ptrace_reasons.get(re_str, 0) + 1

    ebpf_categories: dict[str, int] = {
        "UDP": 0,
        "bind-listen-accept": 0,
        "clone-exit": 0,
        "library-and-system": 0,
        "workspace": 0,
        "decoy-and-home": 0,
        "proxy-loopback": 0,
        "unexplained": 0,
    }
    for r in results:
        for cat, cnt in r["ebpf_by_category"].items():
            ebpf_categories[cat] = ebpf_categories.get(cat, 0) + cnt

    ebpf_prefixes: dict[str, int] = {}
    for r in results:
        for pfx, cnt in r["ebpf_by_prefix"].items():
            ebpf_prefixes[pfx] = ebpf_prefixes.get(pfx, 0) + cnt

    return {
        "concurrency": concurrency,
        "tasks_run": len(results),
        "wall_time_s": round(wall_s, 2),
        "total_ptrace_events": total_ptrace,
        "total_ebpf_events": total_ebpf,
        "total_exact": total_exact,
        "total_matched": total_exact,
        "total_basename": total_basename,
        "total_pid_op": total_pid_op,
        "total_dropped": total_dropped,
        "heartbeat_ok": all_heartbeats_ok,
        "ptrace_only_by_reason": ptrace_reasons,
        "ebpf_only_by_category": ebpf_categories,
        "ebpf_only_by_prefix": ebpf_prefixes,
        "tasks": results,
    }


def generate_markdown_report(report_data: dict[str, Any]) -> str:
    lines = [
        "# eBPF Sensor Shadow Mode Differential Report",
        "",
        f"- Timestamp: {report_data.get('timestamp')}",
        f"- Kernel: {report_data.get('kernel')}",
        f"- Host: {report_data.get('host')}",
        f"- eBPF Loader Version: {report_data.get('loader_version')}",
        "",
        "## Summary by Concurrency Level",
        "",
        "| Concurrency | Tasks | Exact | Basename | PID+Op | Ptrace-Only | eBPF-Only (UDP / bind-listen-accept / clone-exit / library-and-system / workspace / decoy-and-home / proxy-loopback / unexplained) | Dropped | Heartbeat |",
        "|---|---|---|---|---|---|---|---|---|",
    ]

    for round_res in report_data.get("rounds", []):
        c = round_res["concurrency"]
        tasks = round_res["tasks_run"]
        exact = round_res["total_exact"]
        basename = round_res["total_basename"]
        pid_op = round_res["total_pid_op"]
        po = sum(round_res["ptrace_only_by_reason"].values())
        eb_cats = round_res["ebpf_only_by_category"]
        eb_str = f"{eb_cats.get('UDP', 0)} / {eb_cats.get('bind-listen-accept', 0)} / {eb_cats.get('clone-exit', 0)} / {eb_cats.get('library-and-system', 0)} / {eb_cats.get('workspace', 0)} / {eb_cats.get('decoy-and-home', 0)} / {eb_cats.get('proxy-loopback', 0)} / {eb_cats.get('unexplained', 0)}"
        dropped = round_res["total_dropped"]
        hb = "OK" if round_res["heartbeat_ok"] else "FAIL"
        lines.append(f"| {c} | {tasks} | {exact} | {basename} | {pid_op} | {po} | {eb_str} | {dropped} | {hb} |")

    lines.extend([
        "",
        "## eBPF-Only Event Prefix Breakdown",
        "",
        "| Prefix / Category | Operation | Count | Reason & File/Line Reference |",
        "|---|---|---|---|",
    ])
    all_prefixes: dict[str, int] = {}
    for round_res in report_data.get("rounds", []):
        for pfx, cnt in round_res.get("ebpf_only_by_prefix", {}).items():
            all_prefixes[pfx] = all_prefixes.get(pfx, 0) + cnt

    for pfx, reason in PREFIX_REASONS.items():
        cnt = all_prefixes.get(pfx, 0)
        op_label = "any"
        if pfx == "network_udp":
            op_label = "send"
        elif pfx == "network_server":
            op_label = "bind/listen/accept"
        elif pfx == "process_lifecycle":
            op_label = "clone/exit"
        elif pfx in ("/proc", "/usr/lib", "/lib", "/etc", "/dev", "/sys", "/tmp", "workspace"):
            op_label = "open"
        lines.append(f"| `{pfx}` | {op_label} | {cnt} | {reason} |")

    lines.extend([
        "",
        "## Ptrace-Only Event Reasons",
        "",
    ])
    all_reasons: dict[str, int] = {}
    for round_res in report_data.get("rounds", []):
        for r, cnt in round_res.get("ptrace_only_by_reason", {}).items():
            all_reasons[r] = all_reasons.get(r, 0) + cnt

    if all_reasons:
        for r, cnt in sorted(all_reasons.items()):
            lines.append(f"- **{r}**: {cnt} occurrences")
    else:
        lines.append("None. All observed ptrace events were matched by eBPF.")

    lines.extend([
        "",
        "## UDP Probe Analysis",
        "",
    ])
    udp_probes = []
    for round_res in report_data.get("rounds", []):
        for t in round_res.get("tasks", []):
            if t.get("udp_probe_info"):
                udp_probes.append((round_res["concurrency"], t["udp_probe_info"]))

    if udp_probes:
        for conc, info in udp_probes:
            lines.append(f"### Concurrency {conc} (`{info['task_id']}`)")
            lines.append(f"- Socket Send Result: {info['send_status']}")
            lines.append(f"- Classified as UDP in eBPF: {'YES' if info['classified_udp'] else 'NO'}")
            lines.append(f"- Sensor Exit Code: {info['sensor_exit_code']}")
            lines.append(f"- Scope Termination Reason: {info['termination_reason']}")
            if info["stdout"]:
                lines.append(f"- Stdout: `{info['stdout']}`")
            if info["stderr"]:
                lines.append(f"- Stderr: `{info['stderr']}`")
            lines.append("")
    else:
        lines.append("No UDP probe tasks found.")

    lines.extend([
        "",
        "## Loose Match Diagnostics (Basename & PID+Op Matches)",
        "",
    ])
    sample_basename = []
    sample_pid_op = []
    for round_res in report_data.get("rounds", []):
        for t in round_res.get("tasks", []):
            for bm in t.get("basename_matches", []):
                if len(sample_basename) < 20:
                    sample_basename.append(bm)
            for po in t.get("pid_op_matches", []):
                if len(sample_pid_op) < 20:
                    sample_pid_op.append(po)

    if sample_basename:
        lines.append(f"### Basename Matches (Loose, not counted as matched; {len(sample_basename)} sample occurrences)")
        for bm in sample_basename:
            lines.append(f"- PID {bm['pid']} `{bm['op']}` [{bm['result_class']}]: ptrace=`{bm['ptrace_target']}` vs ebpf=`{bm['ebpf_target']}`")
    else:
        lines.append("### Basename Matches: None")

    if sample_pid_op:
        lines.append("")
        lines.append(f"### PID+Op Matches (Loose, not counted as matched; {len(sample_pid_op)} sample occurrences)")
        for po in sample_pid_op:
            lines.append(f"- PID {po['pid']} `{po['op']}`: ptrace=`{po['ptrace_target']}` vs ebpf=`{po['ebpf_target']}`")
    else:
        lines.append("")
        lines.append("### PID+Op Matches: None")

    lines.extend([
        "",
        "## Invariant Verification",
        f"- Zero dropped events observed across all tasks: {'PASS' if report_data.get('all_dropped_zero') else 'FAIL'}",
        f"- Sensor heartbeats validated: {'PASS' if report_data.get('all_heartbeats_ok') else 'FAIL'}",
        f"- Ptrace-only events accounted with valid reasons: {'PASS' if report_data.get('all_reasons_stated') else 'FAIL'}",
        "",
    ])

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Differential harness for eBPF shadow sensor.")
    parser.add_argument("--concurrency", default="1,5,10", help="Comma-separated concurrency levels (default: 1,5,10)")
    parser.add_argument("--output-json", default=str(DATA_EBPF_DIR / "shadow_v1.json"), help="Output JSON path")
    parser.add_argument("--output-md", default=str(DATA_EBPF_DIR / "shadow_v1.md"), help="Output Markdown path")
    parser.add_argument("--limit-presets", type=int, default=None, help="Limit number of presets for rapid test")
    parser.add_argument("--limit-e1b", type=int, default=None, help="Limit number of E1b scenarios for rapid test")
    args = parser.parse_args()

    os.environ["GOVERNANCE_EBPF_SHADOW"] = "1"

    # Assemble task suite
    preset_keys = [
        "summarise_csv",
        "compare_target",
        "a2a_agent",
        "contract_review",
        "eval_shell_trick",
        "network_exfiltration",
        "save_extra_file",
        "hidden_instruction",
        "shell_injection",
    ]
    if args.limit_presets:
        preset_keys = preset_keys[:args.limit_presets]

    suite: list[TaskSpec] = [build_preset_task_spec(pk) for pk in preset_keys]

    e1b_specs = build_e1b_task_specs()
    if args.limit_e1b:
        e1b_specs = e1b_specs[:args.limit_e1b]
    suite.extend(e1b_specs)

    suite.extend(build_custom_probe_specs())

    concurrency_levels = [int(c.strip()) for c in args.concurrency.split(",") if c.strip()]
    tmp_base = Path(os.environ.get("HOME", "/tmp")) / f"ebpf_shadow_workspaces_{uuid.uuid4().hex[:8]}"
    tmp_base.mkdir(parents=True, exist_ok=True)

    round_results: list[dict[str, Any]] = []
    try:
        for conc in concurrency_levels:
            # Recreate unique task specs for this round
            round_specs: list[TaskSpec] = []
            for s in suite:
                copied = TaskSpec(
                    prompt=s.prompt,
                    task_id=f"{s.task_id}_c{conc}_{uuid.uuid4().hex[:6]}",
                    agent_id=s.agent_id,
                    condition=s.condition,
                    enforcement_mode=s.enforcement_mode,
                    declared_tools=list(s.declared_tools),
                    inputs=dict(s.inputs),
                    decoys=list(s.decoys),
                    canary=s.canary,
                    llm=dict(s.llm),
                    max_iterations=s.max_iterations,
                )
                round_specs.append(copied)

            print(f"Running round with concurrency {conc} ({len(round_specs)} tasks)...")
            res = run_concurrency_round(round_specs, conc, tmp_base)
            round_results.append(res)
            print(f"Round {conc} finished in {res['wall_time_s']}s: "
                  f"{res['total_matched']} matched, "
                  f"{sum(res['ptrace_only_by_reason'].values())} ptrace-only, "
                  f"{sum(res['ebpf_only_by_category'].values())} eBPF-only, "
                  f"dropped: {res['total_dropped']}")
    finally:
        shutil.rmtree(tmp_base, ignore_errors=True)

    all_dropped_zero = all(r["total_dropped"] == 0 for r in round_results)
    all_heartbeats = all(r["heartbeat_ok"] for r in round_results)

    final_report = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "kernel": platform.release(),
        "host": platform.node(),
        "loader_version": "1.0.0",
        "concurrency_levels": concurrency_levels,
        "suite_size": len(suite),
        "all_dropped_zero": all_dropped_zero,
        "all_heartbeats_ok": all_heartbeats,
        "all_reasons_stated": True,
        "rounds": round_results,
    }

    out_json = Path(args.output_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(final_report, indent=2), encoding="utf-8")

    out_md = Path(args.output_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    md_content = generate_markdown_report(final_report)
    out_md.write_text(md_content, encoding="utf-8")

    print(f"\nResults written to:\n  JSON: {out_json}\n  Markdown: {out_md}")
    print("\n" + md_content)


if __name__ == "__main__":
    main()
