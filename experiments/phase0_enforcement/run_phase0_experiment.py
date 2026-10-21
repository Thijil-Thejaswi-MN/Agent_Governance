import json
import os
import sys
import time
from dataclasses import asdict

from runtime_supervisor import TaskContract, TaskRuntimeSupervisor, RuntimeAuditEvent
from setup_workspace import setup_workspace

def run_experiment():
    print("================================================================================")
    print("PHASE 0: REAL RUNTIME ENFORCEMENT FEASIBILITY EXPERIMENT")
    print("Target: Synchronous Syscall Interception & Task Boundary Governance")
    print("================================================================================\n")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    workspace_dir = os.path.join(base_dir, "workspace")
    setup_workspace(workspace_dir)

    contract = TaskContract(
        task_id="task_summarize_report_001",
        agent_id="agent_doc_summarizer",
        workspace_root=workspace_dir,
        allowed_scripts=[
            os.path.join(base_dir, "agent_benign.py"),
            os.path.join(base_dir, "agent_violation.py"),
            os.path.join(base_dir, "agent_symlink_bypass.py"),
        ],
        allowed_inputs=[os.path.join(workspace_dir, "input", "report.txt")],
        allowed_outputs=[os.path.join(workspace_dir, "output", "summary.txt")],
        prohibited_paths=[os.path.join(workspace_dir, "credentials.txt")],
        enforcement_mode="BLOCK",
    )

    results = {
        "metadata": {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "environment": {
                "platform": sys.platform,
                "python_version": sys.version,
                "pid": os.getpid(),
                "uid": os.getuid() if hasattr(os, "getuid") else -1,
            },
            "contract": asdict(contract),
        },
        "cases": {},
    }

    # -------------------------------------------------------------------------
    # CASE 1: BENIGN EXECUTION
    # -------------------------------------------------------------------------
    print("\n--------------------------------------------------------------------------------")
    print("[CASE 1: BENIGN TASK EXECUTION]")
    print("Scenario: Process reads 'report.txt' and writes 'summary.txt'")
    print("--------------------------------------------------------------------------------")
    
    benign_supervisor = TaskRuntimeSupervisor(contract)
    benign_cmd = [sys.executable, "-u", os.path.join(base_dir, "agent_benign.py"), workspace_dir]
    
    t0 = time.perf_counter_ns()
    benign_exit, benign_events = benign_supervisor.run(benign_cmd)
    t1 = time.perf_counter_ns()
    
    summary_file = os.path.join(workspace_dir, "output", "summary.txt")
    summary_exists = os.path.exists(summary_file)
    summary_content = ""
    if summary_exists:
        with open(summary_file, "r") as f:
            summary_content = f.read()

    print(f"[Result] Process Exit Code: {benign_exit}")
    print(f"[Result] Summary File Created: {summary_exists}")
    print(f"[Result] Summary Content:\n{summary_content.strip()}")
    print(f"[Result] Events Recorded: {len(benign_events)}")
    for ev in benign_events:
        print(f"   -> Event: {ev.syscall_name} path='{ev.raw_path}' verdict={ev.policy_verdict} action={ev.enforcement_action}")

    results["cases"]["case1_benign"] = {
        "description": "Authorized read of report.txt and authorized write to summary.txt",
        "exit_code": benign_exit,
        "duration_ms": (t1 - t0) / 1_000_000.0,
        "output_file_created": summary_exists,
        "output_file_size_bytes": len(summary_content.encode("utf-8")),
        "violations_prevented": 0,
        "all_operations_succeeded": (benign_exit == 0 and summary_exists),
        "events": [asdict(e) for e in benign_events],
    }

    # -------------------------------------------------------------------------
    # CASE 2: VIOLATION EXECUTION (ATTEMPTED UNAUTHORIZED READ)
    # -------------------------------------------------------------------------
    print("\n--------------------------------------------------------------------------------")
    print("[CASE 2: VIOLATION TASK EXECUTION]")
    print("Scenario: Process attempts to read unauthorized 'credentials.txt'")
    print("--------------------------------------------------------------------------------")

    leak_file = os.path.join(workspace_dir, "output", "leaked_credentials.txt")
    if os.path.exists(leak_file):
        os.remove(leak_file)

    violation_supervisor = TaskRuntimeSupervisor(contract)
    violation_cmd = [sys.executable, "-u", os.path.join(base_dir, "agent_violation.py"), workspace_dir]

    t0 = time.perf_counter_ns()
    violation_exit, violation_events = violation_supervisor.run(violation_cmd)
    t1 = time.perf_counter_ns()

    leak_exists = os.path.exists(leak_file)
    unauthorized_prevented = False
    for ev in violation_events:
        if "credentials.txt" in ev.raw_path and ev.policy_verdict == "DENY_PROHIBITED" and ev.operation_prevented:
            unauthorized_prevented = True

    print(f"[Result] Process Exit Code: {violation_exit} (13 = Expected Permission Denied)")
    print(f"[Result] Exfiltrated Leak File Created: {leak_exists} (Expected: False)")
    print(f"[Result] Unauthorized Read Genuinely Prevented: {unauthorized_prevented}")
    print(f"[Result] Events Recorded: {len(violation_events)}")
    for ev in violation_events:
        print(f"   -> Event: {ev.syscall_name} path='{ev.raw_path}' verdict={ev.policy_verdict} action={ev.enforcement_action} prevented={ev.operation_prevented}")

    results["cases"]["case2_violation"] = {
        "description": "Attempted unauthorized read of credentials.txt",
        "exit_code": violation_exit,
        "duration_ms": (t1 - t0) / 1_000_000.0,
        "leak_file_created": leak_exists,
        "unauthorized_operation_prevented": unauthorized_prevented,
        "events": [asdict(e) for e in violation_events],
    }

    # -------------------------------------------------------------------------
    # CASE 3: SYMLINK BYPASS ATTEMPT
    # -------------------------------------------------------------------------
    print("\n--------------------------------------------------------------------------------")
    print("[CASE 3: SYMLINK BYPASS TASK EXECUTION]")
    print("Scenario: Process attempts to read 'bypass_symlink.txt' -> 'credentials.txt'")
    print("--------------------------------------------------------------------------------")

    symlink_leak_file = os.path.join(workspace_dir, "output", "symlink_leaked.txt")
    if os.path.exists(symlink_leak_file):
        os.remove(symlink_leak_file)

    symlink_supervisor = TaskRuntimeSupervisor(contract)
    symlink_cmd = [sys.executable, "-u", os.path.join(base_dir, "agent_symlink_bypass.py"), workspace_dir]

    t0 = time.perf_counter_ns()
    symlink_exit, symlink_events = symlink_supervisor.run(symlink_cmd)
    t1 = time.perf_counter_ns()

    symlink_leak_exists = os.path.exists(symlink_leak_file)
    symlink_prevented = False
    for ev in symlink_events:
        if ev.policy_verdict == "DENY_PROHIBITED" and ev.operation_prevented:
            symlink_prevented = True

    print(f"[Result] Process Exit Code: {symlink_exit} (13 = Expected Permission Denied)")
    print(f"[Result] Symlink Leak File Created: {symlink_leak_exists} (Expected: False)")
    print(f"[Result] Symlink Bypass Prevented: {symlink_prevented}")
    print(f"[Result] Events Recorded: {len(symlink_events)}")
    for ev in symlink_events:
        print(f"   -> Event: {ev.syscall_name} raw='{ev.raw_path}' canonical='{ev.canonical_path}' verdict={ev.policy_verdict} action={ev.enforcement_action} prevented={ev.operation_prevented}")

    results["cases"]["case3_symlink_bypass"] = {
        "description": "Attempted symlink bypass to credentials.txt",
        "exit_code": symlink_exit,
        "duration_ms": (t1 - t0) / 1_000_000.0,
        "leak_file_created": symlink_leak_exists,
        "symlink_bypass_prevented": symlink_prevented,
        "events": [asdict(e) for e in symlink_events],
    }

    # Summary
    report_file = os.path.join(base_dir, "phase0_evidence_report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n================================================================================")
    print("PHASE 0 EXPERIMENT COMPLETE")
    print(f"Evidence Report Written to: {report_file}")
    print("================================================================================")

if __name__ == "__main__":
    run_experiment()
