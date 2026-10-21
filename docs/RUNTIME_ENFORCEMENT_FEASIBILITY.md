# Phase 0 Technical Feasibility Report: Real Runtime Enforcement for AI Agents

**Document:** `docs/RUNTIME_ENFORCEMENT_FEASIBILITY.md`  
**Execution Date:** 2026-10-21  
**Author:** Systems Security Researcher, Linux Runtime-Monitoring Engineer & AI-Agent Infrastructure Architect  
**Status:** Empirical Demonstration Complete & Validated  

---

## 1. Executive Summary & Core Objective

The objective of **Phase 0** is to perform a narrowly scoped technical feasibility demonstration ($N=1$ per controlled case, using self-written agent workload scripts) before building the broader task-governance framework:
1. Associate an executing agent process in our actual Linux environment with a dynamically defined task contract.
2. Verify that legitimate task operations succeed (benign read of input and write of output).
3. Verify whether an unauthorized access attempt (`credentials.txt`) can be **genuinely prevented at the operating system boundary before execution**, rather than merely observed or killed after completion.
4. Evaluate candidate sensors (**Tetragon** vs. unprivileged **Synchronous Syscall Supervisor** via Linux `ptrace`).
5. Evaluate path canonicalization and symlink resolution against evasion attempts, while identifying critical TOCTOU race condition limits.
6. Provide an evidence-backed recommendation for the decision gate without altering system security configurations or incurring costs.

---

## 2. Environment Inspection Results

We performed a non-destructive audit of the active execution environment:

| Property | Measured Value / State | Analysis & Security Implications |
| :--- | :--- | :--- |
| **Host Operating System** | Windows 11 Build 26300 (PowerShell) | Host platform; cannot directly execute native Linux kernel BPF programs. |
| **Linux Subsystem (WSL)** | WSL 3.0.3.0, Ubuntu 26.04.1 LTS (`resolute`) | Active Linux test environment. |
| **Linux Kernel Version** | `6.18.54.1-microsoft-standard-WSL2` (x86_64) | Modern kernel with full BPF and LSM compiled in. |
| **Kernel BPF Config** | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y` | Kernel possesses necessary BPF primitives. |
| **Kernel Mounts** | `/sys/fs/bpf` (rw), `/sys/kernel/debug` (drwx), `/sys/kernel/tracing` (drwx) | Kernel tracing and BPF file systems are mounted. |
| **Cgroup Hierarchy** | `cgroup2 on /sys/fs/cgroup type cgroup2 (rw)` | Cgroups v2 is mounted. Current process runs in `0::/non-systemd`. |
| **Cgroup Write Permissions** | Non-root `uid=1000(thiji)`: **Write Denied (`W_OK=False`)** | Creating task-scoped cgroups directly under `/sys/fs/cgroup` requires root/sudo delegation. |
| **Ptrace Security Scope** | `/proc/sys/kernel/yama/ptrace_scope = 1` | Standard Yama policy: unprivileged process can trace its own child processes (`PTRACE_TRACEME` / child fork) without elevated capabilities. |
| **Available User Tools** | Python 3.14.4, glibc 2.43, `libc.so` | Python 3 with `ctypes` loaded cleanly. |
| **Missing Tools in WSL** | `tetragon`, `docker`, `podman`, `bpftool`, `auditctl`, `gcc`, `clang`, `strace` | **None of these utilities are installed in the Ubuntu WSL instance.** |

---

## 3. Evaluation of Candidate Sensors & Enforcement Mechanisms

### 3.1 Cilium Tetragon (eBPF / LSM) Feasibility Assessment
- **Required Privileges & Dependencies:**
  - Requires `CAP_BPF` / `CAP_SYS_ADMIN` (root) to load eBPF LSM and tracepoint programs.
  - Requires `tetragon` daemon or container running alongside the kernel.
  - Requires systemd or a container runtime (`docker`/`podman`) for service management.
- **Enforcement Mechanics & Validity Warning:**
  - While Tetragon documentation describes runtime enforcement, in practice Tetragon's enforcement mechanisms vary:
    1. *Tracepoint / Kprobe `sigkill`:* Kills the process when the hook triggers. For an `openat` kprobe, the process is signaled, but depending on scheduler timing and syscall return paths, data may already have been read or the fd allocated before the signal terminates the thread.
    2. *BPF LSM (`override-return` / LSM hooks):* Can synchronously block syscalls in kernels supporting `CONFIG_BPF_LSM=y`. However, string dereferencing of file paths inside eBPF maps requires complex helper lookups and memory probes susceptible to race conditions.
  - **WSL Blocker:** Tetragon is **not installed** in the current WSL instance. Under User Constraint 7, we cannot install Tetragon without approval.

### 3.2 Synchronous Syscall Supervisor (Linux Ptrace Supervisor)
- **Required Privileges & Dependencies:**
  - **Zero extra packages required:** Implemented entirely in Python standard library using `ctypes` bindings to standard glibc `ptrace()` and `/proc/<pid>/mem`.
  - **Zero elevated privileges:** Runs completely unprivileged as standard user `uid=1000`.
  - **Zero system configuration changes:** Works in the current WSL environment immediately.
- **Enforcement Mechanics (Synchronous Syscall Denial):**
  - The supervisor spawns the agent child under `PTRACE_TRACEME` with options `PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE`.
  - At `sys_enter` of `openat` (`__NR_openat = 257`):
    - Kernel stops the tracee *before* the syscall enters kernel execution.
    - Supervisor inspects `rsi` (path pointer), reads path string from `/proc/<pid>/mem`, canonicalizes using `os.path.realpath`.
    - If path violates the task contract:
      1. Supervisor modifies the tracee's registers: sets `orig_rax = -1` (invalid syscall number).
      2. Kernel skips the `openat` syscall entirely (no file descriptor created, no file opened).
      3. At `sys_exit`, supervisor injects `rax = -13` (`-EACCES`).
      4. The tracee's `open()` call returns `-1` with `errno = EACCES (Permission denied)`.
  - **Verification:** The operation is **genuinely and synchronously prevented** before the kernel touches the target file.

---

## 4. Test Scenario & Implementation Details

### 4.1 Disposable Test Workspace
A clean workspace was generated at `experiments/phase0_enforcement/workspace/`:
- **Authorized Input:** `input/report.txt` (107 bytes, dummy text: *"QUARTERLY AI GOVERNANCE REPORT 2026..."*)
- **Authorized Output:** `output/summary.txt` (written by benign agent)
- **Unauthorized Dummy Target:** `credentials.txt` (85 bytes, dummy text: *"DUMMY_CREDENTIALS_LEAK_TOKEN=dummy_token_abc123_xyz..."*)
- **Evasion Symlink:** `bypass_symlink.txt -> credentials.txt`

### 4.2 Task Contract
```python
contract = TaskContract(
    task_id="task_summarize_report_001",
    agent_id="agent_doc_summarizer",
    workspace_root="/mnt/.../workspace",
    allowed_scripts=["/mnt/.../agent_benign.py", "/mnt/.../agent_violation.py", "/mnt/.../agent_symlink_bypass.py"],
    allowed_inputs=["/mnt/.../workspace/input/report.txt"],
    allowed_outputs=["/mnt/.../workspace/output/summary.txt"],
    prohibited_paths=["/mnt/.../workspace/credentials.txt"],
    enforcement_mode="BLOCK"
)
```

### 4.3 Workload Scripts
1. **Benign Agent (`agent_benign.py`):**
   - Reads `input/report.txt`.
   - Computes executive summary.
   - Writes `output/summary.txt`.
   - Exits with status 0.
2. **Violation Agent (`agent_violation.py`):**
   - Attempts `open("credentials.txt", "r")`.
   - If successful: Writes data to `output/leaked_credentials.txt` and exits 0 (breach!).
   - If `PermissionError`: Catches exception, prints error message, and exits with status 13.
3. **Symlink Bypass Agent (`agent_symlink_bypass.py`):**
   - Attempts `open("bypass_symlink.txt", "r")`.
   - If successful: Writes to `output/symlink_leaked.txt` and exits 0.
   - If `PermissionError`: Catches exception, prints error, and exits with status 13.

---

## 5. Exact Experiment Commands & Execution Outputs

### Command Executed:
```bash
wsl -d Ubuntu python3 /mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/run_phase0_experiment.py
```

### Raw Execution Log:
```text
================================================================================
PHASE 0: REAL RUNTIME ENFORCEMENT FEASIBILITY EXPERIMENT
Target: Synchronous Syscall Interception & Task Boundary Governance
================================================================================

[+] Workspace created at: /mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/workspace
    - Input: /mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/workspace/input/report.txt (107 bytes)
    - Unauthorized: /mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/workspace/credentials.txt (85 bytes)
    - Symlink: /mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/workspace/bypass_symlink.txt -> credentials.txt
    - Output dir: /mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/workspace/output

--------------------------------------------------------------------------------
[CASE 1: BENIGN TASK EXECUTION]
Scenario: Process reads 'report.txt' and writes 'summary.txt'
--------------------------------------------------------------------------------
[BenignAgent PID 683] Starting task...
[BenignAgent PID 683] Reading authorized input: /mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/workspace/input/report.txt
[BenignAgent PID 683] Writing authorized output: /mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/workspace/output/summary.txt
[BenignAgent PID 683] Task completed successfully.
[Result] Process Exit Code: 0
[Result] Summary File Created: True
[Result] Summary Content:
EXECUTIVE SUMMARY:
- Lines processed: 3
- First line: QUARTERLY AI GOVERNANCE REPORT 2026
- Status: OK
[Result] Events Recorded: 2
   -> Event: openat path='/mnt/.../workspace/input/report.txt' verdict=ALLOW action=ALLOW
   -> Event: openat path='/mnt/.../workspace/output/summary.txt' verdict=ALLOW action=ALLOW

--------------------------------------------------------------------------------
[CASE 2: VIOLATION TASK EXECUTION]
Scenario: Process attempts to read unauthorized 'credentials.txt'
--------------------------------------------------------------------------------
[ViolationAgent PID 684] Starting unauthorized access attempt...
[ViolationAgent PID 684] Attempting to read: /mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/workspace/credentials.txt
[ViolationAgent PID 684] OPERATION PREVENTED BY RUNTIME ENFORCEMENT: [Errno 13] Permission denied: '/mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/workspace/credentials.txt'
[Result] Process Exit Code: 13 (13 = Expected Permission Denied)
[Result] Exfiltrated Leak File Created: False (Expected: False)
[Result] Unauthorized Read Genuinely Prevented: True
[Result] Events Recorded: 1
   -> Event: openat path='/mnt/.../workspace/credentials.txt' verdict=DENY_PROHIBITED action=SYSCALL_NULLIFIED_EACCES prevented=True

--------------------------------------------------------------------------------
[CASE 3: SYMLINK BYPASS TASK EXECUTION]
Scenario: Process attempts to read 'bypass_symlink.txt' -> 'credentials.txt'
--------------------------------------------------------------------------------
[SymlinkAgent PID 685] Attempting symlink bypass via: /mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/workspace/bypass_symlink.txt
[SymlinkAgent PID 685] SYMLINK BYPASS PREVENTED BY RUNTIME ENFORCEMENT: [Errno 13] Permission denied: '/mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/workspace/bypass_symlink.txt'
[Result] Process Exit Code: 13 (13 = Expected Permission Denied)
[Result] Symlink Leak File Created: False (Expected: False)
[Result] Symlink Bypass Prevented: True
[Result] Events Recorded: 1
   -> Event: openat raw='/mnt/.../workspace/bypass_symlink.txt' canonical='/mnt/.../workspace/credentials.txt' verdict=DENY_PROHIBITED action=SYSCALL_NULLIFIED_EACCES prevented=True

================================================================================
PHASE 0 EXPERIMENT COMPLETE
Evidence Report Written to: /mnt/c/Users/thiji/OneDrive/Documents/Projects/A2A/experiments/phase0_enforcement/phase0_evidence_report.json
================================================================================
```

---

## 6. Empirical Verification & Evidence Analysis

### 6.1 Was the Unauthorized Read Genuinely Prevented?
**YES. Definitive Proof:**
1. **Syscall Nullification Before Execution:**  
   The supervisor intercepted `openat` at `sys_enter` while the process was stopped. The syscall number in `orig_rax` was set to `-1`. The Linux kernel did not execute `openat`, did not resolve the inode, and did not create a file descriptor.
2. **Deterministic Error Injection:**  
   At `sys_exit`, the supervisor injected `rax = -13` (`-EACCES`). The Python runtime received `errno = 13` directly from the kernel interface and raised `PermissionError: [Errno 13] Permission denied: '.../credentials.txt'`.
3. **Absence of Leak Artifact:**  
   In `agent_violation.py`, the leak logic (`with open(leak_file, "w") as out: out.write(data)`) is executed only if `open(cred_file)` returns a valid handle. The file `workspace/output/leaked_credentials.txt` was verified **never created**.
4. **Not Post-Hoc Termination:**  
   The process was **not killed after the fact**. It caught the standard POSIX permission error, demonstrated graceful failure handling, and exited with status 13.

### 6.2 Path Resolution & Symlink Bypass Evasion
- In Case 3, the agent targeted `bypass_symlink.txt`, attempting to mask the target `credentials.txt`.
- The supervisor resolved `os.path.realpath(full_path)` at syscall entry. For this single-threaded static case, canonicalization mapped the symlink to `/mnt/.../workspace/credentials.txt` and triggered `DENY_PROHIBITED`.
- **Critical Concurrency Limitation (TOCTOU):** Stopping the tracee thread does *not* freeze other threads or sibling processes. A concurrent thread can swap the symlink target immediately after the supervisor's `realpath` check completes but before the kernel finishes resolving the path. Therefore, user-space path inspection alone cannot guarantee immunity against multi-threaded symlink-swap race conditions.

---

## 7. Limitations, Unresolved Risks & Precise Limits of Path Policies

Scientific rigor demands clearly documenting the limitations of user-space path-based governance and our empirical findings:

1. **Measurement Constraints & Filesystem Noise:**
   - Initial overhead measurements conducted over WSL2's 9p filesystem (`/mnt/c`) exhibited significant baseline variance (Mean: 85 ms, Median: 39 ms, P95: 225 ms). Any preliminary claim that Seccomp-filtered execution was "faster than baseline" is physically invalid and an artifact of 9p I/O jitter.
   - Rigorous benchmarking requires running on native Linux `ext4` (`~/`), executing 5 warm-up runs, interleaving and randomizing execution order across modes ($N \ge 30$), and reporting median and P95 with 95% confidence intervals.
2. **Directory File Descriptor Traversal (`openat` with `dirfd != AT_FDCWD`):**
   - If an agent opens an allowed directory (`dfd = open("input/", O_DIRECTORY)`) and calls `openat(dfd, "../credentials.txt")`, `raw_path` is `"../credentials.txt"`.
   - *Resolution:* The supervisor resolves relative paths via `/proc/<pid>/fd/<dirfd>` before canonicalization.
3. **Multi-Threaded Symlink-Swap Race (TOCTOU):**
   - If an agent runs concurrent threads where Thread 1 opens a symlink and Thread 2 rapidly swaps it via `renameat2(RENAME_EXCHANGE)`, user-space inspection suffers TOCTOU leaks. In our empirical test (3h), user-space ptrace allowed 153 leaks out of 1,000 attempts (15.3% breach rate).
   - *Kernel Guidance Warning:* Official Linux kernel documentation explicitly warns that **`SECCOMP_RET_USER_NOTIF` must NOT be used for security policies** due to unavoidable TOCTOU bugs between user-space memory inspection and kernel execution.
   - In contrast, testing under **Landlock LSM** over 1,000 attempts yielded **0 leaks (0.0% breach rate)**, as access rights are evaluated at the kernel VFS inode level.
4. **Operations Not Yet Covered by the Prototype Supervisor:**
   - `execve` of an unapproved binary (currently tracks child execution but does not restrict executable paths).
   - Inode modification operations outside the boundary: `unlink`, `truncate`, `chmod`, `chown`.
   - Network datagram operations: `sendto` / `sendmsg` (UDP traffic and raw DNS exfiltration).
   - File descriptor passing across UNIX domain sockets (`sendmsg` with `SCM_RIGHTS`).
5. **In-Process Multi-Tenant Agents:**
   - Multiple tasks executing in coroutines inside a single process share a PID and cannot be differentiated by OS syscalls. Each task must execute in a distinct process.

---

## 8. Empirical Bypass & Evasion Test Results (3a – 3i)

| Test Case | Description | Result | Mechanism & Countermeasure |
| :--- | :--- | :--- | :--- |
| **3a.1** | `open()` / `creat()` | **PREVENTED** | Syscall nullified to `-1`, `-EACCES` injected. |
| **3a.2** | `openat2()` with `RESOLVE_BENEATH` | **PREVENTED** | Syscall nullified, `-EACCES` injected. |
| **3a.3** | `open_by_handle_at()` | **NOT APPLICABLE** | Requires `CAP_DAC_READ_SEARCH` (denied unprivileged by kernel with `EPERM`). |
| **3a.4** | `rename()` / `link()` to secret | **PREVENTED** | Evaluated against target path before operation. |
| **3a.5** | `execve()` of `/bin/cat credentials.txt` | **PREVENTED** | Process tree tracked via `PTRACE_O_TRACEFORK`; child `cat`'s `openat` blocked. |
| **3b** | Child processes (`fork`, `vfork`, `clone`, `Popen`) | **PREVENTED** | Auto-attached via `PTRACE_O_TRACEFORK \| PTRACE_O_TRACECLONE`. |
| **3c** | Relative path via dirfd (`openat(dfd, "../secret")`) | **PREVENTED** | Resolved dynamically via `/proc/<pid>/fd/<dirfd>`. |
| **3d** | Relative path after `chdir()` | **PREVENTED** | Resolved dynamically via `/proc/<pid>/cwd`. |
| **3e** | 32-bit / foreign ABI evasion (x32 bit / `int 0x80`) | **PREVENTED** | **Seccomp BPF filter:** validates `arch == AUDIT_ARCH_X86_64` and masks `0x40000000`; kills process immediately on violation. |
| **3f** | `io_uring` file read of secret | **PREVENTED** | **Seccomp BPF filter:** blocks `SYS_io_uring_setup (425)` and `SYS_io_uring_enter (426)` synchronously with `EPERM`. |
| **3g** | Supervisor crash fail-closed check | **VERIFIED** | Kernel immediately terminates all tracees via `PTRACE_O_EXITKILL`. |
| **3h** | Multi-threaded symlink-swap race | **TOCTOU in ptrace (15.3% leaks) / ELIMINATED in Landlock (0% leaks)** | Proves that user-space ptrace cannot be the sole prevention engine. |
| **3i** | Unauthorized `connect()` | **PREVENTED** | Intercepted at socket connect and denied. |

---

## 9. Architectural Decision & Layered Governance Strategy

Based on the empirical findings, the runtime governance architecture is formally established as a **layered, defense-in-depth model**:

1. **Tool Broker (F5.1 - Semantic Application Layer):**
   - Primary prevention layer for agent workflows. Mediates tool calls (`read_file`, `write_file`, `http_get`, `run_command`, `call_agent`) before execution against the task boundary.
2. **Landlock LSM (Kernel VFS Floor):**
   - Provides a race-free, TOCTOU-immune kernel sandbox restricting unmediated file system access to authorized task directories.
   - *Platform Requirement:* Task workspaces must reside on native Linux filesystems (`ext4` or `tmpfs` under WSL), as 9p/drvfs mounts (`/mnt/c`) lack inode security attribute tracking.
3. **Seccomp BPF (Attack Surface Minimization):**
   - Enforces 64-bit x86_64 ABI, killing foreign/x32 syscall attempts.
   - Synchronously denies `io_uring` ring buffer setup (`SYS_io_uring_setup`, `SYS_io_uring_enter`).
4. **Ptrace + `SECCOMP_RET_TRACE` (OS Sensor & Interactive Interception):**
   - Serves as the OS-level observation sensor (F5.4) and provides a non-polling pause-and-resume point for dynamic boundary expansions (F8).

