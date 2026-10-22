# Milestone 4 OS-Level Enforcement Findings & Security Analysis

## 1. Systemd / D-Bus Confused Deputy Escape & Socket Masking

### Finding (Initial Behavior)
Under Landlock alone, network restrictions (`LANDLOCK_RULE_NET_PORT`) only govern TCP ports. Furthermore, Landlock filesystem hooks (`security_file_open`) intercept file open, create, and truncate operations, but do **not** intercept AF_UNIX pathname `connect()` syscalls. In ABI 6+, Landlock added `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, but this scoping applies strictly to *abstract* sockets (those starting with `\0`), leaving pathname Unix domain sockets unmediated.

As a result, a sandboxed process was able to invoke `/usr/bin/systemd-run --user --pipe cat <decoy_secret>`. The process connected to `/run/user/<uid>/systemd/private` and requested the host user manager (PID 498, running outside the sandbox in `user@1000.service/init.scope`) to execute `cat` on its behalf and pipe back the secret file, completely bypassing Landlock filesystem restrictions.

### Remediation & Architectural Guarantee
1. **Primary Security Guarantee:** Before Landlock initialization, `landlock_enforcer` creates a new mount and user namespace (`CLONE_NEWUSER | CLONE_NEWNS`) and mounts an empty `tmpfs` over `/run/user/<host_uid>`. This physically removes the host session D-Bus socket (`/run/user/<uid>/bus`) and systemd private socket (`/run/user/<uid>/systemd/private`) from the sandbox's mount tree.
2. **Defense-in-Depth:** `/bin/false` is bind-mounted over `/usr/bin/systemd-run`, `/usr/bin/busctl`, and `/usr/bin/dbus-send`. **Note:** These bind-mounts are defense-in-depth only; the fundamental security guarantee rests on the user-session sockets being completely unreachable.
3. **Re-Test:** Direct socket connection to `/run/user/<uid>/bus` fails with `PermissionError` / `FileNotFoundError`, and `systemd-run` fails closed without reading the secret.

---

## 2. Daemon-Handoff Attribution Gap

### Empirical Experiment & Observation
We deployed an experiment where an agent task delegates file-writing work to a background daemon running over a Unix domain socket:
1. The daemon runs in a separate process (`p_daemon.pid`) outside the task's cgroup scope.
2. The agent connects to the daemon socket and sends `DO_WORK`.
3. The daemon performs `open('daemon_out.txt', 'w')`.

### Finding
The OS sensor intercepts the `openat` syscall from `p_daemon.pid` and attributes it to the daemon's cgroup, not the requesting agent task. This confirms an intrinsic limitation of kernel-level sensor attribution: **delegation to pre-existing background daemons or shared services creates an attribution gap at the OS layer unless application-level provenance, socket credential passing (e.g. `SO_PEERCRED`), or IPC tracing is integrated.**

---

## 3. Kernel Mechanism of `/proc/<pid>/environ` Denial

### Active LSMs on Host Kernel (Linux 6.18.54 WSL2)
Inspecting the kernel LSM initialization log (`dmesg`) reveals:
`LSM: initializing lsm=capability,landlock,yama,safesetid,selinux,bpf,ima`
Active security modules: `capability`, `landlock`, `yama`, `safesetid`, `selinux`, `bpf`, `ima`.
Yama ptrace scope is set to `1` (`/proc/sys/kernel/yama/ptrace_scope = 1`). Note that Yama only restricts `PTRACE_MODE_ATTACH` (`security/yama/yama_lsm.c:yama_ptrace_access_check()`), returning 0 for `PTRACE_MODE_READ_FSCREDS`.

### 3-Arm Ablation Experiment
We re-verified the access control against an unconfined same-UID (UID 1000) target holding a dummy secret across three configurations:
1. **Arm 1: User+Mount Namespace with 1000->1000 mapping, NO Landlock**
   - Result: **BLOCKED** with `PermissionError` (`errno 13`).
   - Root Cause: In `kernel/ptrace.c:__ptrace_may_access()`, even though UID check passes, access to process memory/environ across user namespaces requires capability in the target's namespace:
     ```c
     if (!has_ns_capability(__task_cred(target)->user_ns, CAP_SYS_PTRACE))
         return -EPERM;
     ```
     Because the child user namespace explicitly lacks `CAP_SYS_PTRACE` over the parent user namespace, the kernel returns `-EPERM` (`EACCES`/`PermissionError`).

2. **Arm 2: Landlock Only, NO Namespace**
   - Result: **BLOCKED** with `PermissionError` (`errno 13`).
   - Root Cause: Landlock registers an LSM hook for ptrace access checks in `security/landlock/ptrace.c:hook_ptrace_access_check()`:
     ```c
     static int hook_ptrace_access_check(struct task_struct *const target, const unsigned int mode) {
         const struct landlock_ruleset *const dom = landlock_get_current_domain();
         if (!dom) return 0;
         return check_ptrace(dom, target);
     }
     static int check_ptrace(const struct landlock_ruleset *const domain, const struct task_struct *const target) {
         const struct landlock_ruleset *const target_domain = landlock_get_task_domain(target);
         if (!landlock_is_subset(target_domain, domain))
             return -EACCES;
         return 0;
     }
     ```
     Because the unconfined target task is not running within a sub-domain of the caller's Landlock domain, `check_ptrace()` returns `-EACCES`. Reading `/proc/<pid>/environ` routes through `fs/proc/base.c:environ_open()` $\to$ `proc_mem_open(PTRACE_MODE_READ_FSCREDS)` $\to$ `security_ptrace_access_check()`, which Landlock denies with `-EACCES`.

3. **Arm 3: Full Enforcer (User Namespace + 1000->1000 + Landlock Floor)**
   - Result: **BLOCKED** with `PermissionError` (`errno 13`).
   - Root Cause: Defense-in-depth: access is doubly barred by both the User Namespace capability boundary (`kernel/ptrace.c`) AND Landlock's domain subset enforcement (`security/landlock/ptrace.c`). Normal proc files (`stat`, `status`, `cmdline`) remain readable, but privileged memory/environ inspection is completely denied.

---

## 4. Agent Non-Root UID Mapping & Isolation Immutability

To prevent the agent from possessing root privileges within its user namespace:
1. The user namespace `uid_map` maps `host_uid -> host_uid` (e.g. `1000 -> 1000`), ensuring `getuid() == 1000 != 0` and `geteuid() == 1000 != 0`.
2. After initialization and `execvp()`, the process retains no capabilities in the namespace.
3. Attempts by the agent to undo mount isolation (such as calling `umount("/run/user/1000")`) fail immediately with `EPERM` (`Operation not permitted`), guaranteeing that the isolation setup is permanent and immutable.

---

## 5. Host Platform Dependency

The hardened namespace and mount isolation layer relies on the host kernel permitting unprivileged user namespace creation:
- **Requirement:** `kernel.unprivileged_userns_clone = 1` (default on WSL2 Ubuntu, standard upstream Linux).
- **Fail-Closed Behavior:** If user namespaces are disabled by the host sysctl or security policy, `landlock_enforcer` in **ENFORCE** mode aborts task startup immediately with exit code `1` and emits `SECURITY_ERROR: unshare(CLONE_NEWUSER|CLONE_NEWNS) failed`. In **OBSERVE** mode, it records `GOVERNANCE_ISOLATION_LEVEL=landlock_only` and continues.
