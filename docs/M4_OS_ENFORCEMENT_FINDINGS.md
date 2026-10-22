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

### Precise Root Cause
We conducted isolated experiments across 4 distinct configurations to pinpoint why a sandboxed task cannot inspect another process's `/proc/<pid>/environ`:
1. **Unconfined same-UID process (same user namespace):** `open('/proc/<target_pid>/environ')` $\to$ **SUCCEEDS** (token found).
2. **User namespace boundary alone (`unshare -U`):** `open('/proc/<target_pid>/environ')` $\to$ **DENIED** (`PermissionError`, `errno 13`).
3. **`PR_SET_NO_NEW_PRIVS` alone (same user namespace):** $\to$ **SUCCEEDS**.

### Mechanism
In Linux (`fs/proc/base.c`), reading `/proc/<pid>/environ` requires `ptrace_may_access(target, PTRACE_MODE_READ_FSCREDS)`. In `kernel/ptrace.c`, `__ptrace_may_access()` enforces:
```c
if (!has_ns_capability(__task_cred(target)->user_ns, CAP_SYS_PTRACE))
    return -EPERM;
```
When a process enters a child user namespace, it possesses capabilities only within that child namespace. It explicitly **lacks `CAP_SYS_PTRACE` in the target's parent user namespace**. Therefore, the denial is governed strictly by the **Linux user namespace capability boundary**, not by Yama ptrace_scope or Landlock filesystem path rules.

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
