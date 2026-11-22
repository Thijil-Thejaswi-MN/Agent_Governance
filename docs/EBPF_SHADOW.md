# eBPF Shadow Mode & Differential Evaluation

> For overall Condition C sensor architecture (primary eBPF sensor and fallback ptrace sensor), see [docs/SENSOR.md](file:///home/thiji/Agent_Governance/docs/SENSOR.md).

## Overview

The eBPF shadow evaluation mode runs both sensors in parallel for differential verification.

When shadow mode is enabled (`GOVERNANCE_EBPF_SHADOW=1`), the task launcher communicates with the `ebpf_sensor` loader over a UNIX domain socket, registers the task's cgroup ID, streams eBPF syscall records to a separate log (`<task_id>.ebpf.jsonl`), and logs summary metrics in the receipt (`extra.ebpf_shadow`).

## Watched vs Deferred Syscalls

### Watched Syscalls

The eBPF program attaches to `raw_tp/sys_enter` and `raw_tp/sys_exit` raw tracepoints and pairs events by thread ID (`bpf_get_current_pid_tgid`) to record both arguments and return codes:
- **Process execution**: `execve`, `execveat`
- **File opens & creation**: `openat`, `openat2`, `open`
- **File deletion & directory creation**: `unlinkat`, `unlink`, `renameat2`, `renameat`, `rename`, `mkdirat`, `mkdir`
- **Network operations**: `connect`, `bind`, `listen`, `accept4`, `accept`, `sendto`, `sendmsg` (including UDP datagrams)
- **Lifecycle & thread management**: `clone`, `clone3`, `fork`, `vfork`, `exit_group`, `exit`

### Deferred Syscalls

1. **Reads and writes on pre-existing file descriptors**:
   - `read`, `write`, `readv`, `writev`, `sendfile`, `splice` on descriptors opened prior to sandbox activation are deferred.
   - *Rationale*: Tracing bulk I/O on active descriptors generates high trace volume. Boundary enforcement focuses on boundary-crossing events (process execution, file opens, and socket connections). Bulk descriptor tracing is planned for later phases.
2. **BPF LSM blocking**:
   - BPF LSM enforcement hooks are deferred.
   - *Rationale*: Landlock and seccomp provide kernel-level boundary restriction. The eBPF sensor operates in shadow observation mode only.

## Privilege Setup

The API server and task launcher run without administrative privileges (as an unprivileged user). The `ebpf_sensor` binary requires targeted Linux capabilities to load BPF programs and attach to raw tracepoints.

By attaching via `SEC("raw_tp/sys_enter")` and `SEC("raw_tp/sys_exit")` and reading syscall arguments directly from `struct pt_regs`, the loader requires no tracefs directory access, eliminating `CAP_DAC_READ_SEARCH`. Modern Linux kernels (>= 5.11) account BPF map memory via cgroups, eliminating `CAP_SYS_RESOURCE`.

### Required Capabilities

- `CAP_BPF`: load BPF programs and create BPF maps.
- `CAP_PERFMON`: attach BPF programs to raw tracepoints.

### Setting File Capabilities

Grant file capabilities directly to the compiled loader binary:

```bash
sudo setcap cap_bpf,cap_perfmon+ep demo/security_monitor/app/governance/os_layer/ebpf/ebpf_sensor
```

Verify assigned capabilities:

```bash
getcap demo/security_monitor/app/governance/os_layer/ebpf/ebpf_sensor
```

## Control Socket Architecture & Access Controls

The loader exposes a UNIX domain socket for task cgroup registration:
- **Location**: `~/.ebpf_sensor/ebpf_sensor.sock`, residing in a dedicated directory with mode `0700` owned by the user, outside all task workspaces.
- **Permissions**: Created with mode `0600`.
- **Peer Credentials Verification**: On every incoming connection, the loader inspects `SO_PEERCRED`. Commands (`REGISTER`, `UNREGISTER`, `QUIT`) are rejected with `permission_denied` if:
  1. The peer UID does not match the loader UID; OR
  2. The peer PID resides in or under an actively registered task cgroup.
This prevents sandboxed task processes from unregistering monitoring or terminating the sensor daemon.

## Reference Environment

- **Kernel**: 6.18.58.1-microsoft-standard-WSL2 (x86_64)
- **BTF**: `/sys/kernel/btf/vmlinux` present
- **Kernel Config**: `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_FTRACE_SYSCALLS=y`
- **Toolchain**: `clang` (>= 16), `llvm`, `bpftool`, `libbpf-dev`

## Running Differential Evaluation

The differential evaluation harness runs tasks under Condition C with `GOVERNANCE_EBPF_SHADOW=1`, matching ptrace events against eBPF events by `(pid, op, normalised target, result class)`.

```bash
python3 demo/security_monitor/measure_ebpf_shadow.py --concurrency 1,5,10
```

The script evaluates:
- 9 scripted presets (normal and attack scenarios)
- 16 E1b injection scenarios
- 5 custom probes (UDP send, bind/listen, egress proxy curl, rename/delete, fork/exec)

Outputs are generated at:
- `demo/data/ebpf/shadow_v1.json`
- `demo/data/ebpf/shadow_v1.md`
