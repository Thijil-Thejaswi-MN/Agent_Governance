# Operating System Sensor Architecture

## Overview

Condition C uses kernel-level observation to monitor process execution, filesystem access, and network connections. The primary sensor implementation uses eBPF (`ebpf_sensor`), with user-space ptrace acting as a fallback when eBPF is unavailable.

eBPF serves as the primary sensor for three architectural reasons:
1. **Low overhead and latency**: Tracing occurs directly at kernel tracepoints (`raw_tp/sys_enter` and `raw_tp/sys_exit`) without process stop-and-wait traps (`PTRACE_SYSCALL`).
2. **Host-level cgroup tracking**: eBPF attaches to kernel tracepoints host-wide and filters events using the task's 64-bit cgroup ID (`bpf_get_current_cgroup_id`). All processes spawned within the systemd scope are tracked automatically across forks and execs.
3. **Observation of raw network and lifecycle events**: eBPF observes socket creation (`bind`, `listen`, `accept`) and raw UDP datagrams (`sendto`) prior to proxy routing, as well as process lifecycle changes (`clone`, `exit`).

---

## Sensor Selection

The sensor implementation is selected via the environment variable `GOVERNANCE_SENSOR`:

- `auto` (default): Uses eBPF if the loader is running and healthy (active heartbeat within the last 2 seconds and zero dropped events). If unhealthy or absent, falls back to the ptrace sensor.
- `ebpf`: Enforces eBPF observation. If the loader is not running or is unhealthy, the launcher refuses to start the task and raises a `RuntimeError`. A governed task is never launched without active sensor observation.
- `ptrace`: Forces user-space ptrace observation.

The task receipt records the chosen sensor in the `sensor` block:
- `sensor.kind`: `"ebpf"` or `"ptrace"`
- `sensor.reason`: Explanation for the selection (e.g., `"auto: ebpf_sensor running and healthy"` or `"auto fallback: ebpf_sensor unavailable"`).
- `sensor.filtered_runtime_reads`: Total count of read-only runtime opens dropped in kernel by prefix filters.

The web console surfaces this information on the run page with dedicated status badges (`eBPF sensor` / `ptrace sensor`).

---

## Fail-Closed Watchdog

When running with the eBPF sensor, observation fails closed to prevent unmonitored execution. The task is immediately frozen (`_freeze`) under any of the following conditions:

1. **Lost Heartbeat**: The loader emits a periodic heartbeat every second. If no heartbeat is received for more than 2.0 seconds, the watchdog triggers a task freeze with reason `sensor_unhealthy`.
2. **Event Drops**: The loader tracks kernel ring buffer drops (`BPF_MAP_TYPE_RINGBUF`). If drops are detected for the task's cgroup, the task is frozen with reason `sensor_events_dropped`.
3. **Loader Process Termination**: If the loader process exits or disconnects the control socket unexpectedly while a task is running, the task is frozen with reason `sensor_unhealthy`.

---

## Descriptor Hygiene by Construction

To prevent inheritance of file descriptors opened prior to sandbox activation, the agent runtime shim (`agent_shim.py`) sanitizes its descriptor table during startup:

1. Token and task definition descriptors are read into memory and closed.
2. The communication socket to the tool broker is duplicated onto descriptor 3 (`os.dup2(bsock.fileno(), 3)`).
3. All descriptors above 3 are closed via `os.closerange(4, 65536)`.
4. The shim inspects `/proc/self/fd` to confirm that only standard descriptors (0: stdin, 1: stdout, 2: stderr) and the broker socket (3) remain open before executing agent code.

This design ensures no extraneous descriptors predate task monitoring.

---

## In-Kernel Runtime Filtering

To minimize ring buffer traffic and CPU consumption, the eBPF program includes an in-kernel prefix filter for standard runtime libraries:

- **Filter Prefixes**: `/usr/lib`, `/lib`, `/usr/share/zoneinfo`, `/etc/ld.so.cache`, `/lib64`, `/usr/lib64`, `/usr/share/locale`.
- **Filtering Rules**:
  - Only successful (`ret >= 0`) read-only opens (`O_RDONLY` without `O_CREAT`, `O_TRUNC`, or write flags) targeting paths starting with a filter prefix are dropped in kernel.
  - Failed opens (e.g., `ENOENT` or `EACCES`) are never dropped.
  - Write or creation attempts (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`) are never dropped.
  - Modification, execution, or network operations (`execve`, `unlink`, `rename`, `connect`, `bind`, `sendto`) are never dropped regardless of path.
- **Accounting**: In-kernel dropped reads are counted per cgroup in the `cgroup_filtered_reads` BPF hash map and reported to user space on session termination. The receipt records the total count in `sensor.filtered_runtime_reads`.

---

## Capabilities and Host Setup

The sensor loader executes as an unprivileged process. After building with `make`, restrict permissions and set file capabilities:

```bash
chmod 0750 demo/security_monitor/app/governance/os_layer/ebpf/ebpf_sensor
sudo setcap cap_bpf,cap_perfmon+ep demo/security_monitor/app/governance/os_layer/ebpf/ebpf_sensor
```

The binary should be owned by the user (or a dedicated operator group, e.g. `chgrp <group> ebpf_sensor`) with mode `0750` so only authorized accounts execute it.

- `CAP_BPF`: Grants permission to load BPF bytecode and allocate BPF maps.
- `CAP_PERFMON`: Grants permission to attach BPF programs to raw tracepoints.

No superuser execution or root privileges are used during task runs, testing, or API server operation.
