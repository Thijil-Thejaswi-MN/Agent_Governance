# eBPF Sensor Shadow Mode Differential Report

- Timestamp: 2026-11-22T02:14:03.602137+00:00
- Kernel: 6.18.58.1-microsoft-standard-WSL2
- Host: DESKTOP-NHOGMI6
- eBPF Loader Version: 1.0.0

## Summary by Concurrency Level

| Concurrency | Tasks | Exact | Basename | PID+Op | Ptrace-Only | eBPF-Only (UDP / bind-listen-accept / clone-exit / library-and-system / workspace / decoy-and-home / proxy-loopback / unexplained) | Dropped | Heartbeat |
|---|---|---|---|---|---|---|---|---|
| 1 | 30 | 1950 | 0 | 0 | 0 | 0 / 9 / 287 / 11505 / 120 / 179 / 4 / 0 | 0 | OK |
| 5 | 30 | 1950 | 0 | 0 | 0 | 0 / 9 / 287 / 11509 / 120 / 179 / 4 / 0 | 0 | OK |
| 10 | 30 | 1863 | 0 | 0 | 0 | 0 / 7 / 245 / 11125 / 99 / 136 / 3 / 0 | 0 | OK |

## eBPF-Only Event Prefix Breakdown

| Prefix / Category | Operation | Count | Reason & File/Line Reference |
|---|---|---|---|
| `/proc` | open | 33206 | sensor.c:154,192,557-558 reads /proc/<pid>/stat and /proc/<pid>/cgroup for each event; sensor.c does not ptrace-trace itself |
| `/usr/lib` | open | 933 | glibc dynamic linker and runtime libraries loaded during binary execution (dl-open/elf startup) |
| `/lib` | open | 0 | glibc dynamic linker and essential shared libraries loaded during execve initialization |
| `/etc` | open | 0 | system configuration files (ld.so.cache, nsswitch.conf, resolv.conf) opened during glibc startup |
| `/dev` | open | 0 | system device nodes (/dev/null, /dev/urandom) opened during process runtime |
| `/sys` | open | 0 | kernel system information (/sys/devices/system/cpu, /sys/kernel) inspected by runtime environment |
| `/tmp` | open | 0 | temporary files created or inspected by shell commands and tool runners |
| `workspace` | open | 339 | launcher.py:420,1015 and tool runner access to workspace directory files and Python bytecode cache |
| `network_udp` | send | 0 | raw_syscall tracepoint captures UDP sendto/sendmsg datagrams bypassing local TCP proxy |
| `network_server` | bind/listen/accept | 25 | raw_syscall tracepoint records socket server lifecycle (bind/listen/accept) not emitted by ptrace |
| `process_lifecycle` | clone/exit | 819 | raw_syscall tracepoint captures clone/fork/exit handled via ptrace event notifications |
| `decoy_and_home` | any | 0 | launcher.py:1020,1418 and eval_world.py decoy verification and snapshot diffs in user home directory |
| `proxy_loopback` | any | 11 | launcher.py:1193 and proxy.py:150 loopback connect to task proxy port |
| `other` | any | 0 | unmatched event outside standard runtime prefixes |

## Ptrace-Only Event Reasons

None. All observed ptrace events were matched by eBPF.

## UDP Probe Analysis

### Concurrency 1 (`probe_udp_send_86b25b48_c1_bcd2a9`)
- Socket Send Result: succeeded (kernel ret=9)
- Classified as UDP in eBPF: YES
- Sensor Exit Code: None
- Scope Termination Reason: frozen_then_killed_after_timeout

### Concurrency 5 (`probe_udp_send_86b25b48_c5_14c588`)
- Socket Send Result: succeeded (kernel ret=9)
- Classified as UDP in eBPF: YES
- Sensor Exit Code: None
- Scope Termination Reason: frozen_then_killed_after_timeout

### Concurrency 10 (`probe_udp_send_86b25b48_c10_728504`)
- Socket Send Result: succeeded (kernel ret=9)
- Classified as UDP in eBPF: YES
- Sensor Exit Code: None
- Scope Termination Reason: frozen_then_killed_after_timeout


## Loose Match Diagnostics (Basename & PID+Op Matches)

### Basename Matches: None

### PID+Op Matches: None

## Invariant Verification
- Zero dropped events observed across all tasks: PASS
- Sensor heartbeats validated: PASS
- Ptrace-only events accounted with valid reasons: PASS
