"""OS-level enforcement and monitoring layer for AI Agent tasks (Milestone 4).

Provides:
- ext4 isolated task workspaces
- cgroup v2 task scoping (systemd-run --user --scope)
- Landlock ABI v7 sandboxing (complete filesystem and network scoping)
- Seccomp BPF filters (io_uring and ABI denial)
- OS Sensor (ptrace + SECCOMP_RET_TRACE with cgroup event attribution)
- Unix socket proxy mitigation for Landlock network port limitations
"""
