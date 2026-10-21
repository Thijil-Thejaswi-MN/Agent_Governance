import ctypes
import os
import platform
import struct
import sys

def probe():
    print("=== Linux Environment Capability Probe ===")
    print(f"Python: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"Machine: {platform.machine()}")
    print(f"PID: {os.getpid()}, UID: {os.getuid()}, GID: {os.getgid()}")
    
    libc = ctypes.CDLL(None)
    
    # 1. Check ptrace availability
    PTRACE_TRACEME = 0
    PTRACE_SYSCALL = 24
    PTRACE_CONT = 7
    PTRACE_KILL = 8
    ptrace = libc.ptrace
    ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    ptrace.restype = ctypes.c_long
    print("[+] libc.ptrace loaded")

    # 2. Check prctl and PR_SET_NO_NEW_PRIVS
    PR_SET_NO_NEW_PRIVS = 38
    res = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    print(f"[+] prctl(PR_SET_NO_NEW_PRIVS): return={res}")

    # 3. Check seccomp syscall
    __NR_seccomp = 317 # x86_64
    SECCOMP_SET_MODE_FILTER = 1
    # Check if seccomp syscall exists
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    print(f"[+] libc.syscall loaded")

    # 4. Check process_vm_readv
    process_vm_readv = getattr(libc, "process_vm_readv", None)
    print(f"[+] process_vm_readv available: {process_vm_readv is not None}")

    # 5. Check cgroup v2 membership
    if os.path.exists("/proc/self/cgroup"):
        with open("/proc/self/cgroup", "r") as f:
            print(f"[+] /proc/self/cgroup: {f.read().strip()}")

    # 6. Check /sys/fs/cgroup write access
    can_write_cgroup = os.access("/sys/fs/cgroup", os.W_OK)
    print(f"[+] /sys/fs/cgroup writable by uid {os.getuid()}: {can_write_cgroup}")

if __name__ == "__main__":
    probe()
