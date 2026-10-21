import os, sys, time, ctypes, signal
libc = ctypes.CDLL(None)
ptrace = libc.ptrace
ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

child_pid = os.fork()
if child_pid == 0:
    ptrace(0, 0, None, None) # PTRACE_TRACEME
    os.kill(os.getpid(), signal.SIGSTOP)
    time.sleep(10)
    sys.exit(0)

# Parent supervisor
_, status = os.waitpid(child_pid, 0)
PTRACE_O_EXITKILL = (1 << 20)
ptrace(0x4200, child_pid, None, PTRACE_O_EXITKILL)

# Announce PID and flush stdout
print(f"CHILD_PID={child_pid}", flush=True)
sys.stdout.flush()

# Keep parent alive briefly
time.sleep(10)
