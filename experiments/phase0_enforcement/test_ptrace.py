import ctypes
import os
import signal
import sys
import time

PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_TRACEEXEC = (1 << 4)

class UserRegsStruct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

libc = ctypes.CDLL(None)
ptrace = libc.ptrace
ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
ptrace.restype = ctypes.c_long

def read_string_from_tracee(pid, addr, max_len=4096):
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as f:
            f.seek(addr)
            chunk = f.read(max_len)
            idx = chunk.find(b"\x00")
            if idx != -1:
                return chunk[:idx].decode("utf-8", errors="replace")
            return chunk.decode("utf-8", errors="replace")
    except Exception as e:
        return f"<error: {e}>"

def test():
    print("[*] Starting ptrace test...")
    pid = os.fork()
    if pid == 0:
        # Child
        ptrace(PTRACE_TRACEME, 0, None, None)
        os.kill(os.getpid(), signal.SIGSTOP)
        # Try to open a file
        try:
            with open("/tmp/ptrace_test_file.txt", "w") as f:
                f.write("hello")
        except Exception as e:
            print("[Child] Open failed with:", e)
        os._exit(0)
    
    # Parent
    _, status = os.waitpid(pid, 0)
    print(f"[Parent] Child stopped with status: {status}")
    ptrace(PTRACE_SETOPTIONS, pid, None, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC)
    
    in_syscall = False
    openat_count = 0
    regs = UserRegsStruct()

    while True:
        ptrace(PTRACE_SYSCALL, pid, None, None)
        _, status = os.waitpid(pid, 0)
        
        if os.WIFEXITED(status):
            print(f"[Parent] Child exited with code {os.WEXITSTATUS(status)}")
            break
        if os.WIFSIGNALED(status):
            print(f"[Parent] Child killed by signal {os.WTERMSIG(status)}")
            break
        
        if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == (signal.SIGTRAP | 0x80):
            ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(regs))
            syscall_nr = regs.orig_rax
            
            # Syscall entry vs exit alternates
            if not in_syscall:
                in_syscall = True
                if syscall_nr == 257: # __NR_openat
                    path = read_string_from_tracee(pid, regs.rsi)
                    print(f"[Parent] Observed sys_enter openat: path='{path}', flags={regs.rdx}")
                    openat_count += 1
            else:
                in_syscall = False
                if syscall_nr == 257:
                    ret_val = ctypes.c_long(regs.rax).value
                    print(f"[Parent] Observed sys_exit openat: ret={ret_val}")

    print(f"[*] Test finished. Total openat intercepted: {openat_count}")

if __name__ == "__main__":
    test()
