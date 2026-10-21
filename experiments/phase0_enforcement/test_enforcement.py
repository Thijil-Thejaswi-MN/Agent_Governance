import ctypes
import os
import signal
import sys

PTRACE_TRACEME = 0
PTRACE_KILL = 8
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACESYSGOOD = 1

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

def test_denial():
    print("=== Testing Synchronous Syscall Denial (-EACCES) ===")
    pid = os.fork()
    if pid == 0:
        ptrace(PTRACE_TRACEME, 0, None, None)
        os.kill(os.getpid(), signal.SIGSTOP)
        
        # Child attempts to open credentials.txt
        print("[Child] Attempting open('credentials.txt')...")
        try:
            with open("credentials.txt", "r") as f:
                content = f.read()
                print("[Child] LEAK SUCCESS! Read content:", content)
        except PermissionError as e:
            print("[Child] OPEN FAILED WITH EXPECTED PERMISSION ERROR:", e)
        except Exception as e:
            print("[Child] OPEN FAILED WITH OTHER ERROR:", type(e), e)
        os._exit(0)

    # Parent supervisor
    _, status = os.waitpid(pid, 0)
    ptrace(PTRACE_SETOPTIONS, pid, None, PTRACE_O_TRACESYSGOOD)
    
    in_syscall = False
    regs = UserRegsStruct()
    suppressed_syscall = False

    while True:
        ptrace(PTRACE_SYSCALL, pid, None, None)
        _, status = os.waitpid(pid, 0)
        
        if os.WIFEXITED(status):
            print(f"[Parent] Child exited cleanly with code {os.WEXITSTATUS(status)}")
            break
        if os.WIFSIGNALED(status):
            print(f"[Parent] Child terminated by signal {os.WTERMSIG(status)}")
            break
            
        if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == (signal.SIGTRAP | 0x80):
            ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(regs))
            syscall_nr = regs.orig_rax
            
            if not in_syscall:
                in_syscall = True
                if syscall_nr == 257: # openat
                    path = read_string_from_tracee(pid, regs.rsi)
                    if "credentials.txt" in path:
                        print(f"[Parent] POLICY VIOLATION DETECTED: openat('{path}')")
                        print("[Parent] ACTION: Nullifying syscall (orig_rax = -1) to prevent execution")
                        # Nullify syscall so kernel never executes openat
                        regs.orig_rax = ctypes.c_ulonglong(-1).value
                        ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(regs))
                        suppressed_syscall = True
            else:
                in_syscall = False
                if suppressed_syscall:
                    print("[Parent] ACTION: Injecting -EACCES (-13) into rax on sys_exit")
                    regs.rax = ctypes.c_ulonglong(-13).value # -EACCES
                    ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(regs))
                    suppressed_syscall = False

if __name__ == "__main__":
    test_denial()
