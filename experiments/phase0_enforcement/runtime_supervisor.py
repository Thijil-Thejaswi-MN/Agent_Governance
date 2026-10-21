from __future__ import annotations

import ctypes
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any

# x86_64 Linux ptrace constants
PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200

# Options
PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_TRACEFORK = (1 << 1)
PTRACE_O_TRACEVFORK = (1 << 2)
PTRACE_O_TRACECLONE = (1 << 3)
PTRACE_O_TRACEEXEC = (1 << 4)
PTRACE_O_TRACEEXIT = (1 << 6)

# x86_64 System Calls
SYS_OPEN = 2
SYS_OPENAT = 257
SYS_EXECVE = 59
SYS_CLONE = 56
SYS_FORK = 57
SYS_VFORK = 58

# Open flags
O_ACCMODE = 0o003
O_RDONLY  = 0o000
O_WRONLY  = 0o001
O_RDWR    = 0o002
O_CREAT   = 0o100
O_DIRECTORY = 0o200000

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

@dataclass
class TaskContract:
    task_id: str
    agent_id: str
    workspace_root: str
    allowed_scripts: list[str] = field(default_factory=list)
    allowed_inputs: list[str] = field(default_factory=list)
    allowed_outputs: list[str] = field(default_factory=list)
    prohibited_paths: list[str] = field(default_factory=list)
    enforcement_mode: str = "BLOCK" # "BLOCK", "AUDIT"

@dataclass
class RuntimeAuditEvent:
    event_id: str
    timestamp_ns: int
    task_id: str
    agent_id: str
    pid: int
    syscall_name: str
    raw_path: str
    canonical_path: str
    is_write: bool
    policy_verdict: str # "ALLOW", "DENY_PROHIBITED", "DENY_UNAUTHORIZED_WRITE", "DENY_UNAUTHORIZED_READ"
    enforcement_action: str # "ALLOW", "SYSCALL_NULLIFIED_EACCES", "PROCESS_KILLED"
    operation_prevented: bool

def read_string_from_pid(pid: int, addr: int, max_len: int = 4096) -> str:
    if addr == 0:
        return ""
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as f:
            f.seek(addr)
            chunk = f.read(max_len)
            null_idx = chunk.find(b"\x00")
            if null_idx != -1:
                return chunk[:null_idx].decode("utf-8", errors="replace")
            return chunk.decode("utf-8", errors="replace")
    except Exception as e:
        return f"<read_error: {e}>"

class TaskRuntimeSupervisor:
    def __init__(self, contract: TaskContract):
        self.contract = contract
        self.canonical_workspace = os.path.realpath(os.path.abspath(contract.workspace_root))
        self.canonical_scripts = [os.path.realpath(os.path.abspath(p)) for p in contract.allowed_scripts]
        self.canonical_inputs = [os.path.realpath(os.path.abspath(p)) for p in contract.allowed_inputs]
        self.canonical_outputs = [os.path.realpath(os.path.abspath(p)) for p in contract.allowed_outputs]
        self.canonical_prohibited = [os.path.realpath(os.path.abspath(p)) for p in contract.prohibited_paths]
        self.events: list[RuntimeAuditEvent] = []
        self._event_counter = 0

    def evaluate_path_access(self, pid: int, raw_path: str, flags: int) -> tuple[str, str, bool]:
        """
        Evaluate if accessing raw_path is authorized under the task contract.
        Returns (verdict, enforcement_action, operation_prevented).
        """
        if not raw_path or raw_path.startswith("<"):
            return "ALLOW", "ALLOW", False

        # Resolve relative to child cwd if relative
        if not os.path.isabs(raw_path):
            try:
                child_cwd = os.readlink(f"/proc/{pid}/cwd")
                full_path = os.path.join(child_cwd, raw_path)
            except Exception:
                full_path = os.path.join(self.canonical_workspace, raw_path)
        else:
            full_path = raw_path

        canonical = os.path.realpath(os.path.abspath(full_path))
        is_write = bool(flags & (O_WRONLY | O_RDWR | O_CREAT))

        # Check system / interpreter library paths (Python runtime, glibc, etc.)
        system_prefixes = ("/usr", "/lib", "/lib64", "/etc", "/dev", "/proc", "/sys", "/tmp")
        if canonical.startswith(system_prefixes) and not canonical.startswith(self.canonical_workspace):
            # System read is permitted for standard interpreter operations
            if not is_write:
                return "ALLOW", "ALLOW", False
            # Writing to system files is forbidden
            return "DENY_SYSTEM_WRITE", ("SYSCALL_NULLIFIED_EACCES" if self.contract.enforcement_mode == "BLOCK" else "AUDIT"), (self.contract.enforcement_mode == "BLOCK")

        # Allow execution / loading of explicitly authorized agent scripts
        if not is_write and canonical in self.canonical_scripts:
            return "ALLOW", "ALLOW", False

        # Check if canonical path matches prohibited targets
        for prohibited in self.canonical_prohibited:
            if canonical == prohibited or canonical.startswith(prohibited + os.sep):
                action = "SYSCALL_NULLIFIED_EACCES" if self.contract.enforcement_mode == "BLOCK" else "AUDIT"
                return "DENY_PROHIBITED", action, (self.contract.enforcement_mode == "BLOCK")

        # Check workspace operations
        if canonical.startswith(self.canonical_workspace):
            if is_write:
                # Check if writing to allowed output file or output directory
                allowed = False
                for out in self.canonical_outputs:
                    if canonical == out or (os.path.isdir(out) and canonical.startswith(out + os.sep)):
                        allowed = True
                        break
                    # Also allow parent directory of output file
                    if os.path.dirname(canonical) == os.path.dirname(out):
                        allowed = True
                        break
                if allowed:
                    return "ALLOW", "ALLOW", False
                else:
                    action = "SYSCALL_NULLIFIED_EACCES" if self.contract.enforcement_mode == "BLOCK" else "AUDIT"
                    return "DENY_UNAUTHORIZED_WRITE", action, (self.contract.enforcement_mode == "BLOCK")
            else:
                # Read operation: must match allowed input or be a safe workspace metadata check
                allowed = False
                for inp in self.canonical_inputs:
                    if canonical == inp or (os.path.isdir(inp) and canonical.startswith(inp + os.sep)):
                        allowed = True
                        break
                # Also allow reading the workspace directory itself or output directory
                if canonical == self.canonical_workspace or canonical == os.path.join(self.canonical_workspace, "output"):
                    allowed = True
                
                if allowed:
                    return "ALLOW", "ALLOW", False
                else:
                    action = "SYSCALL_NULLIFIED_EACCES" if self.contract.enforcement_mode == "BLOCK" else "AUDIT"
                    return "DENY_UNAUTHORIZED_READ", action, (self.contract.enforcement_mode == "BLOCK")

        # Outside workspace read/write
        action = "SYSCALL_NULLIFIED_EACCES" if self.contract.enforcement_mode == "BLOCK" else "AUDIT"
        return "DENY_OUTSIDE_WORKSPACE", action, (self.contract.enforcement_mode == "BLOCK")

    def run(self, cmd: list[str]) -> tuple[int, list[RuntimeAuditEvent]]:
        """
        Execute command under synchronous ptrace supervision.
        Returns (exit_code, audit_events).
        """
        t0 = time.perf_counter_ns()
        pid = os.fork()
        if pid == 0:
            # In child process: request tracing and pause until supervisor attaches
            ptrace(PTRACE_TRACEME, 0, None, None)
            os.kill(os.getpid(), signal.SIGSTOP)
            # Execute agent command
            os.execvp(cmd[0], cmd)
            sys.exit(1)

        # In supervisor: wait for child initial SIGSTOP
        _, status = os.waitpid(pid, 0)
        options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE
        ptrace(PTRACE_SETOPTIONS, pid, None, options)

        regs = UserRegsStruct()
        in_syscall = False
        suppressed_syscall = False
        last_verdict = "ALLOW"
        last_action = "ALLOW"
        last_prevented = False
        last_raw_path = ""
        last_canonical_path = ""
        last_is_write = False

        while True:
            ptrace(PTRACE_SYSCALL, pid, None, None)
            _, status = os.waitpid(pid, 0)

            if os.WIFEXITED(status):
                exit_code = os.WEXITSTATUS(status)
                break
            if os.WIFSIGNALED(status):
                exit_code = -os.WTERMSIG(status)
                break

            if os.WIFSTOPPED(status):
                sig = os.WSTOPSIG(status)
                if sig == (signal.SIGTRAP | 0x80):
                    # Syscall stop
                    ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(regs))
                    syscall_nr = regs.orig_rax

                    if not in_syscall:
                        # Syscall entry
                        in_syscall = True
                        if syscall_nr in (SYS_OPEN, SYS_OPENAT):
                            path_addr = regs.rsi if syscall_nr == SYS_OPENAT else regs.rdi
                            flags = regs.rdx if syscall_nr == SYS_OPENAT else regs.rsi
                            raw_path = read_string_from_pid(pid, path_addr)

                            verdict, action, prevented = self.evaluate_path_access(pid, raw_path, flags)
                            
                            # Only log events within the workspace or policy violations
                            is_workspace_or_violation = (verdict != "ALLOW") or ("workspace" in raw_path) or ("report.txt" in raw_path) or ("summary.txt" in raw_path) or ("credentials.txt" in raw_path)
                            
                            if is_workspace_or_violation:
                                self._event_counter += 1
                                full_p = os.path.join(self.canonical_workspace, raw_path) if not os.path.isabs(raw_path) else raw_path
                                canonical_p = os.path.realpath(os.path.abspath(full_p))
                                
                                event = RuntimeAuditEvent(
                                    event_id=f"evt_{self._event_counter:04d}",
                                    timestamp_ns=time.perf_counter_ns(),
                                    task_id=self.contract.task_id,
                                    agent_id=self.contract.agent_id,
                                    pid=pid,
                                    syscall_name="openat" if syscall_nr == SYS_OPENAT else "open",
                                    raw_path=raw_path,
                                    canonical_path=canonical_p,
                                    is_write=bool(flags & (O_WRONLY | O_RDWR | O_CREAT)),
                                    policy_verdict=verdict,
                                    enforcement_action=action,
                                    operation_prevented=prevented,
                                )
                                self.events.append(event)

                            if verdict != "ALLOW" and self.contract.enforcement_mode == "BLOCK":
                                # SYNCHRONOUS ENFORCEMENT:
                                # Nullify syscall so kernel never executes openat
                                regs.orig_rax = ctypes.c_ulonglong(-1).value
                                ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(regs))
                                suppressed_syscall = True
                    else:
                        # Syscall exit
                        in_syscall = False
                        if suppressed_syscall:
                            # Inject -EACCES (-13) into return register rax
                            regs.rax = ctypes.c_ulonglong(-13).value # -EACCES
                            ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(regs))
                            suppressed_syscall = False

        return exit_code, self.events
