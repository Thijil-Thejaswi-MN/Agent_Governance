"""Pure-Python ctypes loader for Seccomp BPF filters.

Denies io_uring syscalls (io_uring_setup, io_uring_enter, io_uring_register),
restricts architecture to native x86_64, and optionally marks monitored syscalls
with SECCOMP_RET_TRACE for the OS sensor.
"""
from __future__ import annotations

import ctypes
import os
import sys

# Syscall numbers (x86_64)
SYS_io_uring_setup = 425
SYS_io_uring_enter = 426
SYS_io_uring_register = 427
SYS_open = 2
SYS_openat = 257
SYS_execve = 59
SYS_execveat = 322
SYS_connect = 42

SCMP_ACT_KILL = 0x00000000
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO_BASE = 0x00050000
SCMP_ACT_TRACE_BASE = 0x7FF00000

SCMP_ARCH_X86_64 = 0xC000003E


def SCMP_ACT_ERRNO(err: int) -> int:
    return SCMP_ACT_ERRNO_BASE | (err & 0x0000FFFF)


def SCMP_ACT_TRACE(msg: int) -> int:
    return SCMP_ACT_TRACE_BASE | (msg & 0x0000FFFF)


class SeccompFilter:
    """Manages seccomp filter configuration via libseccomp or compiled binary."""

    def __init__(self) -> None:
        self.lib = None
        if sys.platform == "linux":
            try:
                self.lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
            except OSError:
                try:
                    self.lib = ctypes.CDLL("libseccomp.so", use_errno=True)
                except OSError:
                    pass

    def is_available(self) -> bool:
        return self.lib is not None

    def apply(
        self,
        trace_openat: bool = False,
        trace_execve: bool = False,
        trace_connect: bool = False,
    ) -> None:
        """Applies seccomp filter denying io_uring and non-native ABIs."""
        if not self.is_available():
            raise RuntimeError("libseccomp is not available on this system.")

        # Setup ctypes function signatures
        self.lib.seccomp_init.restype = ctypes.c_void_p
        self.lib.seccomp_init.argtypes = [ctypes.c_uint32]

        self.lib.seccomp_arch_add.restype = ctypes.c_int
        self.lib.seccomp_arch_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

        self.lib.seccomp_rule_add.restype = ctypes.c_int
        self.lib.seccomp_rule_add.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint,
        ]

        self.lib.seccomp_load.restype = ctypes.c_int
        self.lib.seccomp_load.argtypes = [ctypes.c_void_p]

        self.lib.seccomp_release.argtypes = [ctypes.c_void_p]

        ctx = self.lib.seccomp_init(SCMP_ACT_ALLOW)
        if not ctx:
            raise OSError("seccomp_init failed")

        try:
            # Enforce native x86_64 ABI
            self.lib.seccomp_arch_add(ctx, SCMP_ARCH_X86_64)

            # Deny io_uring family with EPERM (errno 1)
            eperm = 1
            self.lib.seccomp_rule_add(ctx, SCMP_ACT_ERRNO(eperm), SYS_io_uring_setup, 0)
            self.lib.seccomp_rule_add(ctx, SCMP_ACT_ERRNO(eperm), SYS_io_uring_enter, 0)
            self.lib.seccomp_rule_add(ctx, SCMP_ACT_ERRNO(eperm), SYS_io_uring_register, 0)

            # Optional tracer hook points
            if trace_openat:
                self.lib.seccomp_rule_add(ctx, SCMP_ACT_TRACE(1), SYS_openat, 0)
                self.lib.seccomp_rule_add(ctx, SCMP_ACT_TRACE(1), SYS_open, 0)
            if trace_execve:
                self.lib.seccomp_rule_add(ctx, SCMP_ACT_TRACE(2), SYS_execve, 0)
                self.lib.seccomp_rule_add(ctx, SCMP_ACT_TRACE(2), SYS_execveat, 0)
            if trace_connect:
                self.lib.seccomp_rule_add(ctx, SCMP_ACT_TRACE(3), SYS_connect, 0)

            rc = self.lib.seccomp_load(ctx)
            if rc < 0:
                raise OSError(abs(rc), f"seccomp_load failed: {rc}")
        finally:
            self.lib.seccomp_release(ctx)
