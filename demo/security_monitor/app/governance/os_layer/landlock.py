"""Landlock Sandboxing Engine (Linux ABI 1 to 7).

Implements kernel-level unprivileged access control for file paths, TCP network ports,
and abstract unix socket / signal scoping.
Provides a pure-Python implementation using ctypes syscalls.
"""
from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Any

# Syscall numbers (x86_64)
SYS_landlock_create_ruleset = 444
SYS_landlock_add_rule = 445
SYS_landlock_restrict_self = 446

# Prctl
PR_SET_NO_NEW_PRIVS = 38

# Landlock Flags
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0

# Rule types
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_RULE_NET_PORT = 2

# ABI 1 Filesystem Access Rights
ACCESS_FS_EXECUTE = 1 << 0
ACCESS_FS_WRITE_FILE = 1 << 1
ACCESS_FS_READ_FILE = 1 << 2
ACCESS_FS_READ_DIR = 1 << 3
ACCESS_FS_REMOVE_DIR = 1 << 4
ACCESS_FS_REMOVE_FILE = 1 << 5
ACCESS_FS_MAKE_CHAR = 1 << 6
ACCESS_FS_MAKE_DIR = 1 << 7
ACCESS_FS_MAKE_REG = 1 << 8
ACCESS_FS_MAKE_SOCK = 1 << 9
ACCESS_FS_MAKE_FIFO = 1 << 10
ACCESS_FS_MAKE_BLOCK = 1 << 11
ACCESS_FS_MAKE_SYM = 1 << 12

# ABI 2 Additions
ACCESS_FS_REFER = 1 << 13

# ABI 3 Additions
ACCESS_FS_TRUNCATE = 1 << 14

# ABI 5 Additions (ioctl on devices)
ACCESS_FS_IOCTL_DEV = 1 << 15

ALL_FS_ABI1 = (1 << 13) - 1
ALL_FS_ABI2 = ALL_FS_ABI1 | ACCESS_FS_REFER
ALL_FS_ABI3 = ALL_FS_ABI2 | ACCESS_FS_TRUNCATE
ALL_FS_ABI5 = ALL_FS_ABI3 | ACCESS_FS_IOCTL_DEV
ALL_FS_ABI7 = ALL_FS_ABI5  # All 16 FS bits

# ABI 4 Network Access Rights
ACCESS_NET_BIND_TCP = 1 << 0
ACCESS_NET_CONNECT_TCP = 1 << 1
ALL_NET_ABI4 = ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP

# ABI 6 Scoping
SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0
SCOPE_SIGNAL = 1 << 1
ALL_SCOPE_ABI6 = SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped_access", ctypes.c_uint64),
    ]


class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class LandlockNetPortAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
    ]


def get_landlock_abi() -> int:
    """Returns the supported Landlock ABI version on Linux, or -1 if unsupported."""
    if sys.platform != "linux":
        return -1
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        abi = libc.syscall(SYS_landlock_create_ruleset, 0, 0, LANDLOCK_CREATE_RULESET_VERSION)
        return int(abi)
    except Exception:
        return -1


class LandlockSandbox:
    """Configures and applies a Landlock security sandbox for an agent task."""

    def __init__(self, proxy_port: int | None = None) -> None:
        self.proxy_port = proxy_port
        self.abi = get_landlock_abi()
        self.libc = ctypes.CDLL(None, use_errno=True) if sys.platform == "linux" else None
        self.ruleset_fd = -1
        self.path_rules: list[tuple[str, int]] = []
        self.net_ports: list[tuple[int, int]] = []

    def allow_read_exec(self, path: str | Path) -> None:
        """Grants read and execute rights (binaries and libraries)."""
        flags = (
            ACCESS_FS_EXECUTE
            | ACCESS_FS_READ_FILE
            | ACCESS_FS_READ_DIR
        )
        self.path_rules.append((str(path), flags))

    def allow_read_only(self, path: str | Path) -> None:
        """Grants read-only access (regular files and directories)."""
        flags = (
            ACCESS_FS_READ_FILE
            | ACCESS_FS_READ_DIR
        )
        self.path_rules.append((str(path), flags))

    def allow_read_write(self, path: str | Path) -> None:
        """Grants full read/write/create/truncate access within a directory."""
        flags = (
            ACCESS_FS_READ_FILE
            | ACCESS_FS_READ_DIR
            | ACCESS_FS_WRITE_FILE
            | ACCESS_FS_MAKE_REG
            | ACCESS_FS_MAKE_DIR
            | ACCESS_FS_REMOVE_FILE
            | ACCESS_FS_REMOVE_DIR
            | ACCESS_FS_MAKE_SYM
            | ACCESS_FS_TRUNCATE
        )
        if self.abi >= 2:
            flags |= ACCESS_FS_REFER
        self.path_rules.append((str(path), flags))

    def allow_tcp_connect(self, port: int) -> None:
        """Permits outbound TCP connections to a specific port."""
        if self.abi >= 4:
            self.net_ports.append((port, ACCESS_NET_CONNECT_TCP))

    def build_default_task_profile(self, task_workspace: str | Path, proxy_port: int | None = None) -> None:
        """
        Builds complete least-privilege Landlock profile for an AI task:
        1. Read+exec on system binary and library paths: /usr, /lib, /lib64, /bin, /sbin
        2. Read-only on essential runtime configuration: /etc, /dev (urandom/null), /proc
        3. Read-only on task input: <workspace>/input
        4. Read+write on task output and scratch: <workspace>/output, <workspace>/scratch, /tmp
        5. Port-restricted network connect to proxy port only
        6. Explicitly NO access granted to $HOME outside task_workspace (e.g. ~/.ssh, ~/.aws)
        """
        ws = Path(task_workspace).resolve()

        # System binaries and shared libraries
        for sys_path in ("/usr", "/lib", "/lib64", "/bin", "/sbin"):
            if os.path.exists(sys_path):
                self.allow_read_exec(sys_path)

        # Essential system configs and devices
        for cfg_path in ("/etc", "/dev/urandom", "/dev/null", "/dev/zero", "/proc"):
            if os.path.exists(cfg_path):
                self.allow_read_only(cfg_path)

        # Task input directory (read-only)
        input_dir = ws / "input"
        input_dir.mkdir(parents=True, exist_ok=True)
        self.allow_read_only(input_dir)

        # Task output directory (read-write)
        output_dir = ws / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        self.allow_read_write(output_dir)

        # Task scratch directory (read-write)
        scratch_dir = ws / "scratch"
        scratch_dir.mkdir(parents=True, exist_ok=True)
        self.allow_read_write(scratch_dir)

        # Task tmp directory (read-write) - /tmp is strictly excluded
        tmp_dir = ws / "tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        self.allow_read_write(tmp_dir)

        # Network egress: proxy port only
        if proxy_port:
            self.allow_tcp_connect(proxy_port)

    def apply(self) -> None:
        """Creates the Landlock ruleset, populates path and net rules, and restricts the calling process."""
        if self.abi < 1:
            raise RuntimeError(f"Landlock is not supported on this kernel (ABI: {self.abi})")

        attr = LandlockRulesetAttr()
        # Filesystem access rights based on ABI
        if self.abi >= 5:
            attr.handled_access_fs = ALL_FS_ABI7
        elif self.abi >= 3:
            attr.handled_access_fs = ALL_FS_ABI3
        elif self.abi >= 2:
            attr.handled_access_fs = ALL_FS_ABI2
        else:
            attr.handled_access_fs = ALL_FS_ABI1

        # Network access rights (ABI >= 4)
        if self.abi >= 4:
            attr.handled_access_net = ALL_NET_ABI4
        else:
            attr.handled_access_net = 0

        # Scoping (ABI >= 6)
        if self.abi >= 6:
            attr.scoped_access = ALL_SCOPE_ABI6
        else:
            attr.scoped_access = 0

        # Create ruleset
        attr_size = ctypes.sizeof(attr) if self.abi >= 6 else (ctypes.sizeof(ctypes.c_uint64) * 2)
        self.ruleset_fd = self.libc.syscall(
            SYS_landlock_create_ruleset,
            ctypes.byref(attr),
            attr_size,
            0,
        )
        if self.ruleset_fd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"Failed to create Landlock ruleset: errno={errno}")

        try:
            # Add path rules
            for path_str, access_mask in self.path_rules:
                if not os.path.exists(path_str):
                    continue
                # Mask to handled rights
                effective_mask = access_mask & attr.handled_access_fs
                if not effective_mask:
                    continue

                fd = os.open(path_str, os.O_PATH | os.O_CLOEXEC)
                try:
                    rule = LandlockPathBeneathAttr()
                    rule.allowed_access = effective_mask
                    rule.parent_fd = fd

                    res = self.libc.syscall(
                        SYS_landlock_add_rule,
                        self.ruleset_fd,
                        LANDLOCK_RULE_PATH_BENEATH,
                        ctypes.byref(rule),
                        0,
                    )
                    if res != 0:
                        errno = ctypes.get_errno()
                        raise OSError(errno, f"Failed to add path rule for '{path_str}': errno={errno}")
                finally:
                    os.close(fd)

            # Add network port rules
            if self.abi >= 4:
                for port, access_mask in self.net_ports:
                    net_rule = LandlockNetPortAttr()
                    net_rule.allowed_access = access_mask & attr.handled_access_net
                    net_rule.port = port

                    res = self.libc.syscall(
                        SYS_landlock_add_rule,
                        self.ruleset_fd,
                        LANDLOCK_RULE_NET_PORT,
                        ctypes.byref(net_rule),
                        0,
                    )
                    if res != 0:
                        errno = ctypes.get_errno()
                        raise OSError(errno, f"Failed to add net port rule for port {port}: errno={errno}")

            # Enforce PR_SET_NO_NEW_PRIVS before restricting
            if self.libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                errno = ctypes.get_errno()
                raise OSError(errno, f"Failed to set PR_SET_NO_NEW_PRIVS: errno={errno}")

            # Enforce Landlock ruleset on calling process and children
            if self.libc.syscall(SYS_landlock_restrict_self, self.ruleset_fd, 0) != 0:
                errno = ctypes.get_errno()
                raise OSError(errno, f"Failed to apply Landlock restrict_self: errno={errno}")

        finally:
            os.close(self.ruleset_fd)
            self.ruleset_fd = -1
