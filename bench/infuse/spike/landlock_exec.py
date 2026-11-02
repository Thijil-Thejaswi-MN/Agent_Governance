#!/usr/bin/env python3
import os, sys, json, ctypes

# System constants (Linux x86_64)
SYS_landlock_create_ruleset = 444
SYS_landlock_add_rule = 445
SYS_landlock_restrict_self = 446
PR_SET_NO_NEW_PRIVS = 38

LANDLOCK_RULE_PATH_BENEATH = 1

# ABI 1 Access Masks
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

READ_ACCESS = ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR | ACCESS_FS_EXECUTE
WRITE_ACCESS = (
    ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SYM
)
ALL_ACCESS = READ_ACCESS | WRITE_ACCESS

class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
    ]

class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]

def apply_landlock(ruleset_path):
    libc = ctypes.CDLL(None, use_errno=True)
    
    with open(ruleset_path) as f:
        rules = json.load(f)
        
    attr = LandlockRulesetAttr()
    attr.handled_access_fs = ALL_ACCESS
    
    ruleset_fd = libc.syscall(
        SYS_landlock_create_ruleset,
        ctypes.byref(attr),
        ctypes.sizeof(attr),
        0
    )
    if ruleset_fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"landlock_create_ruleset failed: errno={err}")
        
    try:
        # Add read rules
        for p in rules.get("read_paths", []):
            if not os.path.exists(p): continue
            fd = os.open(p, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = LandlockPathBeneathAttr()
                rule.allowed_access = READ_ACCESS
                rule.parent_fd = fd
                if libc.syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(rule), 0) != 0:
                    err = ctypes.get_errno()
                    raise OSError(err, f"landlock_add_rule read '{p}' failed: errno={err}")
            finally:
                os.close(fd)
                
        # Add write rules (inherits read)
        for p in rules.get("write_paths", []):
            if not os.path.exists(p): continue
            fd = os.open(p, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = LandlockPathBeneathAttr()
                rule.allowed_access = ALL_ACCESS
                rule.parent_fd = fd
                if libc.syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(rule), 0) != 0:
                    err = ctypes.get_errno()
                    raise OSError(err, f"landlock_add_rule write '{p}' failed: errno={err}")
            finally:
                os.close(fd)
                
        # Set PR_SET_NO_NEW_PRIVS
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            err = ctypes.get_errno()
            raise OSError(err, f"prctl PR_SET_NO_NEW_PRIVS failed: errno={err}")
            
        # Restrict self
        if libc.syscall(SYS_landlock_restrict_self, ruleset_fd, 0) != 0:
            err = ctypes.get_errno()
            raise OSError(err, f"landlock_restrict_self failed: errno={err}")
            
    finally:
        os.close(ruleset_fd)

if __name__ == "__main__":
    if len(sys.argv) < 4 or sys.argv[1] != "--ruleset" or sys.argv[3] != "--":
        print(f"Usage: {sys.argv[0]} --ruleset <ruleset.json> -- <cmd...>", file=sys.stderr)
        sys.exit(1)
        
    ruleset_file = sys.argv[2]
    cmd = sys.argv[4:]
    
    apply_landlock(ruleset_file)
    os.execvp(cmd[0], cmd)