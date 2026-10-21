import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7fff0000
EPERM = 1

BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06

class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]

class SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(SockFilter)),
    ]

filters = (SockFilter * 5)(
    SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),                      # load nr
    SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 425),                  # if 425 goto deny
    SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 426),                  # if 426 goto deny
    SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),               # allow other
    SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM),       # return -EPERM
)
prog = SockFprog(len=5, filter=filters)
libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0)

params = (ctypes.c_uint8 * 128)()
ring_fd = libc.syscall(425, 8, ctypes.byref(params))
err = ctypes.get_errno()
if ring_fd < 0 and err == EPERM:
    print(f"IO_URING: PREVENTED_EPERM (Errno {err})", flush=True)
    sys.exit(0)
elif ring_fd >= 0:
    print(f"IO_URING: BYPASSED (fd {ring_fd})", flush=True)
    os.close(ring_fd)
    sys.exit(1)
else:
    print(f"IO_URING: OTHER_ERROR (Errno {err})", flush=True)
    sys.exit(2)
