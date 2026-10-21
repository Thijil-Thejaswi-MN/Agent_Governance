import ctypes, os, sys
libc = ctypes.CDLL(None)
params = (ctypes.c_uint8 * 128)()
ring_fd = libc.syscall(425, 8, ctypes.byref(params)) # SYS_io_uring_setup
if ring_fd >= 0:
    print(f"IO_URING: AVAILABLE (fd {ring_fd})", flush=True)
    os.close(ring_fd)
    sys.exit(0)
else:
    print(f"IO_URING: NOT_AVAILABLE (Errno {ctypes.get_errno()})", flush=True)
    sys.exit(1)
