import os, sys, ctypes
libc = ctypes.CDLL(None)
workspace = sys.argv[1]
input_dir = os.path.join(workspace, "input")

# Open input directory
dfd = os.open(input_dir, os.O_RDONLY | os.O_DIRECTORY)

# Attempt openat relative to input_dir pointing to ../credentials.txt
SYS_openat = 257
rel_path = "../credentials.txt".encode()
fd = libc.syscall(SYS_openat, dfd, rel_path, 0) # O_RDONLY
if fd >= 0:
    print("DIRFD_TRAVERSAL: SUCCEEDED (Bypass succeeded!)", flush=True)
    os.close(fd)
    sys.exit(0)
else:
    errno = ctypes.get_errno()
    print(f"DIRFD_TRAVERSAL: PREVENTED (Errno {errno})", flush=True)
    sys.exit(13)
