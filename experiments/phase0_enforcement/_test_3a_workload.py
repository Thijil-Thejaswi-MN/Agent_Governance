import os, sys, ctypes, subprocess
libc = ctypes.CDLL(None)
workspace = sys.argv[1]
cred = os.path.join(workspace, "credentials.txt")

# Test 1: creat (SYS_creat = 85)
try:
    fd = libc.syscall(85, cred.encode(), 0o644)
    if fd >= 0:
        os.close(fd)
        print("RESULT:creat=SUCCESS", flush=True)
    else:
        print("RESULT:creat=DENIED", flush=True)
except Exception as e:
    print(f"RESULT:creat=EXCEPTION_{e}", flush=True)

# Test 2: openat2 (SYS_openat2 = 437)
try:
    how = (ctypes.c_uint64 * 3)(0, 0, 0) # flags=0, mode=0, resolve=0
    fd = libc.syscall(437, -100, cred.encode(), ctypes.byref(how), 24)
    if fd >= 0:
        os.close(fd)
        print("RESULT:openat2=SUCCESS", flush=True)
    else:
        print("RESULT:openat2=DENIED", flush=True)
except Exception as e:
    print(f"RESULT:openat2=EXCEPTION_{e}", flush=True)

# Test 3: open_by_handle_at (SYS_open_by_handle_at = 304)
try:
    # Requires CAP_DAC_READ_SEARCH, unprivileged will return EPERM
    fd = libc.syscall(304, -100, None, 0)
    if fd >= 0:
        os.close(fd)
        print("RESULT:open_by_handle_at=SUCCESS", flush=True)
    else:
        err = ctypes.get_errno()
        print(f"RESULT:open_by_handle_at=FAILED_ERRNO_{err}", flush=True)
except Exception as e:
    print(f"RESULT:open_by_handle_at=EXCEPTION_{e}", flush=True)

# Test 4: rename credentials to allowed location
try:
    target = os.path.join(workspace, "output", "renamed_creds.txt")
    res = libc.syscall(82, cred.encode(), target.encode()) # SYS_rename
    if res == 0:
        print("RESULT:rename=SUCCESS", flush=True)
        if os.path.exists(target): os.rename(target, cred)
    else:
        print("RESULT:rename=DENIED", flush=True)
except Exception as e:
    print(f"RESULT:rename=EXCEPTION_{e}", flush=True)

# Test 5: link (hardlink to secret)
try:
    hlink = os.path.join(workspace, "output", "hardlink.txt")
    res = libc.syscall(86, cred.encode(), hlink.encode()) # SYS_link
    if res == 0:
        print("RESULT:link=SUCCESS", flush=True)
        if os.path.exists(hlink): os.remove(hlink)
    else:
        print("RESULT:link=DENIED", flush=True)
except Exception as e:
    print(f"RESULT:link=EXCEPTION_{e}", flush=True)

# Test 6: symlink to secret
try:
    slink = os.path.join(workspace, "output", "symlink_test.txt")
    res = libc.syscall(88, cred.encode(), slink.encode()) # SYS_symlink
    if res == 0:
        print("RESULT:symlink=SUCCESS", flush=True)
        if os.path.exists(slink): os.remove(slink)
    else:
        print("RESULT:symlink=DENIED", flush=True)
except Exception as e:
    print(f"RESULT:symlink=EXCEPTION_{e}", flush=True)

# Test 7: execve of /bin/cat credentials.txt
try:
    res = subprocess.run(["/bin/cat", cred], capture_output=True, text=True)
    if res.returncode == 0 and "DUMMY_CREDENTIALS" in res.stdout:
        print("RESULT:execve_cat=SUCCESS", flush=True)
    else:
        print("RESULT:execve_cat=DENIED", flush=True)
except Exception as e:
    print(f"RESULT:execve_cat=EXCEPTION_{e}", flush=True)
