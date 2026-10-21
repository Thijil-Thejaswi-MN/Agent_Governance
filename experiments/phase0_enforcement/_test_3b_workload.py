import os, sys, subprocess, time
workspace = sys.argv[1]
cred = os.path.join(workspace, "credentials.txt")

# Test 1: Simple fork
pid = os.fork()
if pid == 0:
    try:
        with open(cred, "r") as f:
            print("CHILD_FORK: READ_SUCCESS", flush=True)
    except PermissionError:
        print("CHILD_FORK: PREVENTED", flush=True)
    os._exit(0)
os.waitpid(pid, 0)

# Test 2: subprocess.Popen
try:
    p = subprocess.run([sys.executable, "-c", f"open('{cred}')"], capture_output=True)
    if p.returncode == 0:
        print("CHILD_POPEN: READ_SUCCESS", flush=True)
    else:
        print("CHILD_POPEN: PREVENTED", flush=True)
except Exception as e:
    print(f"CHILD_POPEN: EXCEPTION_{e}", flush=True)
