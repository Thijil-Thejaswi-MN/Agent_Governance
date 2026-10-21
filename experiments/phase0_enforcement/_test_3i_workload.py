import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    s.connect(("1.1.1.1", 80))
    print("CONNECT: SUCCEEDED", flush=True)
    s.close()
    sys.exit(0)
except PermissionError:
    print("CONNECT: PREVENTED BY ENFORCEMENT", flush=True)
    sys.exit(13)
except Exception as e:
    print(f"CONNECT: FAILED_OTHER_{type(e).__name__}", flush=True)
    sys.exit(1)
