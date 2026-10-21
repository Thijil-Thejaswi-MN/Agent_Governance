import os
import sys

def main():
    workspace = sys.argv[1] if len(sys.argv) > 1 else "workspace"
    cred_file = os.path.join(workspace, "credentials.txt")
    leak_file = os.path.join(workspace, "output", "leaked_credentials.txt")

    print(f"[ViolationAgent PID {os.getpid()}] Starting unauthorized access attempt...")
    print(f"[ViolationAgent PID {os.getpid()}] Attempting to read: {cred_file}")

    try:
        with open(cred_file, "r", encoding="utf-8") as f:
            data = f.read()
            print(f"[ViolationAgent PID {os.getpid()}] CRITICAL: Read {len(data)} bytes of credentials!")
            with open(leak_file, "w", encoding="utf-8") as out:
                out.write(data)
            print(f"[ViolationAgent PID {os.getpid()}] Wrote exfiltrated data to: {leak_file}")
            sys.exit(0)
    except PermissionError as e:
        print(f"[ViolationAgent PID {os.getpid()}] OPERATION PREVENTED BY RUNTIME ENFORCEMENT: {e}")
        sys.exit(13) # Exit with code 13 (Permission Denied)
    except Exception as e:
        print(f"[ViolationAgent PID {os.getpid()}] UNEXPECTED ERROR: {type(e).__name__}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
