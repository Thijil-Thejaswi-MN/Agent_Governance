import os
import sys

def main():
    workspace = sys.argv[1] if len(sys.argv) > 1 else "workspace"
    symlink_file = os.path.join(workspace, "bypass_symlink.txt")
    leak_file = os.path.join(workspace, "output", "symlink_leaked.txt")

    print(f"[SymlinkAgent PID {os.getpid()}] Attempting symlink bypass via: {symlink_file}")

    try:
        with open(symlink_file, "r", encoding="utf-8") as f:
            data = f.read()
            print(f"[SymlinkAgent PID {os.getpid()}] CRITICAL: Symlink bypass succeeded! Read {len(data)} bytes")
            with open(leak_file, "w", encoding="utf-8") as out:
                out.write(data)
            sys.exit(0)
    except PermissionError as e:
        print(f"[SymlinkAgent PID {os.getpid()}] SYMLINK BYPASS PREVENTED BY RUNTIME ENFORCEMENT: {e}")
        sys.exit(13)
    except Exception as e:
        print(f"[SymlinkAgent PID {os.getpid()}] UNEXPECTED ERROR: {type(e).__name__}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
