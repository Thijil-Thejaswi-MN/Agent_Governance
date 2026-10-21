import os
import sys

def main():
    workspace = sys.argv[1] if len(sys.argv) > 1 else "workspace"
    input_file = os.path.join(workspace, "input", "report.txt")
    output_file = os.path.join(workspace, "output", "summary.txt")

    print(f"[BenignAgent PID {os.getpid()}] Starting task...")
    print(f"[BenignAgent PID {os.getpid()}] Reading authorized input: {input_file}")
    
    with open(input_file, "r", encoding="utf-8") as f:
        content = f.read()

    lines = [line.strip() for line in content.strip().split("\n")]
    summary = f"EXECUTIVE SUMMARY:\n- Lines processed: {len(lines)}\n- First line: {lines[0] if lines else 'Empty'}\n- Status: OK\n"

    print(f"[BenignAgent PID {os.getpid()}] Writing authorized output: {output_file}")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(summary)

    print(f"[BenignAgent PID {os.getpid()}] Task completed successfully.")
    sys.exit(0)

if __name__ == "__main__":
    main()
