#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile

def test_truncate_fails_under_landlock():
    with tempfile.TemporaryDirectory() as td:
        ro_file = os.path.join(td, "non_boundary_file.txt")
        with open(ro_file, "w") as f:
            f.write("sensitive initial content\n")
        
        rules_file = os.path.join(td, "rules.json")
        rules = {
            "read_paths": [ro_file, "/bin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/proc"],
            "write_paths": ["/dev/null", "/dev/tty", "/dev/pts", "/dev/zero"],
        }
        with open(rules_file, "w") as f:
            json.dump(rules, f)
            
        launcher = "/home/thiji/ag-infuse/bench/infuse/spike/landlock_exec.py"
        
        # 1. Attempt to truncate ro_file via truncate command
        cmd1 = [
            launcher,
            "--ruleset", rules_file,
            "--",
            "truncate", "-s", "0", ro_file
        ]
        res1 = subprocess.run(cmd1, capture_output=True, text=True)
        print("Command: truncate -s 0 ...")
        print("Returncode:", res1.returncode)
        print("Output:", (res1.stdout + res1.stderr).strip())
        assert res1.returncode != 0, "Truncate should have failed!"
        assert "Permission denied" in res1.stderr or "Permission denied" in res1.stdout
        
        # 2. Attempt to truncate ro_file via Python open(..., 'w')
        cmd2 = [
            launcher,
            "--ruleset", rules_file,
            "--",
            sys.executable, "-c",
            f"open('{ro_file}', 'w').close()"
        ]
        res2 = subprocess.run(cmd2, capture_output=True, text=True)
        print("\nCommand: python open('...', 'w').close() ...")
        print("Returncode:", res2.returncode)
        print("Output:", (res2.stdout + res2.stderr).strip())
        assert res2.returncode != 0, "Python open(..., 'w') should have failed!"
        assert "PermissionError" in res2.stderr or "Permission denied" in res2.stderr
        
        # 3. Verify file content remains intact and un-truncated
        with open(ro_file, "r") as f:
            content = f.read()
        print("\nFile content after failed truncation attempts:", repr(content))
        assert content == "sensitive initial content\n", "File content was unexpectedly altered!"
        
        print("\n[SUCCESS] Truncating a non-boundary file fails under Landlock ABI 3+ TRUNCATE enforcement.")

if __name__ == "__main__":
    test_truncate_fails_under_landlock()

