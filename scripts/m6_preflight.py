#!/usr/bin/env python3
"""M6 preflight: checks the WSL2 platform before any M6 run.

Prints PASS/FAIL per check and exits non-zero on any FAIL.
Run from the WSL-native clone with the WSL venv:
    ~/m4_venv/bin/python scripts/m6_preflight.py
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OS_LAYER = ROOT / "demo" / "security_monitor" / "app" / "governance" / "os_layer"
M5_DIGESTS = {
    # From demo/data/full_llm_agent_evaluation_results_*_oracle_N3.jsonl (model_digest field)
    "llama3.1:8b": "46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e",
    "qwen2.5:7b": "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e",
}
OLLAMA = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/").removesuffix("/v1")

results: list[tuple[bool, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((ok, name, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}{(' - ' + detail) if detail else ''}", flush=True)
    return ok


def run(cmd: list[str], timeout: float = 20.0) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def main() -> int:
    if sys.platform != "linux":
        check("platform is Linux/WSL2", False, sys.platform)
        return 1

    # Kernel + Landlock ABI
    rel = platform.release()
    check("kernel", True, rel + (" (WSL2)" if "microsoft" in rel.lower() else ""))
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        abi = int(libc.syscall(444, None, 0, 1))
    except Exception as e:
        abi = -1
        check("Landlock ABI >= 6", False, str(e))
    else:
        check("Landlock ABI >= 6", abi >= 6, f"ABI {abi} (expected 7 on the reference machine)")

    # cgroup v2 + systemd --user
    mounts = Path("/proc/mounts").read_text()
    check("cgroup v2 mounted at /sys/fs/cgroup", any(l.split()[1:3] == ["/sys/fs/cgroup", "cgroup2"] for l in mounts.splitlines()))
    r = run(["systemctl", "--user", "is-system-running"])
    state = r.stdout.strip()
    check("systemd --user running", state in ("running", "degraded"), state or r.stderr.strip())

    # systemd-run --user --scope works and lands in its scope
    unit = f"m6-preflight-{os.getpid()}"
    r = run(["systemd-run", "--user", "--scope", "--quiet", f"--unit={unit}", "--", "cat", "/proc/self/cgroup"])
    in_scope = r.returncode == 0 and f"/{unit}.scope" in r.stdout
    check("systemd-run --user --scope", in_scope, r.stdout.strip() or r.stderr.strip())
    if in_scope:
        r2 = run(["systemd-run", "--user", "--scope", "--quiet", f"--unit={unit}-fz", "--", "sh", "-c",
                  "cg=$(cut -d: -f3 /proc/self/cgroup); test -w /sys/fs/cgroup$cg/cgroup.freeze && test -w /sys/fs/cgroup$cg/cgroup.kill && echo writable"])
        check("scope cgroup.freeze/cgroup.kill writable", "writable" in r2.stdout, r2.stderr.strip())

    # Unprivileged user + mount + net namespaces
    r = run(["unshare", "--user", "--map-root-user", "--mount", "--net", "sh", "-c", "id -u; cat /proc/net/dev | wc -l"])
    lines = r.stdout.split()
    check("unprivileged user+mount+net namespaces", r.returncode == 0 and lines[:1] == ["0"], (r.stderr.strip() or " ".join(lines)))

    # Repo not on 9p/drvfs
    fstype = None
    best = ""
    for l in mounts.splitlines():
        parts = l.split()
        mp = parts[1]
        if str(ROOT).startswith(mp.rstrip("/") + "/") or str(ROOT) == mp or mp == "/":
            if len(mp) >= len(best):
                best, fstype = mp, parts[2]
    check("repo not on 9p/drvfs", fstype not in ("9p", "drvfs", "v9fs"), f"{ROOT} on {fstype} ({best})")

    # Binaries built
    r = run(["make", "-C", str(OS_LAYER), "-q"])
    for b in ("landlock_enforcer", "seccomp_filter", "sensor"):
        p = OS_LAYER / b
        fresh = p.exists() and p.stat().st_mtime >= (OS_LAYER / f"{b}.c").stat().st_mtime
        check(f"binary built: {b}", os.access(p, os.X_OK) and fresh, "up to date" if fresh else "missing or older than source (run make)")

    # Ollama models respond and digests match M5
    try:
        with urllib.request.urlopen(f"{OLLAMA}/api/tags", timeout=5) as resp:
            tags = json.load(resp)
        have = {m.get("name"): m.get("digest") for m in tags.get("models", [])}
    except Exception as e:
        have = {}
        check("Ollama reachable", False, f"{OLLAMA}: {e}")
    for model, digest in M5_DIGESTS.items():
        if not have:
            check(f"model digest matches M5: {model}", False, "Ollama unreachable")
            continue
        got = have.get(model)
        check(f"model digest matches M5: {model}", got == digest, f"{(got or 'absent')[:16]} vs M5 {digest[:16]}")
        if got:
            body = json.dumps({"model": model, "messages": [{"role": "user", "content": "Reply with OK."}],
                               "stream": False, "options": {"temperature": 0, "seed": 42, "num_predict": 4}}).encode()
            req = urllib.request.Request(f"{OLLAMA}/api/chat", data=body, headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=180) as resp:
                    out = json.load(resp)
                check(f"model responds: {model}", bool(out.get("message", {}).get("content") is not None), repr(out.get("message", {}).get("content", ""))[:40])
            except Exception as e:
                check(f"model responds: {model}", False, str(e))

    failed = [n for ok, n, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed" + (f"; FAILED: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
