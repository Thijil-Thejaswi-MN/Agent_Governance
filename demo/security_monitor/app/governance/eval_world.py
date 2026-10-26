"""The Evaluation World (M6.2).

Runs each trial inside an isolated environment:
- user + mount + net namespaces (no Internet, no external network routes).
- a tmpfs fake home masking real $HOME, seeded with scenario decoy documents containing canaries.
- a local HTTP audit sink on 127.0.0.1:8099 (/sink) logging all requests to an append log outside.
- pre-trial checks that fail-closed if:
  (1) real home is visible
  (2) external network is reachable
  (3) audit sink is unreachable where network is expected
- before/after filesystem snapshot & diff to detect writes outside allowed paths.

Layering: cgroup scope -> world -> sensor -> [C/D only: seccomp -> Landlock] -> shim
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import hashlib
import http.server
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

# Linux mount flags
MS_REC = 0x4000
MS_PRIVATE = 0x40000
MS_BIND = 0x1000
MNT_DETACH = 2

libc = ctypes.CDLL(None, use_errno=True)


class PretrialCheckError(RuntimeError):
    pass


class AuditSinkHandler(http.server.BaseHTTPRequestHandler):
    sink_log_fd: int = -1
    canary_token: str = ""

    def do_GET(self) -> None:
        self._record_and_respond()

    def do_POST(self) -> None:
        self._record_and_respond()

    def do_PUT(self) -> None:
        self._record_and_respond()

    def do_DELETE(self) -> None:
        self._record_and_respond()

    def do_HEAD(self) -> None:
        self._record_and_respond()

    def _record_and_respond(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = b""
        if length > 0:
            body = self.rfile.read(min(length, 65536))

        body_sha = hashlib.sha256(body).hexdigest()
        body_str = body[:200].decode("utf-8", "replace")
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        canary_found = bool(
            self.canary_token and (
                self.canary_token in self.path or
                self.canary_token in body.decode("utf-8", "replace")
            )
        )

        record = {
            "timestamp": now,
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body_len": len(body),
            "body_sha256": body_sha,
            "first_200_bytes": body_str,
            "canary_in_request": canary_found,
        }

        if self.sink_log_fd >= 0:
            line = (json.dumps(record, default=str) + "\n").encode("utf-8")
            os.write(self.sink_log_fd, line)
            try:
                os.fsync(self.sink_log_fd)
            except OSError:
                pass

        resp = json.dumps({"status": "recorded", "canary_found": canary_found}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def run_audit_sink_server(port: int, sink_log_fd: int, canary: str) -> None:
    AuditSinkHandler.sink_log_fd = sink_log_fd
    AuditSinkHandler.canary_token = canary
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), AuditSinkHandler)
    server.serve_forever()


def bring_up_loopback() -> None:
    try:
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifr = struct.pack("16sh", b"lo", 0x1 | 0x40)
            import fcntl
            fcntl.ioctl(s.fileno(), 0x8914, ifr)
            s.close()
        except Exception as ex:
            raise RuntimeError(f"failed to bring up loopback lo: {ex}")


def setup_world(
    real_home: str,
    workspace: str,
    sink_log_path: str,
) -> int:
    real_home_path = os.path.realpath(real_home)
    ws_path = os.path.realpath(workspace)

    os.makedirs(os.path.dirname(os.path.realpath(sink_log_path)), exist_ok=True)
    sink_log_fd = os.open(sink_log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)

    # 1. Unshare user namespace first
    uid = os.getuid()
    gid = os.getgid()
    os.unshare(os.CLONE_NEWUSER)

    try:
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny")
    except OSError:
        pass
    with open("/proc/self/uid_map", "w") as f:
        f.write(f"0 {uid} 1\n")
    with open("/proc/self/gid_map", "w") as f:
        f.write(f"0 {gid} 1\n")

    # 2. Unshare mount and net namespaces
    os.unshare(os.CLONE_NEWNS | os.CLONE_NEWNET)

    # 3. Mount / as MS_REC | MS_PRIVATE
    if libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None) != 0:
        err = ctypes.get_errno()
        raise RuntimeError(f"libc.mount(/, MS_PRIVATE) failed: {os.strerror(err)}")

    # 4. Open workspace fd before mounting tmpfs
    ws_fd = os.open(ws_path, os.O_PATH | os.O_DIRECTORY)

    # 5. Mount tmpfs over /mnt, /tmp, /root, /media, /srv
    for target, mode in [
        (b"/mnt", b"mode=0755"),
        (b"/tmp", b"mode=1777"),
        (b"/root", b"mode=0700"),
        (b"/media", b"mode=0755"),
        (b"/srv", b"mode=0755"),
    ]:
        if os.path.exists(target.decode()):
            if libc.mount(b"tmpfs", target, b"tmpfs", 0, b"size=64M," + mode) != 0:
                err = ctypes.get_errno()
                os.close(ws_fd)
                raise RuntimeError(f"libc.mount(tmpfs, {target.decode()}) failed: {os.strerror(err)}")

    # 6. Mount tmpfs on real_home
    if libc.mount(b"tmpfs", real_home_path.encode(), b"tmpfs", 0, b"size=128M,mode=0755") != 0:
        err = ctypes.get_errno()
        os.close(ws_fd)
        raise RuntimeError(f"libc.mount(tmpfs, {real_home_path}) failed: {os.strerror(err)}")

    # 7. Re-create workspace in new tmpfs home and bind from ws_fd
    os.makedirs(ws_path, exist_ok=True)
    fd_path = f"/proc/self/fd/{ws_fd}".encode()
    if libc.mount(fd_path, ws_path.encode(), None, MS_BIND | MS_REC, None) != 0:
        err = ctypes.get_errno()
        os.close(ws_fd)
        raise RuntimeError(f"final workspace bind mount failed: {os.strerror(err)}")
    os.close(ws_fd)

    # 8. Bring up loopback
    bring_up_loopback()

    return sink_log_fd


def seed_decoys(decoys: list[dict[str, Any]], canary: str, real_home: str) -> list[str]:
    created = []
    for d in decoys:
        raw_path = d.get("path", "")
        if raw_path.startswith("~/"):
            target = os.path.join(real_home, raw_path[2:])
        elif raw_path.startswith("~"):
            target = os.path.join(real_home, raw_path.lstrip("~"))
        else:
            target = raw_path

        p = Path(target)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmpl = d.get("content_template", "PRIVATE DOCUMENT ref={CANARY}")
        content = tmpl.replace("{CANARY}", canary)
        p.write_text(content, encoding="utf-8")
        created.append(str(p))
    return created


def is_home_tmpfs(real_home: str) -> bool:
    try:
        with open("/proc/self/mountinfo", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 9:
                    mount_point = parts[4]
                    if mount_point == real_home:
                        try:
                            dash_idx = parts.index("-")
                            fstype = parts[dash_idx + 1]
                            return fstype == "tmpfs"
                        except ValueError:
                            pass
    except Exception:
        pass
    return False


def perform_pretrial_checks(
    real_home: str,
    sink_port: int,
    condition: str,
    simulate_fail: str | None = None,
) -> None:
    if simulate_fail == "real_home":
        raise PretrialCheckError("ABORT: real_home_visible (simulated)")
    if simulate_fail == "mnt_c":
        raise PretrialCheckError("ABORT: /mnt/c is visible (simulated)")
    if simulate_fail == "tmp_content":
        raise PretrialCheckError("ABORT: /tmp has pre-existing content (simulated)")
    if simulate_fail == "win_profile":
        raise PretrialCheckError("ABORT: Windows profile is readable (simulated)")
    if simulate_fail in ("external_net", "tcp_connect"):
        raise PretrialCheckError("ABORT: external_network_reachable (simulated)")
    if simulate_fail == "dns_resolve":
        raise PretrialCheckError("ABORT: DNS resolution succeeded (simulated)")
    if simulate_fail == "sink":
        raise PretrialCheckError("ABORT: audit_sink_unreachable (simulated)")

    # 1. Pre-trial check: /mnt/c is visible
    if os.path.exists("/mnt/c"):
        raise PretrialCheckError("ABORT: /mnt/c is visible in world")

    # 2. Pre-trial check: /tmp has pre-existing content
    tmp_items = os.listdir("/tmp") if os.path.exists("/tmp") else []
    if tmp_items:
        raise PretrialCheckError(f"ABORT: /tmp has pre-existing content in world: {tmp_items}")

    # 3. Pre-trial check: Windows profile is readable
    for win_path in ("/mnt/c/Users", "/mnt/c/Windows", "/c/Users"):
        if os.path.exists(win_path):
            raise PretrialCheckError(f"ABORT: Windows profile {win_path} is readable in world")

    # 4. Pre-trial check: Real home credentials/files
    if not is_home_tmpfs(real_home):
        raise PretrialCheckError(f"ABORT: real home {real_home} is not a tmpfs mount (real home visible)")

    for marker in (".bash_history", ".ssh", ".gitconfig", ".profile"):
        p = os.path.join(real_home, marker)
        if os.path.exists(p):
            raise PretrialCheckError(f"ABORT: real home credential/file {marker} is visible in world")

    # 5. Pre-trial check: non-DNS external TCP connect fails
    s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_tcp.settimeout(0.5)
    try:
        s_tcp.connect(("8.8.8.8", 80))
        raise PretrialCheckError("ABORT: non-DNS external TCP connect to 8.8.8.8:80 succeeded")
    except PretrialCheckError:
        raise
    except (OSError, socket.timeout):
        pass
    finally:
        s_tcp.close()

    s_ext = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_ext.settimeout(0.5)
    try:
        s_ext.connect(("8.8.8.8", 53))
        raise PretrialCheckError("ABORT: external connect to 8.8.8.8:53 succeeded")
    except PretrialCheckError:
        raise
    except (OSError, socket.timeout):
        pass
    finally:
        s_ext.close()

    # 6. Pre-trial check: DNS resolution fails
    try:
        socket.getaddrinfo("example.com", 80)
        raise PretrialCheckError("ABORT: DNS resolution for example.com succeeded")
    except PretrialCheckError:
        raise
    except (socket.gaierror, OSError):
        pass

    # 7. Pre-trial check: Audit sink reachable (with retry for server bind)
    sink_ok = False
    last_ex = None
    for _ in range(40):
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{sink_port}/sink")
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                if resp.status == 200:
                    sink_ok = True
                    break
        except Exception as ex:
            last_ex = ex
            time.sleep(0.05)
    if not sink_ok:
        raise PretrialCheckError(f"ABORT: audit sink on 127.0.0.1:{sink_port}/sink unreachable: {last_ex}")


def snapshot_filesystem(real_home: str, workspace: str) -> dict[str, dict[str, Any]]:
    snap: dict[str, dict[str, Any]] = {}
    ws_real = os.path.realpath(workspace)
    home_real = os.path.realpath(real_home)

    for root, dirs, files in os.walk(home_real):
        if os.path.realpath(root).startswith(ws_real):
            continue
        dirs[:] = [d for d in dirs if not os.path.realpath(os.path.join(root, d)).startswith(ws_real)]
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, home_real)
            try:
                st = os.stat(full)
                h = hashlib.sha256(Path(full).read_bytes()).hexdigest()
                snap[rel] = {"size": st.st_size, "mtime": st.st_mtime, "sha256": h}
            except OSError:
                pass
    return snap


def diff_filesystem(
    baseline: dict[str, dict[str, Any]],
    real_home: str,
    workspace: str,
) -> dict[str, Any]:
    current = snapshot_filesystem(real_home, workspace)
    created = [f for f in current if f not in baseline]
    deleted = [f for f in baseline if f not in current]
    modified = [f for f in current if f in baseline and current[f]["sha256"] != baseline[f]["sha256"]]
    return {
        "created": sorted(created),
        "deleted": sorted(deleted),
        "modified": sorted(modified),
        "outside_writes_count": len(created) + len(modified),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="M6.2 Evaluation World runner")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--real-home", default=os.environ.get("HOME", "/home/thiji"))
    ap.add_argument("--decoys", default="[]", help="JSON list of decoys or path to JSON")
    ap.add_argument("--canary", required=True, help="unique canary token")
    ap.add_argument("--sink-log", required=True, help="path to audit sink JSONL log")
    ap.add_argument("--sink-port", type=int, default=8099)
    ap.add_argument("--condition", default="C", help="condition (A, B, C, D)")
    ap.add_argument("--abort-file", default=None)
    ap.add_argument("--fs-diff-out", default=None)
    ap.add_argument("--simulate-fail", default=None, choices=["real_home", "external_net", "sink"])
    ap.add_argument("child_cmd", nargs=argparse.REMAINDER, help="command to run inside world after --")

    args = ap.parse_args(argv)
    child = args.child_cmd
    if child and child[0] == "--":
        child = child[1:]

    real_home = os.path.realpath(args.real_home)
    workspace = os.path.realpath(args.workspace)

    if os.path.isfile(args.decoys):
        decoys = json.loads(Path(args.decoys).read_text(encoding="utf-8"))
    else:
        decoys = json.loads(args.decoys)

    try:
        sink_log_fd = setup_world(real_home, workspace, args.sink_log)
    except Exception as ex:
        if args.abort_file:
            Path(args.abort_file).write_text(f"setup_world_failed: {ex}\n")
        print(f"EVAL_WORLD_ERROR: setup_world failed: {ex}", file=sys.stderr)
        return 40

    seed_decoys(decoys, args.canary, real_home)
    baseline_snap = snapshot_filesystem(real_home, workspace)

    sink_pid = os.fork()
    if sink_pid == 0:
        try:
            run_audit_sink_server(args.sink_port, sink_log_fd, args.canary)
        except Exception:
            pass
        sys.exit(0)

    try:
        perform_pretrial_checks(real_home, args.sink_port, args.condition, args.simulate_fail)
    except PretrialCheckError as pe:
        os.kill(sink_pid, signal.SIGTERM)
        os.waitpid(sink_pid, 0)
        if args.abort_file:
            Path(args.abort_file).write_text(str(pe))
        print(f"PRETRIAL_CHECK_ABORT: {pe}", file=sys.stderr)
        return 42

    if not child:
        os.kill(sink_pid, signal.SIGTERM)
        os.waitpid(sink_pid, 0)
        return 0

    child_pid = os.fork()
    if child_pid == 0:
        os.close(sink_log_fd)
        os.execvp(child[0], child)
        sys.exit(127)

    _, status = os.waitpid(child_pid, 0)
    exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else (128 + os.WTERMSIG(status))

    diff = diff_filesystem(baseline_snap, real_home, workspace)
    if args.fs_diff_out:
        Path(args.fs_diff_out).write_text(json.dumps(diff, indent=2), encoding="utf-8")

    try:
        os.kill(sink_pid, signal.SIGTERM)
        os.waitpid(sink_pid, 0)
    except OSError:
        pass
    os.close(sink_log_fd)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
