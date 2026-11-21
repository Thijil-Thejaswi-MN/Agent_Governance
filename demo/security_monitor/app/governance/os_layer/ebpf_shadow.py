"""eBPF sensor shadow mode management and receipt integration.

Operates only when GOVERNANCE_EBPF_SHADOW=1.
Starts or connects to the ebpf_sensor loader, registers task cgroup IDs,
collects eBPF events into <receipts>/<task_id>.ebpf.jsonl, and produces
a receipt summary.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
EBPF_DIR = HERE / "ebpf"
EBPF_SENSOR_BIN = EBPF_DIR / "ebpf_sensor"
DEFAULT_SOCKET_DIR = Path.home() / ".ebpf_sensor"
DEFAULT_SOCKET_PATH = DEFAULT_SOCKET_DIR / "ebpf_sensor.sock"


def is_ebpf_shadow_enabled() -> bool:
    return os.environ.get("GOVERNANCE_EBPF_SHADOW", "").strip() == "1"


def get_cgroup_id(cgroup_path: str) -> int | None:
    """Reads the 64-bit cgroup inode id from /sys/fs/cgroup/<path>."""
    full_path = Path("/sys/fs/cgroup") / cgroup_path.lstrip("/")
    try:
        st = os.stat(full_path)
        return st.st_ino
    except OSError:
        return None


class EBPFShadowManager:
    """Manages the background ebpf_sensor loader process."""

    _instance: "EBPFShadowManager | None" = None
    _lock = threading.Lock()

    def __init__(self, socket_path: Path = DEFAULT_SOCKET_PATH) -> None:
        self.socket_path = socket_path
        self.proc: subprocess.Popen | None = None

    @classmethod
    def get_instance(cls) -> "EBPFShadowManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def is_alive(self) -> bool:
        if not self.socket_path.exists():
            return False
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(str(self.socket_path))
            s.sendall(b"PING\n")
            data = s.recv(256)
            s.close()
            return b"pong" in data
        except Exception:
            return False

    def ensure_running(self) -> tuple[bool, str | None]:
        with self._lock:
            if self.is_alive():
                return True, None

            if not EBPF_SENSOR_BIN.exists():
                return False, f"loader binary not found at {EBPF_SENSOR_BIN}"

            if not os.access(EBPF_SENSOR_BIN, os.X_OK):
                return False, f"loader binary not executable: {EBPF_SENSOR_BIN}"

            # Ensure socket directory exists with user-only permissions (0700)
            try:
                self.socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(self.socket_path.parent, 0o700)
            except OSError:
                pass

            # Remove stale socket file if present
            try:
                if self.socket_path.exists():
                    self.socket_path.unlink()
            except OSError:
                pass

            try:
                cmd = [str(EBPF_SENSOR_BIN), "--socket", str(self.socket_path)]
                self.proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            except Exception as e:
                return False, f"failed to spawn loader: {e}"

            # Wait for socket to become responsive
            deadline = time.monotonic() + 3.0
            last_err = None
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    _, err = self.proc.communicate()
                    return False, f"loader exited early ({self.proc.returncode}): {err.strip()}"
                if self.socket_path.exists():
                    try:
                        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(str(self.socket_path))
                        s.sendall(b"PING\n")
                        data = s.recv(256)
                        s.close()
                        if b"pong" in data:
                            return True, None
                    except Exception as ex:
                        last_err = str(ex)
                time.sleep(0.05)

            return False, f"timed out waiting for loader socket: {last_err}"


class EBPFShadowSession:
    """Collects shadow events for a single task."""

    def __init__(
        self,
        task_id: str,
        cgroup_path: str,
        output_path: Path,
        socket_path: Path = DEFAULT_SOCKET_PATH,
    ) -> None:
        self.task_id = task_id
        self.cgroup_path = cgroup_path
        self.output_path = output_path
        self.socket_path = socket_path
        self.cgroup_id = get_cgroup_id(cgroup_path)

        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()

        self.event_count = 0
        self.dropped_count = 0
        self.heartbeat_ok = False
        self.loader_version = "1.0.0"
        self.unavailable_reason: str | None = None

    def start(self) -> None:
        if self.cgroup_id is None:
            self.unavailable_reason = f"cannot determine cgroup id for {self.cgroup_path}"
            return

        manager = EBPFShadowManager.get_instance()
        ok, reason = manager.ensure_running()
        if not ok:
            self.unavailable_reason = reason
            return

        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(2.0)
            self.sock.connect(str(self.socket_path))
            cmd = f"REGISTER {self.cgroup_id}\n"
            self.sock.sendall(cmd.encode("utf-8"))
        except Exception as ex:
            self.unavailable_reason = f"socket connection error: {ex}"
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
            return

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.thread = threading.Thread(
            target=self._reader_loop,
            name=f"ebpf-shadow-{self.task_id}",
            daemon=True,
        )
        self.thread.start()

    def _reader_loop(self) -> None:
        assert self.sock is not None
        out_f = open(self.output_path, "w", encoding="utf-8")
        sock_file = self.sock.makefile("r", encoding="utf-8", errors="replace")
        try:
            while not self.stop_event.is_set():
                line = sock_file.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                ev_type = data.get("type")
                if ev_type == "heartbeat":
                    self.heartbeat_ok = True
                    self.dropped_count = data.get("dropped_total", self.dropped_count)
                    if data.get("version"):
                        self.loader_version = data["version"]
                    continue
                if ev_type == "ack":
                    continue

                if ev_type == "syscall":
                    self.event_count += 1
                    self.dropped_count = data.get("dropped", self.dropped_count)
                    out_f.write(line + "\n")
                    out_f.flush()
        except Exception:
            pass
        finally:
            try:
                sock_file.close()
            except Exception:
                pass
            try:
                out_f.close()
            except Exception:
                pass

    def finish(self) -> dict[str, Any]:
        self.stop_event.set()
        if self.sock:
            try:
                if self.cgroup_id:
                    self.sock.sendall(f"UNREGISTER {self.cgroup_id}\n".encode("utf-8"))
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

        if self.unavailable_reason:
            return {
                "status": "unavailable",
                "reason": self.unavailable_reason,
            }

        return {
            "status": "active",
            "event_count": self.event_count,
            "dropped": self.dropped_count,
            "heartbeat_ok": self.heartbeat_ok,
            "loader_version": self.loader_version,
            "cgroup_id": str(self.cgroup_id),
        }
