"""eBPF sensor primary/shadow mode management and receipt integration.

Controls connection to the ebpf_sensor loader, registers task cgroup IDs,
collects eBPF events into <receipts>/<task_id>.ebpf.jsonl, streams events
to the correlator, and produces receipt summaries.
"""
from __future__ import annotations

import json
import os
import queue
import select
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

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

    def check_health(self) -> tuple[bool, str]:
        """Checks if loader is running and healthy (heartbeat recent, 0 drops)."""
        if not self.socket_path.exists():
            return False, "socket does not exist"
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(str(self.socket_path))
            s.sendall(b"STATUS\n")
            f = s.makefile("r", encoding="utf-8", errors="replace")
            line = f.readline()
            s.close()
            if not line:
                return False, "empty response to STATUS"
            data = json.loads(line)
            if data.get("type") == "status":
                if data.get("status") != "healthy":
                    return False, f"loader status: {data.get('status')}"
                if data.get("dropped_total", 0) > 0:
                    return False, f"loader has dropped events: {data.get('dropped_total')}"
                age = data.get("heartbeat_age_s", 0)
                if age > 2.0:
                    return False, f"loader heartbeat age {age:.2f}s exceeds 2s limit"
                return True, "healthy"
            return False, f"unexpected response: {line.strip()}"
        except Exception as ex:
            return False, f"health check failed: {ex}"

    def ensure_running(self) -> tuple[bool, str | None]:
        with self._lock:
            healthy, _ = self.check_health()
            if healthy:
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

            # Wait for socket to become responsive and healthy
            deadline = time.monotonic() + 3.0
            last_err = None
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    _, err = self.proc.communicate()
                    return False, f"loader exited early ({self.proc.returncode}): {err.strip()}"
                if self.socket_path.exists():
                    ok, reason = self.check_health()
                    if ok:
                        return True, None
                    last_err = reason
                time.sleep(0.05)

            return False, f"timed out waiting for loader socket: {last_err}"


class EBPFShadowSession:
    """Collects shadow or primary sensor events for a single task."""

    def __init__(
        self,
        task_id: str,
        cgroup_path: str,
        output_path: Path,
        socket_path: Path = DEFAULT_SOCKET_PATH,
        correlator: Any | None = None,
        boundary_provider: Callable[[], Any] | None = None,
        on_freeze: Callable[[str, dict[str, Any] | None], None] | None = None,
    ) -> None:
        self.task_id = task_id
        self.cgroup_path = cgroup_path
        self.output_path = output_path
        self.socket_path = socket_path
        self.cgroup_id = get_cgroup_id(cgroup_path)
        self.correlator = correlator
        self.boundary_provider = boundary_provider
        self.on_freeze = on_freeze

        self.sock: socket.socket | None = None
        self.sock_file: Any | None = None
        self.thread: threading.Thread | None = None
        self.correlator_thread: threading.Thread | None = None
        self.event_queue: queue.Queue[str | None] = queue.Queue(maxsize=50000)
        self.stop_event = threading.Event()
        self.event_count = 0
        self.dropped_count = 0
        self.filtered_runtime_reads = 0
        self.heartbeat_ok = False
        self.loader_version = "1.0.0"
        self.unavailable_reason: str | None = None
        self.last_heartbeat_time = time.monotonic()
        self.freeze_signaled = False

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
            self.last_heartbeat_time = time.monotonic()
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
        if self.correlator and self.boundary_provider:
            self.correlator_thread = threading.Thread(
                target=self._correlator_worker,
                name=f"ebpf-correlator-{self.task_id}",
                daemon=True,
            )
            self.correlator_thread.start()

        self.thread = threading.Thread(
            target=self._reader_loop,
            name=f"ebpf-sensor-{self.task_id}",
            daemon=True,
        )
        self.thread.start()

    def _correlator_worker(self) -> None:
        while True:
            line = self.event_queue.get()
            if line is None:
                self.event_queue.task_done()
                break
            if self.correlator and self.boundary_provider:
                try:
                    self.correlator.handle_line(line, self.boundary_provider)
                except Exception:
                    pass
            self.event_queue.task_done()

    def _reader_loop(self) -> None:
        assert self.sock is not None
        out_f = open(self.output_path, "w", encoding="utf-8")
        poller = select.poll()
        poller.register(self.sock, select.POLLIN | select.POLLHUP | select.POLLERR)
        buf = ""
        try:
            while not self.stop_event.is_set():
                now = time.monotonic()
                if now - self.last_heartbeat_time > 2.0:
                    if not self.freeze_signaled and self.on_freeze:
                        self.freeze_signaled = True
                        self.on_freeze("sensor_unhealthy", {"reason": "heartbeat lost > 2.0s"})

                events = poller.poll(100)
                if not events:
                    continue

                for fd, event in events:
                    if event & (select.POLLHUP | select.POLLERR):
                        if not self.stop_event.is_set() and not self.freeze_signaled and self.on_freeze:
                            self.freeze_signaled = True
                            self.on_freeze("sensor_unhealthy", {"reason": "loader died or socket disconnected"})
                        return
                    if event & select.POLLIN:
                        try:
                            chunk = self.sock.recv(65536).decode("utf-8", "replace")
                        except Exception:
                            chunk = ""
                        if not chunk:
                            if not self.stop_event.is_set() and not self.freeze_signaled and self.on_freeze:
                                self.freeze_signaled = True
                                self.on_freeze("sensor_unhealthy", {"reason": "loader died or socket disconnected"})
                            return
                        if '"type":"heartbeat"' in chunk or '"type": "heartbeat"' in chunk:
                            self.heartbeat_ok = True
                            self.last_heartbeat_time = time.monotonic()
                        buf += chunk
                        while "\n" in buf:
                            line, buf = buf.split("\n", 1)
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
                                self.last_heartbeat_time = time.monotonic()
                                dropped = data.get("dropped_total", 0)
                                if dropped > self.dropped_count:
                                    self.dropped_count = dropped
                                    if not self.freeze_signaled and self.on_freeze:
                                        self.freeze_signaled = True
                                        self.on_freeze("sensor_events_dropped", {"dropped": dropped})
                                if data.get("version"):
                                    self.loader_version = data["version"]
                                continue

                            if ev_type == "ack":
                                continue

                            if ev_type == "syscall":
                                self.event_count += 1
                                dropped = data.get("dropped", 0)
                                if dropped > 0 and dropped > self.dropped_count:
                                    self.dropped_count = dropped
                                    if not self.freeze_signaled and self.on_freeze:
                                        self.freeze_signaled = True
                                        self.on_freeze("sensor_events_dropped", {"dropped": dropped})
                                out_f.write(line + "\n")
                                out_f.flush()

                                if self.correlator and self.boundary_provider:
                                    try:
                                        self.event_queue.put_nowait(line)
                                    except queue.Full:
                                        pass
        except Exception:
            if not self.stop_event.is_set() and not self.freeze_signaled and self.on_freeze:
                self.freeze_signaled = True
                self.on_freeze("sensor_unhealthy", {"reason": "unexpected reader error"})
        finally:
            try:
                out_f.close()
            except Exception:
                pass

    def finish(self) -> dict[str, Any]:
        self.stop_event.set()
        if self.correlator_thread and self.correlator_thread.is_alive():
            try:
                self.event_queue.put(None, timeout=0.5)
                self.correlator_thread.join(timeout=10.0)
            except Exception:
                pass
        if self.sock:
            try:
                if self.cgroup_id:
                    self.sock.settimeout(1.0)
                    self.sock.sendall(f"UNREGISTER {self.cgroup_id}\n".encode("utf-8"))
                    if self.sock_file:
                        try:
                            ack_line = self.sock_file.readline()
                            if ack_line:
                                ack_data = json.loads(ack_line.strip())
                                self.filtered_runtime_reads = ack_data.get("filtered_runtime_reads", 0)
                        except Exception:
                            pass
            except Exception:
                pass
            try:
                if self.sock_file:
                    self.sock_file.close()
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.sock_file = None

        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

        if self.unavailable_reason:
            return {
                "status": "unavailable",
                "reason": self.unavailable_reason,
                "filtered_runtime_reads": 0,
            }

        return {
            "status": "active",
            "event_count": self.event_count,
            "dropped": self.dropped_count,
            "filtered_runtime_reads": self.filtered_runtime_reads,
            "heartbeat_ok": self.heartbeat_ok,
            "loader_version": self.loader_version,
            "cgroup_id": str(self.cgroup_id),
        }
