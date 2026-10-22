"""Unix Socket Proxy Mitigation for Landlock Port-Only Limitations.

In Landlock ABI >= 4, TCP access control is port-based rather than destination IP-based:
granting access to port 8080 permits connecting to *any* host listening on 8080.

This module provides the non-root Unix Domain Socket proxy mitigation:
1. The governance egress proxy exposes a local Unix domain socket file at <workspace>/proxy.sock.
2. In Landlock, filesystem access to <workspace>/proxy.sock is permitted (read+write).
3. Landlock network rules declare handled_access_net (TCP connect and bind) but grant NO TCP ports.
4. Consequence: ALL direct TCP sockets fail with EPERM, while the proxy is fully accessible via UDS.
"""
from __future__ import annotations

import asyncio
import os
import socket
import threading
from pathlib import Path
from typing import Callable


class UnixSocketProxyBridge:
    """Bridges a local Unix domain socket inside the task workspace to the governance gateway."""

    def __init__(self, socket_path: str | Path, upstream_host: str = "127.0.0.1", upstream_port: int = 8000) -> None:
        self.socket_path = Path(socket_path)
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.server_sock: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Starts the Unix domain socket forwarder in a background thread."""
        if self.socket_path.exists():
            self.socket_path.unlink()

        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_sock.bind(str(self.socket_path))
        self.server_sock.listen(16)
        self._running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                client_conn, _ = self.server_sock.accept()
                threading.Thread(target=self._forward_conn, args=(client_conn,), daemon=True).start()
            except Exception:
                break

    def _forward_conn(self, client_conn: socket.socket) -> None:
        try:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.connect((self.upstream_host, self.upstream_port))

            def pipe(src: socket.socket, dst: socket.socket) -> None:
                try:
                    while True:
                        data = src.recv(4096)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception:
                    pass
                finally:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass

            t1 = threading.Thread(target=pipe, args=(client_conn, upstream), daemon=True)
            t2 = threading.Thread(target=pipe, args=(upstream, client_conn), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception:
            pass
        finally:
            client_conn.close()

    def stop(self) -> None:
        """Stops the bridge and removes the socket file."""
        self._running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except Exception:
                pass
