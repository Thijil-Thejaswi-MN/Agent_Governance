"""Egress Network Proxy (F5.2).

Shared local HTTP forward/tunnel proxy authenticating via Proxy-Authorization: Bearer <task_token>.
Enforces destination network boundary on both hostname and resolved IP,
rejects unlisted destinations before opening tunnels, records all events (source="EGRESS_PROXY"),
and feeds the Agent Inventory (F10).
"""
from __future__ import annotations

import asyncio
import datetime
import fnmatch
import logging
import socket
import time
from typing import Any
from urllib.parse import urlparse

from .models import (
    EventSource,
    GovernanceEvent,
    RiskTier,
    TaskAction,
    EventVerdict,
)
from .storage import GovernanceStorage
from .evaluator import BoundaryEvaluator
from .policy import TaskPolicyEngine
from .single_use import consume_single_use

logger = logging.getLogger(__name__)


class _EmptyResponseError(Exception):
    """Raised when upstream closes before sending any response bytes."""
    pass


class EgressProxyServer:
    """Asyncio HTTP CONNECT proxy enforcing task-boundary network rules."""

    def __init__(
        self,
        storage: GovernanceStorage,
        evaluator: BoundaryEvaluator | None = None,
        policy_engine: TaskPolicyEngine | None = None,
        host: str = "127.0.0.1",
        port: int = 0,  # 0 = dynamic available port
    ) -> None:
        self.storage = storage
        self.evaluator = evaluator or BoundaryEvaluator()
        self.policy_engine = policy_engine or TaskPolicyEngine()
        self.host = host
        self.port = port
        self.server: asyncio.Server | None = None
        self._is_running = False
        self._event_counter = 0
        self._client_tasks: set[asyncio.Task] = set()
        self.header_timeout: float = 10.0
        self.max_headers: int = 100
        self.max_line_length: int = 8192
        self.max_content_length: int = 1024 * 1024
        self._dns_cache: dict[str, tuple[list[str], float]] = {}
        self._upstream_pool: dict[tuple[str, int], list[tuple[asyncio.StreamReader, asyncio.StreamWriter, float]]] = {}
        self._active_tunnels: dict[str, list[dict[str, Any]]] = {}

    def close_tunnels(self, task_id: str, target: str | None = None) -> int:
        """Closes active CONNECT tunnels for task_id, optionally matching target."""
        closed = 0
        tunnels = self._active_tunnels.get(task_id, [])
        remaining = []
        for tun in tunnels:
            t_match = (
                target is None
                or tun["target"] == target
                or tun["target"].startswith(target)
                or target in tun["target"]
            )
            if t_match:
                closed += 1
                for w in tun.get("writers", []):
                    try:
                        w.close()
                    except Exception:
                        pass
            else:
                remaining.append(tun)
        if remaining:
            self._active_tunnels[task_id] = remaining
        else:
            self._active_tunnels.pop(task_id, None)
        return closed

    def cache_dns(self, host: str, ips: list[str], ttl: int = 60) -> None:
        """Explicitly caches DNS resolution with TTL clamped between 5 s and 300 s."""
        clamped_ttl = max(5, min(300, ttl))
        expire_at = time.monotonic() + clamped_ttl
        self._dns_cache[host.lower()] = (list(ips), expire_at)

    async def _resolve_host(self, host: str, port: int) -> list[str]:
        """Resolves destination host using DNS cache with clamped TTL [5s, 300s]."""
        try:
            socket.inet_aton(host)
            return [host]
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return [host]
        except OSError:
            pass

        now = time.monotonic()
        cached = self._dns_cache.get(host.lower())
        if cached:
            ips, expire_at = cached
            if now < expire_at:
                return list(ips)

        resolved_ips: list[str] = []
        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            for item in addr_info:
                ip = item[4][0]
                if ip not in resolved_ips:
                    resolved_ips.append(ip)
        except Exception:
            pass

        if resolved_ips:
            self.cache_dns(host, resolved_ips, ttl=60)
        return resolved_ips

    async def _get_upstream_conn(
        self, ip: str, port: int, allow_pool: bool = True
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bool]:
        if allow_pool:
            pool = self._upstream_pool.setdefault((ip, port), [])
            now = time.monotonic()
            while pool:
                r, w, ts = pool.pop()
                if (now - ts) > 30.0 or r.at_eof() or w.is_closing():
                    try:
                        w.close()
                    except Exception:
                        pass
                    continue
                return r, w, True
        r, w = await asyncio.open_connection(ip, port)
        return r, w, False

    def _release_upstream_conn(
        self, ip: str, port: int, r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        now = time.monotonic()
        pool = self._upstream_pool.setdefault((ip, port), [])
        surviving: list[tuple[asyncio.StreamReader, asyncio.StreamWriter, float]] = []
        for pr, pw, ts in pool:
            if (now - ts) > 30.0 or pr.at_eof() or pw.is_closing():
                try:
                    pw.close()
                except Exception:
                    pass
            else:
                surviving.append((pr, pw, ts))
        pool = surviving

        if not r.at_eof() and not w.is_closing() and len(pool) < 8:
            pool.append((r, w, now))
            self._upstream_pool[(ip, port)] = pool
        else:
            try:
                w.close()
            except Exception:
                pass
            self._upstream_pool[(ip, port)] = pool

    async def _forward_http_response(
        self,
        remote_reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        request_method: str = "GET",
    ) -> bool:
        while True:
            status_line = await remote_reader.readline()
            if not status_line:
                raise _EmptyResponseError("empty status line")

            parts = status_line.strip().split()
            if len(parts) < 2:
                return False
            try:
                status_code = int(parts[1])
            except ValueError:
                return False

            writer.write(status_line)

            headers: dict[str, str] = {}
            while True:
                line = await remote_reader.readline()
                if not line:
                    return False
                writer.write(line)
                if line == b"\r\n" or line == b"\n":
                    break
                line_str = line.decode("latin1", errors="replace").strip()
                if ":" in line_str:
                    k, v = line_str.split(":", 1)
                    headers[k.lower()] = v.strip()
            await writer.drain()

            if 100 <= status_code < 200 and status_code != 101:
                continue

            break

        is_head = (request_method.upper() == "HEAD")
        has_no_body = is_head or (status_code in (204, 304)) or (100 <= status_code < 200)
        conn_header = headers.get("connection", "").lower()

        if status_code == 101:
            # Protocol switch: this connection is no longer HTTP/1.1; never pool or reuse it.
            return False
        if has_no_body:
            return conn_header != "close"

        te = headers.get("transfer-encoding", "").lower()
        cl_str = headers.get("content-length")

        if "chunked" in te:
            while True:
                chunk_header = await remote_reader.readline()
                if not chunk_header:
                    return False
                writer.write(chunk_header)
                chunk_len_str = chunk_header.strip().split(b";")[0]
                try:
                    chunk_len = int(chunk_len_str, 16)
                except ValueError:
                    return False
                if chunk_len == 0:
                    while True:
                        trailer_line = await remote_reader.readline()
                        if not trailer_line:
                            return False
                        writer.write(trailer_line)
                        if trailer_line == b"\r\n" or trailer_line == b"\n":
                            break
                    await writer.drain()
                    break
                data = await remote_reader.readexactly(chunk_len + 2)
                writer.write(data)
                await writer.drain()
            return conn_header != "close"
        elif cl_str is not None:
            try:
                cl = int(cl_str.strip())
            except ValueError:
                cl = 0
            if cl > 0:
                data = await remote_reader.readexactly(cl)
                writer.write(data)
                await writer.drain()
            return conn_header != "close"
        else:
            while True:
                data = await remote_reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
            return False

    @property
    def listening_port(self) -> int:
        if self.server and self.server.sockets:
            return self.server.sockets[0].getsockname()[1]
        return self.port

    def _generate_event_id(self) -> str:
        self._event_counter += 1
        return f"evt_proxy_{self._event_counter:04d}_{datetime.datetime.now().strftime('%f')}"

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self._is_running = True
        actual_port = self.listening_port
        logger.info(f"Egress Proxy listening on {self.host}:{actual_port}")
        return actual_port

    async def stop(self) -> None:
        self._is_running = False
        if self._client_tasks:
            for task in list(self._client_tasks):
                if not task.done():
                    task.cancel()
            await asyncio.gather(*list(self._client_tasks), return_exceptions=True)
            self._client_tasks.clear()
        for pool in self._upstream_pool.values():
            for item in pool:
                try:
                    item[1].close()
                except Exception:
                    pass
        self._upstream_pool.clear()
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass

    def _record_proxy_event(
        self,
        task_id: str | None,
        agent_id: str,
        target: str,
        verdict: EventVerdict,
        risk_tier: RiskTier,
        prevented: bool,
        rule_matched: str,
        boundary_version: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        evt = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.EGRESS_PROXY,
            task_id=task_id,
            agent_id=agent_id,
            pid=None,
            kind="network_egress",
            target=target,
            details=details or {},
            verdict=verdict,
            risk_tier=risk_tier,
            action_taken=TaskAction.BLOCK_ACTION,
            prevented=prevented,
            rule_matched=rule_matched,
            boundary_version=boundary_version,
        )
        self.storage.record_event(evt)

    async def _drain_and_close(self, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(writer.drain(), timeout=1.0)
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _ensure_scoped_state(self) -> tuple[Any, dict[str, dict[str, Any]]]:
        import threading
        lock = getattr(self, "_scope_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._scope_lock = lock
        tokens = getattr(self, "_scoped_tokens", None)
        if tokens is None:
            tokens = {}
            self._scoped_tokens = tokens
        return lock, tokens

    def grant_scoped_egress(
        self,
        token: str,
        *,
        task_id: str | None,
        agent_id: str,
        allowed_host: str,
        allowed_port: int,
        require_connect: bool = True,
    ) -> None:
        """Opens temporary egress ONLY to (allowed_host, allowed_port) for this proxy token."""
        lock, tokens = self._ensure_scoped_state()
        with lock:
            tokens[token] = {
                "task_id": task_id,
                "agent_id": agent_id,
                "allowed_host": (allowed_host or "").strip().strip("[]").lower(),
                "allowed_port": int(allowed_port),
                "require_connect": bool(require_connect),
            }

    def revoke_scoped_egress(self, token: str) -> None:
        lock, tokens = self._ensure_scoped_state()
        with lock:
            tokens.pop(token, None)
        self.close_tunnels_for_token(token)

    def close_tunnels_for_token(self, token: str) -> None:
        for tid, tuns in list(self._active_tunnels.items()):
            remaining = []
            for t in tuns:
                if t.get("token") == token:
                    for w in t.get("writers", []):
                        try:
                            w.close()
                        except Exception:
                            pass
                else:
                    remaining.append(t)
            if remaining:
                self._active_tunnels[tid] = remaining
            else:
                self._active_tunnels.pop(tid, None)

    def _get_scoped_egress(self, token: str) -> dict[str, Any] | None:
        lock, tokens = self._ensure_scoped_state()
        with lock:
            item = tokens.get(token)
            return dict(item) if item else None

    def _is_proxy_token_active(self, token: str) -> bool:
        scoped = self._get_scoped_egress(token)
        if scoped is not None:
            return True
        return bool(self.storage.lookup_task_by_token(token))

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        curr_task = asyncio.current_task()
        if curr_task is not None:
            self._client_tasks.add(curr_task)
            curr_task.add_done_callback(self._client_tasks.discard)
        try:
            is_first_req = True
            while self._is_running:
                headers: dict[str, str] = {}
                header_count = 0

                async def _read_request_headers() -> tuple[str, str, str, dict[str, str]]:
                    nonlocal header_count
                    reader._limit = self.max_line_length
                    try:
                        line = await reader.readline()
                    except (ValueError, asyncio.LimitOverrunError):
                        raise ValueError("line_too_long")
                    if not line:
                        return "", "", "", {}
                    if len(line) > self.max_line_length:
                        raise ValueError("line_too_long")

                    req_line = line.decode("utf-8", errors="replace").strip()
                    parts = req_line.split()
                    if len(parts) < 3:
                        return "", "", "", {}
                    method, target, version = parts[0], parts[1], parts[2]

                    while True:
                        try:
                            header_line = await reader.readline()
                        except (ValueError, asyncio.LimitOverrunError):
                            raise ValueError("line_too_long")
                        if not header_line or header_line == b"\r\n" or header_line == b"\n":
                            break
                        if len(header_line) > self.max_line_length:
                            raise ValueError("line_too_long")
                        header_count += 1
                        if header_count > self.max_headers:
                            raise ValueError("too_many_headers")
                        decoded = header_line.decode("utf-8", errors="replace").strip()
                        if ":" in decoded:
                            k, v = decoded.split(":", 1)
                            headers[k.strip().lower()] = v.strip()

                    return method, target, version, headers

                try:
                    method, target, version, headers = await asyncio.wait_for(
                        _read_request_headers(), timeout=self.header_timeout
                    )
                except asyncio.TimeoutError:
                    if is_first_req or headers or header_count > 0:
                        self._record_proxy_event(
                            task_id=None,
                            agent_id="UNATTRIBUTED",
                            target="proxy_headers",
                            verdict=EventVerdict.OUTSIDE,
                            risk_tier=RiskTier.HIGH,
                            prevented=True,
                            rule_matched="request line and headers deadline exceeded (10s)",
                        )
                        writer.write(b"HTTP/1.1 408 Request Timeout\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nRequest Timeout\r\n")
                        await self._drain_and_close(writer)
                    return
                except ValueError as ve:
                    err_code = str(ve)
                    if err_code == "line_too_long":
                        self._record_proxy_event(
                            task_id=None,
                            agent_id="UNATTRIBUTED",
                            target="proxy_headers",
                            verdict=EventVerdict.OUTSIDE,
                            risk_tier=RiskTier.HIGH,
                            prevented=True,
                            rule_matched="header line exceeded 8 KB limit",
                        )
                        writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nLine too long\r\n")
                        await self._drain_and_close(writer)
                        return
                    elif err_code == "too_many_headers":
                        self._record_proxy_event(
                            task_id=None,
                            agent_id="UNATTRIBUTED",
                            target="proxy_headers",
                            verdict=EventVerdict.OUTSIDE,
                            risk_tier=RiskTier.HIGH,
                            prevented=True,
                            rule_matched="header line count exceeded limit (100)",
                        )
                        writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nToo many headers\r\n")
                        await self._drain_and_close(writer)
                        return
                    return

                if not method or not target:
                    return

                # Check Content-Length limits
                if "content-length" in headers:
                    cl_raw = headers.get("content-length", "").strip()
                    if not (cl_raw.isascii() and cl_raw.isdigit()):
                        self._record_proxy_event(
                            task_id=None,
                            agent_id="UNATTRIBUTED",
                            target="content-length",
                            verdict=EventVerdict.OUTSIDE,
                            risk_tier=RiskTier.HIGH,
                            prevented=True,
                            rule_matched="non-integer Content-Length",
                        )
                        writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nInvalid Content-Length\r\n")
                        await self._drain_and_close(writer)
                        return
                    cl = int(cl_raw)

                    if cl > self.max_content_length:
                        self._record_proxy_event(
                            task_id=None,
                            agent_id="UNATTRIBUTED",
                            target="content-length",
                            verdict=EventVerdict.OUTSIDE,
                            risk_tier=RiskTier.HIGH,
                            prevented=True,
                            rule_matched="Content-Length exceeded 1 MB limit",
                        )
                        writer.write(b"HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nContent-Length exceeded 1 MB\r\n")
                        await self._drain_and_close(writer)
                        return

                # 1. Authenticate task token from Proxy-Authorization
                proxy_auth = headers.get("proxy-authorization", "")
                task_token = ""
                if proxy_auth.lower().startswith("bearer "):
                    task_token = proxy_auth[7:].strip()

                task_id = None
                agent_id = "UNATTRIBUTED"
                boundary = None
                scoped_egress = None

                if task_token:
                    scoped_egress = self._get_scoped_egress(task_token)
                    if scoped_egress is not None:
                        task_id = scoped_egress.get("task_id")
                        agent_id = scoped_egress.get("agent_id") or "outside_a2a_fetch"
                    else:
                        lookup = self.storage.lookup_task_by_token(task_token)
                        if lookup:
                            task_id, agent_id = lookup
                            boundary = self.storage.get_boundary(task_id)

                # Parse destination host and port
                if method.upper() == "CONNECT":
                    if target.startswith("["):
                        if "]:" in target:
                            h, p_str = target.split("]:", 1)
                            dst_host = h.lstrip("[")
                            dst_port_str = p_str
                        else:
                            dst_host = target.strip("[]")
                            dst_port_str = "443"
                    elif ":" in target:
                        if target.count(":") > 1:
                            dst_host = target
                            dst_port_str = "443"
                        else:
                            dst_host, dst_port_str = target.rsplit(":", 1)
                    else:
                        dst_host = target
                        dst_port_str = "443"
                    try:
                        dst_port = int(dst_port_str)
                    except ValueError:
                        dst_port = 443
                else:
                    parsed = urlparse(target)
                    dst_host = (parsed.hostname or headers.get("host", "").split(":")[0]).strip("[]")
                    dst_port = parsed.port or (443 if parsed.scheme == "https" else 80)

                target_formatted = f"[{dst_host}]:{dst_port}" if ":" in dst_host else f"{dst_host}:{dst_port}"

                # 2. If unauthenticated, reject with 407 and log UNATTRIBUTED event
                if scoped_egress is None and (not task_id or not boundary):
                    self._record_proxy_event(
                        task_id=None,
                        agent_id=agent_id,
                        target=target_formatted,
                        verdict=EventVerdict.OUTSIDE,
                        risk_tier=RiskTier.HIGH,
                        prevented=True,
                        rule_matched="unauthenticated proxy egress attempt",
                        boundary_version=None,
                        details={"method": method, "raw_target": target, "reason": "missing_or_invalid_proxy_auth"},
                    )
                    writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Bearer\r\n\r\n")
                    await self._drain_and_close(writer)
                    return

                # 3. Evaluate destination host and port against scoped A2A grant OR task boundary
                if scoped_egress is not None:
                    import ipaddress
                    import os
                    from .evaluator import EvaluationResult
                    allowed_host = scoped_egress["allowed_host"]
                    allowed_port = scoped_egress["allowed_port"]
                    control_port = int(os.environ.get("GOVERNANCE_CONTROL_PORT", 8000))
                    is_ctrl = (dst_host.lower() in ("localhost", "127.0.0.1", "::1") and dst_port == control_port)
                    method_ok = (not scoped_egress.get("require_connect")) or (method.upper() == "CONNECT")
                    host_port_ok = (dst_host.lower() == allowed_host and dst_port == allowed_port)
                    if is_ctrl or not method_ok or not host_port_ok:
                        rule = (
                            "control-plane port is never reachable from a task"
                            if is_ctrl
                            else (
                                "outside A2A scoped egress requires CONNECT"
                                if not method_ok
                                else f"unlisted outbound network destination (outside A2A scope allows only {allowed_host}:{allowed_port})"
                            )
                        )
                        self._record_proxy_event(
                            task_id=task_id,
                            agent_id=agent_id,
                            target=target_formatted,
                            verdict=EventVerdict.OUTSIDE,
                            risk_tier=RiskTier.HIGH,
                            prevented=True,
                            rule_matched=rule,
                            boundary_version=None,
                            details={
                                "method": method,
                                "dst_host": dst_host,
                                "dst_port": dst_port,
                                "rule_matched": rule,
                                "action_taken": TaskAction.BLOCK_ACTION.value,
                            },
                        )
                        writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nGovernance Proxy: Destination outside outside-A2A call scope\r\n")
                        await self._drain_and_close(writer)
                        return
                    eval_res = EvaluationResult(
                        verdict=EventVerdict.INSIDE,
                        risk_tier=RiskTier.LOW,
                        rule_matched=f"matched outside A2A scoped destination: {allowed_host}:{allowed_port}",
                        resolved_path=target_formatted,
                    )
                    action, prevented = TaskAction.ALLOW, False
                else:
                    eval_res = self.evaluator.evaluate_network(boundary, target_formatted)
                    action, prevented = self.policy_engine.decide(boundary, eval_res)
                    if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
                        self._record_proxy_event(
                            task_id=task_id,
                            agent_id=agent_id,
                            target=target_formatted,
                            verdict=eval_res.verdict,
                            risk_tier=eval_res.risk_tier,
                            prevented=prevented,
                            rule_matched=eval_res.rule_matched,
                            boundary_version=boundary.version if boundary else None,
                            details={
                                "method": method,
                                "dst_host": dst_host,
                                "dst_port": dst_port,
                                "rule_matched": eval_res.rule_matched,
                                "action_taken": action.value,
                            },
                        )
                        writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nGovernance Proxy: Destination outside task boundary\r\n")
                        await self._drain_and_close(writer)
                        return

                # 4. Resolve destination IP
                resolved_ips = await self._resolve_host(dst_host, dst_port)

                if not resolved_ips:
                    self._record_proxy_event(
                        task_id=task_id,
                        agent_id=agent_id,
                        target=target_formatted,
                        verdict=EventVerdict.OUTSIDE,
                        risk_tier=RiskTier.HIGH,
                        prevented=True,
                        rule_matched=f"DNS resolution failed for {dst_host}",
                        boundary_version=boundary.version if boundary else None,
                        details={"dst_host": dst_host, "dst_port": dst_port, "error": "DNS resolution returned no addresses"},
                    )
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nDNS resolution failed\r\n")
                    await self._drain_and_close(writer)
                    return

                target_connect_ip = resolved_ips[0]

                # 5. Evaluate the exact resolved IPs against task boundary (DNS rebinding check)
                is_ip_blocked = False
                if scoped_egress is not None:
                    allowed_is_loopback = scoped_egress["allowed_host"] in ("127.0.0.1", "::1", "localhost")
                    for r_ip in resolved_ips:
                        try:
                            ip_obj = ipaddress.ip_address(r_ip)
                            disallowed = (
                                (not allowed_is_loopback and (
                                    ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
                                ))
                                or (allowed_is_loopback and not ip_obj.is_loopback)
                            )
                        except ValueError:
                            disallowed = True
                        if disallowed:
                            rule = f"resolved IP {r_ip} blocked by outside A2A DNS-rebinding check for {dst_host}"
                            self._record_proxy_event(
                                task_id=task_id,
                                agent_id=agent_id,
                                target=target_formatted,
                                verdict=EventVerdict.OUTSIDE,
                                risk_tier=RiskTier.HIGH,
                                prevented=True,
                                rule_matched=rule,
                                boundary_version=None,
                                details={
                                    "method": method,
                                    "dst_host": dst_host,
                                    "dst_port": dst_port,
                                    "resolved_ip": r_ip,
                                    "rule_matched": rule,
                                    "action_taken": TaskAction.BLOCK_ACTION.value,
                                },
                            )
                            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nGovernance Proxy: Destination outside task boundary\r\n")
                            await self._drain_and_close(writer)
                            is_ip_blocked = True
                            break
                else:
                    for r_ip in resolved_ips:
                        r_formatted = f"[{r_ip}]:{dst_port}" if ":" in r_ip else f"{r_ip}:{dst_port}"
                        ip_eval = self.evaluator.evaluate_network(boundary, r_formatted)
                        if ip_eval.verdict == EventVerdict.OUTSIDE:
                            eval_res = ip_eval
                            action, prevented = self.policy_engine.decide(boundary, eval_res)
                            self._record_proxy_event(
                                task_id=task_id,
                                agent_id=agent_id,
                                target=target_formatted,
                                verdict=eval_res.verdict,
                                risk_tier=eval_res.risk_tier,
                                prevented=prevented,
                                rule_matched=eval_res.rule_matched,
                                boundary_version=boundary.version if boundary else None,
                                details={
                                    "method": method,
                                    "dst_host": dst_host,
                                    "dst_port": dst_port,
                                    "resolved_ip": r_ip,
                                    "rule_matched": eval_res.rule_matched,
                                    "action_taken": action.value,
                                },
                            )
                            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nGovernance Proxy: Destination outside task boundary\r\n")
                            await self._drain_and_close(writer)
                            is_ip_blocked = True
                            break

                if is_ip_blocked:
                    return

                # Record allowed GovernanceEvent
                evt = GovernanceEvent(
                    event_id=self._generate_event_id(),
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    source=EventSource.EGRESS_PROXY,
                    task_id=task_id,
                    agent_id=agent_id,
                    pid=None,
                    kind="network_egress",
                    target=target_formatted,
                    details={
                        "method": method,
                        "dst_host": dst_host,
                        "dst_port": dst_port,
                        "resolved_ips": resolved_ips,
                        "target_connect_ip": target_connect_ip,
                    },
                    verdict=eval_res.verdict,
                    risk_tier=eval_res.risk_tier,
                    action_taken=action,
                    prevented=prevented,
                    rule_matched=eval_res.rule_matched,
                    boundary_version=boundary.version if boundary else None,
                )
                self.storage.record_event(evt)

                # A single-use network grant is used up by this connection
                if boundary is not None:
                    consume_single_use(self.storage, boundary, "network", target_formatted)

                if method.upper() == "CONNECT":
                    try:
                        remote_reader, remote_writer = await asyncio.open_connection(target_connect_ip, dst_port)
                    except Exception as e:
                        writer.write(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{e}\r\n".encode("utf-8"))
                        await self._drain_and_close(writer)
                        return
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await writer.drain()

                    tun_entry = {"target": target_formatted, "writers": [writer, remote_writer], "token": task_token}
                    if task_id not in self._active_tunnels:
                        self._active_tunnels[task_id] = []
                    self._active_tunnels[task_id].append(tun_entry)

                    async def forward(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
                        try:
                            while True:
                                data = await src.read(4096)
                                if not data:
                                    break
                                if not self._is_proxy_token_active(task_token):
                                    break
                                dst.write(data)
                                await dst.drain()
                        except Exception:
                            pass
                        finally:
                            try:
                                dst.close()
                            except Exception:
                                pass

                    try:
                        await asyncio.gather(
                            forward(reader, remote_writer),
                            forward(remote_reader, writer),
                            return_exceptions=True,
                        )
                    finally:
                        tuns = self._active_tunnels.get(task_id, [])
                        if tun_entry in tuns:
                            tuns.remove(tun_entry)
                        if not tuns:
                            self._active_tunnels.pop(task_id, None)
                    return
                else:
                    req_te = headers.get("transfer-encoding", "").lower()
                    is_chunked_req = "chunked" in req_te
                    cl_raw = headers.get("content-length", "").strip()
                    req_cl = int(cl_raw) if (cl_raw and cl_raw.isascii() and cl_raw.isdigit()) else 0

                    parsed = urlparse(target)
                    upstream_path = parsed.path or "/"
                    if parsed.query:
                        upstream_path += f"?{parsed.query}"
                    req_line_bytes = f"{method} {upstream_path} {version}\r\n".encode("utf-8")

                    headers_bytes = bytearray()
                    for hk, hv in headers.items():
                        if hk not in ("proxy-authorization", "proxy-connection"):
                            headers_bytes.extend(f"{hk.title()}: {hv}\r\n".encode("utf-8"))
                    headers_bytes.extend(b"\r\n")

                    # Retry only requests without a body: the body was already read from the client.
                    can_retry = (not is_chunked_req) and req_cl == 0
                    allow_pool = not is_chunked_req

                    try:
                        remote_reader, remote_writer, is_pooled = await self._get_upstream_conn(
                            target_connect_ip, dst_port, allow_pool=allow_pool
                        )
                    except Exception as e:
                        writer.write(f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{e}\r\n".encode("utf-8"))
                        await self._drain_and_close(writer)
                        return

                    async def _send_req_data(r_writer: asyncio.StreamWriter) -> None:
                        r_writer.write(req_line_bytes)
                        r_writer.write(headers_bytes)
                        await r_writer.drain()
                        if is_chunked_req:
                            while True:
                                chunk_header = await reader.readline()
                                if not chunk_header:
                                    raise ValueError("client disconnected mid-chunk")
                                r_writer.write(chunk_header)
                                chunk_len_str = chunk_header.strip().split(b";")[0]
                                try:
                                    chunk_len = int(chunk_len_str, 16)
                                except ValueError:
                                    raise ValueError("invalid chunk length in request")
                                if chunk_len == 0:
                                    while True:
                                        trailer_line = await reader.readline()
                                        if not trailer_line:
                                            break
                                        r_writer.write(trailer_line)
                                        if trailer_line == b"\r\n" or trailer_line == b"\n":
                                            break
                                    await r_writer.drain()
                                    break
                                data = await reader.readexactly(chunk_len + 2)
                                r_writer.write(data)
                                await r_writer.drain()
                        elif req_cl > 0:
                            body_data = await reader.readexactly(req_cl)
                            r_writer.write(body_data)
                            await r_writer.drain()

                    can_keep_upstream = False
                    stage = "send"
                    try:
                        await _send_req_data(remote_writer)
                        stage = "response"
                        can_keep_upstream = await self._forward_http_response(
                            remote_reader, writer, request_method=method
                        )
                    except (_EmptyResponseError, ConnectionResetError, BrokenPipeError, OSError) as exc:
                        try:
                            remote_writer.close()
                        except Exception:
                            pass
                        # Nothing reached the client yet only if the failure was while sending,
                        # or upstream closed before its status line.
                        nothing_forwarded = stage == "send" or isinstance(exc, _EmptyResponseError)
                        if not nothing_forwarded:
                            # Part of a response already went to the client: a retry or a 502
                            # would corrupt it, so just close.
                            await self._drain_and_close(writer)
                            return

                        retried_ok = False
                        if is_pooled and can_retry:
                            stage = "send"
                            try:
                                remote_reader, remote_writer, _ = await self._get_upstream_conn(
                                    target_connect_ip, dst_port, allow_pool=False
                                )
                                remote_writer.write(req_line_bytes)
                                remote_writer.write(headers_bytes)
                                await remote_writer.drain()
                                stage = "response"
                                can_keep_upstream = await self._forward_http_response(
                                    remote_reader, writer, request_method=method
                                )
                                retried_ok = True
                            except Exception as exc2:
                                try:
                                    remote_writer.close()
                                except Exception:
                                    pass
                                if not (stage == "send" or isinstance(exc2, _EmptyResponseError)):
                                    await self._drain_and_close(writer)
                                    return
                        if not retried_ok:
                            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBad Gateway\r\n")
                            await self._drain_and_close(writer)
                            return
                    except Exception as e:
                        try:
                            remote_writer.close()
                        except Exception:
                            pass
                        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBad Gateway\r\n")
                        await self._drain_and_close(writer)
                        return

                    if is_chunked_req:
                        can_keep_upstream = False
                        try:
                            remote_writer.close()
                        except Exception:
                            pass
                    elif can_keep_upstream:
                        self._release_upstream_conn(target_connect_ip, dst_port, remote_reader, remote_writer)
                    else:
                        try:
                            remote_writer.close()
                        except Exception:
                            pass

                    client_conn = headers.get("connection", "").lower()
                    proxy_conn = headers.get("proxy-connection", "").lower()
                    client_keep = (client_conn != "close") and (proxy_conn != "close") and (version in ("HTTP/1.1", "HTTP/2.0")) and (not is_chunked_req)
                    if not client_keep or not can_keep_upstream:
                        await self._drain_and_close(writer)
                        return
                    is_first_req = False

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Proxy connection exception: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass
