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
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass
        if self._client_tasks:
            for task in list(self._client_tasks):
                if not task.done():
                    task.cancel()
            await asyncio.gather(*list(self._client_tasks), return_exceptions=True)
            self._client_tasks.clear()

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

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        curr_task = asyncio.current_task()
        if curr_task is not None:
            self._client_tasks.add(curr_task)
            curr_task.add_done_callback(self._client_tasks.discard)
        try:
            # Enforce 10s deadline for request line plus headers
            # At most 100 header lines
            # At most 8 KB per line
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
                cl_raw = headers.get("content-length", "")
                try:
                    cl = int(cl_raw)
                    if cl < 0:
                        raise ValueError("negative content length")
                except ValueError:
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

            if task_token:
                lookup = self.storage.lookup_task_by_token(task_token)
                if lookup:
                    task_id, agent_id = lookup
                    boundary = self.storage.get_boundary(task_id)

            # Parse destination host and port
            if method.upper() == "CONNECT":
                # target can be [::1]:80 or host:port
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
                # GET/POST full URL or host
                parsed = urlparse(target)
                dst_host = (parsed.hostname or headers.get("host", "").split(":")[0]).strip("[]")
                dst_port = parsed.port or (443 if parsed.scheme == "https" else 80)

            target_formatted = f"[{dst_host}]:{dst_port}" if ":" in dst_host else f"{dst_host}:{dst_port}"

            # 2. If unauthenticated, reject with 407 and log UNATTRIBUTED event
            if not task_id or not boundary:
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

            # 3. Evaluate destination host and port against task boundary
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
            resolved_ips: list[str] = []
            try:
                addr_info = socket.getaddrinfo(dst_host, dst_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in resolved_ips:
                        resolved_ips.append(ip)
            except Exception:
                pass

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
                boundary_version=boundary.version,
            )
            self.storage.record_event(evt)

            # A single-use network grant is used up by this connection, as it is through
            # the broker's http_get (independent audit #2, F-03).
            consume_single_use(self.storage, boundary, "network", target_formatted)

            # 5. Connect to destination exact IP (NO SECOND DNS LOOKUP) and tunnel
            try:
                remote_reader, remote_writer = await asyncio.open_connection(target_connect_ip, dst_port)
            except Exception as e:
                writer.write(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{e}\r\n".encode("utf-8"))
                await self._drain_and_close(writer)
                return

            if method.upper() == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            else:
                # Plain HTTP absolute-form proxying (e.g. GET http://host/path HTTP/1.1)
                parsed = urlparse(target)
                upstream_path = parsed.path or "/"
                if parsed.query:
                    upstream_path += f"?{parsed.query}"
                req_line = f"{method} {upstream_path} {version}\r\n"
                remote_writer.write(req_line.encode("utf-8"))

                # Forward headers, stripping proxy-specific hop headers
                for hk, hv in headers.items():
                    if hk not in ("proxy-authorization", "proxy-connection"):
                        remote_writer.write(f"{hk.title()}: {hv}\r\n".encode("utf-8"))
                remote_writer.write(b"\r\n")
                await remote_writer.drain()

                # If request has a body (e.g. POST), read and forward
                cl = int(headers.get("content-length", 0))
                if cl > 0:
                    body_data = await reader.readexactly(cl)
                    remote_writer.write(body_data)
                    await remote_writer.drain()

            # Bidirectional pipe
            async def forward(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
                try:
                    while True:
                        data = await src.read(4096)
                        if not data:
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

            await asyncio.gather(
                forward(reader, remote_writer),
                forward(remote_reader, writer),
                return_exceptions=True,
            )

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Proxy connection exception: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass
