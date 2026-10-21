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
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self._is_running = False

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            # Read HTTP request line
            line = await reader.readline()
            if not line:
                writer.close()
                await writer.wait_closed()
                return

            req_line = line.decode("utf-8", errors="replace").strip()
            parts = req_line.split()
            if len(parts) < 3:
                writer.close()
                await writer.wait_closed()
                return

            method, target, version = parts[0], parts[1], parts[2]

            # Read headers
            headers: dict[str, str] = {}
            while True:
                header_line = await reader.readline()
                if not header_line or header_line == b"\r\n" or header_line == b"\n":
                    break
                decoded = header_line.decode("utf-8", errors="replace").strip()
                if ":" in decoded:
                    k, v = decoded.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

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
                # target is host:port
                if ":" in target:
                    dst_host, dst_port_str = target.split(":", 1)
                    try:
                        dst_port = int(dst_port_str)
                    except ValueError:
                        dst_port = 443
                else:
                    dst_host = target
                    dst_port = 443
            else:
                # GET/POST full URL or host
                parsed = urlparse(target)
                dst_host = parsed.hostname or headers.get("host", "").split(":")[0]
                dst_port = parsed.port or (443 if parsed.scheme == "https" else 80)

            # 2. If unauthenticated, reject with 407 and log UNATTRIBUTED event
            if not task_id or not boundary:
                evt = GovernanceEvent(
                    event_id=self._generate_event_id(),
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    source=EventSource.EGRESS_PROXY,
                    task_id=None,
                    agent_id=agent_id,
                    pid=None,
                    kind="network_egress",
                    target=f"{dst_host}:{dst_port}",
                    details={"method": method, "raw_target": target, "reason": "missing_or_invalid_proxy_auth"},
                    verdict=EventVerdict.OUTSIDE,
                    risk_tier=RiskTier.HIGH,
                    action_taken=TaskAction.BLOCK_ACTION,
                    prevented=True,
                    rule_matched="unauthenticated proxy egress attempt",
                    boundary_version=None,
                )
                self.storage.record_event(evt)
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Bearer\r\n\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # 3. Resolve destination IP
            resolved_ips: list[str] = []
            try:
                addr_info = socket.getaddrinfo(dst_host, dst_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in resolved_ips:
                        resolved_ips.append(ip)
            except Exception:
                # DNS failure
                pass

            target_connect_ip = resolved_ips[0] if resolved_ips else dst_host

            # 4. Evaluate destination host and resolved IP against task boundary
            eval_res = self.evaluator.evaluate_network(boundary, f"{dst_host}:{dst_port}")
            # Also evaluate the exact resolved IP if it differs from the hostname
            if eval_res.verdict == EventVerdict.INSIDE and resolved_ips:
                for r_ip in resolved_ips:
                    ip_eval = self.evaluator.evaluate_network(boundary, f"{r_ip}:{dst_port}")
                    if ip_eval.verdict == EventVerdict.OUTSIDE:
                        eval_res = ip_eval
                        break

            action, prevented = self.policy_engine.decide(boundary, eval_res)

            # Record GovernanceEvent
            evt = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.EGRESS_PROXY,
                task_id=task_id,
                agent_id=agent_id,
                pid=None,
                kind="network_egress",
                target=f"{dst_host}:{dst_port}",
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

            if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nGovernance Proxy: Destination outside task boundary\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # 5. Connect to destination exact IP (NO SECOND DNS LOOKUP) and tunnel
            try:
                remote_reader, remote_writer = await asyncio.open_connection(target_connect_ip, dst_port)
            except Exception as e:
                writer.write(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{e}\r\n".encode("utf-8"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
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

        except Exception as e:
            logger.debug(f"Proxy connection exception: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
