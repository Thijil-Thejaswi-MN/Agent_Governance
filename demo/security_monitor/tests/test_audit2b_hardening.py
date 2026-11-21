"""Hardening tests from independent audit (network matching, proxy limits, DNS fail-closed)."""
from __future__ import annotations

import asyncio
from pathlib import Path

from demo.security_monitor.app.governance.evaluator import BoundaryEvaluator
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.models import EventVerdict, TaskBoundary
from demo.security_monitor.app.governance.proxy import EgressProxyServer
from demo.security_monitor.app.governance.storage import GovernanceStorage


def test_network_matching_control_plane_and_ports(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CONTROL_PORT", "8000")
    ev = BoundaryEvaluator()
    b = TaskBoundary(task_id="t_net", version=1, workspace_root="/tmp/ws")

    # 1. 127.0.0.1 listed (bare host): :8000 and :22 OUTSIDE, :80 INSIDE
    b.network = ["127.0.0.1"]
    res_80 = ev.evaluate_network(b, "127.0.0.1:80")
    assert res_80.verdict == EventVerdict.INSIDE

    res_443 = ev.evaluate_network(b, "127.0.0.1:443")
    assert res_443.verdict == EventVerdict.INSIDE

    res_22 = ev.evaluate_network(b, "127.0.0.1:22")
    assert res_22.verdict == EventVerdict.OUTSIDE

    res_8000 = ev.evaluate_network(b, "127.0.0.1:8000")
    assert res_8000.verdict == EventVerdict.OUTSIDE
    assert "control-plane port is never reachable from a task" in res_8000.rule_matched

    # 2. 127.0.0.1:8000 listed: still OUTSIDE
    b.network = ["127.0.0.1:8000"]
    res_listed_8000 = ev.evaluate_network(b, "127.0.0.1:8000")
    assert res_listed_8000.verdict == EventVerdict.OUTSIDE
    assert "control-plane port is never reachable from a task" in res_listed_8000.rule_matched

    # 3. 127.0.0.1:11434 listed: INSIDE
    b.network = ["127.0.0.1:11434"]
    res_11434 = ev.evaluate_network(b, "127.0.0.1:11434")
    assert res_11434.verdict == EventVerdict.INSIDE

    # Bare host matches only 80 and 443; host:* or host:port required otherwise
    b.network = ["internal.api"]
    assert ev.evaluate_network(b, "internal.api:80").verdict == EventVerdict.INSIDE
    assert ev.evaluate_network(b, "internal.api:443").verdict == EventVerdict.INSIDE
    assert ev.evaluate_network(b, "internal.api:8080").verdict == EventVerdict.OUTSIDE

    b.network = ["internal.api:*"]
    assert ev.evaluate_network(b, "internal.api:8080").verdict == EventVerdict.INSIDE


def test_network_matching_ipv6_formatting():
    ev = BoundaryEvaluator()
    b = TaskBoundary(task_id="t_v6", version=1, workspace_root="/tmp/ws")
    b.network = ["[::1]:80"]

    res_v6_80 = ev.evaluate_network(b, "[::1]:80")
    assert res_v6_80.verdict == EventVerdict.INSIDE

    # Loopback IPv6 control port refusal
    res_v6_8000 = ev.evaluate_network(b, "[::1]:8000")
    assert res_v6_8000.verdict == EventVerdict.OUTSIDE
    assert "control-plane port is never reachable from a task" in res_v6_8000.rule_matched


def test_proxy_request_header_deadline_timeout(tmp_path: Path):
    async def _run():
        storage = GovernanceStorage(tmp_path / "gov.db")
        proxy = EgressProxyServer(storage=storage, port=0)
        proxy.header_timeout = 0.1  # Fast timeout for test
        port = await proxy.start()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            # Connect and stall without finishing the headers
            writer.write(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n")
            await writer.drain()

            resp = await reader.read(1024)
            assert b"408 Request Timeout" in resp
            writer.close()
            await writer.wait_closed()

            # Check recorded proxy event
            with storage.get_connection() as conn:
                events = conn.execute("SELECT * FROM governance_events WHERE source = 'EGRESS_PROXY'").fetchall()
            timeout_events = [e for e in events if "deadline exceeded" in e["rule_matched"]]
            assert len(timeout_events) == 1
            assert timeout_events[0]["prevented"] == 1
        finally:
            await proxy.stop()

    asyncio.run(_run())


def test_proxy_header_lines_limit(tmp_path: Path):
    async def _run():
        storage = GovernanceStorage(tmp_path / "gov.db")
        proxy = EgressProxyServer(storage=storage, port=0)
        proxy.max_headers = 100
        port = await proxy.start()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            # Send > 100 header lines
            payload = b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n"
            for i in range(105):
                payload += f"X-Header-{i}: value\r\n".encode()
            payload += b"\r\n"
            writer.write(payload)
            await writer.drain()

            resp = await reader.read(1024)
            assert b"431 Request Header Fields Too Large" in resp
            writer.close()
            await writer.wait_closed()

            with storage.get_connection() as conn:
                events = conn.execute("SELECT * FROM governance_events WHERE source = 'EGRESS_PROXY'").fetchall()
            count_events = [e for e in events if "header line count exceeded limit" in e["rule_matched"]]
            assert len(count_events) == 1
            assert count_events[0]["prevented"] == 1
        finally:
            await proxy.stop()

    asyncio.run(_run())


def test_proxy_header_line_length_limit(tmp_path: Path):
    async def _run():
        storage = GovernanceStorage(tmp_path / "gov.db")
        proxy = EgressProxyServer(storage=storage, port=0)
        proxy.max_line_length = 8192
        port = await proxy.start()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            # Send line exceeding 8 KB
            long_line = b"X-Big: " + b"a" * 8200 + b"\r\n\r\n"
            writer.write(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n" + long_line)
            await writer.drain()

            resp = await reader.read(1024)
            assert b"431 Request Header Fields Too Large" in resp
            writer.close()
            await writer.wait_closed()

            with storage.get_connection() as conn:
                events = conn.execute("SELECT * FROM governance_events WHERE source = 'EGRESS_PROXY'").fetchall()
            len_events = [e for e in events if "header line exceeded 8 KB limit" in e["rule_matched"]]
            assert len(len_events) == 1
            assert len_events[0]["prevented"] == 1
        finally:
            await proxy.stop()

    asyncio.run(_run())


def test_proxy_content_length_limits(tmp_path: Path):
    async def _run():
        storage = GovernanceStorage(tmp_path / "gov.db")
        proxy = EgressProxyServer(storage=storage, port=0)
        proxy.max_content_length = 1024 * 1024
        port = await proxy.start()

        try:
            # 1. Non-integer Content-Length -> 400
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"POST http://127.0.0.1:80/ HTTP/1.1\r\nHost: 127.0.0.1:80\r\nContent-Length: abc\r\n\r\n")
            await writer.drain()

            resp = await reader.read(1024)
            assert b"400 Bad Request" in resp
            writer.close()
            await writer.wait_closed()

            with storage.get_connection() as conn:
                events = conn.execute("SELECT * FROM governance_events WHERE source = 'EGRESS_PROXY'").fetchall()
            bad_cl = [e for e in events if "non-integer Content-Length" in e["rule_matched"]]
            assert len(bad_cl) == 1
            assert bad_cl[0]["prevented"] == 1

            # 2. Exceeding 1 MB limit -> 413
            reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
            writer2.write(b"POST http://127.0.0.1:80/ HTTP/1.1\r\nHost: 127.0.0.1:80\r\nContent-Length: 2000000\r\n\r\n")
            await writer2.drain()

            resp2 = await reader2.read(1024)
            assert b"413 Payload Too Large" in resp2
            writer2.close()
            await writer2.wait_closed()

            with storage.get_connection() as conn:
                events2 = conn.execute("SELECT * FROM governance_events WHERE source = 'EGRESS_PROXY'").fetchall()
            large_cl = [e for e in events2 if "Content-Length exceeded 1 MB limit" in e["rule_matched"]]
            assert len(large_cl) == 1
            assert large_cl[0]["prevented"] == 1
        finally:
            await proxy.stop()

    asyncio.run(_run())


def test_proxy_dns_resolution_failure_fails_closed(tmp_path: Path, monkeypatch):
    async def _run():
        storage = GovernanceStorage(tmp_path / "gov.db")
        intake = TaskIntakeService(storage)
        task, boundary = intake.submit_task("DNS fail test", "agent_dns", str(tmp_path))
        boundary.network = ["non-existent-domain-xyz-12345.example:443"]
        storage.save_boundary(boundary)
        token = "tok_dns_fail"
        storage.save_token(token, task.task_id, task.agent_id)

        proxy = EgressProxyServer(storage=storage, port=0)
        port = await proxy.start()

        opened_connections = []
        real_open = asyncio.open_connection

        async def mock_open(host, p, *args, **kwargs):
            opened_connections.append((host, p))
            return await real_open(host, p, *args, **kwargs)

        monkeypatch.setattr(asyncio, "open_connection", mock_open)

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            req = (
                f"CONNECT non-existent-domain-xyz-12345.example:443 HTTP/1.1\r\n"
                f"Host: non-existent-domain-xyz-12345.example:443\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n\r\n"
            ).encode("utf-8")
            writer.write(req)
            await writer.drain()

            resp = await reader.read(1024)
            assert b"502 Bad Gateway" in resp
            writer.close()
            await writer.wait_closed()

            # Destination must never have been connected to
            assert not any("non-existent-domain" in str(h) for h, _ in opened_connections)

            # Blocked event recorded
            events = storage.get_events_for_task(task.task_id)
            dns_events = [e for e in events if "DNS resolution failed" in e.rule_matched]
            assert len(dns_events) == 1
            assert dns_events[0].prevented is True
            assert dns_events[0].verdict == EventVerdict.OUTSIDE
        finally:
            await proxy.stop()

    asyncio.run(_run())
