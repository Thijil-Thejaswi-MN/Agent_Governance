# Tests for egress proxy plain-HTTP keep-alive, pooling, and edge-cases.
from __future__ import annotations

import asyncio
import datetime
import shutil
import tempfile
import time
from pathlib import Path

import pytest
import concurrent.futures


def run_coro(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)

from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    TaskBoundary,
)
from demo.security_monitor.app.governance.proxy import EgressProxyServer
from demo.security_monitor.app.governance.storage import GovernanceStorage


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="proxy_ka_test_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def storage(temp_dir):
    db_path = temp_dir / "governance.db"
    st = GovernanceStorage(str(db_path))
    yield st
    st.close()


def _setup_task(storage, temp_dir, upstream_port: int) -> tuple[str, str]:
    task_id = f"task_proxy_ka_{upstream_port}"
    ws = temp_dir / f"ws_{upstream_port}"
    ws.mkdir(parents=True, exist_ok=True)
    bnd = TaskBoundary(
        task_id=task_id,
        version=1,
        workspace_root=str(ws),
        network=[f"127.0.0.1:{upstream_port}"],
        enforcement_mode=EnforcementMode.ENFORCE,
    )
    storage.save_boundary(bnd)
    token = f"tok_ka_{upstream_port}"
    storage.save_token(token, task_id, "agent_net")
    return task_id, token


def test_head_with_content_length_returns_within_1s(storage, temp_dir):
    async def _run():
        async def handle_upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            # Read request line and headers
            while True:
                line = await reader.readline()
                if not line or line == b"\r\n":
                    break
            # HEAD response: Content-Length: 10 but NO body sent
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: keep-alive\r\n\r\n")
            await writer.drain()

        upstream_srv = await asyncio.start_server(handle_upstream, "127.0.0.1", 0)
        up_port = upstream_srv.sockets[0].getsockname()[1]
        _, token = _setup_task(storage, temp_dir, up_port)

        proxy = EgressProxyServer(storage=storage, host="127.0.0.1", port=0)
        proxy_port = await proxy.start()

        try:
            t0 = time.monotonic()
            r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
            req = (
                f"HEAD http://127.0.0.1:{up_port}/head-check HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            w.write(req)
            await w.drain()

            resp = await asyncio.wait_for(r.read(4096), timeout=1.0)
            elapsed = time.monotonic() - t0
            assert elapsed < 1.0
            assert b"200 OK" in resp
            assert b"Content-Length: 10" in resp
            w.close()
            await w.wait_closed()
        finally:
            await proxy.stop()
            upstream_srv.close()
            await upstream_srv.wait_closed()

    run_coro(_run())


def test_204_and_304_return_within_1s(storage, temp_dir):
    async def _run():
        async def handle_upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            while True:
                req_line = await reader.readline()
                if not req_line:
                    break
                while True:
                    hdr = await reader.readline()
                    if not hdr or hdr == b"\r\n":
                        break
                if b"/no-content" in req_line:
                    writer.write(b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n")
                    await writer.drain()
                elif b"/not-modified" in req_line:
                    writer.write(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 50\r\nConnection: keep-alive\r\n\r\n")
                    await writer.drain()
                else:
                    break

        upstream_srv = await asyncio.start_server(handle_upstream, "127.0.0.1", 0)
        up_port = upstream_srv.sockets[0].getsockname()[1]
        _, token = _setup_task(storage, temp_dir, up_port)

        proxy = EgressProxyServer(storage=storage, host="127.0.0.1", port=0)
        proxy_port = await proxy.start()

        try:
            # Check 204
            t0 = time.monotonic()
            r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
            req1 = (
                f"GET http://127.0.0.1:{up_port}/no-content HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            w.write(req1)
            await w.drain()
            resp1 = await asyncio.wait_for(r.read(4096), timeout=1.0)
            elapsed1 = time.monotonic() - t0
            assert elapsed1 < 1.0
            assert b"204 No Content" in resp1
            w.close()
            await w.wait_closed()

            # Check 304
            t1 = time.monotonic()
            r2, w2 = await asyncio.open_connection("127.0.0.1", proxy_port)
            req2 = (
                f"GET http://127.0.0.1:{up_port}/not-modified HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            w2.write(req2)
            await w2.drain()
            resp2 = await asyncio.wait_for(r2.read(4096), timeout=1.0)
            elapsed2 = time.monotonic() - t1
            assert elapsed2 < 1.0
            assert b"304 Not Modified" in resp2
            w2.close()
            await w2.wait_closed()
        finally:
            await proxy.stop()
            upstream_srv.close()
            await upstream_srv.wait_closed()

    run_coro(_run())


def test_chunked_response_with_trailers_and_subsequent_request(storage, temp_dir):
    async def _run():
        req_count = 0

        async def handle_upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            nonlocal req_count
            while True:
                line = await reader.readline()
                if not line:
                    break
                while True:
                    hdr = await reader.readline()
                    if not hdr or hdr == b"\r\n":
                        break
                req_count += 1
                if req_count == 1:
                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Transfer-Encoding: chunked\r\n"
                        b"Connection: keep-alive\r\n\r\n"
                        b"5\r\nhello\r\n"
                        b"0\r\n"
                        b"X-Trailer-1: foo\r\n"
                        b"X-Trailer-2: bar\r\n"
                        b"\r\n"
                    )
                    writer.write(resp)
                    await writer.drain()
                else:
                    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\nsecond"
                    writer.write(resp)
                    await writer.drain()

        upstream_srv = await asyncio.start_server(handle_upstream, "127.0.0.1", 0)
        up_port = upstream_srv.sockets[0].getsockname()[1]
        _, token = _setup_task(storage, temp_dir, up_port)

        proxy = EgressProxyServer(storage=storage, host="127.0.0.1", port=0)
        proxy_port = await proxy.start()

        try:
            r, w = await asyncio.open_connection("127.0.0.1", proxy_port)

            # Request 1: chunked with trailers
            req1 = (
                f"GET http://127.0.0.1:{up_port}/chunked HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"Connection: keep-alive\r\n\r\n"
            ).encode()
            w.write(req1)
            await w.drain()

            # Read response 1 until trailer end (\r\n after headers)
            buf = bytearray()
            while b"\r\n\r\n" not in buf or b"X-Trailer-2" not in buf:
                chunk = await asyncio.wait_for(r.read(1024), timeout=2.0)
                if not chunk:
                    break
                buf.extend(chunk)

            assert b"hello" in buf
            assert b"X-Trailer-1: foo" in buf
            assert b"X-Trailer-2: bar" in buf

            # Request 2: on the SAME client connection
            req2 = (
                f"GET http://127.0.0.1:{up_port}/second HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            w.write(req2)
            await w.drain()

            resp2 = await asyncio.wait_for(r.read(), timeout=2.0)
            assert b"200 OK" in resp2
            assert b"second" in resp2

            w.close()
            await w.wait_closed()
        finally:
            await proxy.stop()
            upstream_srv.close()
            await upstream_srv.wait_closed()

    run_coro(_run())


def test_chunked_post_body_arrives_intact_upstream(storage, temp_dir):
    async def _run():
        received_body = bytearray()

        async def handle_upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            # Read request line & headers
            headers = {}
            while True:
                line = await reader.readline()
                if not line or line == b"\r\n":
                    break
                decoded = line.decode("latin1", errors="replace").strip()
                if ":" in decoded:
                    k, v = decoded.split(":", 1)
                    headers[k.lower()] = v.strip()

            if "chunked" in headers.get("transfer-encoding", "").lower():
                while True:
                    ch = await reader.readline()
                    if not ch:
                        break
                    ch_len = int(ch.strip().split(b";")[0], 16)
                    if ch_len == 0:
                        while True:
                            tr = await reader.readline()
                            if not tr or tr == b"\r\n":
                                break
                        break
                    data = await reader.readexactly(ch_len + 2)
                    received_body.extend(data[:-2])

            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()

        upstream_srv = await asyncio.start_server(handle_upstream, "127.0.0.1", 0)
        up_port = upstream_srv.sockets[0].getsockname()[1]
        _, token = _setup_task(storage, temp_dir, up_port)

        proxy = EgressProxyServer(storage=storage, host="127.0.0.1", port=0)
        proxy_port = await proxy.start()

        try:
            r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
            req = (
                f"POST http://127.0.0.1:{up_port}/post-chunked HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: close\r\n\r\n"
                f"5\r\nworld\r\n0\r\n\r\n"
            ).encode()
            w.write(req)
            await w.drain()

            resp = await asyncio.wait_for(r.read(4096), timeout=2.0)
            assert b"200 OK" in resp
            assert received_body == b"world"

            w.close()
            await w.wait_closed()
        finally:
            await proxy.stop()
            upstream_srv.close()
            await upstream_srv.wait_closed()

    run_coro(_run())


def test_idle_keepalive_stale_connection_retried(storage, temp_dir):
    async def _run():
        conn_count = 0

        async def handle_upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            nonlocal conn_count
            conn_count += 1
            current_conn = conn_count

            # Read request
            while True:
                line = await reader.readline()
                if not line or line == b"\r\n":
                    break

            if current_conn == 1:
                # Reply and immediately close socket to make pooled conn stale
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            else:
                # Second connection (fresh retry)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfresh")
                await writer.drain()

        upstream_srv = await asyncio.start_server(handle_upstream, "127.0.0.1", 0)
        up_port = upstream_srv.sockets[0].getsockname()[1]
        _, token = _setup_task(storage, temp_dir, up_port)

        proxy = EgressProxyServer(storage=storage, host="127.0.0.1", port=0)
        proxy_port = await proxy.start()

        try:
            # Request 1 through proxy (will populate upstream pool)
            r1, w1 = await asyncio.open_connection("127.0.0.1", proxy_port)
            req1 = (
                f"GET http://127.0.0.1:{up_port}/initial-req HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            w1.write(req1)
            await w1.drain()
            resp1 = await asyncio.wait_for(r1.read(), timeout=2.0)
            assert b"ok" in resp1
            w1.close()
            await w1.wait_closed()

            # Wait briefly to let upstream close event settle on the pooled socket
            await asyncio.sleep(0.05)

            # Request 2: Proxy attempts stale pooled connection, gets EOF/reset, retries on fresh connection
            r2, w2 = await asyncio.open_connection("127.0.0.1", proxy_port)
            req2 = (
                f"GET http://127.0.0.1:{up_port}/retry-req HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            w2.write(req2)
            await w2.drain()
            resp2 = await asyncio.wait_for(r2.read(), timeout=2.0)
            assert b"200 OK" in resp2
            assert b"fresh" in resp2
            assert conn_count == 2

            w2.close()
            await w2.wait_closed()
        finally:
            await proxy.stop()
            upstream_srv.close()
            await upstream_srv.wait_closed()

    run_coro(_run())


def test_bad_content_length_returns_400(storage, temp_dir):
    async def _run():
        proxy = EgressProxyServer(storage=storage, host="127.0.0.1", port=0)
        proxy_port = await proxy.start()

        try:
            # Negative integer
            r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
            req = b"POST http://127.0.0.1:80/data HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: -1\r\n\r\n"
            w.write(req)
            await w.drain()
            resp = await asyncio.wait_for(r.read(4096), timeout=1.0)
            assert b"400 Bad Request" in resp
            assert b"Invalid Content-Length" in resp
            w.close()
            await w.wait_closed()

            # Non-integer string
            r2, w2 = await asyncio.open_connection("127.0.0.1", proxy_port)
            req2 = b"POST http://127.0.0.1:80/data HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: abc\r\n\r\n"
            w2.write(req2)
            await w2.drain()
            resp2 = await asyncio.wait_for(r2.read(4096), timeout=1.0)
            assert b"400 Bad Request" in resp2
            assert b"Invalid Content-Length" in resp2
            w2.close()
            await w2.wait_closed()
        finally:
            await proxy.stop()

    run_coro(_run())
