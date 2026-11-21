"""Single-use grants are used up on every path (independent audit #2, F-03).

- A network grant is used up by the first connection through the egress proxy, which is
  what the shell's curl/wget use, not only by the broker's http_get.
- A network grant named host:port is used up by an http_get of a URL on that host and port.
- An older single-use grant is used up even after a later grant made a newer boundary.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.intake import TaskIntakeService
from demo.security_monitor.app.governance.proxy import EgressProxyServer
from demo.security_monitor.app.governance.single_use import consume_single_use, grant_matches
from demo.security_monitor.app.governance.storage import GovernanceStorage


@pytest.fixture
def world(tmp_path: Path):
    storage = GovernanceStorage(tmp_path / "g.db")
    ws = tmp_path / "ws"
    (ws / "input").mkdir(parents=True)
    (ws / "output").mkdir()
    (ws / "docs").mkdir()
    (ws / "docs" / "a.txt").write_text("A")
    (ws / "docs" / "b.txt").write_text("B")
    task, _ = TaskIntakeService(storage).submit_task("Summarise input/x.txt", "notes_bot", str(ws))
    token = "tok_single_use_f03"
    storage.save_token(token, task.task_id, task.agent_id)
    return storage, task, token, ExpansionService(storage)


@pytest.mark.parametrize("grant,access,ok", [
    ("api.example.com:443", "https://api.example.com/v1/x", True),
    ("api.example.com:443", "api.example.com:443", True),
    ("api.example.com:443", "http://api.example.com/x", False),     # port 80
    ("api.example.com", "http://api.example.com/x", True),          # a bare host covers ports 80 and 443
    ("api.example.com", "https://api.example.com/x", True),
    ("api.example.com", "http://api.example.com:8080/x", False),    # ...and no other port (audit B2)
    ("api.example.com:443", "https://evil.example.com/", False),
])
def test_network_grant_matching(grant, access, ok) -> None:
    assert grant_matches("network", grant, access) is ok


def test_http_get_uses_up_a_host_port_grant(world) -> None:
    storage, task, token, exp = world
    exp.grant_resource_proactively(task.task_id, "operator:ana", "network", "api.example.com:443", single_use=True)
    broker = ToolBroker(storage, expansion_service=exp)
    broker.http_get(token, "https://api.example.com/v1/data")
    assert "api.example.com:443" not in storage.get_boundary(task.task_id).network
    with pytest.raises(PermissionError):
        broker.http_get(token, "https://api.example.com/v1/data")


def test_an_older_single_use_grant_is_used_up_after_a_newer_grant(world) -> None:
    storage, task, token, exp = world
    exp.grant_resource_proactively(task.task_id, "operator:ana", "file_read", "docs/a.txt", single_use=True)
    exp.grant_resource_proactively(task.task_id, "operator:ana", "file_read", "docs/b.txt", single_use=True)
    broker = ToolBroker(storage, expansion_service=exp)
    assert broker.read_file(token, "docs/a.txt") == "A"  # not the grant behind the newest boundary
    with pytest.raises(PermissionError):
        broker.read_file(token, "docs/a.txt")
    assert broker.read_file(token, "docs/b.txt") == "B"
    with pytest.raises(PermissionError):
        broker.read_file(token, "docs/b.txt")


def test_a_grant_for_one_use_is_used_once(world) -> None:
    storage, task, _, exp = world
    exp.grant_resource_proactively(task.task_id, "operator:ana", "network", "127.0.0.1:9", single_use=True)
    b = storage.get_boundary(task.task_id)
    assert len(consume_single_use(storage, b, "network", "127.0.0.1:9")) == 1
    assert consume_single_use(storage, storage.get_boundary(task.task_id), "network", "127.0.0.1:9") == []


def test_the_proxy_uses_up_a_single_use_network_grant(world) -> None:
    storage, task, token, exp = world

    async def run() -> tuple[bytes, bytes]:
        async def target(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readline()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(target, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        exp.grant_resource_proactively(task.task_id, "operator:ana", "network", f"127.0.0.1:{port}", single_use=True)
        proxy = EgressProxyServer(storage=storage, port=0)
        pport = await proxy.start()

        async def connect() -> bytes:
            r, w = await asyncio.open_connection("127.0.0.1", pport)
            w.write(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                    f"Proxy-Authorization: Bearer {token}\r\n\r\n".encode())
            await w.drain()
            line = await r.readline()
            w.close()
            return line

        try:
            return await connect(), await connect()
        finally:
            await proxy.stop()
            server.close()
            await server.wait_closed()

    first, second = asyncio.run(run())
    assert b"200" in first
    assert b"403" in second
    used = [r for r in storage.list_expansion_requests(task_id=task.task_id) if r.resource_type == "network"]
    assert used and used[-1].used_count == 1
