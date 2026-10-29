from __future__ import annotations

import functools
import os
import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "os_layer: needs the M6 OS layer (Linux/WSL2, systemd --user scopes, Landlock, cgroup v2, "
        "built os_layer binaries); skipped with the concrete host problems as the reason otherwise",
    )
    config.addinivalue_line("markers", "playwright: browser test; starts its own server (see playwright_server.py)")


@functools.lru_cache(maxsize=1)
def os_layer_problems() -> tuple[str, ...]:
    from demo.security_monitor.app.governance.launcher import TaskLauncher
    return tuple(TaskLauncher.check_prerequisites())


def pytest_collection_modifyitems(config, items):
    for item in items:
        if item.get_closest_marker("os_layer") and os_layer_problems():
            item.add_marker(pytest.mark.skip(reason="OS layer unavailable on this host: " + "; ".join(os_layer_problems())))


@pytest.fixture(autouse=True)
def isolated_test_db(tmp_path, monkeypatch):
    """
    Ensure every test executes against an isolated temporary SQLite database file.
    Prevents cross-test pollution while testing real SQLite disk persistence.
    """
    test_db = tmp_path / "test_secmon.db"
    monkeypatch.setenv("SECMON_DB_PATH", str(test_db))
    yield test_db


@pytest.fixture
def anyio_backend():
    return "asyncio"
