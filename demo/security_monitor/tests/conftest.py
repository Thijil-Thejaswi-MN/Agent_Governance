from __future__ import annotations

import functools
import os
import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "os_layer: needs the M6 OS layer (Linux/WSL2, systemd --user scopes, Landlock, cgroup v2, "
        "built os_layer binaries, Landlock ABI >= 6, unprivileged user namespaces); skipped with the concrete host problems as the reason otherwise",
    )
    config.addinivalue_line("markers", "playwright: browser test; starts its own server (see playwright_server.py)")


@functools.lru_cache(maxsize=1)
def os_layer_problems() -> tuple[str, ...]:
    from demo.security_monitor.app.governance.launcher import TaskLauncher
    return tuple(TaskLauncher.check_condition_c_support())


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


# ---------------------------------------------------------------------------
# Browser tests: each fixture starts its own server (see playwright_server.py)
# ---------------------------------------------------------------------------

def _server(tmp_path_factory, name: str, env: dict[str, str] | None = None, require_build: bool = True):
    from demo.security_monitor.tests.playwright_server import start_console_server
    return start_console_server(tmp_path_factory.mktemp(name), env, require_build=require_build)


@pytest.fixture(scope="session")
def console_server(tmp_path_factory):
    srv = _server(tmp_path_factory, "console")
    yield srv
    srv.stop()


@pytest.fixture(scope="session")
def preparing_console_server(tmp_path_factory):
    """Runs wait in sandbox preparation (agent not started) until Stop, at most 60 s."""
    srv = _server(tmp_path_factory, "console_hold", {"PLAYWRIGHT_PREPARE_HOLD_S": "60"})
    yield srv
    srv.stop()


@pytest.fixture(scope="session")
def unsupported_host_server(tmp_path_factory):
    """Simulates a host without the OS layer: systemd-run/systemctl are not on PATH."""
    import sys
    srv = _server(tmp_path_factory, "console_unsupported", {"PATH": os.path.dirname(sys.executable)})
    yield srv
    srv.stop()


@pytest.fixture(scope="session")
def unbuilt_console_server(tmp_path_factory):
    """A fresh clone: no dashboard_v2/dist."""
    missing = str(tmp_path_factory.mktemp("no_dist") / "dist")
    srv = _server(tmp_path_factory, "console_unbuilt", {"GOVERNANCE_CONSOLE_DIST": missing}, require_build=False)
    yield srv
    srv.stop()
