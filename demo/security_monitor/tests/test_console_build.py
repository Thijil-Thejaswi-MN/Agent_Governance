"""/dashboard when the Governance Console has not been built (fresh clone).

The server logs a warning and serves a small 'console not built' page with the
build commands and a link to /legacy-dashboard, instead of silently serving the
legacy UI. With a build present, /dashboard serves it (SPA fallback for deep links).
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi.testclient import TestClient

from demo.security_monitor.app.gateway.server import create_app


def test_missing_build_serves_console_not_built_page(tmp_path: Path, monkeypatch, caplog):
    monkeypatch.setenv("GOVERNANCE_CONSOLE_DIST", str(tmp_path / "no_dist_here"))
    with caplog.at_level(logging.WARNING, logger="demo.security_monitor.app.gateway.server"):
        client = TestClient(create_app())
    assert any("Governance Console not built" in r.getMessage() for r in caplog.records)

    for path in ("/dashboard", "/dashboard/run", "/dashboard/tasks/task_x"):
        resp = client.get(path)
        assert resp.status_code == 503, path
        assert "Console not built" in resp.text
        assert "npm ci &amp;&amp; npm run build" in resp.text and "dashboard_v2" in resp.text
        assert 'href="/legacy-dashboard"' in resp.text

    legacy = client.get("/legacy-dashboard")
    assert legacy.status_code == 200
    assert "A2A Security Operations" in legacy.text


def test_built_console_is_served_with_spa_fallback(tmp_path: Path, monkeypatch):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html><div id=root>console</div></html>")
    (dist / "assets" / "app.js").write_text("console.log(1)")
    monkeypatch.setenv("GOVERNANCE_CONSOLE_DIST", str(dist))
    client = TestClient(create_app())

    assert client.get("/dashboard").text == "<html><div id=root>console</div></html>"
    assert "id=root" in client.get("/dashboard/run").text
    assert client.get("/dashboard/assets/app.js").text == "console.log(1)"
