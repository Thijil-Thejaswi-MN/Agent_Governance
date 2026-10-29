"""Starts a real console server for browser tests (no server is assumed to be running).

Each server gets a free port, its own temporary governance DB, RECEIPTS_DIR and
operator token. Workspaces stay under the launcher default ($HOME/agent_workspaces):
the evaluation world refuses workspaces under /tmp.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CONSOLE_DIST = REPO_ROOT / "demo" / "security_monitor" / "app" / "dashboard_v2" / "dist"
OPERATOR_TOKEN = "playwright_operator_token"
OPERATOR_NAME = "test_lead_operator"


@dataclass
class ConsoleServer:
    url: str
    db_path: Path
    receipts_dir: Path
    log_path: Path
    token: str
    proc: subprocess.Popen

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_console_server(workdir: Path, env_overrides: dict[str, str] | None = None,
                         app: str = "demo.security_monitor.tests.playwright_app:app",
                         require_build: bool = True) -> ConsoleServer:
    if require_build and not (CONSOLE_DIST / "index.html").is_file():
        raise RuntimeError(
            f"Governance Console not built ({CONSOLE_DIST}/index.html missing): "
            "run `npm ci && npm run build` in demo/security_monitor/app/dashboard_v2"
        )
    workdir.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    db_path = workdir / "governance.db"
    receipts_dir = workdir / "receipts"
    log_path = workdir / "server.log"
    env = dict(os.environ)
    env.update({
        "GOVERNANCE_OPERATOR_TOKEN": OPERATOR_TOKEN,
        "GOVERNANCE_OPERATOR_NAME": OPERATOR_NAME,
        "GOVERNANCE_DB_PATH": str(db_path),
        "RECEIPTS_DIR": str(receipts_dir),
        "PYTHONUNBUFFERED": "1",
    })
    env.update(env_overrides or {})
    log = open(log_path, "wb")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", app, "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(REPO_ROOT), env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            with urllib.request.urlopen(f"{url}/api/governance/auth/status", timeout=1) as r:
                if r.status == 200:
                    return ConsoleServer(url, db_path, receipts_dir, log_path, OPERATOR_TOKEN, proc)
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError(f"console server did not start:\n{log_path.read_text(errors='replace')[-3000:]}")


def sign_in(page, server: ConsoleServer, path: str = "/dashboard") -> None:
    """Signs in through the UI: the sign-in state, the token modal, POST /auth/session."""
    page.goto(f"{server.url}{path}")
    page.locator("#sign-in-btn").click()
    modal = page.locator('div[role="dialog"]')
    modal.locator("#operator-token-input").fill(server.token)
    modal.locator("#operator-signin-btn").click()
    modal.wait_for(state="hidden")


def save_evidence(page, name: str) -> None:
    """Screenshot into $UI_EVIDENCE_DIR when set (used to produce review evidence); no-op otherwise."""
    out = os.getenv("UI_EVIDENCE_DIR")
    if out:
        Path(out).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(Path(out) / f"{name}.png"), full_page=True)
