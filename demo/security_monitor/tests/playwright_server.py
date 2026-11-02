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


def sign_in(page, server: ConsoleServer, path: str = "/dashboard/history") -> None:
    """Signs in through the UI: the sign-in state, the token modal, POST /auth/session.

    `path` must be a page that reads task data (Home and Results are public)."""
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


# ---------------------------------------------------------------------------
# Plain-language checks (console v3)
# ---------------------------------------------------------------------------

# Never visible on a first screen (outside a Details drawer or panel).
FIRST_SCREEN_JARGON = [
    "Landlock", "seccomp", "cgroup", "provenance", "hash chain", "hash-chain",
    "boundary v1", "boundary v2", "broker", "SSE", "ABI",
]
# Never in the console's own copy.
NEVER_SAY = ["safe", "secure", "guaranteed", "tamper-proof", "first"]

_CASE_SENSITIVE = {"SSE", "ABI"}


def visible_text_outside_details(page) -> str:
    """document.body.innerText with every [data-details] element (drawers, <details>) hidden."""
    return page.evaluate(
        """() => {
            const els = [...document.querySelectorAll('[data-details]')];
            const saved = els.map(e => e.style.display);
            els.forEach(e => { e.style.display = 'none'; });
            const text = document.body.innerText;
            els.forEach((e, i) => { e.style.display = saved[i]; });
            return text;
        }"""
    )


def banned_words_in(text: str, words: list[str]) -> list[str]:
    import re
    found = []
    for w in words:
        flags = 0 if w in _CASE_SENSITIVE else re.IGNORECASE
        if re.search(rf"(?<![A-Za-z]){re.escape(w)}(?![A-Za-z])", text, flags):
            found.append(w)
    return found


def no_horizontal_scroll(page) -> bool:
    return page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth")


# ---------------------------------------------------------------------------
# Seeding (tests that do not need the OS layer)
# ---------------------------------------------------------------------------

def seed_waiting_task(db_path: Path, suffix: str, *, agent_id: str = "finance_bot",
                      learned_from: str = "input/briefing.txt",
                      target: str = "input/quarterly_revenue.csv",
                      timeout_s: float = 600.0) -> tuple[str, str]:
    """A running (ACTIVE) task whose agent read a file mentioning `target`, was refused it,
    and now waits for a decision. Returns (task_id, request_id)."""
    import datetime
    from demo.security_monitor.app.governance.models import (
        EventSource, EventVerdict, ExpansionRequest, ExpansionStatus, GovernanceEvent,
        ProvenanceRecord, RiskTier, TaskAction, TaskBoundary, TaskLifecycle, TaskRecord,
    )
    from demo.security_monitor.app.governance.storage import GovernanceStorage

    storage = GovernanceStorage(db_path)
    now = datetime.datetime.now(datetime.timezone.utc)
    ts = lambda s: (now - datetime.timedelta(seconds=s)).isoformat()  # noqa: E731
    task_id, req_id = f"task_seed_{suffix}", f"exp_seed_{suffix}"
    storage.save_task(TaskRecord(
        task_id=task_id, request_text="Summarise the executive briefing notes", request_hash="h",
        agent_id=agent_id, workspace_root="/tmp/ws_seed", status=TaskLifecycle.ACTIVE, created_at=ts(60)))
    storage.save_boundary(TaskBoundary(
        task_id=task_id, workspace_root="/tmp/ws_seed", files_read=[learned_from],
        files_write=["output/summary.txt"], network=[], tools=["read_file", "write_file"], peer_agents=[]))
    storage.record_provenance(ProvenanceRecord(
        task_id=task_id, timestamp=ts(40), source_type="file_read", source_target=learned_from,
        content_hash="x", content_len=80,
        content_snippet=f"Notice: please consult the reference table in {target}"))
    storage.record_task_step(task_id, kind="tool", layer="broker", verdict="ALLOW",
                             summary=f"read_file allowed: {learned_from}", source_label="enforced")
    storage.record_event(GovernanceEvent(
        event_id=f"ev_seed_{suffix}", timestamp=ts(30), source=EventSource.TOOL_BROKER, task_id=task_id,
        agent_id=agent_id, kind="file_read", target=target, verdict=EventVerdict.OUTSIDE,
        risk_tier=RiskTier.MEDIUM, action_taken=TaskAction.BLOCK_ACTION, prevented=True,
        rule_matched="not in boundary"))
    storage.record_task_step(task_id, kind="tool", layer="broker", verdict="BLOCK_ACTION",
                             summary=f"read_file blocked: {target}", detail="outside the task boundary",
                             source_label="enforced")
    storage.save_expansion_request(ExpansionRequest(
        request_id=req_id, task_id=task_id, agent_id=agent_id, resource_type="file_read",
        resource_target=target, justification="Need the quarterly revenue numbers named in the briefing",
        baseline_risk_tier=RiskTier.LOW, effective_risk_tier=RiskTier.MEDIUM, escalated_by_provenance=True,
        status=ExpansionStatus.PENDING, created_at=ts(10), timeout_seconds=timeout_s))
    storage.record_task_step(task_id, kind="expansion", layer="broker", verdict="PENDING",
                             summary=f"Expansion access requested for {target} (MEDIUM risk)",
                             source_label="enforced")
    return task_id, req_id


def seed_finished_task(db_path: Path, suffix: str) -> str:
    """A completed task with an OS-level block and an output (no receipt file)."""
    import datetime
    from demo.security_monitor.app.governance.models import TaskBoundary, TaskLifecycle, TaskRecord
    from demo.security_monitor.app.governance.storage import GovernanceStorage

    storage = GovernanceStorage(db_path)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    task_id = f"task_done_{suffix}"
    storage.save_task(TaskRecord(
        task_id=task_id, request_text="Summarise input/sales_1.csv", request_hash="h", agent_id="report_bot",
        workspace_root="/tmp/ws_done", status=TaskLifecycle.COMPLETED, created_at=now, completed_at=now))
    storage.save_boundary(TaskBoundary(
        task_id=task_id, workspace_root="/tmp/ws_done", files_read=["input/sales_1.csv"],
        files_write=["output/summary.txt"], network=[], tools=["read_file", "write_file"], peer_agents=[]))
    for kind, layer, verdict, summary in [
        ("phase", "intake", "ALLOW", "Boundary derived from request (1 read, 1 write targets)"),
        ("phase", "launcher", "ALLOW", "Compiled Landlock sandbox rules and seccomp filter"),
        ("phase", "launcher", "ALLOW", "Agent process launched (pid 4242)"),
        ("tool", "broker", "ALLOW", "read_file allowed: input/sales_1.csv"),
        ("sensor", "landlock", "BLOCK_ACTION", "Landlock blocked file_read on /home/u/projects/archive/q3_private_notes.txt"),
        ("output", "broker", "ALLOW", "Output file written: output/summary.txt"),
        ("termination", "launcher", "ALLOW", "Task lifecycle termination: agent_exited"),
        ("finished", "launcher", "COMPLETED", "Run ended: completed"),
    ]:
        storage.record_task_step(task_id, kind=kind, layer=layer, verdict=verdict, summary=summary,
                                 detail="Sales total: 300 across 4 regions." if kind == "output" else "",
                                 source_label="enforced")
    return task_id


def bar_heights(page, chart_id: str) -> list[float]:
    """Rendered height (px) of every bar in a Recharts bar chart, in data order (0 for a zero bar)."""
    return page.evaluate(
        """(id) => [...document.querySelectorAll(`#${id} .recharts-bar-rectangle`)].map(g => {
            const shape = g.querySelector('path, rect');
            return shape ? shape.getBoundingClientRect().height : 0;
        })""",
        chart_id,
    )


def assert_bars_match(page, chart_id: str, values: list[int]) -> None:
    heights = bar_heights(page, chart_id)
    assert len(heights) == len(values), f"{chart_id}: {len(heights)} bars for {len(values)} values"
    for v, h in zip(values, heights):
        assert (h > 0) == (v > 0), f"{chart_id}: value {v} drawn {h:.1f} px high ({heights})"
    nonzero = [(v, h) for v, h in zip(values, heights) if v > 0]
    # Heights are proportional to the values on one axis.
    for (v1, h1), (v2, h2) in zip(nonzero, nonzero[1:]):
        assert abs(h1 / v1 - h2 / v2) < 1.0, f"{chart_id}: bars not proportional ({heights})"
