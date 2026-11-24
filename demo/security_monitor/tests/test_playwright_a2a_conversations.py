"""Playwright end-to-end tests for the A2A 3-panel conversations page."""
from __future__ import annotations

import datetime
import http.server
import json
import os
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Any
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import sign_in, start_console_server, OPERATOR_NAME
from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    ExpansionStatus,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.app.governance.delegation import DelegationManager
from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.expansion import ExpansionService

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed"),
]


class FixtureHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True


class FixtureHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        payload = {"attractions": ["Kinkaku-ji", "Fushimi Inari-taisha", "Kiyomizu-dera"]}
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture(scope="module")
def fixture_server():
    server = None
    try:
        server = FixtureHTTPServer(("127.0.0.1", 8765), FixtureHTTPHandler)
        th = threading.Thread(target=server.serve_forever, daemon=True)
        th.start()
        yield server
    except OSError:
        yield None
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()


@pytest.fixture(scope="module")
def a2a_console_server(tmp_path_factory, fixture_server):
    srv = start_console_server(tmp_path_factory.mktemp("console_a2a_conv"))
    yield srv
    srv.stop()


def test_a2a_conversations_page(page: Page, a2a_console_server, tmp_path: Path):
    console_server = a2a_console_server
    storage = GovernanceStorage(console_server.db_path)
    expansion = ExpansionService(storage)

    root_task_id = "task_planner_pw_01"
    token = "tok_planner_pw_01"
    storage.save_token(token, root_task_id, "planner")

    ws = tmp_path / "workspaces" / root_task_id
    (ws / "input").mkdir(parents=True, exist_ok=True)
    (ws / "output").mkdir(parents=True, exist_ok=True)
    (ws / "input" / "passport_scan.pdf").write_text("CONFIDENTIAL PASSPORT DATA ref=CANARY_123", encoding="utf-8")
    (ws / "input" / "budget_policy.txt").write_text("Max budget for Kyoto trip: $2000 per person.", encoding="utf-8")
    (ws / "input" / "travel_history.csv").write_text("trip_id,year,destination\n1,2023,Tokyo\n2,2024,Osaka\n", encoding="utf-8")

    planner_task = TaskRecord(
        task_id=root_task_id,
        request_text="Plan trip with trip planner multi-agent delegation",
        request_hash="hash_planner_pw",
        agent_id="planner",
        workspace_root=str(ws),
        status=TaskLifecycle.ACTIVE,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        root_task_id=root_task_id,
        depth=0,
        chain=["planner"],
        owner=OPERATOR_NAME,
        team="travel",
    )
    storage.save_task(planner_task)

    planner_boundary = TaskBoundary(
        task_id=root_task_id,
        tools=["read_file", "call_agent", "call_agents", "http_post", "http_get"],
        files_read=["input/*", "input/passport_scan.pdf"],
        files_write=["output/*"],
        network=["127.0.0.1:*", "localhost:*"],
        peer_agents=["researcher", "budget", "booking"],
        workspace_root=str(ws),
        metadata={"canary": "CANARY_TRIP_TEST_123", "private_files": [{"path": "input/passport_scan.pdf"}]},
    )
    storage.save_boundary(planner_boundary)

    mgr = DelegationManager(storage, workspace_base=tmp_path / "workspaces")
    broker = ToolBroker(storage, expansion_service=expansion)
    broker.default_approval_timeout = 30.0
    broker.delegation_manager = mgr

    # Sign in to console server as operator
    sign_in(page, console_server, path="/dashboard/history")

    # Start planner run in background thread
    def _run_planner():
        broker.read_file(token, "input/passport_scan.pdf")
        calls = [
            {"target": "researcher", "message": {"text": "Please research top Kyoto attractions"}},
            {"target": "budget", "message": {"text": "Please calculate budget estimate for Kyoto"}},
            {"target": "booking", "message": {"text": "Please arrange hotel and booking in Kyoto"}},
        ]
        broker.call_agents(token, calls)
        try:
            broker.http_post(token, "https://gion-maru-travel.example/api/v1/booking", file_path="input/passport_scan.pdf")
        except PermissionError:
            pass
        planner_task.status = TaskLifecycle.COMPLETED
        storage.save_task(planner_task)

    runner_thread = threading.Thread(target=_run_planner, daemon=True)
    runner_thread.start()

    # Open conversations page while running at 1440px desktop
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{console_server.url}/dashboard/conversations/{root_task_id}")

    # TopBar title verification (Item 6): shows "Agent conversations" and not "Page not found"
    expect(page.locator("[data-topbar]")).to_contain_text("Agent conversations")
    expect(page.locator("[data-topbar]")).not_to_contain_text("Page not found")

    # 1. Verify header has title and owner request
    expect(page.locator("h1")).to_contain_text("conversations", timeout=10000)
    expect(page.locator("#request-text")).to_contain_text("Plan trip with trip planner")

    # 2. Rule 1 (A2A-2): the Planner opened the passport scan, so its fan-out waits for the
    # owner's OK. The card says why in plain words; pressing Approve lets the three calls go.
    flow_card = page.locator("[id^=approval-card-]").filter(has_text="Your OK is needed")
    expect(flow_card).to_be_visible(timeout=10000)
    expect(flow_card).to_contain_text("Planner wants to message Researcher, Budget, Booking while holding private data")
    expect(flow_card).to_contain_text("data rule")
    flow_card.locator("[id^=approve-btn-]").click()

    # 3. Verify fanout tag "sent 3 at once" appears (Item 4 & 9)
    fanout_tag = page.locator('[data-testid="fanout-tag"]')
    expect(fanout_tag).to_be_visible(timeout=10000)
    expect(fanout_tag).to_contain_text("sent 3 at once")

    # 4. Verify Researcher approval card appears with approve button
    approval_card = page.locator("[id^=approval-card-]").filter(has_text="input/travel_history.csv")
    expect(approval_card).to_be_visible(timeout=10000)

    approve_btn = approval_card.locator("[id^=approve-btn-]")
    expect(approve_btn).to_be_visible()

    # 5. Approving it allows run to proceed
    approve_btn.click()

    # Wait for background thread to conclude
    runner_thread.join(timeout=15)
    assert not runner_thread.is_alive(), "Planner runner thread did not conclude"

    # 6. Verify exactly 8 messages and 2 refused arrows with ✕
    rows = page.locator('[data-testid="timeline-row"]')
    expect(rows).to_have_count(8, timeout=10000)

    refused_marks = page.locator('[data-testid="refused-x"]')
    expect(refused_marks).to_have_count(2)
    expect(refused_marks.nth(0)).to_have_text("✕")
    expect(refused_marks.nth(1)).to_have_text("✕")

    # 6. Verify every timeline arrow has a positive width (Item 9)
    arrow_containers = page.locator('[data-testid="timeline-row"] .h-7 > div')
    arrow_count = arrow_containers.count()
    assert arrow_count == 8, f"Expected 8 arrow graphics, got {arrow_count}"
    for i in range(arrow_count):
        box = arrow_containers.nth(i).bounding_box()
        assert box is not None and box["width"] > 0, f"Arrow {i} has non-positive width: {box}"

    # 7. Verify the page shows no text containing /proc/, /usr/lib, /tmp/pytest or /bin/ (Item 9)
    body_text = page.locator("body").inner_text()
    for forbidden_path in ("/proc/", "/usr/lib", "/tmp/pytest", "/bin/"):
        assert forbidden_path not in body_text, f"Found leaked path {forbidden_path} in page text"

    # 8. Verify names, not ids, everywhere (Item 7): "host:x" shows as "x (website)"
    expect(page.locator("body")).to_contain_text("gion-maru-travel.example (website)")

    # 9. Verify clicking Booking chat highlights Booking rows and dims others
    booking_thread = page.locator("#thread-booking__planner")
    expect(booking_thread).to_be_visible()
    booking_thread.click()

    # Check that rows with booking have opacity-100 and others have opacity-40
    booking_rows = page.locator('[data-testid="timeline-row"][data-from="booking"], [data-testid="timeline-row"][data-to="booking"]')
    expect(booking_rows.first).to_have_class(re.compile(r"opacity-100"))

    non_booking_rows = page.locator('[data-testid="timeline-row"][data-from="planner"][data-to="researcher"]')
    expect(non_booking_rows.nth(0)).to_have_class(re.compile(r"opacity-40"))

    # 10. Save desktop screenshot at 1440px
    screenshot_dir = Path("docs/screenshots/a2a")
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    desktop_png = screenshot_dir / "conversations_1440.png"
    page.screenshot(path=str(desktop_png))

    artifact_dir = Path(os.getenv("ARTIFACT_DIR", "/mnt/c/Users/thiji/.gemini/antigravity/brain/7dfddae5-2ec5-4828-adfc-82c7f1c598c6/screenshots"))
    if artifact_dir.parent.exists():
        artifact_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(desktop_png, artifact_dir / "conversations_1440.png")

    # 11. Phone width checks (Item 8): selected tab always matches panel shown
    page.set_viewport_size({"width": 375, "height": 812})
    tab_chats = page.locator("#mobile-tab-chats")
    tab_conv = page.locator("#mobile-tab-conversation")
    tab_timeline = page.locator("#mobile-tab-timeline")

    panel_chats = page.locator("#panel-chats")
    panel_conv = page.locator("#panel-conversation")
    panel_timeline = page.locator("#panel-timeline")

    # Default is Conversation
    expect(panel_conv).to_be_visible()
    expect(panel_chats).not_to_be_visible()
    expect(panel_timeline).not_to_be_visible()

    # Switching to Chats tab shows Chats panel
    tab_chats.click()
    expect(panel_chats).to_be_visible()
    expect(panel_conv).not_to_be_visible()
    expect(panel_timeline).not_to_be_visible()

    # Picking a chat in tree switches to Conversation panel
    page.locator("#thread-booking__planner").click()
    expect(panel_conv).to_be_visible()
    expect(panel_chats).not_to_be_visible()
    expect(panel_timeline).not_to_be_visible()

    # Switching to Timeline tab shows Timeline panel
    tab_timeline.click()
    expect(panel_timeline).to_be_visible()
    expect(panel_conv).not_to_be_visible()
    expect(panel_chats).not_to_be_visible()

    # Switch back to Conversation tab for mobile view screenshot
    tab_conv.click()
    expect(panel_conv).to_be_visible()

    # Save phone screenshot at 375px
    phone_png = screenshot_dir / "conversations_375.png"
    page.screenshot(path=str(phone_png))
    if artifact_dir.parent.exists():
        shutil.copyfile(phone_png, artifact_dir / "conversations_375.png")
