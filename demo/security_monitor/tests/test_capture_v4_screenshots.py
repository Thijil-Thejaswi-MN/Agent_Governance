"""Capture high-resolution and mobile screenshots of all Console v4 screens.

Screens:
- signin (desktop 1440, mobile 390)
- overview / admin (desktop 1440, mobile 390)
- team lead (desktop 1440, mobile 390)
- reviewer inbox (desktop 1440, mobile 390)
- auditor records (desktop 1440, mobile 390)
- run investigation (desktop 1440, mobile 390)
"""
from __future__ import annotations

import time
from pathlib import Path
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import seed_waiting_task

OUT_DIR = Path(__file__).resolve().parents[3] / "ui_review" / "v4"

VIEWPORTS = [
    ("desktop", 1440, 900),
    ("mobile", 390, 844),
]


def test_capture_v4_screenshots(page: Page, console_server):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    task_id, req_id = seed_waiting_task(console_server.db_path, f"shot_{int(time.time() * 1000)}")

    for vp_name, w, h in VIEWPORTS:
        page.set_viewport_size({"width": w, "height": h})

        # 1. Signin Page
        page.goto(f"{console_server.url}/dashboard/signin")
        page.wait_for_timeout(500)
        page.screenshot(path=str(OUT_DIR / f"01_signin_{vp_name}.png"), full_page=True)

        # Authenticate
        page.locator("#operator-token-input").fill(console_server.token)
        page.locator("#sign-in-submit-btn").click()
        page.wait_for_timeout(1500)

        # 2. Overview / Admin
        page.goto(f"{console_server.url}/dashboard/overview")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT_DIR / f"02_admin_overview_{vp_name}.png"), full_page=True)

        # 3. Team Lead
        page.goto(f"{console_server.url}/dashboard/team")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT_DIR / f"03_team_lead_{vp_name}.png"), full_page=True)

        # 4. Reviewer Inbox
        page.goto(f"{console_server.url}/dashboard/inbox")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT_DIR / f"04_reviewer_inbox_{vp_name}.png"), full_page=True)

        # 5. Auditor Records
        page.goto(f"{console_server.url}/dashboard/records")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT_DIR / f"05_auditor_records_{vp_name}.png"), full_page=True)

        # 6. Run Investigation
        page.goto(f"{console_server.url}/dashboard/runs/{task_id}")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT_DIR / f"06_run_investigation_{vp_name}.png"), full_page=True)

