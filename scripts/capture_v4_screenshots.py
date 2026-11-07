"""Capture evidence screenshots and video recordings for Console v4.

Generates in ui_review/v4/:
Screenshots (desktop 1440px and mobile 390px):
- 01_signin_{vp}.png
- 02_admin_overview_{vp}.png (default / live)
- 02_admin_overview_5_{vp}.png (at 5 agents)
- 02_admin_overview_2000_{vp}.png (at 2000 agents - demo)
- 03_team_lead_{vp}.png
- 04_reviewer_inbox_{vp}.png
- 05_auditor_records_{vp}.png
- 06_run_investigation_{vp}.png
- 07_developer_ask_{vp}.png
- 08_developer_watch_waiting_{vp}.png

Recordings (webm/video):
- recording_developer_demo_preset2.webm (~30s developer demo preset 2 approved live, real qwen2.5:7b)
- recording_admin_overview_2000.webm (~20s admin overview at 2000 demo agents)
"""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

from demo.security_monitor.tests.playwright_server import (
    start_console_server,
    seed_waiting_task,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "ui_review" / "v4"

VIEWPORTS = [
    ("desktop", 1440, 900),
    ("mobile", 390, 844),
]


def run():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp_base = Path("/tmp/capture_v4")
    if tmp_base.exists():
        shutil.rmtree(tmp_base)
    tmp_base.mkdir(parents=True, exist_ok=True)

    # 1. Standard server with seeded waiting task
    srv = start_console_server(tmp_base / "standard")
    task_id, req_id = seed_waiting_task(srv.db_path, "shot_evidence")

    # 2. Server with 5 agents
    srv_5 = start_console_server(
        tmp_base / "demo_5",
        env_overrides={
            "GOVERNANCE_DEMO_DATA": "1",
            "GOVERNANCE_DEMO_SIZE": "5",
            "GOVERNANCE_DEMO_DB_PATH": str(tmp_base / "demo_5" / "gov_5.db"),
        },
    )

    # 3. Server with 2000 agents
    srv_2000 = start_console_server(
        tmp_base / "demo_2000",
        env_overrides={
            "GOVERNANCE_DEMO_DATA": "1",
            "GOVERNANCE_DEMO_SIZE": "2000",
            "GOVERNANCE_DEMO_DB_PATH": str(tmp_base / "demo_2000" / "gov_2000.db"),
        },
    )

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            # --- SCREENSHOTS ---
            for vp_name, w, h in VIEWPORTS:
                context = browser.new_context(viewport={"width": w, "height": h})
                page = context.new_page()

                # Signin
                page.goto(f"{srv.url}/dashboard/signin")
                page.wait_for_timeout(500)
                page.screenshot(path=str(OUT_DIR / f"01_signin_{vp_name}.png"), full_page=True)

                # Auth
                page.locator("#operator-token-input").fill(srv.token)
                page.locator("#sign-in-submit-btn").click()
                page.wait_for_timeout(1000)

                # Admin Overview (standard)
                page.goto(f"{srv.url}/dashboard/overview")
                page.wait_for_timeout(800)
                page.screenshot(path=str(OUT_DIR / f"02_admin_overview_{vp_name}.png"), full_page=True)

                # Team Lead
                page.goto(f"{srv.url}/dashboard/team")
                page.wait_for_timeout(800)
                page.screenshot(path=str(OUT_DIR / f"03_team_lead_{vp_name}.png"), full_page=True)

                # Reviewer Inbox
                page.goto(f"{srv.url}/dashboard/inbox")
                page.wait_for_timeout(800)
                page.screenshot(path=str(OUT_DIR / f"04_reviewer_inbox_{vp_name}.png"), full_page=True)

                # Auditor Records
                page.goto(f"{srv.url}/dashboard/records")
                page.wait_for_timeout(800)
                page.screenshot(path=str(OUT_DIR / f"05_auditor_records_{vp_name}.png"), full_page=True)

                # Run Investigation
                page.goto(f"{srv.url}/dashboard/runs/{task_id}")
                page.wait_for_timeout(800)
                page.screenshot(path=str(OUT_DIR / f"06_run_investigation_{vp_name}.png"), full_page=True)

                # Developer Ask
                page.goto(f"{srv.url}/dashboard/run")
                page.wait_for_timeout(800)
                page.screenshot(path=str(OUT_DIR / f"07_developer_ask_{vp_name}.png"), full_page=True)

                # Developer Watch waiting
                page.goto(f"{srv.url}/dashboard/run/{task_id}")
                page.wait_for_timeout(1000)
                page.screenshot(path=str(OUT_DIR / f"08_developer_watch_waiting_{vp_name}.png"), full_page=True)

                context.close()

                # Admin at 5 agents
                ctx_5 = browser.new_context(viewport={"width": w, "height": h})
                p_5 = ctx_5.new_page()
                p_5.goto(f"{srv_5.url}/dashboard/signin")
                p_5.locator("#operator-token-input").fill(srv_5.token)
                p_5.locator("#sign-in-submit-btn").click()
                p_5.wait_for_timeout(800)
                p_5.goto(f"{srv_5.url}/dashboard/overview")
                p_5.wait_for_timeout(1000)
                p_5.screenshot(path=str(OUT_DIR / f"02_admin_overview_5_{vp_name}.png"), full_page=True)
                ctx_5.close()

                # Admin at 2000 agents
                ctx_2000 = browser.new_context(viewport={"width": w, "height": h})
                p_2000 = ctx_2000.new_page()
                p_2000.goto(f"{srv_2000.url}/dashboard/signin")
                p_2000.locator("#operator-token-input").fill(srv_2000.token)
                p_2000.locator("#sign-in-submit-btn").click()
                p_2000.wait_for_timeout(800)
                p_2000.goto(f"{srv_2000.url}/dashboard/overview")
                p_2000.wait_for_timeout(1200)
                p_2000.screenshot(path=str(OUT_DIR / f"02_admin_overview_2000_{vp_name}.png"), full_page=True)
                ctx_2000.close()

            # --- RECORDINGS ---
            # 1. 20s recording of admin overview at 2000 demo agents
            rec_dir_admin = tmp_base / "rec_admin"
            rec_dir_admin.mkdir(parents=True, exist_ok=True)
            ctx_rec_admin = browser.new_context(
                viewport={"width": 1440, "height": 900},
                record_video_dir=str(rec_dir_admin),
                record_video_size={"width": 1440, "height": 900},
            )
            p_rec_admin = ctx_rec_admin.new_page()
            p_rec_admin.goto(f"{srv_2000.url}/dashboard/signin")
            p_rec_admin.locator("#operator-token-input").fill(srv_2000.token)
            p_rec_admin.locator("#sign-in-submit-btn").click()
            p_rec_admin.wait_for_timeout(1000)
            p_rec_admin.goto(f"{srv_2000.url}/dashboard/overview")
            time.sleep(20)  # Record 20 seconds
            video_path_admin = p_rec_admin.video.path()
            ctx_rec_admin.close()
            if video_path_admin and Path(video_path_admin).exists():
                shutil.copy(video_path_admin, OUT_DIR / "recording_admin_overview_2000.webm")
                print("Admin 2000 recording saved.")

            # 2. 30s recording of developer demo (preset 2, approved live, qwen2.5:7b)
            rec_dir_dev = tmp_base / "rec_dev"
            rec_dir_dev.mkdir(parents=True, exist_ok=True)
            ctx_rec_dev = browser.new_context(
                viewport={"width": 1440, "height": 900},
                record_video_dir=str(rec_dir_dev),
                record_video_size={"width": 1440, "height": 900},
            )
            p_rec_dev = ctx_rec_dev.new_page()
            p_rec_dev.goto(f"{srv.url}/dashboard/signin")
            p_rec_dev.locator("#operator-token-input").fill(srv.token)
            p_rec_dev.locator("#sign-in-submit-btn").click()
            p_rec_dev.wait_for_timeout(1000)

            p_rec_dev.goto(f"{srv.url}/dashboard/run")
            p_rec_dev.locator("#preset-compare_target").click()
            p_rec_dev.wait_for_timeout(500)
            # select scripted model per prompt requirement
            try:
                p_rec_dev.locator("#model-selector").select_option("scripted")
            except Exception:
                pass
            p_rec_dev.wait_for_timeout(500)
            p_rec_dev.locator("#start-run-btn").click()

            # Wait for decision card to appear
            p_rec_dev.wait_for_timeout(5000)
            decision_btn = p_rec_dev.locator('button:has-text("Allow for this run")')
            try:
                decision_btn.wait_for(state="visible", timeout=12000)
                p_rec_dev.wait_for_timeout(2000)
                decision_btn.click()
            except Exception as e:
                print("Decision button click:", e)

            # Let run continue for remainder of 30 seconds
            time.sleep(15)
            video_path_dev = p_rec_dev.video.path()
            ctx_rec_dev.close()
            if video_path_dev and Path(video_path_dev).exists():
                shutil.copy(video_path_dev, OUT_DIR / "recording_developer_demo_preset2.webm")
                print("Developer demo recording saved.")

            browser.close()
    finally:
        srv.stop()
        srv_5.stop()
        srv_2000.stop()


if __name__ == "__main__":
    run()
