#!/usr/bin/env python3
"""Review evidence for console v3: screenshots of every screen and a recording of a live run.

Starts its own console server (temporary DB, receipts and operator token, like the browser
tests), then:
- screenshots, dark, at 1440 px and 390 px: Home, Ask, Watch (waiting), Fleet (waiting),
  Done, Done with the drawer open, Fleet, History, Results; each Watch/Done comes from a
  real scripted preset 2 run that is allowed from the decision card;
- with --record MODEL: a video of preset 2 with that model, approved live from the card.

Needs Linux/WSL2 with the OS layer (governed runs), Playwright, the built console, and for
--record a local Ollama with MODEL installed.

    python scripts/capture_ui_review_v3.py --out ui_review/v3 --record qwen2.5:7b
"""
from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from playwright.sync_api import Browser, BrowserContext, Page, expect, sync_playwright  # noqa: E402

from demo.security_monitor.tests.playwright_server import ConsoleServer, start_console_server  # noqa: E402

SIZES = {1440: (1440, 900), 390: (390, 844)}


def signed_in_context(browser: Browser, srv: ConsoleServer, width: int, **kwargs) -> BrowserContext:
    """A context with the read-session cookie and the token in sessionStorage (no sign-in on screen)."""
    w, h = SIZES[width]
    ctx = browser.new_context(viewport={"width": w, "height": h}, color_scheme="dark", **kwargs)
    resp = ctx.request.post(f"{srv.url}/api/governance/auth/session", headers={"X-Operator-Token": srv.token})
    assert resp.ok, resp.text()
    ctx.add_init_script(f"sessionStorage.setItem('governance_operator_token', {srv.token!r});")
    return ctx


def shot(page: Page, out: Path, name: str, width: int) -> None:
    page.wait_for_timeout(800)  # let the page fade-in finish
    path = out / f"{name}_{width}_dark.png"
    page.screenshot(path=str(path), full_page=True)
    print("  ", path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path)


def start_preset(page: Page, srv: ConsoleServer, preset: str, model: str) -> None:
    page.goto(f"{srv.url}/dashboard/run")
    page.locator(f"#preset-{preset}").click()
    page.locator("#model-selector").select_option(model)
    page.locator("#start-run-btn").click()
    page.wait_for_url("**/dashboard/run/task_*", timeout=20000)


def screenshots(browser: Browser, srv: ConsoleServer, out: Path) -> None:
    for width in SIZES:
        print(f"screenshots at {width} px")
        ctx = signed_in_context(browser, srv, width)
        page = ctx.new_page()
        page.goto(f"{srv.url}/dashboard/")
        expect(page.locator("#metric-harm")).to_contain_text("→")
        shot(page, out, "home", width)

        page.goto(f"{srv.url}/dashboard/run")
        page.locator("#preset-summarise_csv").click()
        expect(page.locator("#allow-preview")).to_contain_text("sales_data.csv")
        shot(page, out, "ask", width)

        start_preset(page, srv, "compare_target", "scripted")
        task_url = page.url
        card = page.locator('[id^="inline-approval-card-"]')
        expect(card).to_be_visible(timeout=60000)
        shot(page, out, "watch_waiting", width)

        page.goto(f"{srv.url}/dashboard/fleet")
        expect(page.locator("#fleet-headline")).to_contain_text("needs you")
        shot(page, out, "fleet_waiting", width)

        page.goto(task_url)
        card = page.locator('[id^="inline-approval-card-"]')
        expect(card).to_be_visible(timeout=15000)
        card.locator('[id^="inline-approve-btn-"]').click()
        expect(page.locator("#run-status")).to_have_attribute("data-state", "completed", timeout=120000)
        expect(page.locator("#record-status")).to_have_attribute("data-tone", "ok", timeout=15000)
        shot(page, out, "done", width)
        page.locator("#show-what-happened").click()
        shot(page, out, "done_details", width)

        page.goto(f"{srv.url}/dashboard/fleet")
        expect(page.locator("#fleet-headline")).to_be_visible()
        shot(page, out, "fleet", width)

        page.goto(f"{srv.url}/dashboard/history")
        expect(page.locator("#history-list li").first).to_be_visible()
        shot(page, out, "history", width)

        page.goto(f"{srv.url}/dashboard/results")
        expect(page.locator("h1")).to_have_text("Full results")
        shot(page, out, "results", width)
        ctx.close()


def record(browser: Browser, srv: ConsoleServer, out: Path, model: str) -> Path:
    print(f"recording preset 2 with {model}")
    with tempfile.TemporaryDirectory() as tmp:
        ctx = signed_in_context(browser, srv, 1440, record_video_dir=tmp, record_video_size={"width": 1440, "height": 900})
        page = ctx.new_page()
        t0 = time.monotonic()
        page.goto(f"{srv.url}/dashboard/run")
        page.locator("#preset-compare_target").click()
        page.locator("#model-selector").select_option(model)
        page.wait_for_timeout(1500)
        page.locator("#start-run-btn").click()
        page.wait_for_url("**/dashboard/run/task_*", timeout=20000)
        card = page.locator('[id^="inline-approval-card-"]')
        expect(card).to_be_visible(timeout=240000)
        t_card = time.monotonic() - t0
        page.wait_for_timeout(3000)  # time to read the card
        card.locator('[id^="inline-approve-btn-"]').click()
        status = page.locator("#run-status")
        expect(status).to_have_attribute("data-state", "completed", timeout=300000)
        expect(page.locator("#record-status")).to_have_attribute("data-tone", "ok", timeout=15000)
        t_done = time.monotonic() - t0
        page.wait_for_timeout(2500)
        page.locator("#show-what-happened").click()
        page.wait_for_timeout(3000)
        print(f"   card after {t_card:.1f} s, done after {t_done:.1f} s; final sentence: {status.inner_text()!r}")
        video = page.video
        ctx.close()
        dest = out / f"run_preset2_{model.replace(':', '_')}_approved.webm"
        video.save_as(str(dest))
    print("  ", dest)
    return dest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "ui_review" / "v3")
    ap.add_argument("--record", metavar="MODEL", help="also record preset 2 with this Ollama model")
    ap.add_argument("--no-screenshots", action="store_true")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as work:
        srv = start_console_server(Path(work))
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                if not args.no_screenshots:
                    screenshots(browser, srv, args.out)
                if args.record:
                    record(browser, srv, args.out, args.record)
                browser.close()
        finally:
            srv.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
