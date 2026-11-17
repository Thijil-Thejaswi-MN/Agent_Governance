from __future__ import annotations

import tempfile
import os
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import (
    NEVER_SAY,
    banned_words_in,
    sign_in,
    visible_text_outside_details,
)

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed"),
]


def test_file_upload_csv(page: Page, console_server):
    # a) set_input_files with a small CSV -> '#attached-files' contains 'input/<name>.csv'
    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/run")
    expect(page.locator("#preset-summarise_csv")).to_be_visible()

    # Open Add your own file panel
    page.locator("button:has-text('Add your own file')").click()

    # Upload small CSV
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write("metric,val\nA,100\nB,200\n")
        csv_path = f.name

    try:
        page.locator("#file-drop-input").set_input_files(csv_path)
        base_name = os.path.basename(csv_path)
        expect(page.locator("#attached-files")).to_contain_text(f"input/{base_name}")
    finally:
        if os.path.exists(csv_path):
            os.unlink(csv_path)

    text = visible_text_outside_details(page)
    assert banned_words_in(text, NEVER_SAY) == [], text


def test_file_upload_oversized_rejected(page: Page, console_server):
    # b) a 60 KB file -> the 50 KB error, nothing added
    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/run")
    expect(page.locator("#preset-summarise_csv")).to_be_visible()

    page.locator("button:has-text('Add your own file')").click()

    # 60 KB text file
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("A" * (60 * 1024))
        big_path = f.name

    try:
        page.locator("#file-drop-input").set_input_files(big_path)
        base_name = os.path.basename(big_path)
        alert = page.locator("[role='alert']")
        expect(alert).to_be_visible()
        expect(alert).to_contain_text("larger than 50 KB")
        # Ensure not added to attached files
        attached = page.locator("#attached-files")
        if attached.count() > 0:
            expect(attached).not_to_contain_text(base_name)
    finally:
        if os.path.exists(big_path):
            os.unlink(big_path)


def test_file_upload_unsupported_rejected(page: Page, console_server):
    # c) a .pdf -> the 'only text files' error
    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/run")
    expect(page.locator("#preset-summarise_csv")).to_be_visible()

    page.locator("button:has-text('Add your own file')").click()

    with tempfile.NamedTemporaryFile("w", suffix=".pdf", delete=False) as f:
        f.write("%PDF-1.4 dummy pdf content")
        pdf_path = f.name

    try:
        page.locator("#file-drop-input").set_input_files(pdf_path)
        base_name = os.path.basename(pdf_path)
        alert = page.locator("[role='alert']")
        expect(alert).to_be_visible()
        expect(alert).to_contain_text("only text files")
        attached = page.locator("#attached-files")
        if attached.count() > 0:
            expect(attached).not_to_contain_text(base_name)
    finally:
        if os.path.exists(pdf_path):
            os.unlink(pdf_path)


def test_old_paste_flow_still_works(page: Page, console_server):
    # d) the old paste flow still adds a file
    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/run")
    expect(page.locator("#preset-summarise_csv")).to_be_visible()

    page.locator("button:has-text('Add your own file')").click()

    # Use paste form inputs with input/ prefix as required by paste flow validation
    page.locator("label:has-text('File name') input").fill("input/manual_data.json")
    page.locator("label:has-text('Text (up to 50 KB)') textarea").fill('{"status": "ok"}')
    page.locator("button:has-text('Add file')").click()

    expect(page.locator("#attached-files")).to_contain_text("input/manual_data.json")


def test_no_horizontal_scroll_375px(page: Page, console_server):
    # e) no horizontal scroll at 375 px
    page.set_viewport_size({"width": 375, "height": 812})
    sign_in(page, console_server)
    page.goto(f"{console_server.url}/dashboard/run")
    expect(page.locator("#preset-summarise_csv")).to_be_visible()

    page.locator("button:has-text('Add your own file')").click()
    expect(page.locator("#file-drop-input")).to_be_attached()

    scroll_width = page.evaluate("() => document.documentElement.scrollWidth")
    client_width = page.evaluate("() => document.documentElement.clientWidth")
    assert scroll_width <= client_width, f"scrollWidth={scroll_width} > clientWidth={client_width}"