"""Playwright test verifying that Results and Home render values from results_summary.json.

Intercepts /dashboard/results_summary.json (or **/results_summary.json) with altered values
and asserts that both pages render the altered values without hard-typed fallbacks.
"""
from __future__ import annotations

import json
import pytest

try:
    from playwright.sync_api import Page, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

from demo.security_monitor.tests.playwright_server import assert_bars_match, sign_in

pytestmark = [
    pytest.mark.playwright,
    pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="playwright not installed (pip install -r demo/security_monitor/requirements-ui-test.txt)"),
]


def test_evaluation_page_intercepts_altered_summary(page: Page, console_server):
    base_url = console_server.url
    sign_in(page, console_server)

    altered_summary = {
        "generated_at": "2026-10-27T19:00:00+00:00",
        "evaluation_label": "Altered Test Evaluation Benchmark 999",
        "model": "altered-model:99b",
        "harm_injected": {
            "A": {"exposed": 29, "total": 35, "rate": 0.828, "ratio": "29/35"},
            "B": {"exposed": 3, "total": 35, "rate": 0.085, "ratio": "3/35"},
            "C": {"exposed": 1, "total": 35, "rate": 0.028, "ratio": "1/35"},
            "D": {"exposed": 0, "total": 35, "rate": 0.0, "ratio": "0/35"},
        },
        "shell_attacks_succeeded": {
            "B": {"succeeded": 7, "total": 7, "ratio": "7 of 7"},
            "C": {"succeeded": 2, "total": 11, "ratio": "2 of 11"},
        },
        "utility_anticipated_correct": {
            "A": {"correct": 28, "total": 35, "rate": 0.8, "ratio": "28/35"},
            "C": {"correct": 33, "total": 35, "rate": 0.94, "ratio": "33/35"},
        },
        "expansion_chain_unanticipated_c": {
            "denied_before_request": 30,
            "requested": 25,
            "granted": 20,
            "delivered_read_ok": 18,
            "total": 30,
            "chain": [30, 25, 20, 18],
            "chain_str": "30 / 25 / 20 / 18",
            "steps": [
                {"name": "Probe Denied (EACCES)", "count": 30, "total": 30},
                {"name": "Expansion Requested", "count": 25, "total": 30},
                {"name": "Expansion Approved", "count": 20, "total": 30},
                {"name": "Delivered File Read", "count": 18, "total": 30},
            ],
        },
        "timings_and_timeouts": {
            "A": {"mean_s": 99, "total_trials": 35, "timeouts": 5, "timeout_ratio": "5/35"},
            "B": {"mean_s": 88, "total_trials": 35, "timeouts": 4, "timeout_ratio": "4/35"},
            "C": {"mean_s": 77, "total_trials": 35, "timeouts": 3, "timeout_ratio": "3/35"},
            "D": {"mean_s": 66, "total_trials": 35, "timeouts": 2, "timeout_ratio": "2/35"},
        },
        "utility_timings_anticipated": {
            "A": {"mean_s": 3.1, "total_trials": 35},
            "C": {"mean_s": 5.6, "total_trials": 35},
            "extra_s_c_vs_a": 2.5,
        },
        "limitations": [
            "Custom intercepted verification rule for empirical evaluation integrity.",
        ],
    }

    def handle_route(route):
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(altered_summary),
        )

    # Intercept any request matching results_summary.json
    page.route("**/results_summary.json*", handle_route)

    # Navigate to the Results page
    page.goto(f"{base_url}/dashboard/results")

    # Assert heading is present
    expect(page.locator("h1")).to_contain_text("Full results")

    # Each chart draws one bar per condition, non-zero exactly where the value is,
    # also right after a resize (no grow-in animation that leaves empty bars)
    page.locator("#chart-harm .recharts-bar-rectangle").first.wait_for(state="attached")
    assert_bars_match(page, "chart-harm", [29, 3, 1, 0])
    assert_bars_match(page, "chart-shell", [7, 2])
    page.set_viewport_size({"width": 390, "height": 844})
    assert_bars_match(page, "chart-harm", [29, 3, 1, 0])
    assert_bars_match(page, "chart-shell", [7, 2])
    page.set_viewport_size({"width": 1280, "height": 720})

    # Assert altered evaluation label is rendered
    expect(page.locator("body")).to_contain_text("Altered Test Evaluation Benchmark 999")

    # Assert altered Harm Injected values are rendered (29/35, 3/35, 1/35)
    expect(page.locator("body")).to_contain_text("29/35")
    expect(page.locator("body")).to_contain_text("3/35")
    expect(page.locator("body")).to_contain_text("1/35")

    # Assert condition labels are strictly formatted
    expect(page.locator("body")).to_contain_text('A "No governance"')
    expect(page.locator("body")).to_contain_text('B "Tool layer only"')
    expect(page.locator("body")).to_contain_text('C "Tool + OS layer"')
    expect(page.locator("body")).to_contain_text('D "Per-task container"')

    # Assert altered shell attack outcomes are rendered (7 of 7, 2 of 11)
    expect(page.locator("body")).to_contain_text("7 of 7")
    expect(page.locator("body")).to_contain_text("2 of 11")

    # Assert altered expansion steps are rendered (30/30, 25/30, 20/30, 18/30)
    expect(page.locator("body")).to_contain_text("30/30")
    expect(page.locator("body")).to_contain_text("25/30")
    expect(page.locator("body")).to_contain_text("20/30")
    expect(page.locator("body")).to_contain_text("18/30")

    # Assert altered trial durations are rendered (99s, 88s, 77s, 66s)
    expect(page.locator("body")).to_contain_text("99s")
    expect(page.locator("body")).to_contain_text("88s")
    expect(page.locator("body")).to_contain_text("77s")
    expect(page.locator("body")).to_contain_text("66s")

    # Assert altered limitations list item is rendered
    expect(page.locator("body")).to_contain_text("Custom intercepted verification rule for empirical evaluation integrity.")

    # Assert altered time per legitimate task is rendered
    expect(page.locator("#utility-timings")).to_contain_text("3.1s")
    expect(page.locator("#utility-timings")).to_contain_text("5.6s")
    expect(page.locator("#utility-timings")).to_contain_text("+2.5s")

    # Home renders its two numbers from the same file: harm A -> C out of the total, extra time
    page.goto(f"{base_url}/dashboard")
    expect(page.locator("#metric-harm")).to_contain_text("29 → 1")
    expect(page.locator("#metric-harm")).to_contain_text("out of 35")
    expect(page.locator("#metric-time")).to_contain_text("+2.5 s")
    expect(page.locator("#metric-time")).to_contain_text("3.1 s → 5.6 s")



def test_results_charts_draw_the_real_values(page: Page, console_server):
    """With the committed results_summary.json: harm A 14, B/C/D 0; shell attacks B 8, C 0."""
    import pathlib
    summary = json.loads((pathlib.Path(__file__).resolve().parents[1] / "app" / "dashboard_v2" / "public" /
                          "results_summary.json").read_text(encoding="utf-8"))
    harm = [summary["harm_injected"][c]["exposed"] for c in "ABCD"]
    shell = [summary["shell_attacks_succeeded"][c]["succeeded"] for c in "BC"]
    assert harm == [14, 0, 0, 0] and shell == [8, 0]
    for width, height in ((1440, 900), (390, 844)):
        page.set_viewport_size({"width": width, "height": height})
        page.goto(f"{console_server.url}/dashboard/results")
        page.locator("#chart-harm .recharts-bar-rectangle").first.wait_for(state="attached")
        assert_bars_match(page, "chart-harm", harm)
        assert_bars_match(page, "chart-shell", shell)
