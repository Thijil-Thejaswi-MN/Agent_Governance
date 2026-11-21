"""Summarise agent efficiency from committed evaluation runs (no new runs).

Processes:
  - inworkspace_v1_qwen2.5_7b.jsonl
  - inworkspace_v1_gpt-oss-20b.jsonl
  - full_v3b_qwen2.5_7b.jsonl
  - utility_v3d_qwen2.5_7b.jsonl
under demo/data/evaluation_v3/results/.

Per condition:
  - median & p95 trial time
  - tool calls (median, p95)
  - model calls (median, p95)
  - tokens (if recorded)
  - refusals
  - timeouts
  - correct answers
Excludes infra errors from all denominators and metrics.

Outputs:
  demo/data/perf/agent_efficiency_v1.json
  demo/data/perf/agent_efficiency_v1.md
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile
from collections import defaultdict
from pathlib import Path
from typing import Any

# Ensure parent directory is on sys.path for app imports
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "demo" / "security_monitor"))

from app.governance.perf_stats import median, percentile


EVAL_RESULTS_DIR = REPO_ROOT / "demo" / "data" / "evaluation_v3" / "results"
RECEIPTS_ARCHIVE = EVAL_RESULTS_DIR / "receipts.tar.gz"
OUTPUT_DIR = REPO_ROOT / "demo" / "data" / "perf"

TARGET_FILES = [
    "inworkspace_v1_qwen2.5_7b.jsonl",
    "inworkspace_v1_gpt-oss-20b.jsonl",
    "full_v3b_qwen2.5_7b.jsonl",
    "utility_v3d_qwen2.5_7b.jsonl",
]


def _build_receipt_cache() -> dict[str, dict[str, Any]]:
    """Index available receipts from disk and tar archive."""
    cache: dict[str, dict[str, Any]] = {}
    if not RECEIPTS_ARCHIVE.is_file():
        return cache
    try:
        with tarfile.open(RECEIPTS_ARCHIVE, "r") as tf:
            for member in tf.getmembers():
                if member.isfile() and member.name.endswith(".json"):
                    base = os.path.basename(member.name)
                    fh = tf.extractfile(member)
                    if fh:
                        try:
                            cache[base] = json.loads(fh.read().decode("utf-8"))
                        except Exception:
                            pass
    except Exception:
        pass
    return cache


def is_infra_error(record: dict[str, Any]) -> bool:
    """Check if record was marked as an infrastructure error."""
    if record.get("infra_error"):
        return True
    if str(record.get("aborted", "")).lower() == "infra_error":
        return True
    return False


def is_timeout(record: dict[str, Any]) -> bool:
    """Check if record timed out."""
    wt = float(record.get("wall_time_s") or 0.0)
    if wt >= 175.0:
        return True
    err_str = str(record.get("trial_error", "")).lower()
    abort_str = str(record.get("aborted", "")).lower()
    return "timeout" in err_str or "timeout" in abort_str


def is_correct_answer(record: dict[str, Any]) -> bool:
    """Check if task answer was evaluated as correct."""
    if record.get("answer_correct") is True:
        return True
    gt = record.get("ground_truth") or {}
    return gt.get("answer_correct") is True


def has_refusal(record: dict[str, Any]) -> bool:
    """Check if any attempted action was prevented or marked outside."""
    attempts = record.get("attempts") or []
    for att in attempts:
        if att.get("prevented_by") or att.get("outside"):
            return True
    return False


def extract_trial_metrics(
    record: dict[str, Any], receipt_cache: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Extract numeric metrics from a single trial."""
    wall_time = float(record.get("wall_time_s") or 0.0)
    
    # Tool calls from tool_history
    tool_history = record.get("tool_history") or []
    tool_calls = len(tool_history)
    
    # Model calls and tokens from receipt or fallback
    model_calls = 0
    tokens = None
    rp = record.get("receipt_path")
    rc = None
    if rp:
        base = os.path.basename(rp)
        if os.path.isfile(rp):
            try:
                with open(rp, "r", encoding="utf-8") as f:
                    rc = json.load(f)
            except Exception:
                pass
        elif base in receipt_cache:
            rc = receipt_cache[base]
        else:
            cand = EVAL_RESULTS_DIR / "receipts" / base
            if cand.is_file():
                try:
                    with open(cand, "r", encoding="utf-8") as f:
                        rc = json.load(f)
                except Exception:
                    pass
    
    if rc:
        extra = rc.get("extra") or {}
        rpc_counts = extra.get("rpc_call_counts") or {}
        model_calls = int(extra.get("llm_calls") or rpc_counts.get("llm_complete") or 0)
        tok_val = extra.get("tokens") or rc.get("tokens")
        if tok_val is not None:
            tokens = int(tok_val)
    else:
        # Fallback heuristic: 1 initial call + 1 per tool call
        model_calls = max(1, tool_calls)

    return {
        "wall_time_s": wall_time,
        "tool_calls": tool_calls,
        "model_calls": model_calls,
        "tokens": tokens,
        "refused": has_refusal(record),
        "timeout": is_timeout(record),
        "correct": is_correct_answer(record),
    }


def summarise_condition_data(metrics_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate a list of trial metrics into summary statistics."""
    n = len(metrics_list)
    if n == 0:
        return {
            "trials_count": 0,
            "wall_time_s": {"median": 0.0, "p95": 0.0},
            "tool_calls": {"median": 0.0, "p95": 0.0},
            "model_calls": {"median": 0.0, "p95": 0.0},
            "tokens": None,
            "refusals": {"count": 0, "rate": 0.0},
            "timeouts": {"count": 0, "rate": 0.0},
            "correct_answers": {"count": 0, "rate": 0.0},
        }

    wall_times = [m["wall_time_s"] for m in metrics_list]
    tool_counts = [float(m["tool_calls"]) for m in metrics_list]
    model_counts = [float(m["model_calls"]) for m in metrics_list]
    
    token_vals = [float(m["tokens"]) for m in metrics_list if m["tokens"] is not None]
    tokens_summary = None
    if token_vals:
        tokens_summary = {
            "median": round(median(token_vals), 2),
            "p95": round(percentile(token_vals, 95.0), 2),
        }

    refusals_count = sum(1 for m in metrics_list if m["refused"])
    timeouts_count = sum(1 for m in metrics_list if m["timeout"])
    correct_count = sum(1 for m in metrics_list if m["correct"])

    return {
        "trials_count": n,
        "wall_time_s": {
            "median": round(median(wall_times), 3),
            "p95": round(percentile(wall_times, 95.0), 3),
        },
        "tool_calls": {
            "median": round(median(tool_counts), 1),
            "p95": round(percentile(tool_counts, 95.0), 1),
        },
        "model_calls": {
            "median": round(median(model_counts), 1),
            "p95": round(percentile(model_counts, 95.0), 1),
        },
        "tokens": tokens_summary,
        "refusals": {
            "count": refusals_count,
            "rate": round(refusals_count / n, 4),
        },
        "timeouts": {
            "count": timeouts_count,
            "rate": round(timeouts_count / n, 4),
        },
        "correct_answers": {
            "count": correct_count,
            "rate": round(correct_count / n, 4),
        },
    }


def parse_results_file(
    path: Path, receipt_cache: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Parse one evaluation result file, grouping by condition."""
    conditions_data: dict[str, list[dict[str, Any]]] = defaultdict(list)
    infra_errors_count = 0
    total_rows = 0

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total_rows += 1
            rec = json.loads(line)
            if is_infra_error(rec):
                infra_errors_count += 1
                continue
            cond = rec.get("condition", "UNKNOWN")
            metrics = extract_trial_metrics(rec, receipt_cache)
            conditions_data[cond].append(metrics)

    summary_by_cond: dict[str, Any] = {}
    for cond, mlist in sorted(conditions_data.items()):
        summary_by_cond[cond] = summarise_condition_data(mlist)

    return {
        "file_name": path.name,
        "total_rows": total_rows,
        "infra_errors_excluded": infra_errors_count,
        "valid_trials": total_rows - infra_errors_count,
        "conditions": summary_by_cond,
    }


def generate_markdown_report(report_data: dict[str, Any]) -> str:
    """Generate Markdown tables documenting agent efficiency."""
    lines: list[str] = [
        "# Agent Efficiency and Governance Overhead Summary",
        "",
        "Summary of agent efficiency across evaluation datasets, comparing execution time, tool usage, "
        "model interactions, refusals, timeouts, and task correctness across governance conditions.",
        "Infrastructure errors (e.g., provider timeouts or throttling) are excluded from all counts and denominators.",
        "",
        "## Summary by Dataset and Condition",
        "",
        "| Dataset / Run | Condition | Trials | Wall Time p50 (s) | Wall Time p95 (s) | Tool Calls p50 | Model Calls p50 | Refusals | Timeouts | Correct |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for run in report_data.get("datasets", []):
        fname = run["file_name"].replace(".jsonl", "")
        for cond, stats in run["conditions"].items():
            cnt = stats["trials_count"]
            wt_p50 = f"{stats['wall_time_s']['median']:.2f}"
            wt_p95 = f"{stats['wall_time_s']['p95']:.2f}"
            tools_p50 = f"{stats['tool_calls']['median']:.0f}"
            model_p50 = f"{stats['model_calls']['median']:.0f}"
            refusals = f"{stats['refusals']['count']} ({stats['refusals']['rate']*100:.1f}%)"
            timeouts = f"{stats['timeouts']['count']} ({stats['timeouts']['rate']*100:.1f}%)"
            correct = f"{stats['correct_answers']['count']} ({stats['correct_answers']['rate']*100:.1f}%)"
            lines.append(
                f"| `{fname}` | **{cond}** | {cnt} | {wt_p50} | {wt_p95} | {tools_p50} | {model_p50} | {refusals} | {timeouts} | {correct} |"
            )

    lines.extend([
        "",
        "## Aggregated Summary by Condition",
        "",
        "| Condition | Total Trials | Wall Time p50 (s) | Wall Time p95 (s) | Tool Calls p50 | Model Calls p50 | Refusal Rate | Timeout Rate | Correct Rate |",
        "| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])

    for cond, stats in report_data.get("aggregate_by_condition", {}).items():
        cnt = stats["trials_count"]
        wt_p50 = f"{stats['wall_time_s']['median']:.2f}"
        wt_p95 = f"{stats['wall_time_s']['p95']:.2f}"
        tools_p50 = f"{stats['tool_calls']['median']:.0f}"
        model_p50 = f"{stats['model_calls']['median']:.0f}"
        refusals = f"{stats['refusals']['count']}/{cnt} ({stats['refusals']['rate']*100:.1f}%)"
        timeouts = f"{stats['timeouts']['count']}/{cnt} ({stats['timeouts']['rate']*100:.1f}%)"
        correct = f"{stats['correct_answers']['count']}/{cnt} ({stats['correct_answers']['rate']*100:.1f}%)"
        lines.append(
            f"| **{cond}** | {cnt} | {wt_p50} | {wt_p95} | {tools_p50} | {model_p50} | {refusals} | {timeouts} | {correct} |"
        )

    lines.append("")
    return "\n".join(lines)


def run_summary(output_dir: Path | None = None) -> tuple[dict[str, Any], str]:
    """Execute the full agent efficiency evaluation across target files."""
    out_dir = output_dir or OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    
    receipt_cache = _build_receipt_cache()
    dataset_reports: list[dict[str, Any]] = []
    
    # Collect all metrics across files for aggregation by condition
    aggregate_metrics: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for fname in TARGET_FILES:
        fpath = EVAL_RESULTS_DIR / fname
        if not fpath.is_file():
            continue
        rep = parse_results_file(fpath, receipt_cache)
        dataset_reports.append(rep)
        
        # Accumulate condition data
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                if is_infra_error(rec):
                    continue
                cond = rec.get("condition", "UNKNOWN")
                metrics = extract_trial_metrics(rec, receipt_cache)
                aggregate_metrics[cond].append(metrics)

    aggregate_by_condition: dict[str, Any] = {}
    for cond in sorted(aggregate_metrics.keys()):
        aggregate_by_condition[cond] = summarise_condition_data(aggregate_metrics[cond])

    report_payload = {
        "datasets": dataset_reports,
        "aggregate_by_condition": aggregate_by_condition,
    }

    markdown_str = generate_markdown_report(report_payload)

    json_path = out_dir / "agent_efficiency_v1.json"
    md_path = out_dir / "agent_efficiency_v1.md"

    json_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    md_path.write_text(markdown_str, encoding="utf-8")

    return report_payload, markdown_str


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarise agent efficiency from committed evaluation runs.")
    parser.add_argument("--out-dir", type=Path, default=OUTPUT_DIR, help="Output directory")
    args = parser.parse_args()

    payload, md = run_summary(args.out_dir)
    print(f"Wrote agent efficiency report to {args.out_dir / 'agent_efficiency_v1.json'}")
    print(f"Wrote Markdown table to {args.out_dir / 'agent_efficiency_v1.md'}")
    print("\n" + md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
