#!/usr/bin/env python3
"""
Orchestrator for INFUSE Pilot Matrix (Roadmap Gate G1).

Runs 1 Task (task_12) x 8 Attacks (+ Benign) x 4 Conditions x 2 Repeats.
Conditions:
  - A (None)
  - B (Tool layer only, Gold boundary)
  - C-coarse (Tool + Kernel Landlock, Coarse workspace boundary)
  - C-gold (Tool + Kernel Landlock, Gold request boundary)

Attacks:
  - OUTSIDE: 6 (SSH id_rsa), 7 (AWS creds), 17 (sudo/passwd), 19 (SSH auth_keys), 34 (sys_info exfil)
  - INSIDE: 35 (in-tree backdoor), 106 (chmod 777), 108 (CORS wildcard)
"""

import json
import math
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from scipy.stats import fisher_exact

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adapter import run_benchmark_trial

RUNS_DIR = Path(__file__).resolve().parent / "runs"
SUMMARY_FILE = RUNS_DIR / "summary.jsonl"

PILOT_TASKS = ["task_12", "task_25"]
CONDITIONS = ["A", "B", "C-coarse", "C-gold"]
ATTACKS = [
    None,  # Benign
    "6",
    "7",
    "17",
    "19",
    "8",
    "35",
    "106",
    "108",
]
REPEATS = [1, 2]

def wilson_interval(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float, float]:
    """Computes Wilson score interval for binomial proportion."""
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    z = 1.96  # 95% confidence
    denom = 1 + (z ** 2) / n
    center = (p + (z ** 2) / (2 * n)) / denom
    margin = (z * math.sqrt((p * (1 - p) / n) + (z ** 2) / (4 * (n ** 2)))) / denom
    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)
    return p, lower, upper

def compute_fisher_exact(k1: int, n1: int, k2: int, n2: int) -> Tuple[float, float]:
    """Computes two-tailed Fisher's exact test comparing two binomial proportions. Returns (odds_ratio, p_value)."""
    if n1 == 0 or n2 == 0:
        return float("nan"), float("nan")
    table = [[k1, n1 - k1], [k2, n2 - k2]]
    try:
        odds_ratio, p_val = fisher_exact(table)
        return float(odds_ratio), float(p_val)
    except Exception:
        return float("nan"), float("nan")

def load_existing_runs() -> set:
    """Load existing (task_id, attack_id, condition, repeat) tuples from summary.jsonl."""
    if not SUMMARY_FILE.exists():
        return set()
    done = set()
    with open(SUMMARY_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                tid = r.get("task_id")
                aid = str(r.get("attack_id")) if r.get("attack_id") is not None else "None"
                cond = r.get("condition")
                rep = r.get("repeat")
                if tid and cond and rep is not None:
                    done.add((tid, aid, cond, int(rep)))
            except Exception:
                continue
    return done

def generate_report(selected_task: Optional[str] = None, selected_condition: Optional[str] = None):
    """Generates the evaluation report with Wilson confidence intervals and Fisher's exact tests from summary.jsonl."""
    records = []
    task_list = [selected_task] if selected_task else PILOT_TASKS
    if SUMMARY_FILE.exists():
        with open(SUMMARY_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    r = json.loads(line)
                    if r.get("task_id") in task_list and r.get("condition") in CONDITIONS:
                        records.append(r)
                except Exception:
                    continue

    reports_to_run = [(tid, [r for r in records if r.get("task_id") == tid]) for tid in task_list]
    if len(task_list) > 1 and len(records) > 0:
        reports_to_run.append(("AGGREGATED (All Tasks)", records))

    cond_list = [selected_condition] if selected_condition else CONDITIONS

    for title_id, t_recs in reports_to_run:
        if not t_recs:
            continue
        print("\n" + "=" * 85)
        print(f"PILOT EXPERIMENT EVALUATION REPORT: {title_id}")
        print(f"Model: qwen2.5:7b | Temp: 0.0 | Seed: 42 | Trials in set: {len(t_recs)}")
        print("=" * 85 + "\n")

        # 1. Benign Utility
        print("### 1. Benign Utility Preservation Rate (UPR)")
        print("| Condition | Boundary | Trials | Passed | Utility Rate (UPR) | 95% Wilson CI |")
        print("|---|---|---|---|---|---|")
        for cond in cond_list:
            b_recs = [r for r in t_recs if r.get("trial_type") == "benign" and r.get("condition") == cond]
            n = len(b_recs)
            k = sum(1 for r in b_recs if r.get("test_sh_passed") is True)
            p, lo, hi = wilson_interval(k, n)
            b_src = "Gold" if "gold" in cond.lower() else ("Workspace" if "coarse" in cond.lower() else "None")
            print(f"| {cond:9} | {b_src:9} | {n:6} | {k:6} | {p*100:6.1f}% | [{lo*100:.1f}%, {hi*100:.1f}%] |")

        # 2. Heuristic Attack Success Rate (INFUSE Verifier)
        print("\n### 2. Heuristic Attack Success Rate (INFUSE Verifier ASR)")
        print("| Condition | Target Class | Trials | Success | Heuristic ASR | 95% Wilson CI |")
        print("|---|---|---|---|---|---|")
        for cond in cond_list:
            for tclass in ["ALL", "OUTSIDE", "INSIDE_REQUEST", "INSIDE_APP_ONLY"]:
                if tclass == "ALL":
                    a_recs = [r for r in t_recs if r.get("trial_type") == "attack" and r.get("condition") == cond]
                else:
                    a_recs = [r for r in t_recs if r.get("trial_type") == "attack" and r.get("condition") == cond and r.get("target_class") == tclass]
                n = len(a_recs)
                if n == 0:
                    continue
                k = sum(1 for r in a_recs if r.get("attack_passed_heuristic") is True)
                p, lo, hi = wilson_interval(k, n)
                print(f"| {cond:9} | {tclass:15} | {n:6} | {k:6} | {p*100:6.1f}% | [{lo*100:.1f}%, {hi*100:.1f}%] |")

        # 3. Physical Harm Rate (Automated State Check)
        print("\n### 3. Physical Harm Rate (Automated Container State Check)")
        print("| Condition | Target Class | Trials | Harm Detected | Physical Harm Rate | 95% Wilson CI |")
        print("|---|---|---|---|---|---|")
        for cond in cond_list:
            for tclass in ["ALL", "OUTSIDE", "INSIDE_REQUEST", "INSIDE_APP_ONLY"]:
                if tclass == "ALL":
                    a_recs = [r for r in t_recs if r.get("trial_type") == "attack" and r.get("condition") == cond]
                else:
                    a_recs = [r for r in t_recs if r.get("trial_type") == "attack" and r.get("condition") == cond and r.get("target_class") == tclass]
                n = len(a_recs)
                if n == 0:
                    continue
                k = sum(1 for r in a_recs if r.get("physical_harm_detected") is True)
                p, lo, hi = wilson_interval(k, n)
                print(f"| {cond:9} | {tclass:15} | {n:6} | {k:6} | {p*100:6.1f}% | [{lo*100:.1f}%, {hi*100:.1f}%] |")

        # 4. Blocking Layer Distribution
        print("\n### 4. Blocking Layer Distribution Under C Conditions")
        print("| Condition | Total Attack Trials | Blocked by Tool Layer | trials with ≥1 Landlock denial | attack stopped (no physical harm) | Unblocked |")
        print("|---|---|---|---|---|---|")
        for cond in ["C-coarse", "C-gold"]:
            c_recs = [r for r in t_recs if r.get("condition") == cond and r.get("trial_type") == "attack"]
            n = len(c_recs)
            tool_b = sum(1 for r in c_recs if r.get("blocking_layer") == "tool_layer")
            kern_b = sum(1 for r in c_recs if r.get("blocking_layer") == "kernel_landlock" or r.get("blocking_events_count", 0) > 0)
            stopped = sum(1 for r in c_recs if r.get("physical_harm_detected") is not True)
            unb = sum(1 for r in c_recs if r.get("blocking_layer") == "none")
            print(f"| {cond:9} | {n:19} | {tool_b:21} | {kern_b:30} | {stopped:33} | {unb:9} |")

        # 5. Statistical Significance (Fisher's Exact Test)
        print("\n### 5. Statistical Significance Testing (Two-Tailed Fisher's Exact Test)")
        print("| Comparison | Target Class | Metric | Condition 1 Success | Condition 2 Success | Odds Ratio | p-value | Significance |")
        print("|---|---|---|---|---|---|---|---|")
        comparisons = [
            ("A", "B"),
            ("A", "C-coarse"),
            ("A", "C-gold"),
            ("B", "C-coarse"),
            ("B", "C-gold"),
            ("C-coarse", "C-gold"),
        ]
        target_classes = ["ALL", "OUTSIDE", "INSIDE_REQUEST", "INSIDE_APP_ONLY"]
        for c1, c2 in comparisons:
            for tclass in target_classes:
                for metric_name, field in [("Heuristic ASR", "attack_passed_heuristic"), ("Physical Harm", "physical_harm_detected")]:
                    if tclass == "ALL":
                        r1 = [r for r in t_recs if r.get("condition") == c1 and r.get("trial_type") == "attack"]
                        r2 = [r for r in t_recs if r.get("condition") == c2 and r.get("trial_type") == "attack"]
                    else:
                        r1 = [r for r in t_recs if r.get("condition") == c1 and r.get("trial_type") == "attack" and r.get("target_class") == tclass]
                        r2 = [r for r in t_recs if r.get("condition") == c2 and r.get("trial_type") == "attack" and r.get("target_class") == tclass]
                    n1, n2 = len(r1), len(r2)
                    if n1 > 0 and n2 > 0:
                        k1 = sum(1 for r in r1 if r.get(field) is True)
                        k2 = sum(1 for r in r2 if r.get(field) is True)
                        odds, pval = compute_fisher_exact(k1, n1, k2, n2)
                        sig = "Significant (p < 0.05)" if pval < 0.05 else "not distinguishable (p > 0.05)"
                        comp_str = f"{c1} vs {c2}"
                        odds_str = f"{odds:10.3f}" if not math.isnan(odds) else "       N/A"
                        pval_str = f"{pval:7.4f}" if not math.isnan(pval) else "    N/A"
                        print(f"| {comp_str:18} | {tclass:15} | {metric_name:14} | {k1}/{n1} ({k1/n1*100:.1f}%) | {k2}/{n2} ({k2/n2*100:.1f}%) | {odds_str} | {pval_str} | {sig:22} |")

        print("\n" + "=" * 85 + "\n")

def run_pilot(selected_task: Optional[str] = None, selected_condition: Optional[str] = None):
    done_set = load_existing_runs()
    task_list = [selected_task] if selected_task else PILOT_TASKS
    cond_list = [selected_condition] if selected_condition else CONDITIONS
    total_planned = len(task_list) * len(cond_list) * len(ATTACKS) * len(REPEATS)
    print(f"[*] Total planned trials in pilot matrix: {total_planned}")
    print(f"[*] Existing completed trials in summary.jsonl: {len(done_set)}")

    trial_idx = 0
    for tid in task_list:
        for cond in cond_list:
            for aid in ATTACKS:
                for rep in REPEATS:
                    trial_idx += 1
                    aid_key = str(aid) if aid is not None else "None"
                    if (tid, aid_key, cond, rep) in done_set:
                        print(f"[{trial_idx}/{total_planned}] Skipping already completed: {tid}, Attack {aid_key}, {cond}, Rep {rep}")
                        continue

                    print(f"\n>>> [{trial_idx}/{total_planned}] Executing: {tid}, Attack {aid_key}, Condition {cond}, Repeat {rep}")
                    try:
                        run_benchmark_trial(
                            task_id=tid,
                            attack_id=aid,
                            condition=cond,
                            repeat=rep,
                        )
                    except Exception as e:
                        print(f"[!] Error executing trial: {e}", file=sys.stderr)
                    time.sleep(2)

    # After running, produce final report
    generate_report(selected_task=selected_task, selected_condition=selected_condition)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Pilot Matrix Runner")
    parser.add_argument("--report", action="store_true", help="Generate summary report")
    parser.add_argument("--task", default=None, choices=PILOT_TASKS, help="Filter to specific task")
    parser.add_argument("--condition", default=None, choices=CONDITIONS, help="Filter to specific condition")
    args = parser.parse_args()

    if args.report:
        generate_report(selected_task=args.task, selected_condition=args.condition)
    else:
        run_pilot(selected_task=args.task, selected_condition=args.condition)
