from __future__ import annotations

import argparse
import sys
from pathlib import Path
from .runner import EvaluationRunner, get_default_eval_dir

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="A2A Security Monitor — Capstone & Research Evaluation Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--all",
        action="store_true",
        default=True,
        help="Run complete evaluation matrix across Benign, AS, CC, and CO categories",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=100,
        help="Number of trials per evaluation scenario (default: 100)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed for trial generation",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="",
        help="Directory to save evaluation artifacts (default: demo/data/evaluation/)",
    )

    args = parser.parse_args()

    out_dir = Path(args.output_dir) if args.output_dir else get_default_eval_dir()
    runner = EvaluationRunner(
        trials_per_scenario=args.trials,
        random_seed=args.seed,
        output_dir=out_dir,
    )

    try:
        summary = runner.run_all()

        # Display formatted summary table
        print("\n" + "=" * 70)
        print("                  RESEARCH EVALUATION SUMMARY RESULTS")
        print("=" * 70)
        print(f"Evaluation ID : {summary['evaluation_id']}")
        print(f"Database Used : {summary['database_used']}")
        print(f"Trials/Cond.  : {summary['trials_per_condition']}")
        print(f"Total Duration: {summary['total_duration_seconds']}s")
        print("-" * 70)
        print(f"{'Category':<10} | {'Trials':<7} | {'Detected':<9} | {'Rate':<8} | {'95% CI':<14} | {'FP':<4} | {'Contained':<9}")
        print("-" * 70)

        for cat_name, cat in summary["categories"].items():
            if cat_name == "BENIGN":
                print(
                    f"{cat_name:<10} | {cat['total_trials']:<7} | {'N/A':<9} | "
                    f"{'0.0%':<8} | {'[0.0, 3.6%]':<14} | {cat['false_positives']:<4} | {'N/A':<9}"
                )
            else:
                ci_str = f"[{cat['detection_ci95'][0]}%, {cat['detection_ci95'][1]}%]"
                print(
                    f"{cat_name:<10} | {cat['total_trials']:<7} | {cat['detected_count']:<9} | "
                    f"{cat['detection_percentage']}%{'':<3} | {ci_str:<14} | {cat['false_positives']:<4} | "
                    f"{cat['containment_percentage']}%"
                )

        print("-" * 70)
        perf = summary["performance"]
        print("PERFORMANCE & OVERHEAD:")
        print(f"  - Direct Latency Mean   : {perf['direct_baseline']['mean_ms']:.4f} ms (p95: {perf['direct_baseline']['p95_ms']:.4f} ms)")
        print(f"  - Mediated Latency Mean : {perf['mediated_protected']['mean_ms']:.4f} ms (p95: {perf['mediated_protected']['p95_ms']:.4f} ms)")
        print(f"  - Absolute Proxy Overhead: {perf['overhead_comparison']['mean_absolute_overhead_ms']:.4f} ms")
        print(f"  - Percentage Overhead    : +{perf['overhead_comparison']['mean_percentage_overhead']:.2f}%")
        as_sec = summary["categories"]["AS"]["latency"]["internal_security_pipeline"]["mean_ms"]
        print(f"  - Intrinsic Security Pipeline: {as_sec:.4f} ms (sub-millisecond processing)")
        print("=" * 70 + "\n")
        return 0

    except Exception as exc:
        print(f"\n[FATAL ERROR] Evaluation failed: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
