from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .comparative_runner import ComparativeEvaluationRunner, get_comparative_eval_dir
from .ablation_robustness_runner import (
    ASAblationRunner,
    CCRobustnessRunner,
    CORobustnessRunner,
    get_ablation_eval_dir,
    get_robustness_eval_dir,
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="A2A Security Monitor — Stage 4 & Stage 5 Comparative & Ablation Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--comparative",
        action="store_true",
        default=True,
        help="Run Stage 4 Comparative Evaluation (Permissive vs Binary vs Graduated)",
    )
    parser.add_argument(
        "--ablation",
        action="store_true",
        default=True,
        help="Run Stage 4B / Stage 5 Ablation & Robustness Studies (AS Ablation, CC Robustness, CO Robustness)",
    )
    parser.add_argument(
        "--trials-per-group",
        type=int,
        default=100,
        help="Number of trials per scenario group (default: 100)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed",
    )

    args = parser.parse_args()

    try:
        # 1. Comparative Evaluation (Stage 4)
        if args.comparative:
            print("\n" + "=" * 70)
            print("STAGE 4: COMPARATIVE POLICY EVALUATION (N=100 per condition)")
            print("=" * 70)
            comp_runner = ComparativeEvaluationRunner(
                trials_per_group=args.trials_per_group,
                random_seed=args.seed,
            )
            comp_summary = comp_runner.run_comparative_experiment()

            print("\n" + "-" * 70)
            print("STAGE 4 COMPARATIVE RESULTS SUMMARY")
            print("-" * 70)
            print(f"{'Policy':<18} | {'Trials':<7} | {'Containment':<12} | {'Legit Avail':<12} | {'Blocked Legit':<13} | {'Mean Latency':<12}")
            print("-" * 70)
            for p_name, p_data in comp_summary["policies"].items():
                print(
                    f"{p_name:<18} | {p_data['total_trials']:<7} | "
                    f"{p_data['containment']['containment_pct']:<12} | "
                    f"{p_data['availability']['availability_pct']:<12} | "
                    f"{p_data['collateral_disruption']['blocked_legitimate_requests']:<13} | "
                    f"{p_data['latency_ms']['mean_ms']:.4f} ms"
                )
            print("-" * 70)

        # 2. AS Ablation Study (Stage 4B / 5)
        if args.ablation:
            print("\n" + "=" * 70)
            print("STAGE 4B / 5: AS DETECTOR ABLATION STUDY")
            print("=" * 70)
            as_runner = ASAblationRunner(seed=args.seed)
            as_summary = as_runner.run_ablation()

            print("\n" + "-" * 70)
            print("AS ABLATION RESULTS SUMMARY")
            print("-" * 70)
            print(f"{'Configuration':<16} | {'Recall':<8} | {'95% CI (Recall)':<16} | {'Precision':<10} | {'F1':<6} | {'FPR':<6}")
            print("-" * 70)
            for cfg_name, cfg_data in as_summary["configurations"].items():
                m = cfg_data["metrics"]
                ci_str = f"[{m['recall_wilson_ci'][0]}%, {m['recall_wilson_ci'][1]}%]"
                print(
                    f"{cfg_name:<16} | {m['recall']*100:.1f}%{'':<2} | "
                    f"{ci_str:<16} | {m['precision']*100:.1f}%{'':<4} | "
                    f"{m['f1_score']:.3f}{'':<1} | {m['fpr']*100:.1f}%"
                )
            print("-" * 70)

            # 3. CC Robustness Study
            print("\n" + "=" * 70)
            print("STAGE 4B / 5: CAPABILITY CLOAKING ROBUSTNESS STUDY")
            print("=" * 70)
            cc_runner = CCRobustnessRunner()
            cc_summary = cc_runner.run_robustness()

            print("\n" + "-" * 70)
            print("CC ROBUSTNESS RESULTS SUMMARY")
            print("-" * 70)
            print(f"{'Category':<35} | {'Cases':<6} | {'Detected':<9} | {'Conformance':<11}")
            print("-" * 70)
            for cat, data in cc_summary["categories"].items():
                print(f"{cat:<35} | {data['total_cases']:<6} | {data['detected_count']:<9} | {data['conformance_rate']*100:.1f}%")
            print("-" * 70)

            # 4. CO Robustness Study
            print("\n" + "=" * 70)
            print("STAGE 4B / 5: CYCLE OVERFLOW ROBUSTNESS STUDY")
            print("=" * 70)
            co_runner = CORobustnessRunner()
            co_summary = co_runner.run_robustness()

            print("\n" + "-" * 70)
            print("CO ROBUSTNESS RESULTS SUMMARY")
            print("-" * 70)
            print(f"{'Category':<35} | {'Cases':<6} | {'Headers?':<9} | {'Detected':<9} | {'Conformance':<11}")
            print("-" * 70)
            for cat, data in co_summary["categories"].items():
                hdr = "YES" if data["headers_present"] else "NO"
                print(f"{cat:<35} | {data['total_cases']:<6} | {hdr:<9} | {data['detected_count']:<9} | {data['conformance_rate']*100:.1f}%")
            print("-" * 70)

        print("\nAll Stage 4 and Stage 5 experiments completed successfully!")
        return 0

    except Exception as exc:
        print(f"\n[FATAL ERROR] Stage 4/5 evaluation failed: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
