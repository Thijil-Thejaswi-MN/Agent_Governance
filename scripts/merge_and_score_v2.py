"""Combines existing v1 unmediated evaluation trials with newly executed governed trials and scores them."""
import json
import subprocess
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
data_dir = repo_root / "demo" / "data"

PAIRS = [
    (
        "full_llm_agent_evaluation_results_llama3.1_8b_oracle_N3_v1.jsonl",
        "full_llm_agent_evaluation_results_llama3.1_8b_oracle_N3_governed.jsonl",
        "full_llm_agent_evaluation_results_llama3.1_8b_oracle_N3.jsonl",
    ),
    (
        "full_llm_agent_evaluation_results_qwen2.5_7b_oracle_N3_v1.jsonl",
        "full_llm_agent_evaluation_results_qwen2.5_7b_oracle_N3_governed.jsonl",
        "full_llm_agent_evaluation_results_qwen2.5_7b_oracle_N3.jsonl",
    ),
]


def merge_and_score() -> None:
    for v1_name, gov_name, out_name in PAIRS:
        v1_path = data_dir / v1_name
        gov_path = data_dir / gov_name
        out_path = data_dir / out_name

        if not v1_path.exists():
            print(f"Warning: {v1_path} not found. Skipping.")
            continue
        if not gov_path.exists():
            print(f"Warning: {gov_path} not found. Skipping.")
            continue

        records = []
        # 1. Collect unmediated records from v1
        with open(v1_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                tr = json.loads(line_str)
                if tr.get("condition") == "unmediated":
                    records.append(tr)

        unmediated_count = len(records)

        # 2. Collect governed records from new run
        with open(gov_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                tr = json.loads(line_str)
                if tr.get("condition") == "governed":
                    records.append(tr)

        governed_count = len(records) - unmediated_count
        print(f"Merging {out_name}: {unmediated_count} unmediated (from v1) + {governed_count} governed (new) = {len(records)} total")

        with open(out_path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        # Score the merged JSONL
        score_script = repo_root / "demo" / "security_monitor" / "score_results.py"
        subprocess.check_call([sys.executable, str(score_script), "--input", str(out_path)])

    # Also score ALWAYS_DENY runs if present
    for ad_name in [
        "full_llm_agent_evaluation_results_llama3.1_8b_alwaysdeny_N1.jsonl",
        "full_llm_agent_evaluation_results_qwen2.5_7b_alwaysdeny_N1.jsonl",
    ]:
        ad_path = data_dir / ad_name
        if ad_path.exists():
            print(f"\nScoring {ad_name}...")
            score_script = repo_root / "demo" / "security_monitor" / "score_results.py"
            subprocess.check_call([sys.executable, str(score_script), "--input", str(ad_path)])


if __name__ == "__main__":
    merge_and_score()
