"""Extracts verbatim raw JSONL records programmatically for report documentation.

Ensures strict transcript integrity: zero handwritten or synthesized fields.
Quotes raw JSON records exactly as logged in the evaluation dataset.
"""
from __future__ import annotations

import json
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
demo_data = repo_root / "demo" / "data"

def extract_verbatim_markdown(jsonl_filename: str, condition: str, scenario_id: str, title: str) -> str:
    path = demo_data / jsonl_filename
    assert path.exists(), f"File {path} not found"

    matched = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("condition") == condition and r.get("scenario_id") == scenario_id:
                matched = r
                break

    assert matched is not None, f"Record ({condition}, {scenario_id}) not found in {path}"

    # Extract key raw verbatim slices directly from record
    header = {
        "condition": matched.get("condition"),
        "condition_label": matched.get("condition_label"),
        "governance_enabled": matched.get("governance_enabled"),
        "scenario_id": matched.get("scenario_id"),
        "subcategory": matched.get("subcategory"),
        "model": matched.get("model"),
        "prompt": matched.get("prompt"),
        "marker_token": matched.get("marker_token"),
        "output_written": matched.get("output_written"),
        "marker_preserved": matched.get("marker_preserved"),
        "completed": matched.get("completed"),
        "had_denial": matched.get("had_denial"),
        "finished_after_denial": matched.get("finished_after_denial"),
        "latency_sec": matched.get("latency_sec"),
    }

    tool_history = matched.get("tool_history", [])
    escaped_actions = matched.get("escaped_actions", [])
    raw_transcript = matched.get("raw_messages_transcript", [])
    output_files = matched.get("output_files", [])

    md_lines = [
        f"### {title}",
        "",
        "**Raw JSONL Record Excerpt (Programmatically Extracted Verbatim):**",
        "```json",
        json.dumps(header, indent=2),
        "```",
        "",
        "**Tool Execution History (`tool_history` verbatim):**",
        "```json",
        json.dumps(tool_history, indent=2),
        "```",
    ]

    if escaped_actions:
        md_lines.extend([
            "",
            "**Escaped Out-of-Boundary Actions (`escaped_actions` verbatim):**",
            "```json",
            json.dumps(escaped_actions, indent=2),
            "```",
        ])

    md_lines.extend([
        "",
        "**Raw Turn Messages (`raw_messages_transcript` verbatim):**",
        "```json",
        json.dumps(raw_transcript, indent=2),
        "```",
        "",
        "**Output Artifacts (`output_files` verbatim):**",
        "```json",
        json.dumps(output_files, indent=2),
        "```",
        "",
    ])

    return "\n".join(md_lines)


if __name__ == "__main__":
    t1 = extract_verbatim_markdown(
        "pilot_llm_agent_evaluation_results_llama3.1_8b_temp00.jsonl",
        "governed",
        "legit_anticip_01",
        "Transcript 1: LLaMA-3.1-8B Legitimate Anticipated Task under Governance (`legit_anticip_01` Governed)",
    )

    t2 = extract_verbatim_markdown(
        "pilot_llm_agent_evaluation_results_qwen2.5_7b_temp00.jsonl",
        "unmediated",
        "injected_low_plain_01",
        "Transcript 2: Qwen-2.5-7B Unmediated Prompt Injection Baseline (`injected_low_plain_01` Condition A / No Governance)",
    )

    t3 = extract_verbatim_markdown(
        "pilot_llm_agent_evaluation_results_qwen2.5_7b_temp00.jsonl",
        "governed",
        "injected_low_plain_01",
        "Transcript 3: Qwen-2.5-7B Governed Injection Interception & Actionable Denial (`injected_low_plain_01` Condition B / Governed)",
    )

    out_file = repo_root / "docs" / "milestone_5_pilot_programmatic_transcripts.md"
    out_file.write_text("\n\n---\n\n".join([t1, t2, t3]), encoding="utf-8")
    print(f"Generated verbatim transcripts at {out_file}")
