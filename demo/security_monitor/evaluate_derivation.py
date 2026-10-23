"""Boundary Derivation v2 Evaluation Benchmark (Milestone 5).

Evaluates BoundaryDerivationV2 against 30 hand-written gold boundary scenarios:
- Precision & Recall per category (files_read, files_write, tools, network, peer_agents)
- Over-grant rate (items granted that gold does NOT include - key safety metric)
- Repeated trials (N=3) per scenario to measure and report variance
- Schema-failure and fallback rate
- Strict provenance metadata: provider, model, model digest/tag, temperature, seed, is_mock, git commit, is_git_dirty
- Refuses to write mock output to a file that does not contain 'MOCK' or 'RULE_EMULATOR'.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

# Ensure repo root is on sys.path
repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from demo.security_monitor.app.governance.catalog import ServiceCatalog
from demo.security_monitor.app.governance.derivation_v2 import BoundaryDerivationV2


def get_git_metadata() -> tuple[str, bool]:
    commit = "unknown"
    is_dirty = False
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo_root)).decode().strip()
        status_out = subprocess.check_output(
            ["git", "status", "--porcelain", "--", ":!demo/data/*.json"],
            cwd=str(repo_root),
        ).decode().strip()
        is_dirty = len(status_out) > 0
    except Exception:
        pass
    return commit, is_dirty


def rule_based_llm_emulator(prompt: str) -> str:
    """
    Deterministic rule-based LLM emulator for pipeline/plumbing validation only
    when no external LLM engine is running.
    Implements the exact schema expected by BoundaryDerivationV2.
    """
    if "USER REQUEST:\n" in prompt:
        user_request = prompt.split("USER REQUEST:\n")[-1].strip()
    else:
        user_request = prompt.strip()

    instruction = user_request
    if "---" in instruction:
        instruction = instruction.split("---")[0].strip()
    if "```" in instruction:
        instruction = instruction.split("```")[0].strip()

    lower = instruction.lower()

    # 1. Detect network
    network = []
    if "api.github.com:443" in lower or "api.github.com" in lower:
        network.append("api.github.com:443")
    if "weather.internal:80" in lower or "weather.internal" in lower:
        network.append("weather.internal:80")
    if "data.internal:8080" in lower or "data.internal" in lower:
        network.append("data.internal:8080")
    if "localhost:8000" in lower:
        network.append("localhost:8000")
    if "127.0.0.1:8000" in lower:
        network.append("127.0.0.1:8000")

    # 2. Detect peer agents
    peer_agents = []
    for ag in ["agent_alice", "agent_bob", "agent_summarizer", "agent_analyst"]:
        if ag in lower:
            peer_agents.append(ag)

    # 3. Detect tools
    tools = []
    if any(k in lower for k in ["read", "analyze", "parse", "compare", "audit", "check", "examine"]):
        tools.append("read_file")
    if any(k in lower for k in ["write", "generate", "save", "summarize", "summarise", "output"]):
        tools.append("write_file")
    if network or any(k in lower for k in ["fetch", "http", "api", "download", "query"]):
        tools.append("http_get")
    if peer_agents or any(k in lower for k in ["notify", "delegate", "peer", "agent"]):
        tools.append("call_agent")
    if any(k in lower for k in ["run", "execute", "shell", "script", "command", "build"]):
        tools.append("run_command")
    if not tools:
        tools = ["read_file", "write_file"]

    # 4. Detect files
    import re
    files_found = re.findall(r'[\w\-./]+\.(?:pdf|txt|json|csv|md|log|py)', instruction, flags=re.IGNORECASE)
    files_read = []
    files_write = []

    for f in files_found:
        f_norm = f.replace("\\", "/")
        f_lower = f_norm.lower()
        if any(w in f_lower for w in ["output", "summary", "result", "stats", "cleaned", "filtered", "report.txt"]):
            files_write.append(f_norm if "/" in f_norm else f"output/{f_norm}")
        elif "scratch/" in f_norm or "tmp" in f_norm:
            files_write.append(f_norm if "/" in f_norm else f"scratch/{f_norm}")
        else:
            if "/" in f_norm:
                files_read.append(f_norm)
            else:
                files_read.append(f"input/{f_norm}")

    if not files_read and any(k in lower for k in ["read", "analyze", "parse", "compare"]) and "report.pdf" in lower:
        files_read = ["input/report.pdf"]
    if not files_write:
        files_write = ["output/summary.txt"]

    res = {
        "files_read": sorted(list(set(files_read))),
        "files_write": sorted(list(set(files_write))),
        "tools": sorted(list(set(tools))),
        "network": sorted(list(set(network))),
        "peer_agents": sorted(list(set(peer_agents))),
    }
    return json.dumps(res, indent=2)


def make_ollama_llm_client(
    model: str,
    base_url: str = "http://127.0.0.1:11434/v1",
    temperature: float = 0.0,
    seed: int = 42,
    timeout: float = 120.0,
) -> tuple[Callable[[str], str], str]:
    """Creates an Ollama client for BoundaryDerivationV2 using the local OpenAI-compatible endpoint."""
    import httpx
    url = f"{base_url.rstrip('/')}/chat/completions"

    # Verify Ollama is reachable
    try:
        with httpx.Client(timeout=10.0) as client:
            test_resp = client.get(f"{base_url.rstrip('/')}/models")
            if test_resp.status_code != 200:
                # Also try native /api/tags
                client.get("http://127.0.0.1:11434/api/tags").raise_for_status()
    except Exception as e:
        raise RuntimeError(f"Ollama local service is unreachable at {base_url}. Error: {e}") from e

    # Retrieve model digest/tag if possible
    model_digest = "unknown"
    try:
        with httpx.Client(timeout=10.0) as client:
            tags_resp = client.get("http://127.0.0.1:11434/api/tags")
            if tags_resp.status_code == 200:
                models_info = tags_resp.json().get("models", [])
                for m in models_info:
                    if m.get("name") == model or m.get("model") == model:
                        model_digest = m.get("digest", m.get("name"))
                        break
    except Exception:
        pass

    def call_ollama(prompt: str) -> str:
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "seed": seed,
        }
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    return call_ollama, model_digest


def evaluate_derivation_suite(
    provider: str = "rule_emulator",
    model: str = "emulator_v1",
    temperature: float = 0.0,
    seed: int = 42,
    n_repeats: int = 3,
    is_mock: bool = True,
    pilot_mode: bool = False,
    output_path: Path | None = None,
) -> dict[str, Any]:
    """Runs the Boundary Derivation v2 benchmark suite across gold scenarios."""
    gold_file = repo_root / "demo" / "data" / "boundary_derivation_gold.json"
    assert gold_file.exists(), f"Missing gold file at {gold_file}"
    all_scenarios = json.loads(gold_file.read_text(encoding="utf-8"))

    scenarios = all_scenarios[:5] if pilot_mode else all_scenarios
    commit_hash, is_dirty = get_git_metadata()

    # Determine default output file
    if output_path is None:
        if is_mock:
            out_file = repo_root / "demo" / "data" / "boundary_derivation_results_RULE_EMULATOR.json"
        else:
            out_file = repo_root / "demo" / "data" / f"boundary_derivation_results_{model.replace(':', '_')}_temp{str(temperature).replace('.', '')}.json"
    else:
        out_file = output_path

    # REQUIREMENT 2: Refuse to write mock output as LLM results
    if is_mock:
        if "RULE_EMULATOR" not in out_file.name and "MOCK" not in out_file.name:
            raise ValueError(
                f"Refusing to write mock/emulator output to '{out_file.name}'. "
                f"File name must include 'RULE_EMULATOR' or 'MOCK' when is_mock is True."
            )

    model_digest = "none"
    llm_callable: Callable[[str], str]

    if provider == "ollama":
        is_mock = False
        llm_callable, model_digest = make_ollama_llm_client(model=model, temperature=temperature, seed=seed)
    elif provider == "rule_emulator":
        is_mock = True
        llm_callable = rule_based_llm_emulator
    else:
        raise ValueError(f"Unsupported provider: {provider}")

    catalog = ServiceCatalog()
    engine = BoundaryDerivationV2(
        catalog=catalog,
        llm_client=llm_callable,
        provider=provider,
        model=model,
        temperature=temperature,
    )

    mode_label = "PILOT (5 tasks)" if pilot_mode else f"FULL ({len(scenarios)} tasks)"
    print(f"=== Running Boundary Derivation v2 Benchmark: {mode_label} ===")
    print(f"Provider: {provider} | Model: {model} | Temp: {temperature} | Seed: {seed} | Mock: {is_mock}")
    print(f"Git Commit: {commit_hash} (Dirty: {is_dirty}) | Repeats: N={n_repeats}")

    categories = ["files_read", "files_write", "tools", "network", "peer_agents"]
    scenario_stats = []
    total_precision = []
    total_recall = []
    total_overgrant = []
    schema_failures = 0
    fallback_count = 0
    total_eval_calls = 0
    call_latencies: list[float] = []

    cat_precision = {cat: [] for cat in categories}
    cat_recall = {cat: [] for cat in categories}
    cat_overgrant = {cat: [] for cat in categories}

    for sc in scenarios:
        sc_id = sc["id"]
        gold_b = sc["gold_boundary"]
        prompt = sc["request_text"]

        trial_precisions = []
        trial_recalls = []
        trial_overgrants = []
        trial_records = []

        for r_idx in range(n_repeats):
            total_eval_calls += 1
            t_start = time.perf_counter()
            derived_boundary = engine.derive(
                task_id=f"bench_{sc_id}_r{r_idx}",
                request_text=prompt,
                workspace_root="/workspace",
            )
            lat = time.perf_counter() - t_start
            call_latencies.append(lat)

            meta = derived_boundary.metadata
            if meta.get("fallback_used"):
                fallback_count += 1
                if "validation failure" in str(meta.get("fallback_reason", "")).lower():
                    schema_failures += 1

            pasted_detected = meta.get("pasted_content_detected", False)
            trial_cat_p = {}
            trial_cat_r = {}
            trial_cat_og = {}

            # Evaluate per category
            for cat in categories:
                gold_set = set(gold_b.get(cat, []))
                derived_set = set(getattr(derived_boundary, cat))

                tp = len(gold_set.intersection(derived_set))
                fp = len(derived_set - gold_set)
                fn = len(gold_set - derived_set)

                prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
                rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
                og = fp / len(derived_set) if len(derived_set) > 0 else 0.0

                trial_cat_p[cat] = prec
                trial_cat_r[cat] = rec
                trial_cat_og[cat] = og

                cat_precision[cat].append(prec)
                cat_recall[cat].append(rec)
                cat_overgrant[cat].append(og)

            overall_p = statistics.mean(trial_cat_p.values())
            overall_r = statistics.mean(trial_cat_r.values())
            overall_og = statistics.mean(trial_cat_og.values())

            trial_precisions.append(overall_p)
            trial_recalls.append(overall_r)
            trial_overgrants.append(overall_og)

            trial_records.append({
                "repeat": r_idx,
                "precision": round(overall_p, 3),
                "recall": round(overall_r, 3),
                "overgrant_rate": round(overall_og, 3),
                "fallback_used": meta.get("fallback_used", False),
                "pasted_content_detected": pasted_detected,
                "latency_sec": round(lat, 3),
            })

        t0 = trial_records[0]
        is_consistent = all(
            t["precision"] == t0["precision"] and t["recall"] == t0["recall"] and t["overgrant_rate"] == t0["overgrant_rate"]
            for t in trial_records
        )

        mean_p = statistics.mean(trial_precisions)
        mean_r = statistics.mean(trial_recalls)
        mean_og = statistics.mean(trial_overgrants)

        total_precision.append(mean_p)
        total_recall.append(mean_r)
        total_overgrant.append(mean_og)

        scenario_stats.append({
            "id": sc_id,
            "description": sc["description"],
            "authored_by": sc.get("authored_by", "AI-generated (Antigravity), pending team review"),
            "pasted_detected": t0["pasted_content_detected"],
            "mean_precision": round(mean_p, 3),
            "mean_recall": round(mean_r, 3),
            "mean_overgrant_rate": round(mean_og, 3),
            "variance_across_repeats": round(statistics.variance(trial_precisions) if len(trial_precisions) > 1 else 0.0, 4),
            "consistent_across_runs": is_consistent,
            "repeats": trial_records,
        })

    avg_call_latency = statistics.mean(call_latencies) if call_latencies else 0.0

    summary = {
        "metadata": {
            "provider": provider,
            "model": model,
            "model_digest_or_tag": model_digest,
            "temperature": temperature,
            "seed": seed,
            "is_mock": is_mock,
            "git_commit": commit_hash,
            "is_git_dirty": is_dirty,
            "pilot_mode": pilot_mode,
            "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pipeline_purpose": "pipeline_and_plumbing_validation_only" if is_mock else "empirical_llm_evaluation",
        },
        "performance": {
            "mean_call_latency_sec": round(avg_call_latency, 3),
            "projected_full_run_sec_at_n3": round(avg_call_latency * 30 * 3, 1),
        },
        "overall": {
            "mean_precision": round(statistics.mean(total_precision), 3),
            "mean_recall": round(statistics.mean(total_recall), 3),
            "mean_overgrant_rate": round(statistics.mean(total_overgrant), 3),
            "variance_across_repeats": round(statistics.mean([s["variance_across_repeats"] for s in scenario_stats]), 4),
            "schema_failure_rate": round(schema_failures / max(1, total_eval_calls), 4),
            "fallback_rate": round(fallback_count / max(1, total_eval_calls), 4),
            "total_scenarios": len(scenarios),
            "n_repeats": n_repeats,
        },
        "by_category": {
            cat: {
                "precision": round(statistics.mean(cat_precision[cat]), 3),
                "recall": round(statistics.mean(cat_recall[cat]), 3),
                "overgrant_rate": round(statistics.mean(cat_overgrant[cat]), 3),
            }
            for cat in categories
        },
        "scenario_results": scenario_stats,
    }

    print("\n" + "=" * 80)
    print(f"{'Category':<20} | {'Precision':<12} | {'Recall':<12} | {'Over-Grant Rate':<15}")
    print("-" * 80)
    for cat in categories:
        c_stats = summary["by_category"][cat]
        print(f"{cat:<20} | {c_stats['precision']:>10.1%} | {c_stats['recall']:>10.1%} | {c_stats['overgrant_rate']:>13.1%}")
    print("=" * 80)
    print(f"Overall Precision:       {summary['overall']['mean_precision']:.1%}")
    print(f"Overall Recall:          {summary['overall']['mean_recall']:.1%}")
    print(f"Over-Grant Rate:         {summary['overall']['mean_overgrant_rate']:.1%}")
    print(f"Fallback Rate:           {summary['overall']['fallback_rate']:.1%}")
    print(f"Mean Latency Per Call:   {avg_call_latency:.3f}s")
    if pilot_mode:
        print(f"Projected 30-Task Run (N=3): {summary['performance']['projected_full_run_sec_at_n3']:.1f}s")
    print("=" * 80 + "\n")

    out_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Results written to: {out_file}")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate Boundary Derivation v2")
    parser.add_argument("--provider", choices=["rule_emulator", "ollama"], default="rule_emulator")
    parser.add_argument("--model", default="emulator_v1")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--pilot", action="store_true", help="Run 5 tasks x 1 repeat as pilot")
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    out_p = Path(args.output) if args.output else None
    evaluate_derivation_suite(
        provider=args.provider,
        model=args.model,
        temperature=args.temperature,
        seed=args.seed,
        n_repeats=1 if args.pilot else args.repeats,
        is_mock=(args.provider == "rule_emulator"),
        pilot_mode=args.pilot,
        output_path=out_p,
    )
