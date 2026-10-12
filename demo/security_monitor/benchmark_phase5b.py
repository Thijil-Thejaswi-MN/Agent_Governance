from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path
import httpx

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def measure_roundtrip_ms(client: httpx.Client, method: str, url: str, **kwargs) -> tuple[float, int, str]:
    t0 = time.perf_counter_ns()
    resp = client.request(method, url, **kwargs)
    t1 = time.perf_counter_ns()
    elapsed_ms = (t1 - t0) / 1_000_000.0
    return elapsed_ms, resp.status_code, resp.text


def compute_series_stats(series: list[float]) -> dict[str, float]:
    if not series:
        return {}
    s_sorted = sorted(series)
    n = len(s_sorted)
    p95_idx = int(n * 0.95)
    return {
        "count": n,
        "mean_ms": round(statistics.mean(series), 4),
        "median_ms": round(statistics.median(series), 4),
        "stdev_ms": round(statistics.stdev(series), 4) if n > 1 else 0.0,
        "min_ms": round(min(series), 4),
        "max_ms": round(max(series), 4),
        "p95_ms": round(s_sorted[p95_idx] if p95_idx < n else s_sorted[-1], 4),
    }


def main():
    print("==================================================================")
    print("PHASE 5B: MULTI-AGENT MEDIATION & LATENCY BENCHMARK")
    print("==================================================================")

    reps = 30
    print(f"Sample size: {reps} repetitions per path (warm-up + stable high-resolution sampling)")

    hw_direct_url = "http://127.0.0.1:9999/.well-known/agent-card.json"
    hw_mediated_url = "http://127.0.0.1:8000/proxy/helloworld/.well-known/agent-card.json"

    alice_direct_url = "http://127.0.0.1:8001/.well-known/agent-card.json"
    alice_mediated_url = "http://127.0.0.1:8000/proxy/agentalice/.well-known/agent-card.json"

    hw_direct_latencies: list[float] = []
    hw_mediated_latencies: list[float] = []
    alice_direct_latencies: list[float] = []
    alice_mediated_latencies: list[float] = []

    with httpx.Client(timeout=10.0) as client:
        # Warm up connections
        client.get(hw_direct_url)
        client.get(hw_mediated_url)
        client.get(alice_direct_url)
        client.get(alice_mediated_url)

        # 1. Benchmark HelloWorld
        print(f"\n[1/4] Benchmarking HelloWorld Direct ({hw_direct_url})...")
        for _ in range(reps):
            dur, code, _ = measure_roundtrip_ms(client, "GET", hw_direct_url)
            assert code == 200
            hw_direct_latencies.append(dur)

        print(f"[2/4] Benchmarking HelloWorld Mediated ({hw_mediated_url})...")
        for _ in range(reps):
            dur, code, _ = measure_roundtrip_ms(client, "GET", hw_mediated_url)
            assert code == 200
            hw_mediated_latencies.append(dur)

        # 2. Benchmark AgentAlice
        print(f"[3/4] Benchmarking AgentAlice Direct ({alice_direct_url})...")
        for _ in range(reps):
            dur, code, _ = measure_roundtrip_ms(client, "GET", alice_direct_url)
            assert code == 200
            alice_direct_latencies.append(dur)

        print(f"[4/4] Benchmarking AgentAlice Mediated ({alice_mediated_url})...")
        for _ in range(reps):
            dur, code, _ = measure_roundtrip_ms(client, "GET", alice_mediated_url)
            assert code == 200
            alice_mediated_latencies.append(dur)

        # 3. Security Tests: Attack 1 - Spoofing Registration
        print("\n--- Testing Attack Family 1: AgentCard Spoofing (AS) ---")
        spoof_card_path = Path("demo/data/agent_cards/spoofed_helloworld_card.json")
        with open(spoof_card_path, "r", encoding="utf-8") as f:
            spoof_card_json = json.load(f)

        t0 = time.perf_counter_ns()
        resp_as = client.post(
            "http://127.0.0.1:8000/api/v1/cards/register",
            json={"candidate_id": "spoofed_hw_phase5b", "card": spoof_card_json},
        )
        t1 = time.perf_counter_ns()
        as_roundtrip_ms = (t1 - t0) / 1_000_000.0
        as_data = resp_as.json()
        print(f"AS Status: {resp_as.status_code} (Expected 403 Forbidden)")
        print(f"AS Violation: {as_data.get('violation', {}).get('violation_code')}")
        print(f"AS Action: {as_data.get('action')}, Severity: {as_data.get('severity')}")

        # 4. Security Tests: Attack 2 - Capability Cloaking (CC)
        print("\n--- Testing Attack Family 2: Capability Cloaking (CC) ---")
        t0 = time.perf_counter_ns()
        resp_cc = client.post(
            "http://127.0.0.1:8000/proxy/helloworld",
            json={"jsonrpc": "2.0", "id": "cc-probe-1", "method": "system_exec", "params": {"cmd": "id"}},
            headers={"x-agent-id": "adversarial_cc_probe"},
        )
        t1 = time.perf_counter_ns()
        cc_roundtrip_ms = (t1 - t0) / 1_000_000.0
        cc_data = resp_cc.json()
        print(f"CC Status: {resp_cc.status_code} (Expected 403 Forbidden)")
        print(f"CC Violation: {cc_data.get('error', {}).get('violation', {}).get('violation_code')}")
        print(f"CC Action: {cc_data.get('error', {}).get('action')}")

        # 5. Fetch telemetry summary
        events_resp = client.get("http://127.0.0.1:8000/api/v1/events")
        metrics_resp = client.get("http://127.0.0.1:8000/api/v1/metrics")
        events_data = events_resp.json()
        metrics_data = metrics_resp.json()

    # Compute comparison metrics
    hw_dir_stats = compute_series_stats(hw_direct_latencies)
    hw_med_stats = compute_series_stats(hw_mediated_latencies)
    hw_abs_overhead = round(hw_med_stats["mean_ms"] - hw_dir_stats["mean_ms"], 4)
    hw_pct_overhead = round((hw_abs_overhead / hw_dir_stats["mean_ms"]) * 100.0, 2)

    alice_dir_stats = compute_series_stats(alice_direct_latencies)
    alice_med_stats = compute_series_stats(alice_mediated_latencies)
    alice_abs_overhead = round(alice_med_stats["mean_ms"] - alice_dir_stats["mean_ms"], 4)
    alice_pct_overhead = round((alice_abs_overhead / alice_dir_stats["mean_ms"]) * 100.0, 2)

    print("\n==================================================================")
    print("EMPIRICAL BENCHMARK RESULTS (N=30)")
    print("==================================================================")
    print(f"HelloWorld Direct Mean:   {hw_dir_stats['mean_ms']:.3f} ms (p95: {hw_dir_stats['p95_ms']:.3f} ms)")
    print(f"HelloWorld Mediated Mean: {hw_med_stats['mean_ms']:.3f} ms (p95: {hw_med_stats['p95_ms']:.3f} ms)")
    print(f"HelloWorld Overhead:      {hw_abs_overhead:.3f} ms ({hw_pct_overhead:+.2f}%)")
    print("------------------------------------------------------------------")
    print(f"AgentAlice Direct Mean:   {alice_dir_stats['mean_ms']:.3f} ms (p95: {alice_dir_stats['p95_ms']:.3f} ms)")
    print(f"AgentAlice Mediated Mean: {alice_med_stats['mean_ms']:.3f} ms (p95: {alice_med_stats['p95_ms']:.3f} ms)")
    print(f"AgentAlice Overhead:      {alice_abs_overhead:.3f} ms ({alice_pct_overhead:+.2f}%)")
    print("==================================================================")

    # Persist experiment record
    experiment_record = {
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "phase": "5B",
        "description": "Multi-agent cross-traffic mediation, baseline vs mediated latency measurement, and second benchmark detector (Capability Cloaking)",
        "sample_size": reps,
        "controlled_agents": {
            "helloworld": {
                "direct_endpoint": "http://127.0.0.1:9999",
                "mediated_endpoint": "http://127.0.0.1:8000/proxy/helloworld",
                "protocol_version": "1.0",
                "direct_stats": hw_dir_stats,
                "mediated_stats": hw_med_stats,
                "absolute_overhead_ms": hw_abs_overhead,
                "percentage_overhead_pct": hw_pct_overhead,
            },
            "agentalice": {
                "direct_endpoint": "http://127.0.0.1:8001/a2a/v1",
                "mediated_endpoint": "http://127.0.0.1:8000/proxy/agentalice",
                "protocol_version": "0.3.0",
                "direct_stats": alice_dir_stats,
                "mediated_stats": alice_med_stats,
                "absolute_overhead_ms": alice_abs_overhead,
                "percentage_overhead_pct": alice_pct_overhead,
            },
        },
        "attacks_evaluated": {
            "attack_1_agentcard_spoofing": {
                "attack_family": "AgentCard Spoofing (AS)",
                "target": "HelloWorld",
                "roundtrip_ms": as_roundtrip_ms,
                "status_code": resp_as.status_code,
                "response": as_data,
            },
            "attack_2_capability_cloaking": {
                "attack_family": "Capability Cloaking (CC)",
                "target": "HelloWorld",
                "requested_method": "system_exec",
                "roundtrip_ms": cc_roundtrip_ms,
                "status_code": resp_cc.status_code,
                "response": cc_data,
            },
        },
        "gateway_telemetry": {
            "metrics_summary": metrics_data,
            "security_events": events_data,
        },
    }

    out_file = Path("demo/data/experiments/phase5b_multi_agent_cc_experiment.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(experiment_record, f, indent=2)

    print(f"\n[OK] Phase 5B experiment record written to: {out_file.resolve()}")


if __name__ == "__main__":
    main()
