import json
import sys
import time
import httpx
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def main():
    print("==================================================================")
    print("PHASE 5A: A2A SECURITY MONITOR LIVE DEMONSTRATION & TELEMETRY")
    print("==================================================================")

    base_url = "http://127.0.0.1:8000"
    fixture_path = Path("demo/data/agent_cards/spoofed_helloworld_card.json")

    with open(fixture_path, "r", encoding="utf-8") as f:
        spoof_card_fixture = json.load(f)

    experiment_record = {
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "phase": "5A",
        "description": "First vertical slice: Homoglyph/Provenance Squatting Detection, Inline Quarantine, and Mediation Gateway",
        "testbed": {
            "monitor_url": base_url,
            "trusted_upstream_url": "http://127.0.0.1:9999",
            "spoofed_fictional_url": "http://127.0.0.1:8002"
        },
        "steps": {}
    }

    with httpx.Client(timeout=10.0) as client:
        # Step 1: Health & Inventory Check
        print("\n--- Step 1: Checking Security Monitor Health & Inventory ---")
        t0 = time.perf_counter_ns()
        resp_health = client.get(f"{base_url}/health")
        t1 = time.perf_counter_ns()
        health_data = resp_health.json()
        print(f"Health Status: {health_data['status']}")
        print(f"Inventory Summary: {health_data['inventory_summary']}")
        roundtrip_health_ms = (t1 - t0) / 1_000_000

        experiment_record["steps"]["step1_health"] = {
            "status_code": resp_health.status_code,
            "data": health_data,
            "roundtrip_ms": roundtrip_health_ms
        }

        # Step 2: Trusted HelloWorld Traffic (Client -> Monitor -> HelloWorld -> Client)
        print("\n--- Step 2: Verifying Trusted HelloWorld Traffic Flow ---")
        t0 = time.perf_counter_ns()
        resp_card = client.get(f"{base_url}/proxy/helloworld/.well-known/agent-card.json")
        t1 = time.perf_counter_ns()
        proxy_card_ms = (t1 - t0) / 1_000_000
        print(f"Proxy Agent Card Status: {resp_card.status_code} ({proxy_card_ms:.3f} ms)")
        card_json = resp_card.json()
        print(f"Agent Name: {card_json.get('name')}")
        assert resp_card.status_code == 200, f"Expected 200, got {resp_card.status_code}"

        # JSON-RPC task message
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": "exp-001",
            "method": "echo_bot",
            "params": {"message": "Hello from secure mediated client"}
        }
        t0 = time.perf_counter_ns()
        resp_rpc = client.post(f"{base_url}/proxy/helloworld", json=rpc_payload)
        t1 = time.perf_counter_ns()
        proxy_rpc_ms = (t1 - t0) / 1_000_000
        print(f"Proxy JSON-RPC Status: {resp_rpc.status_code} ({proxy_rpc_ms:.3f} ms)")
        print(f"Upstream Response: {resp_rpc.text[:200]}")

        experiment_record["steps"]["step2_trusted_path"] = {
            "agent_card_status": resp_card.status_code,
            "agent_card_roundtrip_ms": proxy_card_ms,
            "jsonrpc_status": resp_rpc.status_code,
            "jsonrpc_roundtrip_ms": proxy_rpc_ms,
            "response_snippet": resp_rpc.text[:200]
        }

        # Step 3: Register Controlled Spoof Card
        print("\n--- Step 3: Ingesting Controlled Spoof Card (Homoglyph + Endpoint Conflict) ---")
        candidate_payload = {
            "candidate_id": "spoofed_helloworld",
            "card": spoof_card_fixture
        }
        t0 = time.perf_counter_ns()
        resp_reg = client.post(f"{base_url}/api/v1/cards/register", json=candidate_payload)
        t1 = time.perf_counter_ns()
        client_reg_ms = (t1 - t0) / 1_000_000
        reg_data = resp_reg.json()

        print(f"Registration Status Code: {resp_reg.status_code} (Expected: 403 Forbidden)")
        print(f"Security Action: {reg_data.get('action')}")
        print(f"Assigned Severity: {reg_data.get('severity')}")
        print(f"Violation: {reg_data.get('violation')}")
        print(f"Telemetry Timing (Internal nanosecond measurements): {json.dumps(reg_data.get('timing'), indent=2)}")

        assert resp_reg.status_code == 403, f"Expected 403, got {resp_reg.status_code}"
        assert reg_data.get("action") == "QUARANTINE"
        assert reg_data.get("severity") == "HIGH"

        experiment_record["steps"]["step3_spoof_detection_quarantine"] = {
            "status_code": resp_reg.status_code,
            "client_roundtrip_ms": client_reg_ms,
            "server_response": reg_data
        }

        # Step 4: Attempt Mediated Request to Quarantined Identity
        print("\n--- Step 4: Attempting Traffic to Quarantined Identity (Enforcement Verification) ---")
        t0 = time.perf_counter_ns()
        resp_blocked = client.post(
            f"{base_url}/proxy/spoofed_helloworld",
            json={"jsonrpc": "2.0", "id": "exp-002", "method": "echo_bot"}
        )
        t1 = time.perf_counter_ns()
        blocked_ms = (t1 - t0) / 1_000_000

        print(f"Blocked Request Status Code: {resp_blocked.status_code} (Expected: 403)")
        print(f"Blocked Response: {resp_blocked.text}")
        assert resp_blocked.status_code == 403, f"Expected 403, got {resp_blocked.status_code}"
        assert "QUARANTINED" in resp_blocked.text

        experiment_record["steps"]["step4_quarantine_enforcement"] = {
            "status_code": resp_blocked.status_code,
            "roundtrip_ms": blocked_ms,
            "response": resp_blocked.json()
        }

        # Step 5: Verify Trusted HelloWorld Still Works
        print("\n--- Step 5: Verifying Trusted HelloWorld Remains Unaffected ---")
        t0 = time.perf_counter_ns()
        resp_recheck = client.get(f"{base_url}/proxy/helloworld/.well-known/agent-card.json")
        t1 = time.perf_counter_ns()
        recheck_ms = (t1 - t0) / 1_000_000
        print(f"Re-check Status: {resp_recheck.status_code} ({recheck_ms:.3f} ms)")
        assert resp_recheck.status_code == 200

        experiment_record["steps"]["step5_trusted_path_recheck"] = {
            "status_code": resp_recheck.status_code,
            "roundtrip_ms": recheck_ms
        }

        # Step 6: Fetch Telemetry Metrics and Security Events from Monitor
        print("\n--- Step 6: Retrieving Telemetry Summary and Security Audit Log ---")
        metrics_resp = client.get(f"{base_url}/api/v1/metrics")
        events_resp = client.get(f"{base_url}/api/v1/events")

        metrics_data = metrics_resp.json()
        events_data = events_resp.json()

        print(f"Metrics Summary:\n{json.dumps(metrics_data, indent=2)}")
        print(f"Recorded Security Events Count: {len(events_data)}")

        experiment_record["metrics_summary"] = metrics_data
        experiment_record["audit_events"] = events_data

    # Save to demo/data/experiments/phase5a_first_vertical_slice_experiment.json
    out_path = Path("demo/data/experiments/phase5a_first_vertical_slice_experiment.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(experiment_record, f, indent=2)

    print(f"\n==================================================================")
    print(f"EXPERIMENT RECORD SAVED SUCCESSFULLY TO: {out_path.resolve()}")
    print(f"==================================================================")

if __name__ == "__main__":
    main()
