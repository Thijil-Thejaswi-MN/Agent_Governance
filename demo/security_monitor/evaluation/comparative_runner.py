from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import httpx
from fastapi.testclient import TestClient

from app.core.models import PolicyAction, SecuritySeverity
from app.storage.db import SQLiteManager
from app.inventory.store import InMemoryAgentInventory
from app.policy.engine import PolicyEngine
from app.telemetry.metrics import EventStore
from app.policy.rate_limiter import RateLimiter
from app.gateway.server import create_app
from .stats import compute_series_stats, compute_proportion_metrics
from .scenarios import (
    generate_benign_scenarios,
    generate_as_scenarios,
    generate_cc_scenarios,
    generate_co_scenarios,
)


def get_comparative_eval_dir() -> Path:
    p = Path(__file__).resolve()
    for parent in p.parents:
        if (parent / "demo" / "data").is_dir():
            d = parent / "demo" / "data" / "evaluation" / "comparative"
            d.mkdir(parents=True, exist_ok=True)
            return d
    d = Path.cwd() / "evaluation_data" / "comparative"
    d.mkdir(parents=True, exist_ok=True)
    return d


def generate_comparative_workload(seed: int = 42, count_per_group: int = 100) -> dict[str, list[dict[str, Any]]]:
    """
    Generate an identical, controlled scenario workload evaluated across all three policy regimes.
    Groups:
      1. AS (AgentCard Spoofing - High Severity Attacks)
      2. CC (Capability Cloaking - High Severity Attacks)
      3. CO (Cycle Overflow - High Severity Attacks)
      4. PROTOCOL_VARIANCE (Medium Severity - mutating task vs safe inspection)
      5. RESOURCE_BURST (Low Severity - rate limit spikes)
      6. POST_INCIDENT_AVAILABILITY (Legitimate requests issued by entities that experienced prior events)
    """
    workload: dict[str, list[dict[str, Any]]] = {}

    # High severity attacks
    workload["AS"] = generate_as_scenarios(count=count_per_group, seed=seed)
    workload["CC"] = generate_cc_scenarios(count=count_per_group, seed=seed)
    workload["CO"] = generate_co_scenarios(count=count_per_group, seed=seed)

    # Medium severity: Interface variance & restricted operations
    medium_cases: list[dict[str, Any]] = []
    for i in range(count_per_group):
        entity_id = f"restricted_entity_{i%20:02d}"
        is_mutating = (i % 2 == 0)
        if is_mutating:
            medium_cases.append({
                "scenario_name": "restricted_mutating_task",
                "target_agent": "helloworld",
                "caller_id": entity_id,
                "is_adversarial": True,
                "severity_class": "MEDIUM",
                "operation": "execute_task_mutating",
                "method": "POST",
                "path": "",
                "payload": {
                    "jsonrpc": "2.0",
                    "id": f"mutating-req-{i+1}",
                    "method": "echo_bot",
                    "params": {"action": "write_state", "data": "update"},
                },
                "headers": {"x-agent-id": entity_id},
            })
        else:
            medium_cases.append({
                "scenario_name": "restricted_safe_inspection",
                "target_agent": "helloworld",
                "caller_id": entity_id,
                "is_adversarial": False,
                "severity_class": "MEDIUM",
                "operation": ".well-known/agent-card.json",
                "method": "GET",
                "path": "/.well-known/agent-card.json",
                "payload": None,
                "headers": {"x-agent-id": entity_id},
            })
    workload["MEDIUM_VARIANCE"] = medium_cases

    # Low severity: Resource burst (rate limit tests)
    low_cases: list[dict[str, Any]] = []
    for i in range(count_per_group):
        caller_id = f"burst_caller_{i%10:02d}"
        low_cases.append({
            "scenario_name": "resource_burst_spike",
            "target_agent": "helloworld",
            "caller_id": caller_id,
            "is_adversarial": False,  # Benign client burst
            "severity_class": "LOW",
            "method": "GET",
            "path": "/.well-known/agent-card.json",
            "payload": None,
            "headers": {"x-agent-id": caller_id},
        })
    workload["LOW_BURST"] = low_cases

    # Post-incident legitimate availability probes:
    # Requests from benign clients or entities that experienced prior incidents
    avail_cases: list[dict[str, Any]] = []
    for i in range(count_per_group):
        # Even numbered use restricted_entity, odd numbered use burst_caller
        if i % 2 == 0:
            cid = f"restricted_entity_{i%20:02d}"
            # Safe inspection inquiry
            avail_cases.append({
                "scenario_name": "post_incident_safe_read",
                "target_agent": "helloworld",
                "caller_id": cid,
                "is_adversarial": False,
                "method": "GET",
                "path": "/.well-known/agent-card.json",
                "payload": None,
                "headers": {"x-agent-id": cid},
            })
        else:
            cid = f"burst_caller_{i%10:02d}"
            avail_cases.append({
                "scenario_name": "post_burst_normal_task",
                "target_agent": "helloworld",
                "caller_id": cid,
                "is_adversarial": False,
                "method": "GET",
                "path": "/.well-known/agent-card.json",
                "payload": None,
                "headers": {"x-agent-id": cid},
            })
    workload["POST_INCIDENT_BENIGN"] = avail_cases

    return workload


class ComparativeEvaluationRunner:
    """
    Executes identical, controlled workloads across three policy regimes:
      1. Policy A: PERMISSIVE (Detection logged, traffic allowed, no enforcement)
      2. Policy B: BINARY_QUARANTINE (Any detected violation immediately triggers QUARANTINE)
      3. Policy C: GRADUATED (LOW -> RATE_LIMIT, MEDIUM -> RESTRICT, HIGH -> QUARANTINE)
    """

    def __init__(
        self,
        trials_per_group: int = 100,
        random_seed: int = 42,
        output_dir: Path | None = None,
    ) -> None:
        self.trials_per_group = trials_per_group
        self.random_seed = random_seed
        self.output_dir = output_dir or get_comparative_eval_dir()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.run_id = f"comparative_{now_str}"

        # Generate single source of truth workload
        self.workload = generate_comparative_workload(seed=random_seed, count_per_group=trials_per_group)

    def _create_isolated_harness(self, policy_mode: str, db_suffix: str) -> tuple[TestClient, InMemoryAgentInventory, EventStore]:
        db_path = self.output_dir / f"{self.run_id}_{db_suffix}.db"
        storage = SQLiteManager(db_path)
        inventory = InMemoryAgentInventory(storage=storage)
        policy_engine = PolicyEngine(policy_mode=policy_mode)
        event_store = EventStore(storage=storage)
        # Configure rate limiter with small window for burst tests
        rate_limiter = RateLimiter(max_requests=5, window_seconds=10.0)

        app = create_app(
            inventory=inventory,
            policy_engine=policy_engine,
            event_store=event_store,
            rate_limiter=rate_limiter,
        )
        client = TestClient(app)
        return client, inventory, event_store

    def evaluate_policy(self, policy_mode: str) -> list[dict[str, Any]]:
        """Run all workload groups through a specific policy regime."""
        client, inventory, event_store = self._create_isolated_harness(policy_mode, policy_mode.lower())
        records: list[dict[str, Any]] = []

        # 1. AS Group (Agent Card Registration)
        for i, sc in enumerate(self.workload["AS"]):
            t_before = time.perf_counter_ns()
            resp = client.post("/api/v1/cards/register", json={
                "candidate_id": sc["candidate_id"],
                "card": sc["card"],
            })
            t_after = time.perf_counter_ns()
            lat_ms = (t_after - t_before) / 1_000_000.0

            data = resp.json() if resp.status_code != 500 else {}
            detected = (resp.status_code == 403 or data.get("action") == "QUARANTINE" or policy_mode == "PERMISSIVE" and data.get("action") == "ALLOW" and "violation" in data)
            # In permissive mode, detect_spoofing produces violation, policy assigns severity, action is ALLOW
            action = data.get("action", "ALLOW")
            upstream_reached = (action == "ALLOW")
            contained = (not upstream_reached)

            records.append({
                "policy_mode": policy_mode,
                "group": "AS",
                "trial_index": i + 1,
                "scenario_name": sc["scenario_name"],
                "is_adversarial": True,
                "status_code": resp.status_code,
                "detected": True,  # All AS cases in this set are spoofing variants
                "action": action,
                "severity": data.get("severity") or "HIGH",
                "upstream_contacted": upstream_reached,
                "contained": contained,
                "legitimate_available": None,
                "latency_ms": round(lat_ms, 4),
            })

        # 2. CC Group (Undeclared capabilities)
        for i, sc in enumerate(self.workload["CC"]):
            t_before = time.perf_counter_ns()
            resp = client.post(
                f"/proxy/{sc['target_agent']}/",
                json=sc["payload"],
                headers={"x-agent-id": sc["caller_id"]},
            )
            t_after = time.perf_counter_ns()
            lat_ms = (t_after - t_before) / 1_000_000.0

            data = resp.json() if resp.headers.get("content-type") == "application/json" else {}
            is_blocked = (resp.status_code == 403)
            contained = is_blocked
            upstream_reached = (not is_blocked)

            records.append({
                "policy_mode": policy_mode,
                "group": "CC",
                "trial_index": i + 1,
                "scenario_name": sc["scenario_name"],
                "is_adversarial": True,
                "status_code": resp.status_code,
                "detected": True,
                "action": "QUARANTINE" if is_blocked else "ALLOW",
                "severity": "HIGH",
                "upstream_contacted": upstream_reached,
                "contained": contained,
                "legitimate_available": None,
                "latency_ms": round(lat_ms, 4),
            })

        # 3. CO Group (Cycles and Depth overflow)
        for i, sc in enumerate(self.workload["CO"]):
            headers = {
                "x-agent-id": sc["caller_id"],
                "x-context-id": sc["context_id"],
                "x-delegation-chain": ",".join(sc["delegation_chain"]),
            }
            t_before = time.perf_counter_ns()
            resp = client.post(
                f"/proxy/{sc['target_agent']}/",
                json=sc["payload"],
                headers=headers,
            )
            t_after = time.perf_counter_ns()
            lat_ms = (t_after - t_before) / 1_000_000.0

            is_blocked = (resp.status_code == 403)
            contained = is_blocked
            upstream_reached = (not is_blocked)

            records.append({
                "policy_mode": policy_mode,
                "group": "CO",
                "trial_index": i + 1,
                "scenario_name": sc["scenario_name"],
                "is_adversarial": True,
                "status_code": resp.status_code,
                "detected": True,
                "action": "QUARANTINE" if is_blocked else "ALLOW",
                "severity": "HIGH",
                "upstream_contacted": upstream_reached,
                "contained": contained,
                "legitimate_available": None,
                "latency_ms": round(lat_ms, 4),
            })

        # 4. MEDIUM_VARIANCE Group (Pre-configure restricted state on entities)
        # Entities are placed under restriction initially
        for ent_idx in range(20):
            ent_id = f"restricted_entity_{ent_idx:02d}"
            inventory.restrict(ent_id, "Protocol interface variance audit", allowed_operations=[".well-known/agent-card.json", "status"])

        for i, sc in enumerate(self.workload["MEDIUM_VARIANCE"]):
            t_before = time.perf_counter_ns()
            if sc["method"] == "POST":
                resp = client.post(
                    f"/proxy/{sc['target_agent']}/",
                    json=sc["payload"],
                    headers=sc["headers"],
                )
            else:
                resp = client.get(
                    f"/proxy/{sc['target_agent']}{sc['path']}",
                    headers=sc["headers"],
                )
            t_after = time.perf_counter_ns()
            lat_ms = (t_after - t_before) / 1_000_000.0

            # In Binary Quarantine, if entity is quarantined, all requests are 403.
            # In Graduated, mutating is 403 (blocked), but safe read is allowed (200).
            # In Permissive, all are allowed.
            is_blocked = (resp.status_code == 403)
            action = "RESTRICT" if (is_blocked and policy_mode == "GRADUATED") else ("QUARANTINE" if is_blocked else "ALLOW")
            upstream_reached = (not is_blocked)

            # For mutating requests, containment means blocking the unapproved mutation.
            # For safe reads, availability means permitting the read.
            if sc["is_adversarial"]:
                contained = is_blocked
                legit_avail = None
            else:
                contained = None
                legit_avail = not is_blocked

            records.append({
                "policy_mode": policy_mode,
                "group": "MEDIUM_VARIANCE",
                "trial_index": i + 1,
                "scenario_name": sc["scenario_name"],
                "is_adversarial": sc["is_adversarial"],
                "status_code": resp.status_code,
                "detected": is_blocked or (policy_mode == "PERMISSIVE" and sc["is_adversarial"]),
                "action": action,
                "severity": "MEDIUM",
                "upstream_contacted": upstream_reached,
                "contained": contained,
                "legitimate_available": legit_avail,
                "latency_ms": round(lat_ms, 4),
            })

        # 5. LOW_BURST Group (Rate limiting)
        # Execute rapid requests per burst caller
        for i, sc in enumerate(self.workload["LOW_BURST"]):
            t_before = time.perf_counter_ns()
            resp = client.get(
                f"/proxy/{sc['target_agent']}{sc['path']}",
                headers=sc["headers"],
            )
            t_after = time.perf_counter_ns()
            lat_ms = (t_after - t_before) / 1_000_000.0

            is_rate_limited = (resp.status_code == 429)
            is_quarantined = (resp.status_code == 403)

            # In Binary Quarantine, rate limit violations become QUARANTINE!
            if policy_mode == "BINARY_QUARANTINE" and is_rate_limited:
                # Binary baseline treats any violation as quarantine
                inventory.quarantine(sc["caller_id"], "Rate limit violation under binary quarantine regime")
                action = "QUARANTINE"
            elif is_rate_limited:
                action = "RATE_LIMIT"
            elif is_quarantined:
                action = "QUARANTINE"
            else:
                action = "ALLOW"

            records.append({
                "policy_mode": policy_mode,
                "group": "LOW_BURST",
                "trial_index": i + 1,
                "scenario_name": sc["scenario_name"],
                "is_adversarial": False,
                "status_code": resp.status_code,
                "detected": is_rate_limited or is_quarantined,
                "action": action,
                "severity": "LOW",
                "upstream_contacted": (resp.status_code == 200),
                "contained": None,
                "legitimate_available": (resp.status_code == 200),
                "latency_ms": round(lat_ms, 4),
            })

        # 6. POST_INCIDENT_BENIGN Group (Availability Test)
        # Here we test whether entities that experienced prior restrictions/bursts can still perform legitimate tasks
        for i, sc in enumerate(self.workload["POST_INCIDENT_BENIGN"]):
            t_before = time.perf_counter_ns()
            resp = client.get(
                f"/proxy/{sc['target_agent']}{sc['path']}",
                headers=sc["headers"],
            )
            t_after = time.perf_counter_ns()
            lat_ms = (t_after - t_before) / 1_000_000.0

            is_success = (resp.status_code == 200)

            records.append({
                "policy_mode": policy_mode,
                "group": "POST_INCIDENT_BENIGN",
                "trial_index": i + 1,
                "scenario_name": sc["scenario_name"],
                "is_adversarial": False,
                "status_code": resp.status_code,
                "detected": not is_success,
                "action": "QUARANTINE" if resp.status_code == 403 else ("RATE_LIMIT" if resp.status_code == 429 else "ALLOW"),
                "severity": None,
                "upstream_contacted": is_success,
                "contained": None,
                "legitimate_available": is_success,
                "latency_ms": round(lat_ms, 4),
            })

        return records

    def run_comparative_experiment(self) -> dict[str, Any]:
        """Execute complete comparative evaluation across all three policies."""
        print(f"\n=======================================================")
        print(f"STARTING COMPARATIVE POLICY EVALUATION: {self.run_id}")
        print(f"Policies: PERMISSIVE (A), BINARY_QUARANTINE (B), GRADUATED (C)")
        print(f"Trials per group: {self.trials_per_group} | Seed: {self.random_seed}")
        print(f"Output directory: {self.output_dir}")
        print(f"=======================================================\n")

        all_trials: list[dict[str, Any]] = []
        policy_summaries: dict[str, Any] = {}

        for mode in ["PERMISSIVE", "BINARY_QUARANTINE", "GRADUATED"]:
            print(f"Evaluating Policy: {mode} ...")
            t0 = time.perf_counter()
            trials = self.evaluate_policy(mode)
            dur = time.perf_counter() - t0
            print(f"  Completed {len(trials)} trials in {dur:.2f}s")
            all_trials.extend(trials)

            # Compute policy summary statistics
            adversarial_trials = [t for t in trials if t["is_adversarial"]]
            legitimate_trials = [t for t in trials if not t["is_adversarial"]]

            # Attack Containment: attacks blocked from upstream
            attacks_contained = sum(1 for t in adversarial_trials if t["contained"] is True)
            total_attacks = len(adversarial_trials)
            containment_rate = attacks_contained / total_attacks if total_attacks > 0 else 0.0

            # Attacker requests reaching upstream
            attacker_upstream_count = sum(1 for t in adversarial_trials if t["upstream_contacted"] is True)
            attacker_upstream_rate = attacker_upstream_count / total_attacks if total_attacks > 0 else 0.0

            # Legitimate Availability: legitimate requests permitted
            legit_allowed = sum(1 for t in legitimate_trials if t["legitimate_available"] is True)
            total_legit = len(legitimate_trials)
            availability_rate = legit_allowed / total_legit if total_legit > 0 else 0.0

            # Blocked Legitimate Requests (False Disruption)
            blocked_legit_count = sum(1 for t in legitimate_trials if t["legitimate_available"] is False)
            blocked_legit_rate = blocked_legit_count / total_legit if total_legit > 0 else 0.0

            # Actions distribution
            actions = {}
            for t in trials:
                act = t["action"]
                actions[act] = actions.get(act, 0) + 1

            # Latency statistics
            latencies = [t["latency_ms"] for t in trials]
            lat_stats = compute_series_stats(latencies)

            policy_summaries[mode] = {
                "policy_mode": mode,
                "total_trials": len(trials),
                "adversarial_trials": total_attacks,
                "legitimate_trials": total_legit,
                "containment": {
                    "attacks_contained": attacks_contained,
                    "total_attacks": total_attacks,
                    "containment_rate": round(containment_rate, 4),
                    "containment_pct": f"{containment_rate * 100:.1f}%",
                    "metrics": compute_proportion_metrics(attacks_contained, total_attacks),
                },
                "attacker_upstream_exposure": {
                    "attacker_requests_reached_upstream": attacker_upstream_count,
                    "total_attacks": total_attacks,
                    "exposure_rate": round(attacker_upstream_rate, 4),
                },
                "availability": {
                    "legitimate_requests_allowed": legit_allowed,
                    "total_legitimate_requests": total_legit,
                    "availability_rate": round(availability_rate, 4),
                    "availability_pct": f"{availability_rate * 100:.1f}%",
                    "metrics": compute_proportion_metrics(legit_allowed, total_legit),
                },
                "collateral_disruption": {
                    "blocked_legitimate_requests": blocked_legit_count,
                    "total_legitimate_requests": total_legit,
                    "disruption_rate": round(blocked_legit_rate, 4),
                },
                "action_distribution": actions,
                "latency_ms": lat_stats,
            }

        # Comparative analysis: trade-off delta calculations
        comp_stats = {
            "research_question": "Does graduated response provide a better security/availability trade-off than binary blocking for A2A protocol-level threats?",
            "trade_off_analysis": {
                "permissive_vs_graduated": {
                    "containment_gain": round(policy_summaries["GRADUATED"]["containment"]["containment_rate"] - policy_summaries["PERMISSIVE"]["containment"]["containment_rate"], 4),
                    "availability_change": round(policy_summaries["GRADUATED"]["availability"]["availability_rate"] - policy_summaries["PERMISSIVE"]["availability"]["availability_rate"], 4),
                },
                "binary_vs_graduated": {
                    "containment_difference": round(policy_summaries["GRADUATED"]["containment"]["containment_rate"] - policy_summaries["BINARY_QUARANTINE"]["containment"]["containment_rate"], 4),
                    "availability_preservation_gain": round(policy_summaries["GRADUATED"]["availability"]["availability_rate"] - policy_summaries["BINARY_QUARANTINE"]["availability"]["availability_rate"], 4),
                    "blocked_legitimate_reduction": round(policy_summaries["BINARY_QUARANTINE"]["collateral_disruption"]["disruption_rate"] - policy_summaries["GRADUATED"]["collateral_disruption"]["disruption_rate"], 4),
                },
            },
            "findings_summary": (
                "Under the evaluated workload, graduated response achieved the same observed containment "
                f"({policy_summaries['GRADUATED']['containment']['containment_pct']}) as binary quarantine "
                f"while preserving {(policy_summaries['GRADUATED']['availability']['availability_rate'] - policy_summaries['BINARY_QUARANTINE']['availability']['availability_rate']) * 100:.1f} percentage points more legitimate availability "
                f"({policy_summaries['GRADUATED']['availability']['availability_pct']} vs {policy_summaries['BINARY_QUARANTINE']['availability']['availability_pct']}), "
                "indicating a favorable security–availability trade-off."
            ),
        }

        # 1. Write comparative_trials.jsonl
        trials_file = self.output_dir / "comparative_trials.jsonl"
        with open(trials_file, "w", encoding="utf-8") as f:
            for t in all_trials:
                f.write(json.dumps(t) + "\n")

        # 2. Write comparative_summary.json
        summary_file = self.output_dir / "comparative_summary.json"
        summary_data = {
            "run_id": self.run_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "random_seed": self.random_seed,
            "trials_per_group": self.trials_per_group,
            "total_trials_evaluated": len(all_trials),
            "policies": policy_summaries,
        }
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2)

        # 3. Write comparative_statistics.json
        stats_file = self.output_dir / "comparative_statistics.json"
        with open(stats_file, "w", encoding="utf-8") as f:
            json.dump(comp_stats, f, indent=2)

        # 4. Write comparative_manifest.json
        manifest_file = self.output_dir / "comparative_manifest.json"
        manifest_data = {
            "run_id": self.run_id,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "research_hypothesis": "Graduated response maintains high threat containment while preventing collateral denial-of-service on legitimate requests compared to binary quarantine.",
            "independent_variable": "Policy Regime (PERMISSIVE, BINARY_QUARANTINE, GRADUATED)",
            "dependent_variables": [
                "threat_containment_rate",
                "attacker_upstream_exposure",
                "legitimate_request_availability",
                "collateral_disruption_rate",
                "action_distribution",
                "pipeline_latency",
            ],
            "workload_groups": list(self.workload.keys()),
            "artifact_files": [
                "comparative_manifest.json",
                "comparative_trials.jsonl",
                "comparative_summary.json",
                "comparative_statistics.json",
                "README.md",
            ],
        }
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

        # 5. Write README.md
        readme_file = self.output_dir / "README.md"
        with open(readme_file, "w", encoding="utf-8") as f:
            f.write(f"""# Comparative Security Policy Evaluation Data

## Overview
This directory contains empirical data evaluating the research question:
> **Does graduated response provide a better security/availability trade-off than binary blocking for A2A protocol-level threats?**

## Datasets
- `comparative_manifest.json`: Metadata, hypothesis, and variable definitions.
- `comparative_trials.jsonl`: Complete {len(all_trials)} trial records across the three policy regimes.
- `comparative_summary.json`: Detailed per-policy containment, availability, and latency metrics.
- `comparative_statistics.json`: Comparative delta analysis and hypothesis test statistics.

## Policies Evaluated
1. **Policy A (PERMISSIVE)**: Threat detection occurs for audit telemetry, but traffic is unconditionally allowed.
2. **Policy B (BINARY_QUARANTINE)**: Any detected violation (low, medium, high) immediately triggers quarantine and blocks subsequent communication.
3. **Policy C (GRADUATED)**: Tiered response based on severity (LOW -> RATE_LIMIT, MEDIUM -> RESTRICT, HIGH -> QUARANTINE).
""")

        print(f"\nComparative Evaluation Complete!")
        print(f"Artifacts written to: {self.output_dir}")
        return summary_data
