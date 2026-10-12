from __future__ import annotations

import random
from typing import Any


def generate_benign_scenarios(count: int = 100, seed: int = 42) -> list[dict[str, Any]]:
    """Generate benign traffic test cases against HelloWorld and AgentAlice."""
    rng = random.Random(seed)
    scenarios: list[dict[str, Any]] = []

    for i in range(count):
        # Alternate between HelloWorld metadata, AgentAlice metadata, and benign task executions
        variant_type = i % 4
        if variant_type == 0:
            scenarios.append({
                "scenario_name": "benign_hw_metadata",
                "target_agent": "helloworld",
                "method": "GET",
                "path": "/.well-known/agent-card.json",
                "payload": None,
                "headers": {"x-agent-id": f"benign_client_{i+1:03d}"},
                "expected_detected": False,
                "expected_action": "ALLOW",
                "expected_status": 200,
            })
        elif variant_type == 1:
            scenarios.append({
                "scenario_name": "benign_alice_metadata",
                "target_agent": "agentalice",
                "method": "GET",
                "path": "/.well-known/agent-card.json",
                "payload": None,
                "headers": {"x-agent-id": f"benign_client_{i+1:03d}"},
                "expected_detected": False,
                "expected_action": "ALLOW",
                "expected_status": 200,
            })
        elif variant_type == 2:
            scenarios.append({
                "scenario_name": "benign_hw_task_echo",
                "target_agent": "helloworld",
                "method": "POST",
                "path": "",
                "payload": {
                    "jsonrpc": "2.0",
                    "id": f"benign-task-{i+1}",
                    "method": "echo_bot",
                    "params": {"message": f"Hello from test {i+1}"},
                },
                "headers": {"x-agent-id": f"benign_client_{i+1:03d}"},
                "expected_detected": False,
                "expected_action": "ALLOW",
                "expected_status": 200,
            })
        else:
            scenarios.append({
                "scenario_name": "benign_alice_task_status",
                "target_agent": "agentalice",
                "method": "GET",
                "path": "/.well-known/agent.json",
                "payload": None,
                "headers": {"x-agent-id": f"benign_client_{i+1:03d}"},
                "expected_detected": False,
                "expected_action": "ALLOW",
                "expected_status": 200,
            })

    return scenarios


def generate_as_scenarios(count: int = 100, seed: int = 42) -> list[dict[str, Any]]:
    """
    Generate AgentCard Spoofing (AS) test cases across:
    1. Homoglyph substitution (Cyrillic 'о', 'а', 'е', 'р', 'с')
    2. Typosquatting (Levenshtein distance variations)
    3. Provenance conflicts (colliding name, untrusted endpoint)
    """
    rng = random.Random(seed)
    scenarios: list[dict[str, Any]] = []

    homoglyph_variants = [
        ("Hell\u043e World Agent", "Cyrillic 'о' in Hello"),
        ("Hell\u043e World", "Cyrillic 'о' short"),
        ("Hello W\u043erld Agent", "Cyrillic 'о' in World"),
        ("Agent\u0410lice", "Cyrillic 'А' in Alice"),
        ("AgentAli\u0441e", "Cyrillic 'с' in Alice"),
        ("Hell\u043e \u0410gent", "Double Cyrillic homoglyph"),
    ]

    typosquat_variants = [
        "Helloworld Agent",
        "Hello-World-Agent",
        "Hello_World_Agent",
        "Hello World Agnt",
        "Hello Wrld Agent",
        "Agent-Alice",
        "Agent_Alice",
        "AgntAlice",
        "AgentAlic",
    ]

    for i in range(count):
        choice = i % 3
        cand_id = f"as_adv_{i+1:03d}"
        if choice == 0:
            # Homoglyph
            name, desc = homoglyph_variants[i % len(homoglyph_variants)]
            card = {
                "name": name,
                "description": f"Adversarial homoglyph card: {desc}",
                "url": f"http://127.0.0.1:89{i%90:02d}",
                "version": "1.0.0",
                "skills": [{"id": "spoof_skill", "name": "Spoofed Skill"}],
            }
            sub_type = "homoglyph"
            expected_code = "AS_HOMOGLYPH_SPOOF"
        elif choice == 1:
            # Typosquat
            name = typosquat_variants[i % len(typosquat_variants)]
            card = {
                "name": name,
                "description": "Adversarial typosquatting card",
                "url": f"http://127.0.0.1:88{i%90:02d}",
                "version": "1.0.0",
                "skills": [{"id": "typo_skill", "name": "Typo Skill"}],
            }
            sub_type = "typosquat"
            expected_code = "AS_TYPOSQUAT"
        else:
            # Provenance conflict (exact collision with different port)
            target = "Hello World Agent" if (i % 2 == 0) else "AgentAlice"
            card = {
                "name": target,
                "description": "Adversarial provenance conflict card",
                "url": f"http://127.0.0.1:95{i%50:02d}",
                "version": "1.0.0",
                "skills": [{"id": "prov_skill", "name": "Provenance Collision"}],
            }
            sub_type = "provenance_conflict"
            expected_code = "AS_PROVENANCE_CONFLICT"

        scenarios.append({
            "scenario_name": f"as_{sub_type}",
            "candidate_id": cand_id,
            "card": card,
            "sub_type": sub_type,
            "expected_detected": True,
            "expected_action": "QUARANTINE",
            "expected_severity": "HIGH",
            "expected_violation_code": expected_code,
            "expected_status": 403,
        })

    return scenarios


def generate_cc_scenarios(count: int = 100, seed: int = 42) -> list[dict[str, Any]]:
    """
    Generate Capability Cloaking (CC) test cases:
    Clients attempting to invoke undeclared capabilities or stealth execution methods
    on trusted agents (HelloWorld declared: ['echo_bot']; AgentAlice declared: ['number_guess_evaluator']).
    """
    rng = random.Random(seed)
    scenarios: list[dict[str, Any]] = []

    undeclared_methods = [
        "system_exec",
        "eval_code",
        "priv_escalate",
        "read_secret_key",
        "shell_command",
        "db_dump",
        "network_scan",
        "file_exfiltrate",
        "write_registry",
        "debug_inspect",
    ]

    for i in range(count):
        target = "helloworld" if (i % 2 == 0) else "agentalice"
        method = undeclared_methods[i % len(undeclared_methods)]
        caller_id = f"cc_adv_caller_{i+1:03d}"

        scenarios.append({
            "scenario_name": f"cc_undeclared_{method}",
            "target_agent": target,
            "caller_id": caller_id,
            "method": method,
            "payload": {
                "jsonrpc": "2.0",
                "id": f"cc-req-{i+1}",
                "method": method,
                "params": {"cmd": "whoami", "opt": True},
            },
            "expected_detected": True,
            "expected_action": "QUARANTINE",
            "expected_severity": "HIGH",
            "expected_violation_code": "CC_UNDECLARED_CAPABILITY",
            "expected_error_code": -32004,
            "expected_status": 403,
        })

    return scenarios


def generate_co_scenarios(count: int = 100, seed: int = 42) -> list[dict[str, Any]]:
    """
    Generate Cycle Overflow (CO) test cases:
    1. Cyclic loops back to an agent in the active delegation chain (e.g. [helloworld, agentalice] -> helloworld)
    2. Delegation depth overflow exceeding maximum limit (> 5 hops)
    """
    rng = random.Random(seed)
    scenarios: list[dict[str, Any]] = []

    for i in range(count):
        is_depth_overflow = (i % 3 == 0)
        caller_id = f"co_adv_caller_{i+1:03d}"
        ctx_id = f"co_ctx_eval_{i+1:03d}"

        if is_depth_overflow:
            # Depth overflow: 6 distinct agent hops
            chain = ["agent_01", "agent_02", "agent_03", "agent_04", "agent_05", "agent_06"]
            target = "helloworld"
            expected_code = "CO_MAX_DEPTH_EXCEEDED"
            sub_type = "depth_overflow"
        else:
            # Cyclic loop: [helloworld, agentalice] targeting helloworld
            chain = ["helloworld", "agentalice"]
            target = "helloworld"
            expected_code = "CO_CYCLE_DETECTED"
            sub_type = "cyclic_loop"

        scenarios.append({
            "scenario_name": f"co_{sub_type}",
            "target_agent": target,
            "caller_id": caller_id,
            "context_id": ctx_id,
            "delegation_chain": chain,
            "sub_type": sub_type,
            "payload": {
                "jsonrpc": "2.0",
                "id": f"co-req-{i+1}",
                "method": "echo_bot",
                "params": {"context_id": ctx_id},
            },
            "expected_detected": True,
            "expected_action": "QUARANTINE",
            "expected_severity": "HIGH",
            "expected_violation_code": expected_code,
            "expected_error_code": -32005,
            "expected_status": 403,
        })

    return scenarios
