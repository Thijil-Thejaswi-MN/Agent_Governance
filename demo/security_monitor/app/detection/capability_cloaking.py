from __future__ import annotations

from typing import Any
from ..core.models import NormalizedAgentCard, SecurityViolation

# Standard A2A protocol-level methods (both v1.0 PascalCase and v0.3 slash formats)
STANDARD_A2A_PROTOCOL_METHODS: set[str] = {
    # v0.3 style
    "message/send",
    "message/stream",
    "tasks/get",
    "tasks/cancel",
    "tasks/sendSubscribe",
    "agent/authenticatedExtendedCard",
    # v1.0 style
    "SendMessage",
    "SendStreamingMessage",
    "GetTask",
    "CancelTask",
    "GetExtendedAgentCard",
}

# Known sensitive or high-risk capability triggers commonly exploited in cloaking/misuse
DISALLOWED_UNADVERTISED_PATTERNS: set[str] = {
    "system_exec",
    "exec",
    "eval",
    "eval_code",
    "shell",
    "bash",
    "run_command",
    "admin_reset",
    "admin_shell",
    "file_read",
    "file_write",
    "exfiltrate_keys",
    "internal_proxy",
}


def extract_declared_capabilities(agent: NormalizedAgentCard) -> set[str]:
    """
    Extract the set of explicitly declared skills and capability identifiers
    from the normalized Agent Card.
    """
    declared: set[str] = set()
    for s in agent.skills:
        if s.id:
            declared.add(s.id.strip().lower())
        if s.name:
            declared.add(s.name.strip().lower())

    # Include raw capabilities dictionary flags if set to True
    raw_caps = agent.raw_card.get("capabilities", {})
    if isinstance(raw_caps, dict):
        for k, v in raw_caps.items():
            if bool(v):
                declared.add(str(k).strip().lower())

    return declared


def detect_runtime_capability_cloaking(
    agent: NormalizedAgentCard,
    method_name: str,
    payload: dict[str, Any] | None = None,
) -> SecurityViolation | None:
    """
    Deterministic Runtime Capability Envelope Enforcement Heuristic.
    
    RESEARCH DISTINCTION & METHODOLOGICAL CLARIFICATION:
    - A2ASecBench CC evaluates static capability-set discrepancies between published AgentCard
      skills and backend executable capability manifests (RulesComparator).
    - This detector is our inline runtime defense heuristic: it enforces that methods invoked
      at the mediation gateway fall strictly within the agent's published capability envelope
      or standard A2A protocol specifications.
    - Evaluators must distinguish our runtime capability-envelope enforcement heuristic from
      the offline benchmark suite.
    """
    if not method_name or not method_name.strip():
        declared_set = extract_declared_capabilities(agent)
        return SecurityViolation(
            violation_code="CC_UNDECLARED_CAPABILITY",
            description=(
                f"Capability Cloaking: Attempted invocation with missing or empty capability method "
                f"not present in declared capabilities of agent '{agent.name}'."
            ),
            candidate_name=agent.name,
            candidate_endpoint=agent.endpoint_url,
            colliding_trusted_name=agent.name,
            colliding_trusted_endpoint=agent.endpoint_url,
            details={
                "requested_method": method_name,
                "declared_capabilities": sorted(declared_set),
                "standard_protocol_methods": sorted(STANDARD_A2A_PROTOCOL_METHODS),
                "detection_type": "capability_cloaking_runtime",
            },
        )

    clean_method = method_name.strip()
    clean_method_lower = clean_method.lower()

    # 1. Check if it's a standard A2A protocol method
    if clean_method in STANDARD_A2A_PROTOCOL_METHODS or clean_method_lower in {m.lower() for m in STANDARD_A2A_PROTOCOL_METHODS}:
        # Standard protocol method is allowed
        return None

    # 2. Check if it matches an explicitly declared skill/capability
    declared_set = extract_declared_capabilities(agent)
    if clean_method_lower in declared_set:
        return None

    # 3. Method is undeclared in the Agent Card.
    # Deterministic violation: Capability Cloaking (invoking unadvertised / hidden capability)
    return SecurityViolation(
        violation_code="CC_UNDECLARED_CAPABILITY",
        description=(
            f"Capability Cloaking: Attempted invocation of undeclared or cloaked capability "
            f"'{clean_method}' not present in declared capabilities of agent '{agent.name}'."
        ),
        candidate_name=agent.name,
        candidate_endpoint=agent.endpoint_url,
        colliding_trusted_name=agent.name,
        colliding_trusted_endpoint=agent.endpoint_url,
        details={
            "requested_method": clean_method,
            "declared_capabilities": sorted(declared_set),
            "standard_protocol_methods": sorted(STANDARD_A2A_PROTOCOL_METHODS),
            "detection_type": "capability_cloaking_runtime",
        },
    )


def detect_manifest_capability_cloaking(
    card_skills: list[str],
    manifest_actual_skills: list[str],
    agent_name: str = "Unknown",
    endpoint: str = "",
) -> SecurityViolation | None:
    """
    Static / Registration-time Capability Cloaking Detector (matching A2ASecBench RulesComparator).
    
    Compares declared skills in the Agent Card against the actual executable manifest.
    If actual contains undeclared skills, returns a SecurityViolation.
    """
    declared = {s.strip().lower() for s in card_skills if s.strip()}
    actual = {s.strip().lower() for s in manifest_actual_skills if s.strip()}

    undeclared = actual - declared
    if undeclared:
        return SecurityViolation(
            violation_code="CC_UNDECLARED_CAPABILITY",
            description=(
                f"Capability Cloaking: Manifest contains undeclared capabilities "
                f"{sorted(undeclared)} not published in Agent Card."
            ),
            candidate_name=agent_name,
            candidate_endpoint=endpoint,
            colliding_trusted_name=agent_name,
            colliding_trusted_endpoint=endpoint,
            details={
                "declared_capabilities": sorted(declared),
                "actual_capabilities": sorted(actual),
                "hidden_capabilities": sorted(undeclared),
                "detection_type": "capability_cloaking_manifest_mismatch",
            },
        )

    return None
