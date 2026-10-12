from __future__ import annotations

from typing import Any
from ..core.models import NormalizedAgentCard, NormalizedSkill


def normalize_agent_card(raw: dict[str, Any]) -> NormalizedAgentCard:
    """Normalize multi-version Agent Card dictionary into a canonical NormalizedAgentCard."""
    name = str(raw.get("name") or "").strip()
    description = str(raw.get("description") or "").strip()
    version = str(raw.get("version") or "0.0.1").strip()

    # Extract endpoint URL and interface parameters
    endpoint_url = ""
    protocol_version = str(raw.get("protocolVersion") or "1.0").strip()
    protocol_binding = str(raw.get("preferredTransport") or "JSONRPC").strip()

    supported_interfaces = raw.get("supportedInterfaces")
    if isinstance(supported_interfaces, list) and len(supported_interfaces) > 0:
        iface = supported_interfaces[0]
        if isinstance(iface, dict):
            endpoint_url = str(iface.get("url") or "").strip()
            if iface.get("protocolVersion"):
                protocol_version = str(iface.get("protocolVersion")).strip()
            if iface.get("protocolBinding"):
                protocol_binding = str(iface.get("protocolBinding")).strip()

    if not endpoint_url:
        endpoint_url = str(raw.get("url") or "").strip()

    # Normalize skills
    raw_skills = raw.get("skills") or []
    skills: list[NormalizedSkill] = []
    if isinstance(raw_skills, list):
        for s in raw_skills:
            if isinstance(s, dict):
                skills.append(
                    NormalizedSkill(
                        id=str(s.get("id") or ""),
                        name=str(s.get("name") or ""),
                        description=str(s.get("description") or ""),
                        tags=[str(t) for t in s.get("tags") or []],
                    )
                )

    # Security schemes
    security_schemes = raw.get("securitySchemes")
    if not isinstance(security_schemes, dict):
        security_schemes = {}

    return NormalizedAgentCard(
        name=name,
        description=description,
        version=version,
        protocol_version=protocol_version,
        protocol_binding=protocol_binding,
        endpoint_url=endpoint_url,
        skills=skills,
        security_schemes=security_schemes,
        raw_card=raw,
    )
