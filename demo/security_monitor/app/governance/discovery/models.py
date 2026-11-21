"""Data models for discovery of agents, tools, local model servers, and repositories."""
from __future__ import annotations

import datetime
import hashlib
from typing import Any, Literal
from pydantic import BaseModel, Field


DiscoveredKind = Literal[
    "process",
    "repo",
    "mcp_server",
    "local_model_server",
    "coding_agent",
    "a2a_agent",
]

DiscoveredStatus = Literal[
    "governed",
    "known",
    "shadow",
]


class EvidenceItem(BaseModel):
    signal: str
    detail: str
    first_seen: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class DiscoveredAgent(BaseModel):
    org_id: str = "default"
    discovery_id: str
    host: str
    kind: DiscoveredKind
    name: str
    frameworks: list[str] = Field(default_factory=list)
    llm_endpoints: list[str] = Field(default_factory=list)
    key_names: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    status: DiscoveredStatus = "shadow"
    owner: str | None = None
    purpose: str | None = None
    linked_agent_id: str | None = None
    retired_at: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class DiscoveryScanRecord(BaseModel):
    scan_id: str
    org_id: str = "default"
    started_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    completed_at: str | None = None
    status: str = "running"
    findings_count: int = 0
    unreadable_count: int = 0
    details: dict[str, Any] = Field(default_factory=dict)


def compute_discovery_id(host: str, kind: str, key_evidence: str) -> str:
    """Generates a stable fingerprint across rescans based on host, kind, and key evidence."""
    raw = f"{host.strip().lower()}:{kind.strip().lower()}:{key_evidence.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
