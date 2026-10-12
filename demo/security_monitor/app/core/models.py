from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class SecuritySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    RATE_LIMIT = "RATE_LIMIT"
    RESTRICT = "RESTRICT"
    QUARANTINE = "QUARANTINE"


class AgentStatus(str, Enum):
    TRUSTED = "TRUSTED"
    PROVISIONAL = "PROVISIONAL"
    RESTRICTED = "RESTRICTED"
    QUARANTINED = "QUARANTINED"


class NormalizedSkill(BaseModel):
    id: str
    name: str
    description: str = ""
    tags: list[str] = Field(default_factory=list)


class NormalizedAgentCard(BaseModel):
    name: str
    description: str = ""
    version: str = "0.0.1"
    protocol_version: str = "1.0"
    protocol_binding: str = "JSONRPC"
    endpoint_url: str
    skills: list[NormalizedSkill] = Field(default_factory=list)
    security_schemes: dict[str, Any] = Field(default_factory=dict)
    raw_card: dict[str, Any] = Field(default_factory=dict)


class SecurityViolation(BaseModel):
    violation_code: str
    description: str
    candidate_name: str = ""
    candidate_endpoint: str = ""
    colliding_trusted_name: str = ""
    colliding_trusted_endpoint: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class TimingBreakdown(BaseModel):
    t_recv_ns: int
    t_detect_ns: int
    t_decide_ns: int
    t_enforce_ns: int
    detection_latency_ms: float
    decision_latency_ms: float
    enforcement_latency_ms: float
    total_pipeline_latency_ms: float


class SecurityEvent(BaseModel):
    event_id: str
    timestamp_utc: str
    candidate_id: str
    candidate_name: str
    candidate_endpoint: str
    violation: SecurityViolation | None = None
    severity: SecuritySeverity | None = None
    action_taken: PolicyAction
    timing: TimingBreakdown
