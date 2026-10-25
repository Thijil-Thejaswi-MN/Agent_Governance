"""Task-Aware Governance Layer Models (F1, F2, F3, F6, F7, F9)."""
from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class TaskLifecycle(str, Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TERMINATED = "TERMINATED"
    EXPIRED = "EXPIRED"


class EnforcementMode(str, Enum):
    OBSERVE = "OBSERVE"
    ENFORCE = "ENFORCE"


class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TaskAction(str, Enum):
    ALLOW = "ALLOW"
    LOG = "LOG"
    ALERT = "ALERT"
    ASK_USER = "ASK_USER"
    RESTRICT = "RESTRICT"
    BLOCK_ACTION = "BLOCK_ACTION"
    PAUSE_TASK = "PAUSE_TASK"
    KILL_TASK = "KILL_TASK"
    QUARANTINE_AGENT = "QUARANTINE_AGENT"
    REVOKE_TOKEN = "REVOKE_TOKEN"


class EventSource(str, Enum):
    TOOL_BROKER = "TOOL_BROKER"
    EGRESS_PROXY = "EGRESS_PROXY"
    A2A_GATEWAY = "A2A_GATEWAY"
    OS_SENSOR = "OS_SENSOR"


class EventVerdict(str, Enum):
    INSIDE = "INSIDE"
    OUTSIDE = "OUTSIDE"
    AMBIGUOUS = "AMBIGUOUS"
    UNATTRIBUTED = "UNATTRIBUTED"  # OS event whose cgroup maps to no recorded task (M6)


class TaskBoundary(BaseModel):
    """Execution contract bounding a specific task."""
    task_id: str
    version: int = 1
    workspace_root: str
    files_read: list[str] = Field(default_factory=list)
    files_write: list[str] = Field(default_factory=list)
    network: list[str] = Field(default_factory=list)  # e.g. ["127.0.0.1:8000", "localhost:8080"]
    tools: list[str] = Field(default_factory=list)    # e.g. ["read_file", "write_file"]
    peer_agents: list[str] = Field(default_factory=list)  # e.g. ["agent_bob"]
    max_duration_sec: int = 3600
    max_processes: int = 1
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE
    derived_by: str = "template_v1"
    prompt_hash: str | None = None
    model_name: str | None = None
    parent_expansion_id: str | None = None
    requires_user_review: bool = True
    contains_pasted_content: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class TaskRecord(BaseModel):
    """Metadata tracking an assigned task from intake through completion."""
    task_id: str
    request_text: str
    request_hash: str
    agent_id: str
    workspace_root: str
    status: TaskLifecycle = TaskLifecycle.PENDING
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    current_boundary_version: int = 1
    pid: int | None = None


class GovernanceEvent(BaseModel):
    """Normalized observation schema emitted by all governance sensors."""
    event_id: str
    timestamp: str
    source: EventSource
    task_id: str | None = None
    agent_id: str
    pid: int | None = None
    kind: str  # file_read, file_write, network_http, run_command, peer_agent
    target: str
    details: dict[str, Any] = Field(default_factory=dict)
    verdict: EventVerdict
    risk_tier: RiskTier
    action_taken: TaskAction
    prevented: bool  # True if blocked BEFORE operation took place; False if observed post-facto
    rule_matched: str
    boundary_version: int | None = None


class ProvenanceRecord(BaseModel):
    """Provenance tracking record for untrusted runtime reads."""
    task_id: str
    timestamp: str
    source_type: str  # "file_read", "http_get", "peer_message"
    source_target: str
    content_hash: str  # SHA-256 of content read
    content_len: int
    content_snippet: str | None = None


class ExpansionStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


class ExpansionRequest(BaseModel):
    """Dynamic request to expand an active task boundary mid-execution."""
    request_id: str
    task_id: str
    agent_id: str
    resource_type: str  # "file_read", "file_write", "network", "peer_agent"
    resource_target: str  # Exact resource only (no wildcards allowed)
    justification: str
    baseline_risk_tier: RiskTier
    effective_risk_tier: RiskTier
    escalated_by_provenance: bool = False
    status: ExpansionStatus = ExpansionStatus.PENDING
    created_at: str
    resolved_at: str | None = None
    resolved_by: str | None = None  # "auto_policy", "human_user", "timeout_fail_closed"
    single_use: bool = False  # True for human-approved HIGH grants
    used_count: int = 0
    timeout_seconds: float = 5.0
