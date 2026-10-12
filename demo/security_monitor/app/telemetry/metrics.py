from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any
from ..core.models import TimingBreakdown, SecurityEvent, SecurityViolation, SecuritySeverity, PolicyAction


def current_time_ns() -> int:
    """Return high-resolution monotonic timer value in nanoseconds."""
    return time.perf_counter_ns()


def iso_timestamp_utc() -> str:
    """Return ISO 8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def compute_timing(
    t_recv_ns: int,
    t_detect_ns: int,
    t_decide_ns: int,
    t_enforce_ns: int,
) -> TimingBreakdown:
    """Compute exact latency durations from nanosecond monotonic timestamps."""
    detection_ms = (t_detect_ns - t_recv_ns) / 1_000_000.0
    decision_ms = (t_decide_ns - t_detect_ns) / 1_000_000.0
    enforcement_ms = (t_enforce_ns - t_decide_ns) / 1_000_000.0
    total_ms = (t_enforce_ns - t_recv_ns) / 1_000_000.0

    return TimingBreakdown(
        t_recv_ns=t_recv_ns,
        t_detect_ns=t_detect_ns,
        t_decide_ns=t_decide_ns,
        t_enforce_ns=t_enforce_ns,
        detection_latency_ms=round(detection_ms, 4),
        decision_latency_ms=round(decision_ms, 4),
        enforcement_latency_ms=round(enforcement_ms, 4),
        total_pipeline_latency_ms=round(total_ms, 4),
    )


from ..storage.db import SQLiteManager


class EventStore:
    """Security event store backed by SQLite persistence."""

    def __init__(self, storage: SQLiteManager | None = None) -> None:
        self.storage = storage or SQLiteManager()
        self._events: list[SecurityEvent] = []
        self._init_from_storage()

    def _init_from_storage(self) -> None:
        raw_events = self.storage.load_events()
        for e in raw_events:
            viol = SecurityViolation.model_validate(e["violation"]) if e.get("violation") else None
            timing = TimingBreakdown.model_validate(e["timing"]) if e.get("timing") else TimingBreakdown(
                t_recv_ns=0, t_detect_ns=0, t_decide_ns=0, t_enforce_ns=0,
                detection_latency_ms=0.0, decision_latency_ms=0.0, enforcement_latency_ms=0.0, total_pipeline_latency_ms=0.0
            )
            event = SecurityEvent(
                event_id=e["event_id"],
                timestamp_utc=e["timestamp_utc"],
                candidate_id=e["candidate_id"],
                candidate_name=e["candidate_name"],
                candidate_endpoint=e["candidate_endpoint"],
                violation=viol,
                severity=SecuritySeverity(e["severity"]) if e.get("severity") else None,
                action_taken=PolicyAction(e["action_taken"]),
                timing=timing,
            )
            self._events.append(event)

    def record_event(
        self,
        candidate_id: str,
        candidate_name: str,
        candidate_endpoint: str,
        violation: SecurityViolation | None,
        severity: SecuritySeverity | None,
        action_taken: PolicyAction,
        timing: TimingBreakdown,
    ) -> SecurityEvent:
        event = SecurityEvent(
            event_id=f"evt_{len(self._events) + 1:04d}",
            timestamp_utc=iso_timestamp_utc(),
            candidate_id=candidate_id,
            candidate_name=candidate_name,
            candidate_endpoint=candidate_endpoint,
            violation=violation,
            severity=severity,
            action_taken=action_taken,
            timing=timing,
        )
        self._events.append(event)
        self.storage.save_event(event.model_dump())
        return event

    def get_events(self) -> list[SecurityEvent]:
        return list(self._events)

    def get_metrics_summary(self) -> dict[str, Any]:
        total = len(self._events)
        if total == 0:
            return {
                "total_events": 0,
                "quarantined_count": 0,
                "allowed_count": 0,
                "avg_detection_latency_ms": 0.0,
                "avg_decision_latency_ms": 0.0,
                "avg_enforcement_latency_ms": 0.0,
                "avg_total_latency_ms": 0.0,
            }

        quarantined = sum(1 for e in self._events if e.action_taken == PolicyAction.QUARANTINE)
        allowed = sum(1 for e in self._events if e.action_taken == PolicyAction.ALLOW)

        avg_detect = sum(e.timing.detection_latency_ms for e in self._events) / total
        avg_decide = sum(e.timing.decision_latency_ms for e in self._events) / total
        avg_enforce = sum(e.timing.enforcement_latency_ms for e in self._events) / total
        avg_total = sum(e.timing.total_pipeline_latency_ms for e in self._events) / total

        return {
            "total_events": total,
            "quarantined_count": quarantined,
            "allowed_count": allowed,
            "avg_detection_latency_ms": round(avg_detect, 4),
            "avg_decision_latency_ms": round(avg_decide, 4),
            "avg_enforcement_latency_ms": round(avg_enforce, 4),
            "avg_total_latency_ms": round(avg_total, 4),
        }
