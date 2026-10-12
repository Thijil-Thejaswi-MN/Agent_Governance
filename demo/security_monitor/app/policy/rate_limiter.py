from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any
from dataclasses import dataclass
from ..core.models import SecurityViolation


@dataclass
class RateLimitCheckResult:
    is_exceeded: bool
    current_count: int
    limit_threshold: int
    window_seconds: float
    retry_after_seconds: float


class RateLimiter:
    """
    Deterministic sliding-window rate limiter for A2A security gateway.
    
    Tracks requests per caller or per agent endpoint over a rolling window.
    Triggers LOW severity RATE_LIMIT enforcement when the threshold is exceeded.
    """

    def __init__(
        self,
        max_requests: int = 20,
        window_seconds: float = 1.0,
        per_key_limits: dict[str, int] | None = None,
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.per_key_limits = per_key_limits or {}
        self._windows: dict[str, deque[float]] = defaultdict(deque)

    def check_rate_limit(self, key: str, cost: int = 1) -> RateLimitCheckResult:
        """
        Check whether the given key has exceeded its rate limit.
        """
        now = time.monotonic()
        q = self._windows[key]
        cutoff = now - self.window_seconds

        # Evict timestamps outside rolling window
        while q and q[0] <= cutoff:
            q.popleft()

        limit = self.per_key_limits.get(key, self.max_requests)
        current_count = len(q)

        if current_count + cost > limit:
            oldest = q[0] if q else now
            retry_after = max(0.001, (oldest + self.window_seconds) - now)
            return RateLimitCheckResult(
                is_exceeded=True,
                current_count=current_count,
                limit_threshold=limit,
                window_seconds=self.window_seconds,
                retry_after_seconds=round(retry_after, 3),
            )

        for _ in range(cost):
            q.append(now)

        return RateLimitCheckResult(
            is_exceeded=False,
            current_count=len(q),
            limit_threshold=limit,
            window_seconds=self.window_seconds,
            retry_after_seconds=0.0,
        )

    def is_rate_limited(self, key: str, cost: int = 1) -> tuple[bool, int, float]:
        res = self.check_rate_limit(key, cost)
        return res.is_exceeded, res.current_count, res.retry_after_seconds

    def reset(self, key: str | None = None) -> None:
        if key is not None:
            if key in self._windows:
                del self._windows[key]
        else:
            self._windows.clear()

    def set_key_limit(self, key: str, limit: int) -> None:
        self.per_key_limits[key] = limit

    def get_stats(self) -> dict[str, Any]:
        now = time.monotonic()
        active_tracked = {}
        for k, q in list(self._windows.items()):
            cutoff = now - self.window_seconds
            while q and q[0] <= cutoff:
                q.popleft()
            if q:
                active_tracked[k] = len(q)
        return {
            "default_limit": self.max_requests,
            "window_seconds": self.window_seconds,
            "active_keys_count": len(active_tracked),
            "active_keys": active_tracked,
        }

    def create_violation(
        self,
        key: str,
        current_count: int,
        retry_after: float,
        target_endpoint: str = "",
    ) -> SecurityViolation:
        limit = self.per_key_limits.get(key, self.max_requests)
        return SecurityViolation(
            violation_code="RATE_LIMIT_EXCEEDED",
            description=(
                f"Rate limit exceeded for key '{key}': {current_count} requests in "
                f"{self.window_seconds}s window (limit: {limit}). "
                f"Retry after {retry_after:.2f}s."
            ),
            candidate_name=key,
            candidate_endpoint=target_endpoint or f"ratelimit://{key}",
            colliding_trusted_name=key,
            colliding_trusted_endpoint=target_endpoint or f"ratelimit://{key}",
            details={
                "detection_type": "rate_limit_exceeded",
                "key": key,
                "current_count": current_count,
                "max_requests": limit,
                "window_seconds": self.window_seconds,
                "retry_after_seconds": retry_after,
            },
        )
