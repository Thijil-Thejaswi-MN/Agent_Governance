"""Consuming single-use grants, for every path that uses them (independent audit #2, F-03).

A grant approved for one use ("Allow once", and every HIGH-risk grant) is used up by the
first access that matches it, whichever way the agent reaches it: the broker's tools or, for
network grants, the per-task egress proxy that the shell's curl/wget go through. Each
unused single-use grant of the task is checked, not only the one that made the newest
boundary version, so an older single-use grant is not left open by a later grant.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from .evaluator import BoundaryEvaluator
from .models import EventVerdict, ExpansionStatus
from .pathnorm import strip_dot_slash

_LISTS = {"file_read": "files_read", "file_write": "files_write", "network": "network", "peer_agent": "peer_agents"}


def _norm_path(p: str) -> str:
    return strip_dot_slash(str(p).strip().replace("\\", "/"))


def grant_matches(resource_type: str, grant_target: str, access: str) -> bool:
    """Does an access (a file path, a URL or host:port, an agent id) use this grant?"""
    if resource_type == "network":
        probe = SimpleNamespace(network=[grant_target])
        return BoundaryEvaluator().evaluate_network(probe, access).verdict == EventVerdict.INSIDE
    if resource_type == "peer_agent":
        return grant_target.strip().lower() == str(access).strip().lower()
    return _norm_path(grant_target) == _norm_path(access)


def consume_single_use(storage: Any, boundary: Any, resource_type: str, access: str) -> list[str]:
    """Marks every unused single-use grant of this task that `access` matches as used, and
    removes its target from the boundary so the next access is refused. Returns the ids used."""
    if boundary is None or resource_type not in _LISTS:
        return []
    used: list[str] = []
    for req in storage.list_expansion_requests(task_id=boundary.task_id):
        if not req.single_use or req.status != ExpansionStatus.APPROVED or (req.used_count or 0) > 0:
            continue
        if req.resource_type != resource_type or not grant_matches(resource_type, req.resource_target, access):
            continue
        storage.increment_expansion_usage(req.request_id)
        entries = getattr(boundary, _LISTS[resource_type])
        if req.resource_target in entries:
            entries.remove(req.resource_target)
        used.append(req.request_id)
    if used:
        storage.save_boundary(boundary)
    return used
