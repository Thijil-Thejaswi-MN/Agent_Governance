"""Fleet summary for the console's Fleet page.

Pure functions over stored records (tasks, inventory, events, expansions, provenance):
how many agents are at work, which decisions are waiting, and the blocked actions of
the last 24 hours grouped into a few plain-language classes. Nothing here changes
enforcement; it only reads.
"""
from __future__ import annotations

import datetime
from collections import Counter, defaultdict
from pathlib import PurePosixPath
from typing import Any, Iterable

BLOCKED_WINDOW_H = 24
RECENT_BLOCK_WINDOW_H = 1

# Order matters: the first class that matches wins.
TARGET_CLASSES = ("mentioned_in_input", "outside_website", "private_folder", "other")

_NETWORK_KINDS = {"network", "network_http", "http_get", "network_connect", "connect", "egress"}
_PRIVATE_MARKERS = ("/.ssh", "/.config", "/.aws", "/.gnupg", "/.netrc", "/etc/shadow", "/root")


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def _plain_sentence(target_class: str, n: int) -> str:
    attempts = f"{n} {_plural(n, 'attempt', 'attempts')}"
    if target_class == "mentioned_in_input":
        return f"{attempts} to open a file that was only mentioned inside another file"
    if target_class == "outside_website":
        return f"{attempts} to reach a website outside the task"
    if target_class == "private_folder":
        return f"{attempts} to read a private or home folder"
    return f"{n} other {_plural(n, 'action', 'actions')} outside what the request allows"


def _val(x: Any) -> str:
    """Enum members (model_dump keeps them) and plain values as their string value."""
    return str(getattr(x, "value", x) if x is not None else "")


def parse_ts(ts: Any) -> datetime.datetime | None:
    """ISO timestamp -> aware UTC datetime (naive values are taken as UTC)."""
    if not ts:
        return None
    if isinstance(ts, datetime.datetime):
        dt = ts
    else:
        s = str(ts).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.datetime.fromisoformat(s)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def event_layer(event: dict[str, Any]) -> str:
    """The layer that stopped the action: landlock / seccomp / broker / proxy / gateway / sensor."""
    prevented_by = _val(event.get("prevented_by") or (event.get("details") or {}).get("prevented_by")).lower()
    if prevented_by in ("landlock", "seccomp"):
        return prevented_by
    source = _val(event.get("source")).upper()
    return {
        "TOOL_BROKER": "broker",
        "EGRESS_PROXY": "proxy",
        "A2A_GATEWAY": "gateway",
        "OS_SENSOR": "sensor",
    }.get(source, source.lower() or "unknown")


def is_blocked(event: dict[str, Any]) -> bool:
    return bool(event.get("prevented")) or _val(event.get("action_taken")) == "BLOCK_ACTION"


def _mentioned(target: str, snippets: Iterable[str], request_text: str) -> bool:
    """True if the target (path or file name) appears in content the agent read, but not in the request."""
    t = (target or "").strip().lower()
    if not t:
        return False
    name = PurePosixPath(t.replace("~", "")).name
    needles = [n for n in {t, t.lstrip("~/"), name} if n and len(n) >= 3]
    req = (request_text or "").lower()
    if any(n in req for n in needles):
        return False
    return any(n in (s or "").lower() for s in snippets for n in needles)


def classify_target(event: dict[str, Any], snippets: Iterable[str] = (), request_text: str = "") -> str:
    """One of TARGET_CLASSES for a blocked event."""
    target = str(event.get("target") or "")
    kind = _val(event.get("kind")).lower()
    if _mentioned(target, snippets, request_text):
        return "mentioned_in_input"
    t = target.lower()
    if kind in _NETWORK_KINDS or t.startswith(("http://", "https://")):
        return "outside_website"
    if t.startswith(("~", "/home/", "/root")) or any(m in t for m in _PRIVATE_MARKERS):
        return "private_folder"
    return "other"


def group_blocked_events(
    events: Iterable[dict[str, Any]],
    snippets_by_task: dict[str, list[str]] | None = None,
    request_by_task: dict[str, str] | None = None,
    now: datetime.datetime | None = None,
    window_hours: float = BLOCKED_WINDOW_H,
) -> dict[str, Any]:
    """Groups blocked events of the last `window_hours` by target class.

    Each group carries a count, the tasks and agents involved, a breakdown by layer and
    by event kind (shown only in Details), and one plain sentence.
    """
    snippets_by_task = snippets_by_task or {}
    request_by_task = request_by_task or {}
    now = now or datetime.datetime.now(datetime.timezone.utc)
    since = now - datetime.timedelta(hours=window_hours)

    buckets: dict[str, dict[str, Any]] = {}
    seen: set[tuple[Any, ...]] = set()
    for ev in events:
        if not is_blocked(ev):
            continue
        ts = parse_ts(ev.get("timestamp"))
        if ts is None or ts < since or ts > now + datetime.timedelta(minutes=5):
            continue
        task_id = ev.get("task_id") or ""
        # The same attempt can arrive from two sources (broker event + receipt OS event).
        key = (task_id, ev.get("target"), ev.get("kind"), ev.get("event_id") or ts.isoformat())
        if key in seen:
            continue
        seen.add(key)
        cls = classify_target(ev, snippets_by_task.get(task_id, []), request_by_task.get(task_id, ""))
        b = buckets.setdefault(cls, {
            "target_class": cls, "count": 0, "tasks": set(), "agents": set(),
            "by_layer": Counter(), "by_kind": Counter(), "examples": [],
        })
        b["count"] += 1
        if task_id:
            b["tasks"].add(task_id)
        if ev.get("agent_id"):
            b["agents"].add(ev["agent_id"])
        b["by_layer"][event_layer(ev)] += 1
        b["by_kind"][str(ev.get("kind") or "unknown")] += 1
        if len(b["examples"]) < 3 and ev.get("target") and ev["target"] not in b["examples"]:
            b["examples"].append(ev["target"])

    groups = []
    for cls in TARGET_CLASSES:
        b = buckets.get(cls)
        if not b:
            continue
        groups.append({
            "target_class": cls,
            "count": b["count"],
            "task_count": len(b["tasks"]),
            "task_ids": sorted(b["tasks"]),
            "agent_count": len(b["agents"]),
            "by_layer": dict(b["by_layer"]),
            "by_kind": dict(b["by_kind"]),
            "examples": b["examples"],
            "plain": _plain_sentence(cls, b["count"]),
        })
    return {
        "window_hours": window_hours,
        "total": sum(g["count"] for g in groups),
        "groups": groups,
    }


def _expansion_deadline(exp: dict[str, Any]) -> datetime.datetime | None:
    created = parse_ts(exp.get("created_at"))
    if created is None:
        return None
    return created + datetime.timedelta(seconds=float(exp.get("timeout_seconds") or 0))


def build_fleet_summary(
    tasks: list[dict[str, Any]],
    inventory: list[dict[str, Any]],
    pending_expansions: list[dict[str, Any]],
    blocked_events: list[dict[str, Any]],
    snippets_by_task: dict[str, list[str]] | None = None,
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Everything the Fleet page shows, from real stored records only.

    tasks: dicts with task_id, agent_id, status, request_text, created_at, started_at.
    inventory: AgentInventoryItem dicts. pending_expansions: enriched expansion dicts
    (with prior_untrusted_reads). blocked_events: unified task events (any verdict).
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    task_by_id = {t["task_id"]: t for t in tasks}
    running = [t for t in tasks if t.get("status") == "ACTIVE"]
    running_ids = {t["task_id"] for t in running}

    # A decision is waiting only while its task runs and its fail-closed deadline is ahead.
    needs_you = []
    for e in pending_expansions:
        if _val(e.get("status")) != "PENDING" or e.get("task_id") not in running_ids:
            continue
        deadline = _expansion_deadline(e)
        if deadline is not None and deadline <= now:
            continue
        linked = [r for r in (e.get("prior_untrusted_reads") or []) if r.get("linked")]
        needs_you.append({
            "request_id": e["request_id"],
            "task_id": e["task_id"],
            "agent_id": e.get("agent_id") or "",
            "resource_type": e.get("resource_type") or "",
            "resource_target": e.get("resource_target") or "",
            "escalated_by_provenance": bool(e.get("escalated_by_provenance")),
            "learned_from": linked[0].get("source_target") if linked else None,
            "baseline_risk_tier": _val(e.get("baseline_risk_tier")),
            "effective_risk_tier": _val(e.get("effective_risk_tier")),
            "created_at": e.get("created_at"),
            "deadline": deadline.isoformat() if deadline else None,
        })
    waiting_tasks = {n["task_id"] for n in needs_you}

    request_by_task = {t["task_id"]: t.get("request_text") or "" for t in tasks}
    blocked = group_blocked_events(blocked_events, snippets_by_task, request_by_task, now=now)

    recent_since = now - datetime.timedelta(hours=RECENT_BLOCK_WINDOW_H)
    recently_blocked_tasks: set[str] = set()
    recently_blocked_agents: set[str] = set()
    for ev in blocked_events:
        ts = parse_ts(ev.get("timestamp"))
        if is_blocked(ev) and ts is not None and ts >= recent_since:
            if ev.get("task_id"):
                recently_blocked_tasks.add(ev["task_id"])
            if ev.get("agent_id"):
                recently_blocked_agents.add(ev["agent_id"])

    def task_state(task_id: str) -> str:
        if task_id in waiting_tasks:
            return "waiting"
        if task_id in recently_blocked_tasks:
            return "blocked"
        if task_id in running_ids:
            return "working"
        return "idle"

    latest_task_by_agent: dict[str, dict[str, Any]] = {}
    for t in sorted(tasks, key=lambda t: str(t.get("created_at") or "")):
        latest_task_by_agent[t.get("agent_id") or ""] = t
    running_by_agent: dict[str, list[str]] = defaultdict(list)
    for t in running:
        running_by_agent[t.get("agent_id") or ""].append(t["task_id"])

    dots = []
    if inventory:
        basis = "inventory"
        for a in inventory:
            agent_id = a.get("agent_id") or ""
            agent_running = running_by_agent.get(agent_id, [])
            states = [task_state(tid) for tid in agent_running]
            if "waiting" in states:
                state = "waiting"
            elif "blocked" in states or agent_id in recently_blocked_agents:
                state = "blocked"
            elif agent_running:
                state = "working"
            elif _val(a.get("classification")) == "SHADOW":
                state = "no_task"
            else:
                state = "idle"
            focus_task = agent_running[0] if agent_running else (
                a.get("current_task_id") or (latest_task_by_agent.get(agent_id) or {}).get("task_id"))
            dots.append({
                "id": agent_id,
                "label": a.get("name") or agent_id,
                "state": state,
                "task_id": focus_task,
                "view": "watch" if agent_running else ("history" if focus_task else None),
                "classification": a.get("classification"),
            })
    else:
        basis = "tasks"
        for t in running:
            dots.append({
                "id": t["task_id"],
                "label": t.get("agent_id") or t["task_id"],
                "state": task_state(t["task_id"]),
                "task_id": t["task_id"],
                "view": "watch",
                "classification": "GOVERNED",
            })

    return {
        "generated_at": now.isoformat(),
        "agents_at_work": len(running),
        "need_you": len(needs_you),
        "running_tasks": [
            {
                "task_id": t["task_id"],
                "agent_id": t.get("agent_id"),
                "request_text": t.get("request_text"),
                "started_at": t.get("started_at") or t.get("created_at"),
                "state": task_state(t["task_id"]),
            }
            for t in running
        ],
        "dots": {"basis": basis, "items": dots, "counts": dict(Counter(d["state"] for d in dots))},
        "needs_you": needs_you,
        "blocked": blocked,
        "inventory_size": len(inventory),
        "known_tasks": len(task_by_id),
    }
