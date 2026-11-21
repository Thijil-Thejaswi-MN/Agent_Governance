"""Agent Inventory and Discovery (F10).

Tracks registered and discovered agents across the organization, classifying each
as GOVERNED (bound to an active task) or UNGOVERNED / SHADOW (acting with no assigned task).
Calculates live compliance metrics and alerts from real stored events.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field

from .discovery.host_scan import HostScanner
from .discovery.repo_scan import RepoScanner
from .discovery.models import (
    DiscoveredAgent,
    DiscoveryScanRecord,
    EvidenceItem,
    compute_discovery_id,
)

logger = logging.getLogger(__name__)

DEFAULT_A2A_CARD_URLS = [
    "http://127.0.0.1:9999/.well-known/agent-card.json",
    "http://127.0.0.1:9999/.well-known/agent.json",
]


def is_local_url(url: str) -> bool:
    """Checks if a URL points strictly to loopback (127.0.0.1 / localhost)."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = (parsed.hostname or "").lower()
        return hostname in ("127.0.0.1", "localhost", "::1")
    except Exception:
        return False


def discover_local_a2a_cards(
    urls: list[str] | None = None,
    storage: GovernanceStorage | None = None,
) -> list[dict[str, Any]]:
    """Reads A2A Agent Cards only from local URLs (127.0.0.1 / localhost) with 1s timeout.
    Fails closed: rejects non-local URLs and malformed cards."""
    if urls is None:
        configured = os.getenv("A2A_AGENT_CARD_URLS")
        if configured:
            urls = [u.strip() for u in configured.split(",") if u.strip()]
        else:
            urls = list(DEFAULT_A2A_CARD_URLS)

    discovered: list[dict[str, Any]] = []
    seen_names: set[str] = set()

    governed_ids: set[str] = set()
    if storage is not None:
        try:
            governed_ids = {
                t.agent_id.lower()
                for t in storage.list_tasks()
                if getattr(t, "condition", None) != "B"
            }
        except Exception:
            pass

    failed_hosts: set[tuple[str, int]] = set()

    for u in urls:
        if not is_local_url(u):
            continue  # Fail closed: reject non-local URLs immediately

        parsed = urllib.parse.urlparse(u)
        hostname = (parsed.hostname or "127.0.0.1").lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        host_key = (hostname, port)

        if host_key in failed_hosts:
            continue

        try:
            with socket.create_connection((hostname, port), timeout=0.05):
                pass
        except Exception:
            failed_hosts.add(host_key)
            continue

        try:
            req = urllib.request.Request(
                u,
                headers={"Accept": "application/json", "User-Agent": "AgentGovernance/1.0"},
            )
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status != 200:
                    continue
                content = resp.read()
                data = json.loads(content.decode("utf-8"))
        except Exception:
            failed_hosts.add(host_key)
            continue

        if not isinstance(data, dict):
            continue

        name = data.get("name")
        description = data.get("description")
        skills_raw = data.get("skills")

        if not name or not isinstance(name, str) or not name.strip():
            continue
        if not description or not isinstance(description, str) or not description.strip():
            continue
        if not isinstance(skills_raw, list):
            continue

        skills: list[str] = []
        for s in skills_raw:
            if isinstance(s, str) and s.strip():
                skills.append(s.strip())
            elif isinstance(s, dict) and s.get("name"):
                skills.append(str(s["name"]).strip())

        name_clean = name.strip()
        if name_clean.lower() in seen_names:
            continue
        seen_names.add(name_clean.lower())

        agent_key = name_clean.lower().replace(" ", "_")
        is_governed = agent_key in governed_ids or name_clean.lower() in governed_ids

        discovered.append({
            "name": name_clean,
            "agent_id": agent_key,
            "description": description.strip(),
            "skills": skills,
            "url": u,
            "provider": str(data.get("provider") or "A2A"),
            "version": str(data.get("version") or "1.0"),
            "governance_state": "Governed" if is_governed else "Not governed yet",
        })

    return discovered

from .models import (
    EventSource,
    EventVerdict,
    TaskAction,
    TaskLifecycle,
)
from .storage import GovernanceStorage


class AgentInventoryItem(BaseModel):
    agent_id: str
    name: str
    owner: str = "Engineering"
    classification: str  # "GOVERNED" or "SHADOW"
    status: str          # "ACTIVE", "IDLE", "QUARANTINED"
    current_task_id: str | None = None
    boundary_version: int | None = None
    actions_inside: int = 0
    actions_outside: int = 0
    violations_count: int = 0
    last_seen_utc: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    description: str | None = None
    skills: list[str] = Field(default_factory=list)
    governance_state: str | None = None


class AgentInventoryService:
    """Maintains organizational inventory of governed and discovered agents."""

    def __init__(self, storage: GovernanceStorage) -> None:
        self.storage = storage
        self._stop_discovery: threading.Event | None = None
        self._discovery_thread: threading.Thread | None = None
        self._init_periodic_discovery()

    def _init_periodic_discovery(self) -> None:
        interval_str = os.getenv("GOVERNANCE_DISCOVERY_INTERVAL_S")
        if not interval_str:
            return
        try:
            interval = float(interval_str)
            if interval <= 0:
                return
        except ValueError:
            return

        self._stop_discovery = threading.Event()

        def _loop() -> None:
            while not self._stop_discovery.wait(interval):
                try:
                    self.run_discovery_scan()
                except Exception:
                    logger.exception("Periodic discovery scan failed")

        self._discovery_thread = threading.Thread(target=_loop, name="discovery-scanner", daemon=True)
        self._discovery_thread.start()

    def stop_periodic_discovery(self) -> None:
        if self._stop_discovery:
            self._stop_discovery.set()
        if self._discovery_thread:
            self._discovery_thread.join(timeout=2.0)
            self._discovery_thread = None

    def run_discovery_scan(
        self,
        org_id: str = "default",
        proc_root: str = "/proc",
        home_dir: str | Path | None = None,
        repo_paths: list[str | Path] | None = None,
        extra_path_dirs: list[str | Path] | None = None,
        known_llm_ips: set[str] | None = None,
        scan_id: str | None = None,
    ) -> DiscoveryScanRecord:
        scan_id = scan_id or f"scan_{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        scan_rec = DiscoveryScanRecord(
            scan_id=scan_id,
            org_id=org_id,
            started_at=now,
            status="RUNNING",
        )
        self.storage.save_discovery_scan(scan_rec)

        unreadable_count = 0
        discovered: list[DiscoveredAgent] = []

        try:
            # 1. Host scan
            host_scanner = HostScanner(
                proc_root=proc_root,
                home_dir=home_dir,
                extra_path_dirs=extra_path_dirs,
                known_llm_ips=known_llm_ips,
            )
            host_res = host_scanner.scan(org_id=org_id)
            if isinstance(host_res, tuple):
                host_agents = host_res[0]
            else:
                host_agents = host_res
            discovered.extend(host_agents)
            unreadable_count += host_scanner.unreadable_count

            # 2. Local A2A cards
            a2a_cards = discover_local_a2a_cards(storage=self.storage)
            for card in a2a_cards:
                cid = card["agent_id"]
                cname = card["name"]
                skills = card.get("skills", [])
                card_url = card.get("url", "")
                card_agent = DiscoveredAgent(
                    org_id=org_id,
                    discovery_id=compute_discovery_id(host_scanner.host_name, "a2a_agent", card_url or cid),
                    host=host_scanner.host_name,
                    kind="a2a_agent",
                    name=cname,
                    frameworks=["a2a_agent"],
                    evidence=[
                        EvidenceItem(
                            signal="a2a_card",
                            detail=f"Local A2A card at {card_url} with skills: {', '.join(skills)}",
                        )
                    ],
                    status="shadow",
                )
                discovered.append(card_agent)

            # 3. Repository scan
            repo_scanner = RepoScanner(host_name=host_scanner.host_name)
            targets = repo_paths
            if targets is None:
                cwd = Path.cwd()
                targets = [cwd]
                demo_ws = cwd / "demo" / "data" / "demo_workspace"
                if demo_ws.exists():
                    targets.append(demo_ws)
            for target in targets:
                repo_agents = repo_scanner.scan_path(target, org_id=org_id)
                discovered.extend(repo_agents)

            # Determine status & persist
            governed_ids = {
                t.agent_id.lower()
                for t in self.storage.list_tasks()
                if getattr(t, "condition", None) != "B"
            }
            for agent in discovered:
                if agent.linked_agent_id and agent.linked_agent_id.lower() in governed_ids:
                    agent.status = "governed"
                elif agent.name.lower() in governed_ids or agent.discovery_id.lower() in governed_ids:
                    agent.status = "governed"
                else:
                    existing = self.storage.get_discovered_agent(org_id, agent.discovery_id)
                    if existing:
                        if existing.status == "known" or (existing.owner and existing.purpose):
                            agent.status = "known"
                            agent.owner = existing.owner
                            agent.purpose = existing.purpose
                        elif existing.status == "governed":
                            agent.status = "governed"
                        if existing.linked_agent_id:
                            agent.linked_agent_id = existing.linked_agent_id
                        if existing.retired_at:
                            agent.retired_at = existing.retired_at

                self.storage.upsert_discovered_agent(agent)

            completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            details: dict[str, Any] = {
                "unreadable_processes": unreadable_count,
            }
            if unreadable_count > 0:
                details["warning"] = f"partial scan: {unreadable_count} processes not readable"

            scan_rec.completed_at = completed_at
            scan_rec.status = "DONE"
            scan_rec.findings_count = len(discovered)
            scan_rec.unreadable_count = unreadable_count
            scan_rec.details = details
            self.storage.save_discovery_scan(scan_rec)

        except Exception as e:
            logger.exception("Discovery scan %s failed: %s", scan_id, e)
            scan_rec.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            scan_rec.status = "FAILED"
            scan_rec.details = {"error": str(e)}
            self.storage.save_discovery_scan(scan_rec)

        return scan_rec

    def get_discovered_agents(
        self,
        org_id: str = "default",
        status: str | None = None,
        kind: str | None = None,
        host: str | None = None,
        include_retired: bool = False,
    ) -> list[DiscoveredAgent]:
        return self.storage.list_discovered_agents(
            org_id=org_id,
            status=status,
            kind=kind,
            host=host,
            include_retired=include_retired,
        )

    def patch_discovered_agent(
        self,
        org_id: str,
        discovery_id: str,
        owner: str | None = None,
        purpose: str | None = None,
        status: str | None = None,
        linked_agent_id: str | None = None,
    ) -> DiscoveredAgent | None:
        return self.storage.patch_discovered_agent(
            org_id=org_id,
            discovery_id=discovery_id,
            owner=owner,
            purpose=purpose,
            status=status,
            linked_agent_id=linked_agent_id,
        )

    def retire_discovered_agent(
        self,
        org_id: str,
        discovery_id: str,
        retired_by: str = "operator",
    ) -> DiscoveredAgent | None:
        return self.storage.retire_discovered_agent(
            org_id=org_id,
            discovery_id=discovery_id,
            retired_by=retired_by,
        )

    def get_discovery_scan(self, scan_id: str, org_id: str = "default") -> DiscoveryScanRecord | None:
        return self.storage.get_discovery_scan(scan_id=scan_id, org_id=org_id)

    def get_inventory(self) -> list[AgentInventoryItem]:
        """
        Builds the live agent inventory dynamically from:
        1. Registered tasks in governance_tasks
        2. Audit events in governance_events
        3. Egress proxy and A2A discovery logs
        """
        inventory: dict[str, AgentInventoryItem] = {}

        # 1. Inspect all tasks (excluding comparison runs)
        comparison_task_ids = {t.task_id for t in self.storage.list_tasks() if getattr(t, "condition", None) == "B"}
        tasks = [t for t in self.storage.list_tasks() if t.task_id not in comparison_task_ids]
        active_task_by_agent: dict[str, tuple[str, int]] = {}
        for t in tasks:
            if t.status == TaskLifecycle.ACTIVE:
                active_task_by_agent[t.agent_id] = (t.task_id, t.current_boundary_version)

            if t.agent_id not in inventory:
                inventory[t.agent_id] = AgentInventoryItem(
                    agent_id=t.agent_id,
                    name=t.agent_id.replace("_", " ").title(),
                    classification="GOVERNED",
                    status="ACTIVE" if t.status == TaskLifecycle.ACTIVE else "IDLE",
                    current_task_id=t.task_id if t.status == TaskLifecycle.ACTIVE else None,
                    boundary_version=t.current_boundary_version if t.status == TaskLifecycle.ACTIVE else None,
                    last_seen_utc=t.started_at or t.created_at,
                )

        # 2. Inspect all recorded events to compute compliance and discover shadow agents
        with self.storage.get_connection() as conn:
            rows = conn.execute("SELECT * FROM governance_events ORDER BY timestamp ASC").fetchall()

            for r in rows:
                agent_id = r["agent_id"]
                if not agent_id or agent_id == "UNATTRIBUTED":
                    continue

                ts = r["timestamp"]
                verdict = r["verdict"]
                action = r["action_taken"]
                rule = r["rule_matched"]
                task_id = r["task_id"]
                if task_id in comparison_task_ids:
                    continue

                # If agent was seen without a task or not yet in inventory, classify as SHADOW
                if agent_id not in inventory:
                    is_shadow = (task_id is None)
                    inventory[agent_id] = AgentInventoryItem(
                        agent_id=agent_id,
                        name=f"Discovered Agent ({agent_id})",
                        classification="SHADOW" if is_shadow else "GOVERNED",
                        status="ACTIVE",
                        current_task_id=task_id,
                        last_seen_utc=ts,
                    )

                item = inventory[agent_id]
                item.last_seen_utc = ts

                if verdict == EventVerdict.INSIDE.value:
                    item.actions_inside += 1
                else:
                    item.actions_outside += 1
                    if action in (TaskAction.BLOCK_ACTION.value, TaskAction.ALERT.value, TaskAction.KILL_TASK.value, TaskAction.PAUSE_TASK.value):
                        item.violations_count += 1

                # If agent triggered a quarantine or kill action
                if action == TaskAction.QUARANTINE_AGENT.value:
                    item.status = "QUARANTINED"

        # Update active task references
        for agent_id, item in inventory.items():
            if agent_id in active_task_by_agent:
                tid, bver = active_task_by_agent[agent_id]
                item.current_task_id = tid
                item.boundary_version = bver
                item.status = "ACTIVE"
                item.classification = "GOVERNED"

        # 3. Discover local A2A Agent Cards
        discovered_cards = discover_local_a2a_cards(storage=self.storage)
        for card in discovered_cards:
            cid = card["agent_id"]
            if cid in inventory:
                item = inventory[cid]
                item.description = item.description or card["description"]
                item.skills = card["skills"]
                item.governance_state = card["governance_state"]
                item.metadata["a2a_card"] = True
                item.metadata["card_url"] = card.get("url")
            else:
                inventory[cid] = AgentInventoryItem(
                    agent_id=cid,
                    name=card["name"],
                    owner=card.get("provider") or "A2A",
                    classification="DISCOVERED_A2A",
                    status="IDLE",
                    description=card["description"],
                    skills=card["skills"],
                    governance_state=card["governance_state"],
                    metadata={
                        "discovered": True,
                        "a2a_card": True,
                        "card_url": card.get("url"),
                        "version": card.get("version"),
                    },
                )

        return sorted(list(inventory.values()), key=lambda x: (x.classification != "SHADOW", x.agent_id))

    def get_alerts(self) -> list[dict[str, Any]]:
        """Returns live security and compliance alerts from stored events."""
        alerts = []
        comparison_task_ids = {t.task_id for t in self.storage.list_tasks() if getattr(t, "condition", None) == "B"}
        with self.storage.get_connection() as conn:
            # Query violations and shadow detections
            rows = conn.execute(
                """
                SELECT * FROM governance_events 
                WHERE action_taken IN ('BLOCK_ACTION', 'ALERT', 'PAUSE_TASK', 'KILL_TASK', 'QUARANTINE_AGENT')
                ORDER BY timestamp DESC LIMIT 50
                """
            ).fetchall()

            for r in rows:
                if r["task_id"] in comparison_task_ids:
                    continue
                alerts.append({
                    "event_id": r["event_id"],
                    "timestamp": r["timestamp"],
                    "source": r["source"],
                    "task_id": r["task_id"],
                    "agent_id": r["agent_id"],
                    "target": r["target"],
                    "severity": r["risk_tier"],
                    "action_taken": r["action_taken"],
                    "rule_matched": r["rule_matched"],
                    "is_shadow": (r["task_id"] is None),
                })
        return alerts
