"""eBPF-based host-wide discovery signal processing for agents, LLM traffic, and MCP children.

Operates host-wide when GOVERNANCE_DISCOVERY_EBPF=1.
Processes events from the eBPF sensor loader and generates DiscoveredAgent records
grouped by systemd unit or container ID.
"""
from __future__ import annotations

import datetime
import logging
import os
import re
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any

from .host_scan import (
    AGENT_FRAMEWORKS,
    CODING_AGENT_BINARIES,
    LLM_API_DOMAINS,
    sanitize_cmdline,
)
from .models import DiscoveredAgent, EvidenceItem, compute_discovery_id
from ..llm_providers import redact_llm_error

logger = logging.getLogger(__name__)

# Known LLM domain suffixes
LLM_DOMAIN_SUFFIXES = [
    "openai.com",
    "anthropic.com",
    "groq.com",
    "cerebras.ai",
    "googleapis.com",
    "cohere.ai",
    "mistral.ai",
    "deepseek.com",
    "together.xyz",
    "together.ai",
    "perplexity.ai",
]


def is_ebpf_discovery_enabled() -> bool:
    """Returns True if eBPF discovery mode is enabled via environment variable."""
    return os.environ.get("GOVERNANCE_DISCOVERY_EBPF", "").strip() == "1"


def parse_dns_question_name(payload: bytes) -> str | None:
    """Parses the DNS Question QNAME from a raw DNS wire-format payload.

    Returns the dotted domain name in lowercase, or None if malformed or truncated.
    Discards any payload beyond the Question section.
    """
    if not payload or len(payload) < 13:
        return None

    try:
        # Header is 12 bytes. Verify QDCOUNT (offset 4, 2 bytes big-endian) >= 1
        qdcount = struct.unpack("!H", payload[4:6])[0]
        if qdcount == 0:
            return None

        pos = 12
        labels: list[str] = []
        visited_pointers: set[int] = set()

        while pos < len(payload):
            label_len = payload[pos]
            pos += 1

            if label_len == 0:
                # End of QNAME
                break

            # Handle compression pointers (0xC0 prefix)
            if (label_len & 0xC0) == 0xC0:
                if pos >= len(payload):
                    return None
                ptr = ((label_len & 0x3F) << 8) | payload[pos]
                pos += 1
                if ptr in visited_pointers or ptr >= len(payload):
                    # Loop or out of bounds pointer
                    return None
                visited_pointers.add(ptr)
                pos = ptr
                continue

            # Standard label: length must not exceed 63
            if label_len > 63 or pos + label_len > len(payload):
                return None

            label_bytes = payload[pos : pos + label_len]
            pos += label_len

            # Validate characters (alphanumeric, hyphen, underscore)
            label_str = label_bytes.decode("ascii", errors="strict")
            if not re.match(r"^[a-zA-Z0-9_\-]+$", label_str):
                return None

            labels.append(label_str.lower())

        if not labels:
            return None

        domain = ".".join(labels)
        if len(domain) > 253:
            return None
        return domain
    except Exception:
        return None


def parse_cgroup_identity(
    cgroup_path: str,
    unit: str | None = None,
    container_id: str | None = None,
) -> tuple[str, str, str | None]:
    """Derives a stable grouping key, display name, and systemd unit from cgroup metadata.

    Returns: (group_key, display_name, unit_or_none)
    """
    if container_id and len(container_id.strip()) >= 12:
        cid = container_id.strip()[:12]
        return f"container:{cid}", f"Container {cid}", unit

    if unit and unit.strip():
        u = unit.strip()
        return f"unit:{u}", f"Systemd Unit {u}", u

    if cgroup_path and cgroup_path.strip():
        cp = cgroup_path.strip().strip("/")
        # Check if unit or container can be derived from the path
        parts = cp.split("/")
        for part in reversed(parts):
            if part.endswith(".service") or part.endswith(".scope"):
                return f"unit:{part}", f"Systemd Unit {part}", part
            if len(part) == 64 and re.match(r"^[0-9a-fA-F]{64}$", part):
                cid = part[:12]
                return f"container:{cid}", f"Container {cid}", None

        key = f"cgroup:{cp}" if cp else "cgroup:root"
        return key, f"Cgroup {cp}" if cp else "Host Root", None

    return "host:default", "Host Process", None


def sanitize_ebpf_argv(argv: list[str]) -> str:
    """Joins and sanitizes argv, capping at 300 chars and redacting credentials."""
    if not argv:
        return ""
    joined = " ".join(argv)
    return sanitize_cmdline(joined)


def match_exec_agent(
    op: str,
    target: str,
    argv: list[str],
) -> tuple[bool, str, list[str]]:
    """Checks whether an exec event corresponds to a known agent or framework.

    Returns: (is_match, agent_name, frameworks)
    """
    if op not in ("exec", "execve", "execveat"):
        return False, "", []

    target_base = Path(target).name.lower()
    argv0_base = Path(argv[0]).name.lower() if argv else ""

    # 1. Direct binary match
    for b in CODING_AGENT_BINARIES:
        if target_base == b or argv0_base == b or target_base == f"{b}-agent" or argv0_base == f"{b}-agent":
            return True, b, [b]

    # Additional coding agents
    for b in ("cursor-agent", "cursor"):
        if target_base == b or argv0_base == b:
            return True, "cursor", ["cursor"]

    # 2. Python or Node interpreter running an agent framework
    interpreters = {"python", "python3", "node", "bun", "deno"}
    is_interp = any(
        target_base.startswith(interp) or argv0_base.startswith(interp)
        for interp in interpreters
    )

    if is_interp and argv:
        full_line = " ".join(argv).lower()
        found_fw: list[str] = []
        for fw in AGENT_FRAMEWORKS:
            if f"-m {fw}" in full_line or f"/{fw}/" in full_line or f" {fw} " in f" {full_line} ":
                found_fw.append(fw)
        if found_fw:
            agent_name = found_fw[0]
            return True, agent_name, sorted(list(set(found_fw)))

    return False, "", []


def match_mcp_child(
    op: str,
    target: str,
    argv: list[str],
    is_child_of_agent: bool = False,
) -> tuple[bool, str]:
    """Checks whether an exec event represents an MCP server child process.

    Returns: (is_match, detail_string)
    """
    if op not in ("exec", "execve", "execveat"):
        return False, ""

    cmd_str = " ".join(argv) if argv else target
    cmd_lower = cmd_str.lower()
    target_lower = target.lower()

    is_mcp = False
    if "@modelcontextprotocol" in cmd_lower:
        is_mcp = True
    elif "uvx mcp-server" in cmd_lower or "npx -y @modelcontextprotocol" in cmd_lower:
        is_mcp = True
    elif "mcp-server" in target_lower or "mcp_server" in target_lower or "mcp" in Path(target_lower).name:
        is_mcp = True
    elif is_child_of_agent and ("mcp" in cmd_lower):
        is_mcp = True

    if is_mcp:
        sanitized = sanitize_cmdline(cmd_str)
        return True, f"MCP server process: {sanitized}"

    return False, ""


def match_llm_connect(
    op: str,
    target: str,
    known_ips: set[str],
) -> tuple[bool, str]:
    """Checks whether a connect event targets a known LLM IP address."""
    if op != "connect":
        return False, ""

    # Target format: inet:1.2.3.4:443 or inet6:[2001:...]:443
    dest_ip = ""
    port = ""
    if target.startswith("inet:"):
        parts = target[5:].split(":")
        if len(parts) == 2:
            dest_ip, port = parts[0], parts[1]
    elif target.startswith("inet6:["):
        idx = target.find("]:")
        if idx > 7:
            dest_ip = target[7:idx]
            port = target[idx + 2 :]

    if dest_ip and dest_ip in known_ips:
        return True, f"{dest_ip}:{port}"

    return False, ""


def match_llm_dns(dns_question: str | None) -> tuple[bool, str]:
    """Checks whether a DNS query targets a known LLM domain."""
    if not dns_question:
        return False, ""

    q = dns_question.strip().lower()
    for dom in LLM_API_DOMAINS:
        if q == dom:
            return True, q

    for suffix in LLM_DOMAIN_SUFFIXES:
        if q == suffix or q.endswith(f".{suffix}"):
            return True, q

    return False, ""


class EBPFDiscoveryProcessor:
    """Consumes and filters discovery events from the eBPF sensor."""

    def __init__(
        self,
        storage: Any | None = None,
        host_name: str | None = None,
        rate_limit: int = 200,
        known_llm_ips: set[str] | None = None,
    ) -> None:
        self.storage = storage
        self.host_name = host_name or socket.gethostname()
        self.rate_limit = rate_limit
        self.known_llm_ips: set[str] = set(known_llm_ips or set())
        self.agent_pids: set[int] = set()
        self.discovered_by_group: dict[str, DiscoveredAgent] = {}
        self.rate_limited_count: int = 0
        self._lock = threading.Lock()
        self._resolve_domains()

    def _resolve_domains(self) -> None:
        """Populates known LLM IP set from static domain list."""
        for dom in LLM_API_DOMAINS:
            try:
                res = socket.getaddrinfo(dom, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for item in res:
                    self.known_llm_ips.add(item[4][0])
            except Exception:
                pass

    def add_llm_ip(self, ip: str) -> None:
        with self._lock:
            self.known_llm_ips.add(ip)

    def get_rate_limited_count(self) -> int:
        with self._lock:
            return self.rate_limited_count

    def process_event(
        self,
        event: dict[str, Any],
        org_id: str = "default",
    ) -> DiscoveredAgent | None:
        """Processes one eBPF JSON event and updates discovered agents."""
        if not event:
            return None

        # Check rate limited metric
        if "rate_limited" in event:
            try:
                val = int(event["rate_limited"])
                with self._lock:
                    if val > self.rate_limited_count:
                        self.rate_limited_count = val
            except (ValueError, TypeError):
                pass

        # Only process discovery mode events or syscalls
        is_discovery = event.get("mode") == "discovery" or event.get("is_discovery")
        op = event.get("op", "")
        if not op:
            return None

        target = event.get("target", "") or event.get("abs_target", "")
        argv = event.get("argv", []) or []
        pid = event.get("pid", 0)
        ppid = event.get("ppid", 0)
        cgroup_path = event.get("cgroup_path", "")
        unit = event.get("unit")
        container_id = event.get("container_id")
        dns_q = event.get("dns_question")

        now = event.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Check signals
        matched_signals: list[tuple[str, str]] = []
        frameworks: list[str] = []
        endpoints: list[str] = []
        agent_name = ""
        kind = "process"

        # Signal 1: ebpf_exec_agent
        is_agent, bin_name, fws = match_exec_agent(op, target, argv)
        if is_agent:
            cmd_sanitized = sanitize_ebpf_argv(argv) if argv else sanitize_cmdline(target)
            matched_signals.append(("ebpf_exec_agent", f"Process executed: {cmd_sanitized}"))
            agent_name = bin_name
            frameworks.extend(fws)
            kind = "coding_agent" if bin_name in CODING_AGENT_BINARIES or bin_name == "cursor" else "process"
            with self._lock:
                self.agent_pids.add(pid)

        # Signal 2: ebpf_mcp_child
        with self._lock:
            parent_is_agent = ppid in self.agent_pids
        is_mcp, mcp_detail = match_mcp_child(op, target, argv, is_child_of_agent=parent_is_agent)
        if is_mcp:
            matched_signals.append(("ebpf_mcp_child", mcp_detail))
            if not agent_name:
                agent_name = "MCP Server"
                kind = "mcp_server"

        # Signal 3: ebpf_llm_connect
        with self._lock:
            current_known_ips = set(self.known_llm_ips)
        is_conn, conn_detail = match_llm_connect(op, target, current_known_ips)
        if is_conn:
            matched_signals.append(("ebpf_llm_connect", f"Connection to LLM IP: {conn_detail}"))
            endpoints.append(conn_detail)

        # Signal 4: ebpf_llm_dns
        is_dns, dns_detail = match_llm_dns(dns_q)
        if is_dns:
            matched_signals.append(("ebpf_llm_dns", f"DNS query for LLM domain: {dns_detail}"))
            endpoints.append(dns_detail)
            # Resolve DNS query asynchronously or opportunistically
            try:
                addrs = socket.getaddrinfo(dns_detail, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for item in addrs:
                    self.add_llm_ip(item[4][0])
            except Exception:
                pass

        if not matched_signals:
            return None

        # Grouping by systemd unit or container ID
        group_key, display_name, derived_unit = parse_cgroup_identity(cgroup_path, unit, container_id)

        with self._lock:
            existing = self.discovered_by_group.get(group_key)
            if existing:
                if existing.kind in ("coding_agent", "mcp_server") and kind == "process":
                    kind = existing.kind
                if not agent_name and existing.name:
                    agent_name = existing.name

        final_name = agent_name or display_name
        disc_id = compute_discovery_id(self.host_name, kind, group_key)

        with self._lock:
            existing = self.discovered_by_group.get(group_key)
            ev_items: list[EvidenceItem] = []
            if existing:
                ev_items = list(existing.evidence)
                frameworks = sorted(list(set(existing.frameworks) | set(frameworks)))
                endpoints = sorted(list(set(existing.llm_endpoints) | set(endpoints)))

            for sig, det in matched_signals:
                # Update existing evidence item if signal+detail already recorded
                updated = False
                for item in ev_items:
                    if item.signal == sig and item.detail == det:
                        item.last_seen = now
                        updated = True
                        break
                if not updated:
                    ev_items.append(EvidenceItem(signal=sig, detail=det, first_seen=now, last_seen=now))

            agent = DiscoveredAgent(
                org_id=org_id,
                discovery_id=disc_id,
                host=self.host_name,
                kind=kind,  # type: ignore
                name=final_name,
                frameworks=frameworks,
                llm_endpoints=endpoints,
                key_names=[],
                evidence=ev_items,
                status="shadow",
                owner=existing.owner if existing else None,
                purpose=existing.purpose if existing else None,
                linked_agent_id=existing.linked_agent_id if existing else None,
                created_at=existing.created_at if existing else now,
                updated_at=now,
            )
            self.discovered_by_group[group_key] = agent

        if self.storage:
            try:
                agent = self.storage.upsert_discovered_agent(agent)
            except Exception as ex:
                logger.warning(f"Error persisting discovered agent {disc_id}: {ex}")

        return agent

    def process_line(self, line: str, org_id: str = "default") -> DiscoveredAgent | None:
        """Parses a JSON line and processes it."""
        import json
        try:
            ev = json.loads(line)
            return self.process_event(ev, org_id=org_id)
        except Exception:
            return None
