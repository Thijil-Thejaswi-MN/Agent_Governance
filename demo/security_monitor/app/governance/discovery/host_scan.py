"""Host scanner for agents, framework processes, local model servers, MCP configs, and tools."""
from __future__ import annotations

import datetime
import json
import logging
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import urllib.request
from typing import Any

from .models import DiscoveredAgent, EvidenceItem, compute_discovery_id
from ..llm_providers import redact_llm_error

logger = logging.getLogger(__name__)

AGENT_FRAMEWORKS = [
    "langchain",
    "langgraph",
    "crewai",
    "autogen",
    "agents",          # OpenAI Agents SDK
    "claude_agent_sdk",
    "claude_agent",
    "llama_index",
    "semantic_kernel",
    "mcp",
]

KNOWN_LLM_KEY_NAMES = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GROQ_API_KEY",
    "GEMINI_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_API_KEY",
    "COHERE_API_KEY",
    "MISTRAL_API_KEY",
    "CEREBRAS_API_KEY",
    "AI21_API_KEY",
    "TOGETHER_API_KEY",
    "VOYAGE_API_KEY",
    "PERPLEXITY_API_KEY",
    "DEEPSEEK_API_KEY",
    "AWS_BEDROCK_API_KEY",
    "HUGGINGFACE_API_KEY",
    "HF_TOKEN",
    "TAVILY_API_KEY",
    "SERPAPI_API_KEY",
    "LANGCHAIN_API_KEY",
    "LANGFUSE_API_KEY",
    "WANDB_API_KEY",
}

LLM_API_DOMAINS = [
    "api.openai.com",
    "api.anthropic.com",
    "api.groq.com",
    "generativelanguage.googleapis.com",
    "api.cerebras.ai",
]

CODING_AGENT_BINARIES = [
    "claude",
    "cursor",
    "codex",
    "gemini",
    "aider",
    "antigravity",
]


def sanitize_cmdline(cmd: str) -> str:
    """Caps command line at 300 chars and redacts auth tokens and key values."""
    if not cmd:
        return ""
    redacted = redact_llm_error(cmd, max_chars=300) or ""
    redacted = re.sub(r"(--?(?:token|auth_token|auth-token|secret)=)[^\s]+", r"\1[REDACTED_AUTH]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"(\btoken=)[^\s]+", r"\1[REDACTED_AUTH]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"(--?(?:key|api_key|api-key)=)[^\s]+", r"\1[REDACTED_KEY]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"(--?(?:token|auth_token|auth-token|secret|password|key|api_key|api-key))\s+[^\s]+", r"\1 [REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted[:300]


def is_llm_key_name(name: str) -> bool:
    upper = name.strip().upper()
    if upper in KNOWN_LLM_KEY_NAMES:
        return True
    if upper.endswith("_API_KEY") or upper.endswith("_LLM_KEY"):
        return True
    return False


def hex_to_ipv4(hex_str: str) -> str:
    """Converts little-endian hex string from /proc/net/tcp to dotted-quad IPv4."""
    try:
        ip_int = int(hex_str, 16)
        return socket.inet_ntoa(struct.pack("<I", ip_int))
    except Exception:
        return ""


def hex_to_ipv6(hex_str: str) -> str:
    """Converts hex string from /proc/net/tcp6 to standard IPv6 notation."""
    try:
        words = [int(hex_str[i:i+8], 16) for i in range(0, 32, 8)]
        packed = struct.pack("<4I", *words)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return ""


class HostScanner:
    """Scans the host system for agent processes, listeners, MCP servers, and tools."""

    def __init__(
        self,
        proc_root: str | Path = "/proc",
        home_dir: str | Path | None = None,
        host_name: str | None = None,
        storage: GovernanceStorage | None = None,
        known_llm_ips: set[str] | None = None,
        extra_path_dirs: list[str | Path] | None = None,
    ) -> None:
        self.proc_root = Path(proc_root)
        self.home_dir = Path(home_dir) if home_dir else Path.home()
        self.host_name = host_name or socket.gethostname()
        self.storage = storage
        self.known_llm_ips = set(known_llm_ips or set())
        self.extra_path_dirs = [Path(p) for p in (extra_path_dirs or [])]
        self.unreadable_count: int = 0
        self._resolve_llm_ips()

    def _resolve_llm_ips(self) -> None:
        """Resolves known LLM API domains to IP addresses for connection matching."""
        for dom in LLM_API_DOMAINS:
            try:
                addr_info = socket.getaddrinfo(dom, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for item in addr_info:
                    ip = item[4][0]
                    self.known_llm_ips.add(ip)
            except Exception:
                pass

    def scan(self, org_id: str = "default") -> tuple[list[DiscoveredAgent], int, str]:
        """Runs a host scan. Returns (discovered_agents, unreadable_processes_count, partial_scan_note)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        discovered: list[DiscoveredAgent] = []
        unreadable_pids: list[int] = []

        # 1. Parse network connections and map socket inodes to processes
        inode_to_pid: dict[str, int] = {}
        pid_connections: dict[int, list[str]] = {}
        listening_ports: set[int] = set()

        if self.proc_root.exists():
            self._parse_proc_net(inode_to_pid, pid_connections, listening_ports)

        # 2. Scan processes in /proc
        if self.proc_root.exists():
            proc_agents, unreadable_count = self._scan_processes(org_id, now, pid_connections, unreadable_pids)
            discovered.extend(proc_agents)
        else:
            unreadable_count = 0

        # 3. Scan local model servers
        model_servers = self._scan_local_model_servers(org_id, now, listening_ports)
        discovered.extend(model_servers)

        # 4. Scan MCP configurations
        mcp_servers = self._scan_mcp_configs(org_id, now)
        discovered.extend(mcp_servers)

        # 5. Scan installed coding agent tools
        coding_tools = self._scan_coding_agents(org_id, now)
        discovered.extend(coding_tools)

        # 6. Discover A2A agents
        a2a_agents = self._scan_a2a_cards(org_id, now)
        discovered.extend(a2a_agents)

        # 7. Merge eBPF discovery signals if enabled
        if os.environ.get("GOVERNANCE_DISCOVERY_EBPF", "").strip() == "1" and self.storage:
            try:
                ebpf_agents = [
                    a for a in self.storage.list_discovered_agents(org_id=org_id)
                    if any(ev.signal.startswith("ebpf_") for ev in a.evidence)
                ]
                existing_ids = {a.discovery_id: a for a in discovered}
                for ea in ebpf_agents:
                    if ea.discovery_id in existing_ids:
                        merged_ev = {(e.signal, e.detail): e for e in existing_ids[ea.discovery_id].evidence}
                        for e in ea.evidence:
                            merged_ev[(e.signal, e.detail)] = e
                        existing_ids[ea.discovery_id].evidence = list(merged_ev.values())
                    else:
                        discovered.append(ea)
            except Exception as ex:
                logger.warning(f"Failed to query eBPF discovered agents: {ex}")

        self.unreadable_count = unreadable_count
        partial_note = f"partial scan: {unreadable_count} processes not readable"
        return discovered, unreadable_count, partial_note

    def _parse_proc_net(
        self,
        inode_to_pid: dict[str, int],
        pid_connections: dict[int, list[str]],
        listening_ports: set[int],
    ) -> None:
        """Reads /proc/net/tcp and tcp6 for listening ports and outbound connections."""
        # Read socket inodes for readable processes
        for entry in self.proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            fd_dir = entry / "fd"
            if not fd_dir.exists():
                continue
            try:
                for fd_link in fd_dir.iterdir():
                    try:
                        target = os.readlink(fd_link)
                        if target.startswith("socket:[") and target.endswith("]"):
                            inode = target[8:-1]
                            inode_to_pid[inode] = pid
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue

        for net_file, is_v6 in [
            (self.proc_root / "net" / "tcp", False),
            (self.proc_root / "net" / "tcp6", True),
        ]:
            if not net_file.exists():
                continue
            try:
                lines = net_file.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in lines[1:]:  # skip header
                    parts = line.strip().split()
                    if len(parts) < 10:
                        continue
                    local_addr = parts[1]
                    rem_addr = parts[2]
                    state = parts[3]
                    inode = parts[9]

                    # Parse local port
                    if ":" in local_addr:
                        _, l_port_hex = local_addr.split(":", 1)
                        try:
                            l_port = int(l_port_hex, 16)
                            if state == "0A":  # TCP_LISTEN
                                listening_ports.add(l_port)
                        except ValueError:
                            pass

                    # Parse remote established connections (01 = TCP_ESTABLISHED)
                    if state == "01" and ":" in rem_addr:
                        r_ip_hex, r_port_hex = rem_addr.split(":", 1)
                        r_ip = hex_to_ipv6(r_ip_hex) if is_v6 else hex_to_ipv4(r_ip_hex)
                        try:
                            r_port = int(r_port_hex, 16)
                        except ValueError:
                            r_port = 0

                        endpoint_str = f"{r_ip}:{r_port}"
                        if r_ip in self.known_llm_ips:
                            pid = inode_to_pid.get(inode)
                            if pid:
                                pid_connections.setdefault(pid, []).append(endpoint_str)
            except Exception as e:
                logger.debug(f"Unable to read {net_file}: {e}")

    def _scan_processes(
        self,
        org_id: str,
        now: str,
        pid_connections: dict[int, list[str]],
        unreadable_pids: list[int],
    ) -> tuple[list[DiscoveredAgent], int]:
        """Scans process folders for Python/Node agent frameworks and environment keys."""
        agents: list[DiscoveredAgent] = []

        for entry in self.proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)

            cmdline_file = entry / "cmdline"
            maps_file = entry / "maps"
            environ_file = entry / "environ"

            # Check readability
            try:
                if not cmdline_file.exists() and not maps_file.exists() and not environ_file.exists():
                    unreadable_pids.append(pid)
                    continue
                cmd_raw = cmdline_file.read_bytes() if cmdline_file.exists() else b""
            except (PermissionError, OSError):
                unreadable_pids.append(pid)
                continue

            cmd_parts = [p.decode("utf-8", errors="replace").strip() for p in cmd_raw.split(b"\x00") if p]
            if not cmd_parts and cmdline_file.exists():
                try:
                    txt = cmdline_file.read_text(encoding="utf-8", errors="replace").strip()
                    cmd_parts = txt.split()
                except Exception:
                    pass

            cmd_str = " ".join(cmd_parts)
            proc_basename = Path(cmd_parts[0]).name if cmd_parts else ""

            # Check maps for loaded framework libraries
            detected_frameworks: set[str] = set()
            try:
                if maps_file.exists():
                    maps_text = maps_file.read_text(encoding="utf-8", errors="replace").lower()
                    for fw in AGENT_FRAMEWORKS:
                        if fw in maps_text:
                            detected_frameworks.add(fw)
            except (PermissionError, OSError):
                unreadable_pids.append(pid)

            # Check cmdline for framework mentions
            cmd_lower = cmd_str.lower()
            for fw in AGENT_FRAMEWORKS:
                if f"-m {fw}" in cmd_lower or f"/{fw}/" in cmd_lower or fw in cmd_lower:
                    detected_frameworks.add(fw)

            # Check environ for key names (PRIVACY RULE: store NAMES ONLY, never values!)
            detected_key_names: list[str] = []
            try:
                if environ_file.exists():
                    env_raw = environ_file.read_bytes()
                    for item in env_raw.split(b"\x00"):
                        if not item:
                            continue
                        line = item.decode("utf-8", errors="replace").strip()
                        if "=" in line:
                            var_name, _ = line.split("=", 1)
                            var_name = var_name.strip()
                            if is_llm_key_name(var_name):
                                detected_key_names.append(var_name)
            except (PermissionError, OSError):
                if pid not in unreadable_pids:
                    unreadable_pids.append(pid)

            detected_key_names = sorted(list(set(detected_key_names)))
            llm_endpoints = pid_connections.get(pid, [])

            # An agent process is identified if it has framework imports, LLM keys, or LLM connections
            if detected_frameworks or detected_key_names or llm_endpoints:
                sanitized_cmd = sanitize_cmdline(cmd_str)
                evidence_list: list[EvidenceItem] = []

                for fw in sorted(detected_frameworks):
                    evidence_list.append(EvidenceItem(
                        signal="framework_import",
                        detail=f"Process loaded library: {fw}",
                        first_seen=now,
                        last_seen=now,
                    ))

                for kn in detected_key_names:
                    evidence_list.append(EvidenceItem(
                        signal="env_key_name",
                        detail=f"Environment variable present: {kn}",
                        first_seen=now,
                        last_seen=now,
                    ))

                for ep in llm_endpoints:
                    evidence_list.append(EvidenceItem(
                        signal="llm_connection",
                        detail=f"Outbound connection to model endpoint: {ep}",
                        first_seen=now,
                        last_seen=now,
                    ))

                if sanitized_cmd:
                    evidence_list.append(EvidenceItem(
                        signal="process_cmdline",
                        detail=f"Command line: {sanitized_cmd}",
                        first_seen=now,
                        last_seen=now,
                    ))

                # Stable fingerprint
                key_ev = f"pid:{pid}:{proc_basename}"
                disc_id = compute_discovery_id(self.host_name, "process", key_ev)
                name = f"{proc_basename or 'Process'} (pid {pid})"

                agent = DiscoveredAgent(
                    org_id=org_id,
                    discovery_id=disc_id,
                    host=self.host_name,
                    kind="process",
                    name=name,
                    frameworks=sorted(list(detected_frameworks)),
                    llm_endpoints=llm_endpoints,
                    key_names=detected_key_names,
                    evidence=evidence_list,
                    status="shadow",
                    created_at=now,
                    updated_at=now,
                )
                agents.append(agent)

        return agents, len(unreadable_pids)

    def _scan_local_model_servers(
        self,
        org_id: str,
        now: str,
        listening_ports: set[int],
    ) -> list[DiscoveredAgent]:
        """Probes for Ollama (:11434) and LM Studio (:1234) listeners."""
        servers: list[DiscoveredAgent] = []

        targets = [
            ("Ollama Server", 11434, "http://127.0.0.1:11434/api/tags"),
            ("LM Studio Server", 1234, "http://127.0.0.1:1234/v1/models"),
        ]

        for srv_name, port, probe_url in targets:
            detected = False
            detail_msg = ""

            if port in listening_ports:
                detected = True
                detail_msg = f"Listening on TCP port {port}"

            # Harmless HTTP probe with short timeout
            if not detected:
                try:
                    req = urllib.request.Request(probe_url, headers={"User-Agent": "AgentGovernance/1.0"})
                    with urllib.request.urlopen(req, timeout=0.2) as resp:
                        if resp.status in (200, 404):
                            detected = True
                            detail_msg = f"HTTP probe responded on {probe_url}"
                except Exception:
                    pass

            if detected:
                key_ev = f"port:{port}"
                disc_id = compute_discovery_id(self.host_name, "local_model_server", key_ev)
                agent = DiscoveredAgent(
                    org_id=org_id,
                    discovery_id=disc_id,
                    host=self.host_name,
                    kind="local_model_server",
                    name=srv_name,
                    frameworks=["local_inference"],
                    llm_endpoints=[f"http://127.0.0.1:{port}"],
                    key_names=[],
                    evidence=[
                        EvidenceItem(
                            signal="local_model_listener",
                            detail=detail_msg,
                            first_seen=now,
                            last_seen=now,
                        )
                    ],
                    status="shadow",
                    created_at=now,
                    updated_at=now,
                )
                servers.append(agent)

        return servers

    def _scan_mcp_configs(self, org_id: str, now: str) -> list[DiscoveredAgent]:
        """Discovers configured Model Context Protocol servers."""
        configs_to_check = [
            Path(".mcp.json"),
            self.home_dir / ".mcp.json",
            self.home_dir / ".cursor" / "mcp.json",
            self.home_dir / ".vscode" / "mcp.json",
            self.home_dir / ".config" / "Claude" / "claude_desktop_config.json",
            self.home_dir / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            self.home_dir / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
            self.home_dir / ".codeium" / "windsurf" / "mcp_config.json",
            self.home_dir / ".gemini" / "mcp.json",
            self.home_dir / ".gemini" / "antigravity" / "mcp.json",
        ]

        mcp_agents: list[DiscoveredAgent] = []

        for p in configs_to_check:
            if not p.exists() or not p.is_file():
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue

            if not isinstance(data, dict):
                continue

            servers_dict = data.get("mcpServers") or data.get("servers") or {}
            if not isinstance(servers_dict, dict):
                continue

            for srv_name, srv_conf in servers_dict.items():
                if not isinstance(srv_conf, dict):
                    continue
                cmd = str(srv_conf.get("command") or "")
                raw_args = srv_conf.get("args") or []
                args_str = " ".join(str(a) for a in raw_args) if isinstance(raw_args, list) else ""
                full_cmd = f"{cmd} {args_str}".strip()
                sanitized_cmd = sanitize_cmdline(full_cmd)

                # Store environment variable NAMES ONLY, never values!
                env_dict = srv_conf.get("env") or {}
                key_names: list[str] = []
                if isinstance(env_dict, dict):
                    for k in env_dict.keys():
                        if is_llm_key_name(str(k)):
                            key_names.append(str(k).strip())
                key_names = sorted(list(set(key_names)))

                key_ev = f"{p}:{srv_name}"
                disc_id = compute_discovery_id(self.host_name, "mcp_server", key_ev)

                agent = DiscoveredAgent(
                    org_id=org_id,
                    discovery_id=disc_id,
                    host=self.host_name,
                    kind="mcp_server",
                    name=f"MCP: {srv_name}",
                    frameworks=["mcp"],
                    llm_endpoints=[],
                    key_names=key_names,
                    evidence=[
                        EvidenceItem(
                            signal="mcp_config",
                            detail=f"Configured in {p.name} with command: {sanitized_cmd}",
                            first_seen=now,
                            last_seen=now,
                        )
                    ],
                    status="shadow",
                    created_at=now,
                    updated_at=now,
                )
                mcp_agents.append(agent)

        return mcp_agents

    def _scan_coding_agents(self, org_id: str, now: str) -> list[DiscoveredAgent]:
        """Discovers coding agent command-line tools installed on PATH or user bin."""
        found_tools: list[DiscoveredAgent] = []

        search_dirs = [
            self.home_dir / ".local" / "bin",
            self.home_dir / ".npm-global" / "bin",
            self.home_dir / "bin",
        ] + self.extra_path_dirs

        for bin_name in CODING_AGENT_BINARIES:
            resolved_path: str | None = None

            # Check PATH
            which_res = shutil.which(bin_name)
            if which_res:
                resolved_path = which_res
            else:
                for d in search_dirs:
                    candidate = d / bin_name
                    if candidate.exists() and os.access(candidate, os.X_OK):
                        resolved_path = str(candidate)
                        break

            if resolved_path:
                key_ev = f"binary:{resolved_path}"
                disc_id = compute_discovery_id(self.host_name, "coding_agent", key_ev)
                agent = DiscoveredAgent(
                    org_id=org_id,
                    discovery_id=disc_id,
                    host=self.host_name,
                    kind="coding_agent",
                    name=f"{bin_name.title()} CLI",
                    frameworks=[bin_name],
                    llm_endpoints=[],
                    key_names=[],
                    evidence=[
                        EvidenceItem(
                            signal="installed_binary",
                            detail=f"Binary located at: {resolved_path}",
                            first_seen=now,
                            last_seen=now,
                        )
                    ],
                    status="shadow",
                    created_at=now,
                    updated_at=now,
                )
                found_tools.append(agent)

        return found_tools

    def _scan_a2a_cards(self, org_id: str, now: str) -> list[DiscoveredAgent]:
        """Discovers local A2A agent cards."""
        try:
            from ..inventory import discover_local_a2a_cards
            discovered_cards = discover_local_a2a_cards(storage=self.storage)
        except Exception:
            discovered_cards = []
        agents: list[DiscoveredAgent] = []

        for card in discovered_cards:
            cid = card.get("agent_id") or "a2a_agent"
            cname = card.get("name") or cid
            url = card.get("url") or ""
            key_ev = f"card:{url or cid}"
            disc_id = compute_discovery_id(self.host_name, "a2a_agent", key_ev)

            status = "governed" if card.get("governance_state") == "Governed" else "shadow"

            agent = DiscoveredAgent(
                org_id=org_id,
                discovery_id=disc_id,
                host=self.host_name,
                kind="a2a_agent",
                name=cname,
                frameworks=["A2A"],
                llm_endpoints=[url] if url else [],
                key_names=[],
                evidence=[
                    EvidenceItem(
                        signal="a2a_card",
                        detail=f"Local A2A card at: {url}",
                        first_seen=now,
                        last_seen=now,
                    )
                ],
                status=status,
                owner=card.get("provider") or "A2A",
                purpose=card.get("description"),
                created_at=now,
                updated_at=now,
            )
            agents.append(agent)

        return agents
