"""Service Catalog and Rule-Based Boundary Derivation (F2)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field

from .models import TaskBoundary, EnforcementMode, RiskTier


class ServiceItem(BaseModel):
    name: str
    category: str  # "tool", "workspace", "network", "peer_agent"
    description: str
    risk_level: RiskTier
    metadata: dict[str, Any] = Field(default_factory=dict)


class ServiceCatalog:
    """Registry of environmental capabilities that can be granted in a task boundary."""

    def __init__(self) -> None:
        self.tools: dict[str, ServiceItem] = {
            "read_file": ServiceItem(
                name="read_file",
                category="tool",
                description="Read file contents within authorized task directory",
                risk_level=RiskTier.LOW,
            ),
            "write_file": ServiceItem(
                name="write_file",
                category="tool",
                description="Write content to authorized task output directory",
                risk_level=RiskTier.LOW,
            ),
            "http_get": ServiceItem(
                name="http_get",
                category="tool",
                description="Perform outbound HTTP GET to authorized host:port destinations",
                risk_level=RiskTier.MEDIUM,
            ),
            "run_command": ServiceItem(
                name="run_command",
                category="tool",
                description="Direct command / process execution (restricted until OS enforcement)",
                risk_level=RiskTier.HIGH,
            ),
            "call_agent": ServiceItem(
                name="call_agent",
                category="tool",
                description="Invoke peer A2A agents",
                risk_level=RiskTier.MEDIUM,
            ),
            "request_access": ServiceItem(
                name="request_access",
                category="tool",
                description="Request dynamic boundary expansion",
                risk_level=RiskTier.LOW,
            ),
            "llm_complete": ServiceItem(
                name="llm_complete",
                category="tool",
                description="Invoke LLM inference via secure gateway (broker-held API key)",
                risk_level=RiskTier.LOW,
            ),
        }

        self.peer_agents: dict[str, ServiceItem] = {
            "agent_alice": ServiceItem(
                name="agent_alice",
                category="peer_agent",
                description="A2A Alice Agent",
                risk_level=RiskTier.LOW,
            ),
            "agent_bob": ServiceItem(
                name="agent_bob",
                category="peer_agent",
                description="A2A Bob Agent",
                risk_level=RiskTier.LOW,
            ),
            "agent_summarizer": ServiceItem(
                name="agent_summarizer",
                category="peer_agent",
                description="Summarization Specialist Agent",
                risk_level=RiskTier.LOW,
            ),
            "agent_analyst": ServiceItem(
                name="agent_analyst",
                category="peer_agent",
                description="Data Analysis Specialist Agent",
                risk_level=RiskTier.LOW,
            ),
        }

        self.network_destinations: dict[str, ServiceItem] = {
            "api.github.com:443": ServiceItem(
                name="api.github.com:443",
                category="network",
                description="GitHub Public API",
                risk_level=RiskTier.LOW,
            ),
            "weather.internal:80": ServiceItem(
                name="weather.internal:80",
                category="network",
                description="Internal Weather Service",
                risk_level=RiskTier.LOW,
            ),
            "data.internal:8080": ServiceItem(
                name="data.internal:8080",
                category="network",
                description="Internal Analytics Cluster",
                risk_level=RiskTier.MEDIUM,
            ),
            "localhost:8000": ServiceItem(
                name="localhost:8000",
                category="network",
                description="Local Gateway / Mock Endpoint",
                risk_level=RiskTier.LOW,
            ),
            "127.0.0.1:8000": ServiceItem(
                name="127.0.0.1:8000",
                category="network",
                description="Local Loopback Gateway",
                risk_level=RiskTier.LOW,
            ),
        }

    def get_tool(self, name: str) -> ServiceItem | None:
        return self.tools.get(name)

    def get_peer_agent(self, name: str) -> ServiceItem | None:
        return self.peer_agents.get(name)

    def get_network(self, host_port: str) -> ServiceItem | None:
        return self.network_destinations.get(host_port)


def normalize_workspace_path(workspace_root: str, path_str: str) -> str:
    """Normalize a path and verify it stays inside workspace_root."""
    w_root = Path(workspace_root).resolve()
    target = Path(path_str)
    if not target.is_absolute():
        target = (w_root / target).resolve()
    else:
        target = target.resolve()

    try:
        rel = target.relative_to(w_root)
        return str(rel).replace("\\", "/")
    except ValueError:
        # Path escapes workspace root!
        return "__ESCAPED__"


class BoundaryDerivationV1:
    """Template-based Task Boundary Derivation (v1)."""

    def __init__(self, catalog: ServiceCatalog | None = None) -> None:
        self.catalog = catalog or ServiceCatalog()

    def derive(
        self,
        task_id: str,
        request_text: str,
        workspace_root: str,
        enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE,
        output_targets: list[str] | None = None,
    ) -> TaskBoundary:
        """
        Derives an initial task boundary from user request text using rule-based templates.
        
        Example: 'Analyse report.pdf and write summary.txt'
        Maps to:
        - files_read: ['input/report.pdf', 'report.pdf']
        - files_write: ['output/summary.txt', 'summary.txt']
        - tools: ['read_file', 'write_file']
        - network: []
        - peer_agents: []
        """
        req_lower = request_text.lower()

        # Identify all files mentioned in request (any extension, inside input/ or bare)
        # Avoid matching URLs, port numbers, or decimal versions
        raw_tokens = re.findall(r'[a-zA-Z0-9_./\\-]+\.[a-zA-Z0-9_-]+', request_text)
        file_matches = []
        for tok in raw_tokens:
            tok = tok.strip(".,;:!?()'\"")
            if tok.startswith(("http://", "https://")):
                continue
            if ":" in tok or "/" in tok.split(".")[-1]:
                continue
            ext = tok.split(".")[-1]
            if ext.isdigit():
                continue
            file_matches.append(tok)

        files_read: list[str] = []
        files_write: list[str] = []
        tools: list[str] = ["read_file", "write_file"]
        network: list[str] = []
        peer_agents: list[str] = []

        # Determine read vs write files from explicitly mentioned files
        for f in file_matches:
            f_norm = f.replace("\\", "/").strip()
            f_lower = f_norm.lower()
            basename = Path(f_norm).name
            base_lower = basename.lower()

            # Output / write target classification
            if f_lower.startswith("output/") or base_lower in ["summary.txt", "summary.md", "output.txt", "research_notes.txt"]:
                files_write.append(f_norm if "/" in f_norm else f"output/{basename}")
                files_write.append(basename)
            else:
                # Explicit input file mentioned in user request
                if "/" in f_norm:
                    files_read.append(f_norm)
                    if not f_norm.startswith("input/"):
                        files_read.append(f"input/{basename}")
                else:
                    files_read.append(f"input/{basename}")
                    files_read.append(basename)

        # Classification heuristics for auxiliary tools / templates
        if any(w in req_lower for w in ["research", "web", "fetch", "http"]):
            if "http_get" not in tools:
                tools.append("http_get")
            if not files_write:
                files_write.append("output/research_notes.txt")
            network.extend(["localhost:8000", "127.0.0.1:8000"])

        if any(w in req_lower for w in ["fix", "code", "refactor", "patch"]):
            files_read.extend(["src/**", "tests/**"])
            files_write.extend(["src/**", "tests/**"])

        # Fallbacks if regex didn't catch explicit names
        if not files_read:
            files_read = ["input/*"]
        if not files_write:
            files_write = ["output/summary.txt"]

        # Always include explicitly specified task output targets (e.g. output/summary.txt)
        if output_targets:
            for out_t in output_targets:
                out_norm = out_t.replace("\\", "/").strip()
                # Reject absolute paths and path-traversal attempts
                if out_norm.startswith("/") or out_norm.startswith("\\") or ".." in out_norm:
                    raise ValueError(
                        f"Invalid output_target '{out_t}': must be a relative path "
                        f"without '..' components"
                    )
                if len(out_norm) > 0 and ":" in out_norm:
                    raise ValueError(
                        f"Invalid output_target '{out_t}': absolute Windows path not allowed"
                    )
                files_write.append(out_norm)

        # Ensure unique, normalized lists
        files_read = sorted(list(set(files_read)))
        files_write = sorted(list(set(files_write)))
        tools = sorted(list(set(tools)))
        network = sorted(list(set(network)))
        peer_agents = sorted(list(set(peer_agents)))

        return TaskBoundary(
            task_id=task_id,
            version=1,
            workspace_root=str(Path(workspace_root).resolve()),
            files_read=files_read,
            files_write=files_write,
            network=network,
            tools=tools,
            peer_agents=peer_agents,
            max_duration_sec=3600,
            max_processes=1,
            enforcement_mode=enforcement_mode,
            derived_by="template_v1",
        )
