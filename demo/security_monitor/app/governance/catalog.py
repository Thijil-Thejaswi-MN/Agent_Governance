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
        }

    def get_tool(self, name: str) -> ServiceItem | None:
        return self.tools.get(name)


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

        # Identify files mentioned in request
        # Regex captures filenames with extensions (.pdf, .txt, .json, .csv, .md, .log, .py)
        file_matches = re.findall(r'[\w\-./]+\.(?:pdf|txt|json|csv|md|log|py)', request_text, flags=re.IGNORECASE)

        files_read: list[str] = []
        files_write: list[str] = []
        tools: list[str] = []
        network: list[str] = []
        peer_agents: list[str] = []

        # Classification heuristics
        if any(w in req_lower for w in ["summarise", "summarize", "analyse", "analyze", "report"]):
            # Document analysis template
            tools = ["read_file", "write_file"]
            
            # Determine read vs write files
            for f in file_matches:
                f_norm = f.replace("\\", "/")
                f_lower = f_norm.lower()
                basename = Path(f_norm).name
                
                # Check if path explicitly has directory or was bare
                if any(w in f_lower for w in ["summary", "output", "result", "analysis"]):
                    if "/" in f_norm:
                        files_write.append(f_norm)
                    else:
                        files_write.append(f"output/{basename}")
                else:
                    if "/" in f_norm:
                        files_read.append(f_norm)
                    else:
                        files_read.append(f"input/{basename}")

            # Fallbacks if regex didn't catch explicit names
            if not files_read:
                files_read = ["input/report.pdf"]
            if not files_write:
                files_write = ["output/summary.txt"]

        elif any(w in req_lower for w in ["research", "web", "fetch", "http"]):
            # Web research template
            tools = ["read_file", "write_file", "http_get"]
            files_write = ["output/research_notes.txt", "research_notes.txt"]
            # Network hosts extracted or local stub
            network = ["localhost:8000", "127.0.0.1:8000"]
        elif any(w in req_lower for w in ["fix", "code", "refactor", "patch"]):
            # Code fix template
            tools = ["read_file", "write_file"]
            files_read = ["src/**", "tests/**"]
            files_write = ["src/**", "tests/**"]
        else:
            # Minimal default template: read/write only within assigned workspace
            tools = ["read_file", "write_file"]
            files_read = ["input/*"]
            files_write = ["output/*"]

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
