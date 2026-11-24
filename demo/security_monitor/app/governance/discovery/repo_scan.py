"""Repository scanner for AI agent and MCP configurations.

Inspects local repositories and workspaces for agent dependencies,
manifests, and agent definitions without making network requests.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from .models import DiscoveredAgent, EvidenceItem, compute_discovery_id

logger = logging.getLogger(__name__)

AGENT_FRAMEWORKS = [
    "langchain",
    "langgraph",
    "crewai",
    "autogen",
    "agents",
    "openai-agents",
    "claude_agent_sdk",
    "claude-agent-sdk",
    "llama_index",
    "llama-index",
    "semantic_kernel",
    "semantic-kernel",
    "mcp",
    "modelcontextprotocol",
]

KEY_PATTERNS = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GROQ_API_KEY",
    "GEMINI_API_KEY",
    "AZURE_OPENAI_API_KEY",
]


def safe_read_file(repo_root: Path, file_path: Path, max_bytes: int = 1024 * 1024) -> str | None:
    """Reads a file safely:
    - verifies with lstat that it is a regular file and NOT a symlink
    - verifies that the resolved path stays inside repo_root
    - opens with O_RDONLY | O_NOFOLLOW
    - caps read at max_bytes (1 MB)
    """
    try:
        resolved_root = repo_root.resolve()
        st = os.lstat(str(file_path))
        import stat
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
            return None
        resolved_file = file_path.resolve()
        if not (resolved_file == resolved_root or str(resolved_file).startswith(str(resolved_root) + os.sep)):
            return None
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(file_path), flags)
        try:
            with open(fd, "rb", closefd=True) as f:
                content = f.read(max_bytes)
                return content.decode("utf-8", errors="replace")
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            return None
    except Exception as e:
        logger.debug("safe_read_file failed for %s: %s", file_path, e)
        return None


def safe_read_json(repo_root: Path, file_path: Path, max_bytes: int = 1024 * 1024) -> Any | None:
    text = safe_read_file(repo_root, file_path, max_bytes=max_bytes)
    if text is None:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


class RepoScanner:
    """Scans repository roots for agent frameworks, agent cards, and MCP configurations."""

    def __init__(self, host_name: str | None = None) -> None:
        self.host_name = host_name or os.uname().nodename if hasattr(os, "uname") else "localhost"

    def scan_path(self, target_path: str | Path, org_id: str = "default") -> list[DiscoveredAgent]:
        path = Path(target_path).resolve()
        if not path.exists():
            return []

        # Find repositories (dirs containing .git or manifest files)
        repos: list[Path] = []
        if (path / ".git").is_dir() or self._is_repo_root(path):
            repos.append(path)
        else:
            # Check immediate children or subdirectories up to depth 2
            try:
                for entry in path.iterdir():
                    if entry.is_dir() and not entry.name.startswith("."):
                        if (entry / ".git").is_dir() or self._is_repo_root(entry):
                            repos.append(entry)
            except (PermissionError, OSError):
                pass

        results: list[DiscoveredAgent] = []
        for repo in repos:
            agent = self._scan_single_repo(repo, org_id=org_id)
            if agent:
                results.append(agent)
        return results

    def _is_repo_root(self, p: Path) -> bool:
        indicators = [
            "pyproject.toml",
            "requirements.txt",
            "package.json",
            "Pipfile",
            "agent.json",
            "agent-card.json",
            ".mcp.json",
        ]
        return any((p / ind).is_file() for ind in indicators)

    def _scan_single_repo(self, repo: Path, org_id: str = "default") -> DiscoveredAgent | None:
        frameworks: set[str] = set()
        evidence: list[EvidenceItem] = []
        key_names: set[str] = set()
        repo_name = repo.name

        # 1. Python manifests
        self._inspect_python_manifests(repo, frameworks, evidence, key_names)

        # 2. Node manifests
        self._inspect_node_manifests(repo, frameworks, evidence)

        # 3. Agent cards and well-known configs
        self._inspect_agent_cards(repo, frameworks, evidence)

        # 4. MCP configs in repo
        self._inspect_mcp_configs(repo, frameworks, evidence, key_names)

        # 5. Dockerfiles
        self._inspect_dockerfiles(repo, frameworks, evidence, key_names)

        # Only register an entry if agent-related signals were found
        if not frameworks and not evidence and not key_names:
            return None

        # Sort values
        sorted_frameworks = sorted(list(frameworks))
        sorted_keys = sorted(list(key_names))

        # Stable fingerprint based on host, kind, and path
        stable_key = str(repo.resolve())
        discovery_id = compute_discovery_id(self.host_name, "repo", stable_key)

        return DiscoveredAgent(
            org_id=org_id,
            discovery_id=discovery_id,
            host=self.host_name,
            kind="repo",
            name=repo_name,
            frameworks=sorted_frameworks,
            llm_endpoints=[],
            key_names=sorted_keys,
            evidence=evidence,
            status="shadow",
        )

    def _inspect_python_manifests(
        self,
        repo: Path,
        frameworks: set[str],
        evidence: list[EvidenceItem],
        key_names: set[str],
    ) -> None:
        # Check requirements*.txt
        try:
            for req_file in repo.glob("requirements*.txt"):
                if req_file.is_file():
                    self._parse_requirements_file(repo, req_file, frameworks, evidence)
        except (PermissionError, OSError):
            pass

        # Check pyproject.toml
        pyproject = repo / "pyproject.toml"
        if pyproject.is_file():
            text = safe_read_file(repo, pyproject)
            if text:
                matched = self._find_frameworks_in_text(text)
                if matched:
                    frameworks.update(matched)
                    evidence.append(
                        EvidenceItem(
                            signal="manifest",
                            detail=f"pyproject.toml includes: {', '.join(sorted(matched))}",
                        )
                    )

        # Check Pipfile / Pipfile.lock / poetry.lock
        for lock_name in ("Pipfile", "poetry.lock", "Pipfile.lock"):
            lock_path = repo / lock_name
            if lock_path.is_file():
                text = safe_read_file(repo, lock_path)
                if text:
                    matched = self._find_frameworks_in_text(text)
                    if matched:
                        frameworks.update(matched)
                        evidence.append(
                            EvidenceItem(
                                signal="manifest",
                                detail=f"{lock_name} references: {', '.join(sorted(matched))}",
                            )
                        )

    def _parse_requirements_file(
        self,
        repo: Path,
        req_file: Path,
        frameworks: set[str],
        evidence: list[EvidenceItem],
    ) -> None:
        content = safe_read_file(repo, req_file)
        if not content:
            return
        matched: set[str] = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg_name = re.split(r"[=<>!~;@\s]", line)[0].lower().replace("_", "-")
            for fw in AGENT_FRAMEWORKS:
                fw_norm = fw.lower().replace("_", "-")
                if pkg_name == fw_norm or pkg_name.startswith(f"{fw_norm}-"):
                    matched.add(fw)
        if matched:
            frameworks.update(matched)
            evidence.append(
                EvidenceItem(
                    signal="manifest",
                    detail=f"{req_file.name} specifies: {', '.join(sorted(matched))}",
                )
            )

    def _inspect_node_manifests(
        self,
        repo: Path,
        frameworks: set[str],
        evidence: list[EvidenceItem],
    ) -> None:
        pkg_json = repo / "package.json"
        if pkg_json.is_file():
            data = safe_read_json(repo, pkg_json)
            if isinstance(data, dict):
                deps: dict[str, Any] = {}
                deps.update(data.get("dependencies", {}))
                deps.update(data.get("devDependencies", {}))
                matched: set[str] = set()
                for dep in deps.keys():
                    dep_norm = dep.lower()
                    if "langchain" in dep_norm:
                        matched.add("langchain")
                    if "modelcontextprotocol" in dep_norm or dep_norm == "@modelcontextprotocol/sdk":
                        matched.add("mcp")
                    if "crewai" in dep_norm:
                        matched.add("crewai")
                if matched:
                    frameworks.update(matched)
                    evidence.append(
                        EvidenceItem(
                            signal="manifest",
                            detail=f"package.json declares: {', '.join(sorted(matched))}",
                        )
                    )

    def _inspect_agent_cards(
        self,
        repo: Path,
        frameworks: set[str],
        evidence: list[EvidenceItem],
    ) -> None:
        card_candidates = [
            repo / ".well-known" / "agent.json",
            repo / ".well-known" / "agent-card.json",
            repo / "agent.json",
            repo / "agent-card.json",
        ]
        for candidate in card_candidates:
            if candidate.is_file():
                data = safe_read_json(repo, candidate)
                if isinstance(data, dict):
                    card_name = data.get("name", "Unnamed")
                    evidence.append(
                        EvidenceItem(
                            signal="agent_card",
                            detail=f"Agent card found at {candidate.name}: {card_name}",
                        )
                    )
                    if "skills" in data:
                        frameworks.add("a2a_agent")

    def _inspect_mcp_configs(
        self,
        repo: Path,
        frameworks: set[str],
        evidence: list[EvidenceItem],
        key_names: set[str],
    ) -> None:
        mcp_candidates = [
            repo / ".mcp.json",
            repo / "mcp.json",
            repo / ".vscode" / "mcp.json",
            repo / ".cursor" / "mcp.json",
        ]
        for cand in mcp_candidates:
            if cand.is_file():
                data = safe_read_json(repo, cand)
                if isinstance(data, dict):
                    frameworks.add("mcp")
                    servers = data.get("mcpServers", {})
                    names = list(servers.keys())
                    detail = f"Repo MCP config ({cand.name}) with servers: {', '.join(names[:5])}"
                    evidence.append(EvidenceItem(signal="mcp_config", detail=detail))
                    for srv in servers.values():
                        env_vars = srv.get("env", {})
                        for k in env_vars.keys():
                            if k.upper().endswith("_KEY") or k.upper().endswith("_TOKEN"):
                                key_names.add(k)

    def _inspect_dockerfiles(
        self,
        repo: Path,
        frameworks: set[str],
        evidence: list[EvidenceItem],
        key_names: set[str],
    ) -> None:
        try:
            for item in repo.iterdir():
                if item.is_file() and ("dockerfile" in item.name.lower()):
                    text = safe_read_file(repo, item)
                    if text:
                        matched = self._find_frameworks_in_text(text)
                        if matched:
                            frameworks.update(matched)
                            evidence.append(
                                EvidenceItem(
                                    signal="dockerfile",
                                    detail=f"{item.name} references: {', '.join(sorted(matched))}",
                                )
                            )
                        for key in KEY_PATTERNS:
                            if key in text:
                                key_names.add(key)
        except (PermissionError, OSError):
            pass

    def _find_frameworks_in_text(self, text: str) -> set[str]:
        found: set[str] = set()
        text_lower = text.lower()
        for fw in AGENT_FRAMEWORKS:
            fw_lower = fw.lower()
            if re.search(r"\b" + re.escape(fw_lower) + r"\b", text_lower):
                found.add(fw)
        return found
