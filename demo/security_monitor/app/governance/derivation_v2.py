"""Boundary Derivation v2 (F2).

LLM-driven task boundary derivation with:
1. Strict schema validation against ServiceCatalog (no wildcards, only catalog items).
2. Untrusted pasted content isolation (derive from instructions only).
3. Review-first default (requires_user_review=True).
4. Safe fallback to BoundaryDerivationV1 on any validation/parse failure.
5. Complete audit metadata (provider, model, temperature, prompt_hash, raw_output).
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, Field, ValidationError

from .catalog import ServiceCatalog, BoundaryDerivationV1
from .models import TaskBoundary, EnforcementMode


class DerivedBoundarySchema(BaseModel):
    """Strict schema for LLM boundary derivation output."""
    files_read: list[str] = Field(default_factory=list, description="Explicit workspace files to read (no wildcards)")
    files_write: list[str] = Field(default_factory=list, description="Explicit workspace files to write (no wildcards)")
    tools: list[str] = Field(default_factory=list, description="Authorized tools from catalog")
    network: list[str] = Field(default_factory=list, description="Authorized network host:port from catalog")
    peer_agents: list[str] = Field(default_factory=list, description="Authorized peer agents from catalog")


class PastedContentResult(BaseModel):
    clean_instruction: str
    contains_pasted_content: bool
    pasted_block_chars: int
    flag_reason: str | None = None

    def __iter__(self):
        yield self.contains_pasted_content
        yield self.clean_instruction


class PastedContentDetector:
    """Isolates untrusted pasted text blocks from user instructions."""

    @staticmethod
    def detect_and_isolate(request_text: str) -> PastedContentResult:
        # Common delimiters marking pasted email, document or log content
        delimiters = [
            r'---\s*\n',
            r'```[a-zA-Z]*\n',
            r'(?:email|message|content|text|payload|data):\s*\n',
            r'From:\s+.*?\nTo:\s+.*?\n',
        ]

        text = request_text.strip()
        contains_pasted = False
        flag_reason = None
        pasted_chars = 0
        instruction = text

        for delim in delimiters:
            m = re.search(delim, text, flags=re.IGNORECASE)
            if m:
                contains_pasted = True
                flag_reason = f"Delimiter matched: {delim.strip()}"
                split_idx = m.start()
                instruction = text[:split_idx].strip() + "\n[UNTRUSTED_PASTED_CONTENT_BLOCK_1]"
                pasted_chars = len(text) - split_idx
                break

        # Also check for large blocks without delimiter (e.g. > 300 chars with multiple paragraphs)
        if not contains_pasted and len(text) > 400 and "\n\n" in text:
            parts = text.split("\n\n", 1)
            if len(parts[0]) < 200:
                contains_pasted = True
                flag_reason = "Multi-paragraph structure with large body"
                instruction = parts[0].strip() + "\n[UNTRUSTED_PASTED_CONTENT_BLOCK_1]"
                pasted_chars = len(parts[1])

        if not instruction:
            instruction = text  # Fallback if split left nothing

        return PastedContentResult(
            clean_instruction=instruction,
            contains_pasted_content=contains_pasted,
            pasted_block_chars=pasted_chars,
            flag_reason=flag_reason,
        )


class BoundaryDerivationV2:
    """LLM Boundary Derivation Engine with strict schema validation and fallback."""

    def __init__(
        self,
        catalog: ServiceCatalog | None = None,
        llm_client: Callable[[str], str] | None = None,
        provider: str = "mock",
        model: str = "gpt-4o-mini",
        temperature: float = 0.0,
    ) -> None:
        self.catalog = catalog or ServiceCatalog()
        self.v1_fallback = BoundaryDerivationV1(self.catalog)
        self.llm_client = llm_client
        self.provider = provider
        self.model = model
        self.temperature = temperature

    def build_system_prompt(self) -> str:
        tools_desc = "\n".join(f"- {name}: {item.description}" for name, item in self.catalog.tools.items())
        peer_desc = "\n".join(f"- {name}: {item.description}" for name, item in self.catalog.peer_agents.items())
        net_desc = "\n".join(f"- {name}: {item.description}" for name, item in self.catalog.network_destinations.items())

        return (
            "You are a strict security boundary derivation system for an AI Agent Governance platform.\n"
            "Given a user request, derive the minimal least-privilege boundary contract required.\n"
            "\n"
            "SERVICE CATALOG:\n"
            f"Authorized Tools:\n{tools_desc}\n\n"
            f"Authorized Peer Agents:\n{peer_desc}\n\n"
            f"Authorized Network Destinations (host:port):\n{net_desc}\n\n"
            "FILE CONVENTIONS:\n"
            "- Files to read MUST start with 'input/' or be relative to workspace (e.g. 'input/data.csv').\n"
            "- Files to write MUST start with 'output/' or 'scratch/' (e.g. 'output/summary.txt').\n"
            "- NEVER use wildcards (* or **). List only explicit filenames.\n"
            "\n"
            "OUTPUT FORMAT:\n"
            "You MUST respond ONLY with valid JSON conforming to this schema:\n"
            "{\n"
            '  "files_read": ["input/..."],\n'
            '  "files_write": ["output/..."],\n'
            '  "tools": ["read_file", ...],\n'
            '  "network": ["localhost:8000", ...],\n'
            '  "peer_agents": ["agent_bob", ...]\n'
            "}\n"
        )

    def validate_boundary(self, derived: DerivedBoundarySchema) -> tuple[bool, str | None]:
        """Validates derived boundary against service catalog and strict syntax rules."""
        # 1. No wildcards allowed
        for f in derived.files_read + derived.files_write:
            if "*" in f or "?" in f:
                return False, f"Wildcards are forbidden in file path: '{f}'"

        # 2. Tools must exist in catalog
        for t in derived.tools:
            if not self.catalog.get_tool(t):
                return False, f"Unknown tool '{t}' not in catalog"

        # 3. Network destinations must exist in catalog
        for n in derived.network:
            if not self.catalog.get_network(n):
                return False, f"Unknown network host '{n}' not in catalog"

        # 4. Peer agents must exist in catalog
        for a in derived.peer_agents:
            if not self.catalog.get_peer_agent(a):
                return False, f"Unknown peer agent '{a}' not in catalog"

        # 5. Output files must be inside output/ or scratch/
        for fw in derived.files_write:
            norm = fw.replace("\\", "/").lstrip("/")
            if not (norm.startswith("output/") or norm.startswith("scratch/") or "/" not in norm):
                return False, f"Write file must target output/ or scratch/: '{fw}'"

        return True, None

    def derive(
        self,
        task_id: str,
        request_text: str,
        workspace_root: str,
        enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE,
    ) -> TaskBoundary:
        """Derives a task boundary using the LLM with strict validation and fallback."""
        now_utc = datetime.now(timezone.utc).isoformat()

        # Step 1: Detect and isolate pasted content
        pasted_res = PastedContentDetector.detect_and_isolate(request_text)
        prompt_content = pasted_res.clean_instruction
        prompt_hash = hashlib.sha256(prompt_content.encode("utf-8")).hexdigest()

        raw_output = None
        validation_passed = False
        error_msg = None
        derived_schema: DerivedBoundarySchema | None = None

        # Step 2: Call LLM (if client provided)
        if self.llm_client:
            try:
                system_prompt = self.build_system_prompt()
                full_input = f"{system_prompt}\n\nUSER REQUEST:\n{prompt_content}\n"
                raw_output = self.llm_client(full_input)

                # Extract JSON
                json_str = raw_output
                if "```json" in raw_output:
                    json_str = raw_output.split("```json")[1].split("```")[0].strip()
                elif "```" in raw_output:
                    json_str = raw_output.split("```")[1].split("```")[0].strip()

                parsed = json.loads(json_str)
                derived_schema = DerivedBoundarySchema(**parsed)

                # Validate against catalog and constraints
                val_ok, val_err = self.validate_boundary(derived_schema)
                if val_ok:
                    validation_passed = True
                else:
                    error_msg = val_err
            except (json.JSONDecodeError, ValidationError, Exception) as e:
                error_msg = str(e)
                validation_passed = False

        # Step 3: Use LLM derivation if valid; otherwise fallback to template derivation
        if validation_passed and derived_schema:
            boundary = TaskBoundary(
                task_id=task_id,
                version=1,
                workspace_root=str(Path(workspace_root).resolve()),
                files_read=sorted(list(set(derived_schema.files_read))),
                files_write=sorted(list(set(derived_schema.files_write))),
                network=sorted(list(set(derived_schema.network))),
                tools=sorted(list(set(derived_schema.tools))),
                peer_agents=sorted(list(set(derived_schema.peer_agents))),
                max_duration_sec=3600,
                max_processes=1,
                enforcement_mode=enforcement_mode,
                derived_by="llm_v2",
                prompt_hash=prompt_hash,
                model_name=self.model,
                requires_user_review=True,
                contains_pasted_content=pasted_res.contains_pasted_content,
                metadata={
                    "provider": self.provider,
                    "model": self.model,
                    "temperature": self.temperature,
                    "pasted_content_detected": pasted_res.contains_pasted_content,
                    "pasted_block_chars": pasted_res.pasted_block_chars,
                    "pasted_flag_reason": pasted_res.flag_reason,
                    "raw_output": raw_output,
                    "fallback_used": False,
                    "derived_at": now_utc,
                },
            )
            return boundary

        # Fallback to template derivation v1
        fallback_boundary = self.v1_fallback.derive(
            task_id=task_id,
            request_text=prompt_content,
            workspace_root=workspace_root,
            enforcement_mode=enforcement_mode,
        )
        fallback_boundary.derived_by = "fallback_v1"
        fallback_boundary.prompt_hash = prompt_hash
        fallback_boundary.model_name = self.model
        fallback_boundary.requires_user_review = True
        fallback_boundary.contains_pasted_content = pasted_res.contains_pasted_content
        fallback_boundary.metadata = {
            "provider": self.provider,
            "model": self.model,
            "temperature": self.temperature,
            "fallback_used": True,
            "fallback_reason": error_msg or "No LLM output or validation failure",
            "raw_output": raw_output,
            "pasted_content_detected": pasted_res.contains_pasted_content,
            "pasted_block_chars": pasted_res.pasted_block_chars,
            "derived_at": now_utc,
        }
        return fallback_boundary

    def derive_from_llm_output(
        self,
        prompt: str,
        raw_output: str,
        task_id: str,
        agent_id: str = "agent_worker",
        workspace_root: str = "/workspace",
        provider: str = "mock",
        model: str = "gpt-4o-mini",
        enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE,
    ) -> tuple[TaskBoundary, dict[str, Any]]:
        """Convenience method to parse and evaluate raw LLM string output into a boundary and metadata."""
        orig_client = self.llm_client
        orig_prov = self.provider
        orig_model = self.model
        try:
            self.llm_client = lambda _inp: raw_output
            self.provider = provider
            self.model = model
            b = self.derive(
                task_id=task_id,
                request_text=prompt,
                workspace_root=workspace_root,
                enforcement_mode=enforcement_mode,
            )
            meta = dict(b.metadata)
            meta["prompt_hash"] = b.prompt_hash
            meta["provider"] = provider
            meta["model"] = model
            return b, meta
        finally:
            self.llm_client = orig_client
            self.provider = orig_prov
            self.model = orig_model
