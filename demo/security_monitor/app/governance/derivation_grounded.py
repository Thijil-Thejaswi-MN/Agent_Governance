"""Grounded LLM boundary derivation (roadmap item 1b): the model proposes, rules dispose.

The template derivation (catalog.BoundaryDerivationV1_1) only understands file names written
in the request. For a vague request ("summarise last quarter's sales") it falls back to
input/*, every input file. A model can map the description to the right file, but a model
can also invent paths, reach outside the workspace, or add a website nobody asked for.

So the model's output is never used directly. Every entry it proposes is checked by
deterministic rules and labelled with where it came from:

- named:    the request itself names it (exact path or file name).
- inferred: not named, but it is a file that exists in the task's inputs (reads), or a new
            file under output/ (writes). Inferred reads are kept for a person to review, or
            dropped in strict mode (no person present, e.g. an unattended run).
- dropped:  anything else, with a reason: outside the workspace, a reserved folder, a
            wildcard, a file that does not exist, a host or agent the request never names
            or the catalog does not list.

If the model's reply cannot be parsed, the template derivation is used instead (and the
boundary says so). The launcher compiles the result through the one resolved boundary, so
the broker and the kernel still enforce the same list.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

from .catalog import BoundaryDerivationV1_1, ServiceCatalog
from .derivation_v2 import PastedContentDetector
from .models import EnforcementMode, TaskBoundary

RESERVED_TOP = ("tmp", "runtime", "granted", "staged", "broker.sock")
WILDCARD = re.compile(r"[*?\[\]]")

SYSTEM_PROMPT = (
    "You decide the least access an AI agent needs to do one task. The agent works in a task folder.\n"
    "Files the agent may read are listed under AVAILABLE INPUT FILES. New files it writes go under output/.\n"
    "Pick only the input files the task actually needs, and only the output files it should create.\n"
    "Never invent a file. Never use wildcards. Never name paths outside the task folder.\n"
    "Only add a network host or a peer agent if the request explicitly names it.\n"
    "Reply with JSON only, exactly this shape:\n"
    '{"files_read": ["input/..."], "files_write": ["output/..."], "network": [], "peer_agents": []}\n'
)


def _norm(path: str) -> str:
    p = str(path or "").strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _bad_path(p: str) -> str | None:
    """Why this path can never be granted, or None."""
    if not p:
        return "empty"
    if p.startswith("/") or p.startswith("~") or re.match(r"^[A-Za-z]:", p):
        return "outside_workspace"
    parts = p.split("/")
    if any(x in ("..", ".", "") for x in parts):
        return "outside_workspace"
    if WILDCARD.search(p):
        return "wildcard"
    if parts[0] in RESERVED_TOP:
        return "reserved_folder"
    return None


def _named_in(request: str, path: str) -> bool:
    """Does the request name this file (its path, or its file name as a whole word)?"""
    low = request.lower()
    p = path.lower()
    if p in low:
        return True
    base = Path(p).name
    return bool(base) and re.search(rf"(?<![\w./-]){re.escape(base)}(?![\w-])", low) is not None


def parse_model_reply(raw: str) -> dict[str, list[str]]:
    """The JSON object in a model reply (fenced or bare). Raises ValueError when there is none."""
    text = raw or ""
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    blob = m.group(1) if m else None
    if blob is None:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise ValueError("no JSON object in the model reply")
        blob = text[start:end + 1]
    data = json.loads(blob)
    if not isinstance(data, dict):
        raise ValueError("the model reply is not a JSON object")
    out: dict[str, list[str]] = {}
    for key in ("files_read", "files_write", "network", "peer_agents"):
        val = data.get(key, [])
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise ValueError(f"'{key}' must be a list of strings")
        out[key] = val
    return out


def ground(
    proposal: dict[str, list[str]],
    request: str,
    available_inputs: list[str],
    catalog: ServiceCatalog,
    output_targets: list[str] | None = None,
    keep_inferred_reads: bool = True,
) -> dict[str, Any]:
    """Applies the rules to a model proposal. Returns the kept lists and a per-entry account."""
    inputs = {_norm(p) for p in available_inputs}
    inputs_by_name: dict[str, list[str]] = {}
    for p in inputs:
        inputs_by_name.setdefault(Path(p).name.lower(), []).append(p)
    named: list[str] = []
    inferred: list[str] = []
    dropped: list[dict[str, str]] = []
    files_read: list[str] = []
    files_write: list[str] = []

    for raw in proposal.get("files_read", []):
        p = _norm(raw)
        if "/" not in p and p.lower() in inputs_by_name and len(inputs_by_name[p.lower()]) == 1:
            p = inputs_by_name[p.lower()][0]  # a bare name of exactly one input file
        why = _bad_path(p)
        if why:
            dropped.append({"field": "files_read", "entry": raw, "reason": why})
            continue
        if inputs and p not in inputs:
            dropped.append({"field": "files_read", "entry": raw, "reason": "not_an_input_file"})
            continue
        if _named_in(request, p):
            named.append(p)
        elif inputs and keep_inferred_reads:
            inferred.append(p)
        else:
            dropped.append({"field": "files_read", "entry": raw,
                            "reason": "not_named_in_request" if not keep_inferred_reads else "not_named_no_inputs_listed"})
            continue
        files_read.append(p)

    for raw in list(proposal.get("files_write", [])) + list(output_targets or []):
        p = _norm(raw)
        if p and "/" not in p:
            p = f"output/{p}"
        why = _bad_path(p)
        if why:
            dropped.append({"field": "files_write", "entry": raw, "reason": why})
            continue
        if not p.startswith("output/"):
            dropped.append({"field": "files_write", "entry": raw, "reason": "write_outside_output"})
            continue
        if raw in (output_targets or []) or _named_in(request, p):
            named.append(p)
        else:
            inferred.append(p)
        files_write.append(p)

    network: list[str] = []
    for raw in proposal.get("network", []):
        host = str(raw).strip()
        if not catalog.get_network(host):
            dropped.append({"field": "network", "entry": raw, "reason": "not_in_catalog"})
        elif host.split(":")[0].lower() not in request.lower():
            dropped.append({"field": "network", "entry": raw, "reason": "not_named_in_request"})
        else:
            named.append(host)
            network.append(host)

    peers: list[str] = []
    for raw in proposal.get("peer_agents", []):
        agent = str(raw).strip()
        if not catalog.get_peer_agent(agent):
            dropped.append({"field": "peer_agents", "entry": raw, "reason": "not_in_catalog"})
        elif agent.lower() not in request.lower():
            dropped.append({"field": "peer_agents", "entry": raw, "reason": "not_named_in_request"})
        else:
            named.append(agent)
            peers.append(agent)

    return {
        "files_read": sorted(set(files_read)),
        "files_write": sorted(set(files_write)),
        "network": sorted(set(network)),
        "peer_agents": sorted(set(peers)),
        "named": sorted(set(named)),
        "inferred": sorted(set(inferred)),
        "dropped": dropped,
    }


class GroundedLLMDerivation:
    """Drop-in for TaskIntakeService(derivation=...): the model proposes, `ground` disposes."""

    def __init__(
        self,
        llm_client: Callable[[str], str] | None,
        available_inputs: list[str] | None = None,
        catalog: ServiceCatalog | None = None,
        model: str = "unknown",
        keep_inferred_reads: bool = True,
    ) -> None:
        self.llm_client = llm_client
        self.available_inputs = list(available_inputs or [])
        self.catalog = catalog or ServiceCatalog()
        self.model = model
        self.keep_inferred_reads = keep_inferred_reads
        self.template = BoundaryDerivationV1_1(self.catalog)

    def build_prompt(self, instruction: str) -> str:
        listing = "\n".join(f"- {p}" for p in sorted(self.available_inputs)) or "- (none listed)"
        return f"{SYSTEM_PROMPT}\nAVAILABLE INPUT FILES:\n{listing}\n\nREQUEST:\n{instruction}\n"

    def derive(
        self,
        task_id: str,
        request_text: str,
        workspace_root: str,
        enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE,
        output_targets: list[str] | None = None,
        explicit_files_read: list[str] | None = None,
    ) -> TaskBoundary:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        pasted = PastedContentDetector.detect_and_isolate(request_text)
        instruction = pasted.clean_instruction  # pasted text never decides access
        template = self.template.derive(task_id=task_id, request_text=request_text, workspace_root=workspace_root,
                                        enforcement_mode=enforcement_mode, output_targets=output_targets,
                                        explicit_files_read=explicit_files_read)
        meta: dict[str, Any] = {
            "deriver": "grounded_llm_v1",
            "model": self.model,
            "available_inputs": sorted(self.available_inputs),
            "keep_inferred_reads": self.keep_inferred_reads,
            "pasted_content_detected": pasted.contains_pasted_content,
            "derived_at": now,
        }
        raw = None
        try:
            if self.llm_client is None:
                raise ValueError("no model configured")
            raw = self.llm_client(self.build_prompt(instruction))
            proposal = parse_model_reply(raw)
        except Exception as exc:  # any model failure: the template boundary, marked as such
            template.metadata.update(meta)
            template.metadata.update({"fallback_used": True, "fallback_reason": str(exc)[:300],
                                      "raw_output_sha256": hashlib.sha256((raw or "").encode()).hexdigest() if raw else None})
            template.derived_by = "grounded_llm_fallback_template_v1_1"
            template.requires_user_review = True
            return template

        g = ground(proposal, instruction, self.available_inputs, self.catalog, output_targets, self.keep_inferred_reads)
        files_read = list(explicit_files_read) if explicit_files_read is not None else g["files_read"]
        boundary = template.model_copy(deep=True)
        boundary.files_read = files_read
        boundary.files_write = g["files_write"] or list(template.files_write)
        boundary.network = g["network"]
        boundary.peer_agents = g["peer_agents"]
        # Tools stay as the template and the requester declared them; the agent's own tool limit applies on top.
        boundary.derived_by = "grounded_llm_v1"
        boundary.model_name = self.model
        boundary.prompt_hash = hashlib.sha256(instruction.encode("utf-8")).hexdigest()
        boundary.requires_user_review = bool(g["inferred"]) or pasted.contains_pasted_content
        boundary.contains_pasted_content = pasted.contains_pasted_content
        meta.update({
            "fallback_used": False,
            "named": g["named"],
            "inferred": g["inferred"],
            "dropped": g["dropped"],
            "template_files_read": list(template.files_read),
            "raw_output_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        })
        boundary.metadata.update(meta)
        return boundary


def ollama_client(model: str, base_url: str | None = None, timeout_s: float = 120.0,
                  seed: int = 42) -> Callable[[str], str]:
    """A deterministic local Ollama completion (temperature 0, JSON output) for derivation.
    Called by the control plane before the sandbox starts; the agent never sees it."""
    import os
    import urllib.request

    root = (base_url or os.environ.get("OLLAMA_BASE_URL") or "http://127.0.0.1:11434").rstrip("/")
    if root.endswith("/v1"):
        root = root[:-3]

    def call(prompt: str) -> str:
        body = json.dumps({"model": model, "prompt": prompt, "stream": False, "format": "json",
                           "options": {"temperature": 0, "seed": seed, "num_ctx": 8192}}).encode()
        req = urllib.request.Request(f"{root}/api/generate", data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return json.loads(resp.read().decode("utf-8")).get("response", "")

    return call
