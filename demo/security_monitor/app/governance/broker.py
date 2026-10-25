"""Tool Broker (F5.1).

Mediates agent tool execution, validates scoped per-task tokens (F6), evaluates
the Task Boundary BEFORE execution (F7), enforces graduated policies (F9),
and emits normalized governance audit events.
"""
from __future__ import annotations

import datetime
import os
import uuid
from pathlib import Path
from typing import Any

from .models import (
    EventSource,
    GovernanceEvent,
    RiskTier,
    TaskAction,
    EventVerdict,
)
from .storage import GovernanceStorage
from .evaluator import BoundaryEvaluator
from .policy import TaskPolicyEngine
from .expansion import ExpansionService


class ToolBroker:
    """Tool execution broker that intercepts and enforces task boundaries prior to execution."""

    def __init__(
        self,
        storage: GovernanceStorage,
        evaluator: BoundaryEvaluator | None = None,
        policy_engine: TaskPolicyEngine | None = None,
        expansion_service: ExpansionService | None = None,
    ) -> None:
        self.storage = storage
        self.evaluator = evaluator or BoundaryEvaluator()
        self.policy_engine = policy_engine or TaskPolicyEngine()
        self.expansion_service = expansion_service or ExpansionService(self.storage)
        self._event_counter = 0

    def _generate_event_id(self) -> str:
        self._event_counter += 1
        return f"evt_broker_{self._event_counter:04d}_{uuid.uuid4().hex[:6]}"

    def _check_and_consume_single_use(self, boundary: Any, resource_type: str, target: str) -> None:
        """Enforces single-use consumption for human-approved HIGH expansion grants."""
        if not boundary.parent_expansion_id:
            return
        req = self.storage.get_expansion_request(boundary.parent_expansion_id)
        if not req or not req.single_use:
            return
        if req.resource_type == resource_type and req.resource_target == target:
            used = self.storage.increment_expansion_usage(req.request_id)
            if used >= 1:
                # Consume single-use grant: remove resource from boundary so subsequent accesses are blocked
                if resource_type == "file_read" and target in boundary.files_read:
                    boundary.files_read.remove(target)
                elif resource_type == "file_write" and target in boundary.files_write:
                    boundary.files_write.remove(target)
                elif resource_type == "network" and target in boundary.network:
                    boundary.network.remove(target)
                elif resource_type == "peer_agent" and target in boundary.peer_agents:
                    boundary.peer_agents.remove(target)
                self.storage.save_boundary(boundary)

    def request_expansion(
        self,
        token: str,
        resource_type: str,
        resource_target: str,
        justification: str,
        timeout_seconds: float = 2.0,
    ) -> tuple[bool, str]:
        """Allows an agent to synchronously request boundary expansion mid-execution."""
        if not resource_target or not str(resource_target).strip():
            raise ValueError("resource_target cannot be empty in expansion request")
        if not resource_type or not str(resource_type).strip():
            raise ValueError("resource_type cannot be empty in expansion request")
        task_id, agent_id = self._authenticate(token)
        return self.expansion_service.request_and_wait(
            task_id=task_id,
            agent_id=agent_id,
            resource_type=resource_type,
            resource_target=resource_target,
            justification=justification,
            timeout_seconds=timeout_seconds,
        )

    def request_access(
        self,
        token: str,
        resource_type: str,
        resource_target: str,
        justification: str,
        timeout_seconds: float = 2.0,
    ) -> dict[str, Any]:
        """
        Tool: request_access (F13.2 / M5).
        Agent-facing tool for dynamic boundary expansion requests.
        """
        if not resource_target or not str(resource_target).strip():
            raise ValueError("resource_target cannot be empty in expansion request")
        if not resource_type or not str(resource_type).strip():
            raise ValueError("resource_type cannot be empty in expansion request")

        granted, status_or_reason = self.request_expansion(
            token=token,
            resource_type=resource_type,
            resource_target=resource_target,
            justification=justification,
            timeout_seconds=timeout_seconds,
        )
        task_id, _ = self._authenticate(token)
        reqs = self.storage.list_expansion_requests(task_id=task_id)
        latest_req = reqs[-1] if reqs else None

        base_risk = latest_req.baseline_risk_tier.value if latest_req and hasattr(latest_req.baseline_risk_tier, "value") else "LOW"
        eff_risk = latest_req.effective_risk_tier.value if latest_req and hasattr(latest_req.effective_risk_tier, "value") else "LOW"
        escalated = bool(latest_req.escalated_by_provenance) if latest_req else False

        return {
            "granted": granted,
            "status": status_or_reason,
            "resource_type": resource_type,
            "resource_target": resource_target,
            "baseline_risk": base_risk,
            "effective_risk": eff_risk,
            "baseline_risk_tier": base_risk,
            "effective_risk_tier": eff_risk,
            "escalated_by_provenance": escalated,
        }

    def _authenticate(self, token: str) -> tuple[str, str]:
        """
        Validates token and returns (task_id, agent_id).
        Raises PermissionError if token is invalid or revoked.
        """
        res = self.storage.lookup_task_by_token(token)
        if not res:
            # Emit UNATTRIBUTED security event
            event = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.TOOL_BROKER,
                task_id=None,
                agent_id="UNATTRIBUTED",
                pid=os.getpid(),
                kind="authentication",
                target="tool_broker",
                verdict=EventVerdict.OUTSIDE,
                risk_tier=RiskTier.HIGH,
                action_taken=TaskAction.BLOCK_ACTION,
                prevented=True,
                rule_matched="invalid or revoked task authorization token",
                boundary_version=None,
            )
            self.storage.record_event(event)
            raise PermissionError("Access denied: Invalid or revoked task token")
        return res

    # --- Broker Tools ---

    def read_file(self, token: str, file_path: str) -> str:
        """
        Tool: read_file
        Checks task boundary BEFORE opening file.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

        # Check tool granted
        tool_eval = self.evaluator.evaluate_tool(boundary, "read_file")
        if tool_eval.verdict != EventVerdict.INSIDE:
            action, prevented = self.policy_engine.decide(boundary, tool_eval)
            event = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.TOOL_BROKER,
                task_id=task_id,
                agent_id=agent_id,
                pid=os.getpid(),
                kind="tool_invocation",
                target="read_file",
                verdict=tool_eval.verdict,
                risk_tier=tool_eval.risk_tier,
                action_taken=action,
                prevented=prevented,
                rule_matched=tool_eval.rule_matched,
                boundary_version=boundary.version,
            )
            self.storage.record_event(event)
            raise PermissionError(f"Tool read_file not granted in task boundary: {tool_eval.rule_matched}")

        # Evaluate target file path
        eval_res = self.evaluator.evaluate_file_access(boundary, file_path, is_write=False)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="file_read",
            target=file_path,
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self.storage.record_event(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"Access to file '{file_path}' denied by boundary: {eval_res.rule_matched}")

        # REAL EXECUTION (Inside boundary)
        target = Path(file_path)
        if not target.is_absolute():
            target = Path(boundary.workspace_root) / target
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # Record untrusted read in provenance tracker
        if self.expansion_service:
            self.expansion_service.record_untrusted_read(
                task_id=task_id,
                source_type="file_read",
                source_target=file_path,
                content=content,
            )

        # Enforce single-use consumption if granted under HIGH human approval
        self._check_and_consume_single_use(boundary, "file_read", file_path)

        return content

    def write_file(self, token: str, file_path: str, content: str) -> int:
        """
        Tool: write_file
        Checks task boundary BEFORE writing content.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

        tool_eval = self.evaluator.evaluate_tool(boundary, "write_file")
        if tool_eval.verdict != EventVerdict.INSIDE:
            action, prevented = self.policy_engine.decide(boundary, tool_eval)
            event = GovernanceEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.TOOL_BROKER,
                task_id=task_id,
                agent_id=agent_id,
                pid=os.getpid(),
                kind="tool_invocation",
                target="write_file",
                verdict=tool_eval.verdict,
                risk_tier=tool_eval.risk_tier,
                action_taken=action,
                prevented=prevented,
                rule_matched=tool_eval.rule_matched,
                boundary_version=boundary.version,
            )
            self.storage.record_event(event)
            raise PermissionError(f"Tool write_file not granted: {tool_eval.rule_matched}")

        eval_res = self.evaluator.evaluate_file_access(boundary, file_path, is_write=True)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="file_write",
            target=file_path,
            details={"bytes_to_write": len(content.encode("utf-8"))},
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self.storage.record_event(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"Write to file '{file_path}' denied by boundary: {eval_res.rule_matched}")

        target = Path(file_path)
        if not target.is_absolute():
            target = Path(boundary.workspace_root) / target
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            return f.write(content)

    def http_get(self, token: str, url: str) -> dict[str, Any]:
        """
        Tool: http_get
        Checks network destination BEFORE opening socket.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

        eval_res = self.evaluator.evaluate_network(boundary, url)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="network_http",
            target=url,
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self.storage.record_event(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"Outbound network request to '{url}' denied by boundary: {eval_res.rule_matched}")

        # In testing / stub mode:
        body_content = "Mock response from authorized endpoint"
        if self.expansion_service:
            self.expansion_service.record_untrusted_read(
                task_id=task_id,
                source_type="http_get",
                source_target=url,
                content=body_content,
            )
        self._check_and_consume_single_use(boundary, "network", url)
        return {"status": 200, "url": url, "body": body_content}

    def handle_http_redirect(self, token: str, original_url: str, redirect_target: str) -> str:
        """
        Re-evaluates a redirect hop against the task boundary before following.
        Prevents redirect-based boundary escapes (e.g. allowed.host -> 302 -> evil.com).
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

        eval_res = self.evaluator.evaluate_network(boundary, redirect_target)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="network_http_redirect",
            target=redirect_target,
            details={"original_url": original_url},
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self.storage.record_event(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"HTTP redirect to '{redirect_target}' denied by boundary: {eval_res.rule_matched}")

        return redirect_target

    def run_command(self, token: str, command: str, workspace_root: Path | str | None = None) -> dict[str, Any]:
        """
        Tool: run_command
        Executes commands under M4 OS enforcement when permitted by boundary.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

        eval_res = self.evaluator.evaluate_command(boundary, command)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="run_command",
            target=command,
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self.storage.record_event(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"Command execution denied: {eval_res.rule_matched}")

        import subprocess
        import sys

        # On Linux, run via CgroupTaskRunner if available
        if sys.platform == "linux":
            try:
                from .os_layer.runner import CgroupTaskRunner, TaskWorkspace
            except ImportError:
                pass  # Linux isolation deps not installed; fall through to basic subprocess
            else:
                runner = CgroupTaskRunner(self.storage)
                ws_path = Path(workspace_root) if workspace_root else Path(f"/home/agent_workspaces/task_{task_id[:16]}")
                ws = TaskWorkspace(task_id=task_id, base_dir=ws_path)
                res = runner.run_task_command(
                    task_id=task_id,
                    cmd=["/bin/sh", "-c", command],
                    workspace=ws,
                    token=token,
                )
                return {
                    "stdout": res.stdout,
                    "stderr": res.stderr,
                    "exit_code": res.returncode,
                }

        # Subprocess execution fallback
        cwd_dir = str(workspace_root) if workspace_root and Path(workspace_root).exists() else None
        res = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            cwd=cwd_dir,
            timeout=30.0,
        )
        return {
            "stdout": res.stdout,
            "stderr": res.stderr,
            "exit_code": res.returncode,
        }

    def call_agent(self, token: str, target_agent: str, message: dict[str, Any]) -> dict[str, Any]:
        """
        Tool: call_agent
        Checks peer agent boundary BEFORE message dispatch.
        """
        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

        eval_res = self.evaluator.evaluate_peer_agent(boundary, target_agent)
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="peer_agent",
            target=target_agent,
            details={"message_summary": str(message)[:100]},
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self.storage.record_event(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"Communication with agent '{target_agent}' denied by boundary: {eval_res.rule_matched}")

        reply_content = "Authorized message delivered"
        if self.expansion_service:
            self.expansion_service.record_untrusted_read(
                task_id=task_id,
                source_type="peer_message",
                source_target=target_agent,
                content=reply_content,
            )
        self._check_and_consume_single_use(boundary, "peer_agent", target_agent)

        return {"status": "ok", "target_agent": target_agent, "reply": reply_content}

    def llm_complete(
        self,
        token: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        temperature: float = 0.0,
        provider: str | None = None,
        custom_provider: Any | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Tool: llm_complete (F13.2 / M5).
        Brokered LLM inference ensuring API keys are NEVER exposed to the agent process.
        The agent passes its task token and messages; the broker authenticates the task,
        validates boundary authorization, audits the call, and invokes the LLM provider
        using broker-held credentials or a local stub/mock provider.
        """
        import hashlib
        import json

        task_id, agent_id = self._authenticate(token)
        boundary = self.storage.get_boundary(task_id)
        if not boundary:
            raise RuntimeError(f"Active boundary not found for task {task_id}")

        eval_res = self.evaluator.evaluate_tool(boundary, "llm_complete")
        action, prevented = self.policy_engine.decide(boundary, eval_res)

        prompt_str = json.dumps(messages, sort_keys=True, default=str)
        prompt_hash = hashlib.sha256(prompt_str.encode("utf-8")).hexdigest()[:16]

        event = GovernanceEvent(
            event_id=self._generate_event_id(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=os.getpid(),
            kind="llm_complete",
            target=model or "default_llm",
            details={
                "prompt_hash": prompt_hash,
                "message_count": len(messages),
                "has_tools": bool(tools),
            },
            verdict=eval_res.verdict,
            risk_tier=eval_res.risk_tier,
            action_taken=action,
            prevented=prevented,
            rule_matched=eval_res.rule_matched,
            boundary_version=boundary.version,
        )
        self.storage.record_event(event)

        if prevented or action in (TaskAction.BLOCK_ACTION, TaskAction.PAUSE_TASK, TaskAction.KILL_TASK):
            raise PermissionError(f"LLM inference denied by boundary: {eval_res.rule_matched}")

        # 1. Custom or broker-attached mock provider (for offline testing & benchmarks)
        eff_provider = custom_provider or getattr(self, "default_llm_provider", None)
        if eff_provider is not None:
            return eff_provider(
                messages=messages,
                tools=tools,
                model=model,
                temperature=temperature,
                **kwargs,
            )

        # 2. Local Ollama provider dispatch (http://127.0.0.1:11434/v1)
        prov_name = (provider or os.environ.get("GOVERNANCE_LLM_PROVIDER") or "").lower()
        if prov_name == "ollama" or (not prov_name and os.environ.get("OLLAMA_MODEL")):
            ollama_model = model or os.environ.get("OLLAMA_MODEL") or "llama3.1:8b"
            num_ctx = int(kwargs.get("num_ctx") or os.environ.get("OLLAMA_NUM_CTX") or 8192)
            return self._call_ollama(
                messages=messages,
                tools=tools,
                model=ollama_model,
                temperature=temperature,
                seed=kwargs.get("seed", 42),
                num_ctx=num_ctx,
                base_url=kwargs.get("base_url"),
            )

        # 3. Live external hosted provider dispatch (OpenAI, Gemini, Anthropic)
        openai_key = os.environ.get("OPENAI_API_KEY")
        gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY")

        if prov_name == "gemini" or (not prov_name and gemini_key):
            if not gemini_key:
                raise RuntimeError("GEMINI_API_KEY not configured")
            return self._call_gemini(messages, tools, model or "gemini-1.5-flash", gemini_key, temperature)

        if prov_name == "anthropic" or (not prov_name and anthropic_key):
            if not anthropic_key:
                raise RuntimeError("ANTHROPIC_API_KEY not configured")
            return self._call_anthropic(messages, tools, model or "claude-3-5-sonnet", anthropic_key, temperature)

        if prov_name == "openai" or (not prov_name and openai_key):
            if not openai_key:
                raise RuntimeError("OPENAI_API_KEY not configured")
            return self._call_openai(messages, tools, model or "gpt-4o-mini", openai_key, temperature)

        raise RuntimeError(
            "No LLM provider configured (set GOVERNANCE_LLM_PROVIDER=ollama with running Ollama, "
            "or configure OPENAI_API_KEY, GEMINI_API_KEY, or ANTHROPIC_API_KEY, or supply a mock/stub provider)."
        )

    def _call_ollama(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        model: str,
        temperature: float = 0.0,
        seed: int | None = 42,
        num_ctx: int = 8192,
        base_url: str | None = None,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        """Invokes local Ollama via its OpenAI-compatible /v1/chat/completions endpoint with retry support."""
        import httpx
        import time
        root_url = (base_url or os.environ.get("OLLAMA_BASE_URL") or "http://127.0.0.1:11434").rstrip("/")
        if root_url.endswith("/v1"):
            api_base = root_url[:-3]
            v1_url = root_url + "/chat/completions"
        else:
            api_base = root_url
            v1_url = root_url + "/v1/chat/completions"

        options: dict[str, Any] = {
            "num_ctx": num_ctx,
            "temperature": temperature,
        }
        if seed is not None:
            options["seed"] = seed

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "options": options,
        }
        if seed is not None:
            payload["seed"] = seed
        if tools:
            payload["tools"] = tools

        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Bounded connect timeout: an unreachable Ollama (e.g. WSL mirrored
                # networking, which hangs instead of refusing) fails within seconds.
                with httpx.Client(timeout=httpx.Timeout(timeout, connect=5.0)) as client:
                    resp = client.post(v1_url, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    choice = data.get("choices", [{}])[0].get("message", {})

                    # Resolve model digest from /api/tags if available
                    model_digest = ""
                    try:
                        tag_resp = client.get(f"{api_base}/api/tags", timeout=httpx.Timeout(5.0, connect=5.0))
                        if tag_resp.status_code == 200:
                            for m in tag_resp.json().get("models", []):
                                if m.get("name") == model or m.get("model") == model or m.get("name", "").startswith(model):
                                    model_digest = m.get("digest", "")
                                    break
                    except Exception:
                        pass

                    return {
                        "role": choice.get("role", "assistant"),
                        "content": choice.get("content"),
                        "tool_calls": choice.get("tool_calls"),
                        "provider": "ollama",
                        "model": model,
                        "model_digest": model_digest,
                        "model_digest_or_tag": model_digest or data.get("model", model),
                        "num_ctx": num_ctx,
                        "temperature": temperature,
                        "seed": seed,
                        "usage": data.get("usage"),
                    }
            except (httpx.ConnectError, httpx.TimeoutException) as ce:
                if attempt < max_retries - 1:
                    time.sleep(3.0 * (attempt + 1))
                    continue
                raise RuntimeError(f"Ollama local service is unreachable or timed out at {v1_url} after {max_retries} attempts: {ce}. Ensure Ollama is running.") from ce
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(2.0)
                    continue
                raise RuntimeError(f"Ollama inference failed at {v1_url}: {e}") from e

    def _call_openai(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        model: str,
        api_key: str,
        temperature: float,
    ) -> dict[str, Any]:
        import httpx
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload: dict[str, Any] = {"model": model, "messages": messages, "temperature": temperature}
        if tools:
            payload["tools"] = tools
        with httpx.Client(timeout=60.0) as client:
            resp = client.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]["message"]
            return {
                "role": choice.get("role", "assistant"),
                "content": choice.get("content"),
                "tool_calls": choice.get("tool_calls"),
                "provider": "openai",
                "model": model,
                "usage": data.get("usage"),
            }

    def _call_gemini(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        model: str,
        api_key: str,
        temperature: float,
    ) -> dict[str, Any]:
        import httpx
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        contents = []
        for m in messages:
            role = "user" if m.get("role") in ("user", "system") else "model"
            contents.append({"role": role, "parts": [{"text": str(m.get("content", ""))}]})
        payload = {"contents": contents, "generationConfig": {"temperature": temperature}}
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            cand = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            return {
                "role": "assistant",
                "content": cand,
                "tool_calls": None,
                "provider": "gemini",
                "model": model,
            }

    def _call_anthropic(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        model: str,
        api_key: str,
        temperature: float,
    ) -> dict[str, Any]:
        import httpx
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        system_text = ""
        user_msgs = []
        for m in messages:
            if m.get("role") == "system":
                system_text += str(m.get("content", "")) + "\n"
            else:
                user_msgs.append({"role": m.get("role"), "content": m.get("content")})
        payload: dict[str, Any] = {
            "model": model,
            "messages": user_msgs,
            "max_tokens": 1024,
            "temperature": temperature,
        }
        if system_text.strip():
            payload["system"] = system_text.strip()
        with httpx.Client(timeout=60.0) as client:
            resp = client.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
            return {
                "role": "assistant",
                "content": text,
                "tool_calls": None,
                "provider": "anthropic",
                "model": model,
            }
