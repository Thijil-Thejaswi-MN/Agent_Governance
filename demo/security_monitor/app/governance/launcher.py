"""Task launcher: OS identity + sandbox before the agent acts (M6.1).

    user prompt -> intake (task + boundary) -> workspace -> cgroup scope
    -> per-task broker socket + egress proxy
    -> sensor -> seccomp -> Landlock -> agent shim (LLMAgent)
    -> correlator -> evaluator -> graduated response -> Task Receipt

One task = one systemd user scope. The task <-> cgroup mapping is read back
from /proc/<pid>/cgroup of the launched process. The sensor holds the agent at
a gate until the mapping is recorded; the broker socket refuses calls until the
enforcer's kernel-sourced isolation status has been checked ("armed").

Fail-closed and freeze: if the sensor exits early, the isolation level is below
what ENFORCE requires, the broker socket dies, or an OUTSIDE OS access succeeds
under ENFORCE, the task cgroup is frozen, the reason recorded, and the task is
killed after `freeze_timeout_s` (in experiments nobody is there to resume).

CLI:
    python -m demo.security_monitor.app.governance.launcher run --task-file task.json
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import json
import os
import select
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .pathnorm import strip_dot_slash
from .broker import ToolBroker
from .broker_rpc import BrokerRPCServer
from .catalog import BoundaryDerivationV1_1
from .derivation_grounded import GroundedLLMDerivation, ollama_client
from .correlator import OSEventCorrelator
from .expansion import ExpansionService
from .intake import TaskIntakeService
from .models import EnforcementMode, ExpansionStatus, TaskLifecycle
from .os_layer import cgroup_ctl
from .os_layer.sandbox_spec import (
    BROKER_SOCKET_NAME,
    SYSTEM_RX_PATHS,
    compile_landlock_rules,
    compile_landlock_rules_resolved,
    compile_landlock_rules_workspace_sandbox,
    write_rules_file,
)
from .proxy import EgressProxyServer
from .receipt import build_receipt, verify_chain
from .resolved_boundary import ResolvedBoundaryEvaluator
from .llm_providers import HOSTED_PROVIDERS
from .policy_sim import receipt_policy_section
from .staged_writes import land_snapshot, normalize_write_target, snapshot_staged
from .storage import GovernanceStorage
from .os_layer.ebpf_shadow import is_ebpf_shadow_enabled, EBPFShadowSession, EBPFShadowManager

HERE = Path(__file__).resolve().parent
OS_LAYER = HERE / "os_layer"
SENSOR_BIN = OS_LAYER / "sensor"
SECCOMP_BIN = OS_LAYER / "seccomp_filter"
ENFORCER_BIN = OS_LAYER / "landlock_enforcer"
EVAL_WORLD_PY = HERE / "eval_world.py"
RUNTIME_FILES = ("agent_shim.py", "llm_agent.py")
REPO_ROOT = HERE.parents[3]


BOUNDARY_MODELS = ("v1", "v1.1")


def default_workspace_base() -> Path:
    return Path(os.environ.get("HOME", "/tmp")) / "agent_workspaces"


# ---------------------------------------------------------------------------
# Task specification
# ---------------------------------------------------------------------------

@dataclass
class TaskSpec:
    prompt: str
    task_id: str | None = None
    requester: str = "local_user"
    agent_id: str = "m6_agent"
    inputs: dict[str, str] = field(default_factory=dict)        # workspace-relative path -> text
    output_targets: list[str] = field(default_factory=list)
    files_read: list[str] | None = None
    declared_tools: list[str] = field(default_factory=lambda: ["run_command"])
    enforcement_mode: str = "ENFORCE"
    llm: dict[str, Any] = field(default_factory=lambda: {"provider": "ollama", "model": "llama3.1:8b"})
    system_prompt: str | None = None
    max_iterations: int = 10
    timeout_s: float = 900.0
    command_timeout_s: float = 60.0
    freeze_timeout_s: float = 5.0
    approval_policy: str = "deny"                                # "deny" | "oracle" | "operator"
    approval_timeout_s: float = 120.0
    oracle_allowed: list[str] = field(default_factory=list)
    condition: str | None = None
    tools_schema: list[dict[str, Any]] | None = None
    # The agent's own tool limit (from the agent list). None: no per-agent limit.
    agent_tools: list[str] | None = None
    decoys: list[dict[str, Any]] = field(default_factory=list)
    canary: str = ""
    use_eval_world: bool = False
    owner: str | None = None
    team: str | None = None
    network: list[str] = field(default_factory=list)
    # "v1": the frozen M6 path (BoundaryDerivationV1, BoundaryEvaluator, compile_landlock_rules),
    # kept as the default for the evaluation harness. "v1.1": the M7 path (BoundaryDerivationV1_1;
    # broker and Landlock both compiled from resolve_boundary). Selected by the Run page and the CLI.
    boundary_model: str = "v1"
    # How the boundary is derived on the v1.1 path. "template": the file names written in the
    # request (BoundaryDerivationV1_1). "llm": a model proposes the files from the request and the
    # task's input list, and deterministic rules keep only what is grounded
    # (derivation_grounded.py); on any model failure the template is used and the boundary says so.
    derivation: str = "template"
    derivation_model: str | None = None
    # Strict: inferred (not named) reads are dropped, for runs with no person to review them.
    derivation_strict: bool = False
    # A boundary the requester checked on the Run page (run_manager.take_file_review): the model's
    # grounded choice, minus any file they unticked. Applied as derived, with its account.
    reviewed_boundary: dict[str, Any] | None = None

    @classmethod
    def from_file(cls, path: str | Path) -> "TaskSpec":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"unknown task-file keys: {sorted(unknown)}")
        return cls(**data)


class ScriptedLLMProvider:
    """MOCK LLM for tests and attribution checks (labelled 'scripted_mock' in receipts).

    Each call returns the next scripted step: {"tool": name, "args": {...}} becomes
    a single tool call; {"final": text} ends the run.
    """

    label = "scripted_mock"

    def __init__(self, steps: list[dict[str, Any]]) -> None:
        self.steps = list(steps)
        self.i = 0

    def __call__(self, messages: list[dict[str, Any]], tools: Any = None, model: Any = None, **_: Any) -> dict[str, Any]:
        if self.i >= len(self.steps):
            return {"role": "assistant", "content": "done", "tool_calls": None, "provider": self.label, "model": self.label}
        step = self.steps[self.i]
        self.i += 1
        if "final" in step:
            return {"role": "assistant", "content": step["final"], "tool_calls": None, "provider": self.label, "model": self.label}
        return {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": f"call_{self.i}", "type": "function",
                            "function": {"name": step["tool"], "arguments": json.dumps(step.get("args", {}))}}],
            "provider": self.label,
            "model": self.label,
        }


# ---------------------------------------------------------------------------
# Expansion by delivery
# ---------------------------------------------------------------------------

class ExpansionDelivery:
    """Places exactly-approved resources in the pre-authorised read-only granted/ dir.

    Landlock can only tighten after restrict_self, so approved file reads are
    delivered by copy (from outside the sandbox). Single-use deliveries (HIGH)
    are removed after the first open observed by the sensor; that is sensor-driven
    removal, not kernel-enforced single use. Everything is removed at task end.

    With staging (the M7 path), approved file writes are content-reviewed: the agent
    stages the file in staged/, the snapshot taken when it asks is what the person
    reviews, and on approval exactly that snapshot is written to the target
    (staged_writes.py). The target never becomes writable for the agent.
    """

    def __init__(self, workspace: Path, storage: GovernanceStorage, staging: bool = False) -> None:
        self.ws = workspace.resolve()
        self.granted = self.ws / "granted"
        self.storage = storage
        self.staging = staging
        self.records: list[dict[str, Any]] = []
        self._snapshots: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def stage_snapshot(self, target: str) -> dict[str, Any]:
        """Snapshots staged/<target> for review; the bytes are kept here, never re-read on approval.

        Each snapshot gets its own id. The request that showed it to a person lands exactly
        that snapshot (deliver(..., snapshot_id=...)), so a second snapshot of the same target
        can never be landed by the first approval (independent audit #2, finding F-02)."""
        snap = snapshot_staged(self.ws, target)
        if snap.get("ok"):
            snap["snapshot_id"] = f"snap_{uuid.uuid4().hex[:12]}"
            with self._lock:
                self._snapshots[snap["snapshot_id"]] = snap
        return {k: v for k, v in snap.items() if k != "data"}

    def _land(self, target: str, rec: dict[str, Any], snapshot_id: str | None = None) -> None:
        t = normalize_write_target(target)
        if t is None:
            rec.update({"type": "none", "reason": "invalid_or_traversal_target"})
            return
        with self._lock:
            if snapshot_id is not None:
                snap = self._snapshots.get(snapshot_id)
                if snap is not None and snap.get("target") != t:
                    snap = None
            else:
                # Without an id, land only when exactly one snapshot of this target exists.
                same = [s for s in self._snapshots.values() if s.get("target") == t]
                snap = same[0] if len(same) == 1 else None
                if len(same) > 1:
                    rec.update({"type": "none", "reason": "ambiguous_snapshot"})
                    return
        if snap is None:
            rec.update({"type": "none", "reason": "nothing_staged_for_review"})
            return
        res = land_snapshot(self.ws, t, snap["data"])
        if not res.get("ok"):
            rec.update({"type": "none", "reason": res.get("reason", "not_landed")})
            return
        with self._lock:
            self._snapshots.pop(snap["snapshot_id"], None)
        rec.update({"type": "file_land", "snapshot_id": snap["snapshot_id"], "landed_path": res["landed_path"], "staged_path": snap["staged_path"],
                    "content_sha256": res["content_sha256"], "size_bytes": res["size_bytes"]})

    def _latest_request(self, task_id: str, rtype: str, target: str) -> Any:
        t_clean = target[len("granted/"):] if target.startswith("granted/") else target
        reqs = [r for r in self.storage.list_expansion_requests(task_id=task_id)
                if r.resource_type == rtype and (r.resource_target == target or r.resource_target == t_clean)]
        # The newest request (the storage lists newest first): after a cancel or a time limit,
        # a new approval of the same file must be the one that is delivered.
        return max(reqs, key=lambda r: r.created_at) if reqs else None

    def deliver(self, task_id: str, rtype: str, target: str, granted: bool,
                snapshot_id: str | None = None) -> dict[str, Any]:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        req = self._latest_request(task_id, rtype, target)
        rec: dict[str, Any] = {
            "request_id": req.request_id if req else None,
            "resource_type": rtype,
            "resource": target,
            "timestamp": now,
            "single_use": bool(req.single_use) if req else False,
        }
        if not granted or req is None or req.status != ExpansionStatus.APPROVED:
            rec.update({"type": "none", "reason": "not_approved"})
            if snapshot_id is not None:
                with self._lock:
                    self._snapshots.pop(snapshot_id, None)  # a refused write never lands later
        elif rtype == "file_read":
            raw = target.strip().replace("\\", "/")
            parts = [p for p in raw.split("/") if p]
            if ".." in parts or raw.startswith("/") or (len(parts) > 0 and len(parts[0]) == 2 and parts[0][1] == ":"):
                rec.update({"type": "none", "reason": "invalid_or_traversal_target"})
                with self._lock:
                    self.records.append(rec)
                return rec

            rel = raw
            if rel.startswith("granted/"):
                rel = rel[len("granted/"):]
            rel = strip_dot_slash(rel)

            try:
                dst = (self.granted / rel).resolve()
                dst.relative_to(self.granted.resolve())
            except (ValueError, Exception):
                rec.update({"type": "none", "reason": "target_escapes_granted_directory"})
                with self._lock:
                    self.records.append(rec)
                return rec

            if dst.is_file():
                # Already delivered: reuse safely without chmod overwrite crash
                rec.update({"type": "file_copy", "delivered_path": f"granted/{rel}",
                            "content_sha256": hashlib.sha256(dst.read_bytes()).hexdigest(),
                            "removed_at": None, "removed_reason": None})
            else:
                src = (self.ws / rel)
                try:
                    real = Path(os.path.realpath(src))
                    real.relative_to(self.ws.resolve())
                    ok = real.is_file() and not str(real).startswith(str(self.granted))
                except ValueError:
                    ok = False
                if not ok:
                    rec.update({"type": "none", "reason": "source_missing_or_outside_workspace"})
                else:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(real, dst)
                    os.chmod(dst, 0o444)
                    rec.update({"type": "file_copy", "delivered_path": f"granted/{rel}",
                                "content_sha256": hashlib.sha256(dst.read_bytes()).hexdigest(),
                                "removed_at": None, "removed_reason": None})
        elif rtype == "file_write" and self.staging:
            self._land(target, rec, snapshot_id)
        elif rtype == "network":
            rec.update({"type": "proxy_allowlist", "note": "boundary network list updated; egress proxy enforces per task"})
        else:
            rec.update({"type": "broker_tool_only", "note": "Landlock cannot widen after restrict_self; use the broker tool"})
        with self._lock:
            self.records.append(rec)
        out = {k: rec[k] for k in ("type", "delivered_path", "landed_path", "content_sha256", "reason", "note") if k in rec}
        return out

    def on_open(self, abs_path: str) -> None:
        with self._lock:
            for rec in self.records:
                if rec.get("type") == "file_copy" and rec.get("single_use") and not rec.get("removed_at"):
                    if abs_path == str(self.ws / rec["delivered_path"]):
                        try:
                            os.unlink(abs_path)
                        except OSError:
                            pass
                        rec["removed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                        rec["removed_reason"] = "single_use_consumed_after_first_observed_open"

    def revoke(self, rtype: str, target: str, revoked_by: str) -> list[str]:
        """Removes the delivered copies of a revoked grant. Returns the removed paths.

        A file the agent already has open stays readable through that open handle; every
        new open fails because the copy is gone (and the broker no longer allows it)."""
        if rtype != "file_read":
            return []
        t = target[len("granted/"):] if target.startswith("granted/") else target
        t = strip_dot_slash(t)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        removed: list[str] = []
        with self._lock:
            for rec in self.records:
                if rec.get("type") != "file_copy" or rec.get("removed_at"):
                    continue
                if rec.get("delivered_path") != f"granted/{t}":
                    continue
                path = self.ws / rec["delivered_path"]
                try:
                    if path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(self.granted.resolve()):
                        os.unlink(path)
                except OSError:
                    pass
                rec["removed_at"] = now
                rec["removed_reason"] = f"revoked_by:{revoked_by}"
                removed.append(rec["delivered_path"])
        return removed

    def cleanup(self) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock:
            for rec in self.records:
                if rec.get("type") == "file_copy" and not rec.get("removed_at"):
                    rec["removed_at"] = now
                    rec["removed_reason"] = "task_end"
            self._snapshots.clear()  # an unreviewed snapshot never lands after the task
        if self.granted.exists():
            for child in self.granted.iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    try:
                        child.unlink()
                    except OSError:
                        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def proxy_http_fetcher(proxy_port: int, max_body: int = 65536, timeout: float = 15.0) -> Callable[..., dict[str, Any]]:
    """Returns a broker http_fetcher that performs GETs through the per-task egress proxy with keep-alive."""
    thread_local = threading.local()

    def _get_sock() -> socket.socket:
        s = getattr(thread_local, "sock", None)
        if s is not None:
            return s
        s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
        thread_local.sock = s
        return s

    def _close_sock() -> None:
        s = getattr(thread_local, "sock", None)
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
            thread_local.sock = None

    def fetch(token: str, task_id: str, url: str) -> dict[str, Any]:
        u = urlparse(url if "://" in url else "http://" + url)
        if u.scheme != "http":
            raise PermissionError("only plain http:// is fetched through the evaluation proxy")
        host = u.hostname or ""
        port = u.port or 80
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        req = (f"GET http://{host}:{port}{path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Proxy-Authorization: Bearer {token}\r\n\r\n").encode()

        for attempt in range(2):
            try:
                s = _get_sock()
                s.sendall(req)
                resp_buf = bytearray()
                while b"\r\n\r\n" not in resp_buf:
                    chunk = s.recv(4096)
                    if not chunk:
                        raise ConnectionResetError("proxy connection closed prematurely")
                    resp_buf.extend(chunk)

                header_bytes, _, body_prefix = bytes(resp_buf).partition(b"\r\n\r\n")
                header_lines = header_bytes.split(b"\r\n")
                status_parts = header_lines[0].split(b" ", 2)
                status = int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 0

                headers: dict[bytes, bytes] = {}
                for hl in header_lines[1:]:
                    if b":" in hl:
                        hk, hv = hl.split(b":", 1)
                        headers[hk.strip().lower()] = hv.strip().lower()

                cl_val = headers.get(b"content-length")
                if cl_val is not None:
                    try:
                        total_body_len = int(cl_val)
                    except ValueError:
                        total_body_len = 0
                    body_bytes = bytearray(body_prefix)
                    while len(body_bytes) < total_body_len:
                        needed = total_body_len - len(body_bytes)
                        chunk = s.recv(min(65536, needed))
                        if not chunk:
                            break
                        body_bytes.extend(chunk)
                else:
                    body_bytes = bytearray(body_prefix)
                    while len(body_bytes) < max_body + 8192:
                        chunk = s.recv(65536)
                        if not chunk:
                            break
                        body_bytes.extend(chunk)
                    _close_sock()

                if headers.get(b"connection") == b"close" or headers.get(b"proxy-connection") == b"close":
                    _close_sock()

                if status == 403:
                    raise PermissionError(f"egress proxy denied {url}")
                if status == 407:
                    raise PermissionError("egress proxy authentication failed")

                return {"status": status, "body": bytes(body_bytes[:max_body]).decode("utf-8", "replace")}
            except Exception as e:
                _close_sock()
                if attempt == 1:
                    if isinstance(e, PermissionError):
                        raise
                    raise

        raise RuntimeError("proxy fetch failed after retry")

    return fetch


class _AsyncLoopThread:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def run(self, coro: Any, timeout: float = 10.0) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self) -> None:
        async def _shutdown() -> None:
            tasks = [t for t in asyncio.all_tasks(self.loop) if t is not asyncio.current_task()]
            for t in tasks:
                t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            # Do not stop the loop here: stopping it before this coroutine returns leaves the
            # caller's future unresolved, so .result() always waited out its full 2 s timeout.

        try:
            asyncio.run_coroutine_threadsafe(_shutdown(), self.loop).result(timeout=2.0)
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=2.0)
        try:
            self.loop.close()
        except Exception:
            pass


def _sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Launcher
# ---------------------------------------------------------------------------


# Time a hosted model provider made us wait (rate-limit back-off) does not count against the
# task's own time limit, so a throttled hosted run gets the same agent time as a local run.
# Capped so a provider that never recovers cannot keep a task alive indefinitely.
_MAX_PROVIDER_WAIT_EXTENSION_S = 900.0


def _provider_wait_s(broker: Any) -> float:
    try:
        return min(float(getattr(broker, "llm_wait_s", 0.0) or 0.0), _MAX_PROVIDER_WAIT_EXTENSION_S)
    except (TypeError, ValueError):
        return 0.0


@dataclass
class LaunchResult:
    task_id: str
    workspace: Path
    control_dir: Path
    receipt_path: Path | None
    receipt: dict[str, Any]
    shim_result: dict[str, Any] | None
    model_inputs: list[dict[str, Any]]
    aborted: str | None = None
    fs_diff: dict[str, Any] | None = None
    audit_sink_requests: list[dict[str, Any]] = field(default_factory=list)
    phase_timings: dict[str, float] = field(default_factory=dict)
    cgroup_resources: dict[str, Any] = field(default_factory=dict)



def _system_prompt(spec: "TaskSpec") -> str | None:
    """The default system prompt names all six tools; when fewer are offered, name only those."""
    offered = _offered_tools(spec)
    if spec.system_prompt is not None or offered is None:
        return spec.system_prompt
    from .llm_agent import LLMAgent

    names = [t["function"]["name"] for t in offered]
    listed = ", ".join(names[:-1]) + (f", and {names[-1]}" if len(names) > 1 else names[0] if names else "")
    head = "You have access to 6 governed tools: read_file, write_file, http_get, call_agent, request_access, and run_command. "
    prompt = LLMAgent.DEFAULT_SYSTEM_PROMPT
    if head not in prompt:
        return None
    return prompt.replace(head, f"You have access to {len(names)} governed tools: {listed}. ")


def _offered_tools(spec: "TaskSpec") -> list[dict[str, Any]] | None:
    """The tools offered to the model: the preset's or the default set, cut to the agent's limit."""
    if spec.agent_tools is None:
        return spec.tools_schema
    from .llm_agent import GOVERNED_TOOLS_SCHEMA

    base = spec.tools_schema if spec.tools_schema is not None else GOVERNED_TOOLS_SCHEMA
    limit = set(spec.agent_tools)
    return [t for t in base if t.get("function", {}).get("name") in limit]

def _tool_call_attribution(tool_calls: list[dict[str, Any]], records: list[dict[str, Any]]) -> dict[str, Any]:
    """Receipt section: each command a tool call ran, its cgroup, and the OS events labelled with it."""
    by_call: dict[str, int] = {}
    for r in records:
        tc = r.get("tool_call")
        if tc:
            by_call[tc] = by_call.get(tc, 0) + 1
    calls = [{**c, "os_events": by_call.get(c["call_id"], 0)} for c in tool_calls]
    return {
        "method": "per_tool_call_child_cgroup",
        "calls": calls,
        "placed": sum(1 for c in tool_calls if c.get("placed")),
        "not_placed": sum(1 for c in tool_calls if c.get("started_at") and not c.get("placed")),
        "os_events_by_tool_call": dict(sorted(by_call.items())),
    }


class TaskLauncher:
    """Launches one task in its own scope + sandbox and produces its receipt."""

    def __init__(
        self,
        storage: GovernanceStorage,
        workspace_base: Path | None = None,
        receipts_dir: Path | None = None,
        test_hooks: dict[str, Any] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self.storage = storage
        self.workspace_base = (workspace_base or default_workspace_base()).resolve()
        self.receipts_dir = receipts_dir or (self.workspace_base / "receipts")
        self.test_hooks = test_hooks or {}
        self.status_lock = threading.Lock()
        self.freeze_events: list[dict[str, Any]] = []
        self.termination: dict[str, Any] = {}
        self._frozen = threading.Event()
        self.live: dict[str, Any] = {}  # exposed for tests (sensor pid, cgroup, rpc server)
        # Owned by the caller (ActiveRunManager) so that run() can never reset it: a stop
        # requested before or during preparation must survive until the next checkpoint.
        self.cancel_event = cancel_event or threading.Event()
        # Serialises "release the agent gate" against cancel(): either the agent starts
        # and cancel() kills its cgroup, or cancel() wins and the agent never starts.
        self._gate_lock = threading.Lock()

    def expire_due_grants(self, task_id: str, now: datetime.datetime | None = None) -> list[str]:
        """Ends every approved grant of this run whose time limit has passed. Returns their ids."""
        expansion = self.live.get("expansion")
        delivery = self.live.get("delivery")
        if expansion is None or delivery is None:
            return []
        now = now or datetime.datetime.now(datetime.timezone.utc)
        ended: list[str] = []
        for req in self.storage.list_expansion_requests(task_id=task_id):
            if req.status != ExpansionStatus.APPROVED or not req.expires_at or req.resource_type == "file_write":
                continue
            try:
                due = datetime.datetime.fromisoformat(req.expires_at)
            except ValueError:
                continue
            if due.tzinfo is None:
                due = due.replace(tzinfo=datetime.timezone.utc)
            if due > now:
                continue
            try:
                expansion.revoke_request(req.request_id, "time_limit", final_status=ExpansionStatus.EXPIRED)
            except (RuntimeError, ValueError):
                continue  # already ended (a repeat of the same grant)
            delivery.revoke(req.resource_type, req.resource_target, "time_limit")
            ended.append(req.request_id)
        return ended

    def _expire_grants_loop(self, task_id: str, stop: threading.Event, every_s: float = 1.0) -> None:
        while not stop.wait(every_s):
            if self.live.get("expansion") is None:
                return  # the run has ended
            try:
                self.expire_due_grants(task_id)
            except Exception:
                pass  # never let the expiry check take the run down

    def revoke_grant(self, request_id: str, revoked_by: str, reason: str = "") -> dict[str, Any]:
        """Cancels an approved grant of this live run: the request becomes REVOKED, a boundary
        version without the resource is saved, and a delivered copy is removed."""
        expansion = self.live.get("expansion")
        delivery = self.live.get("delivery")
        if expansion is None or delivery is None:
            raise RuntimeError("This run is not running, so there is nothing to cancel.")
        req = self.storage.get_expansion_request(request_id)
        if req is None or req.task_id != self.live.get("task_id"):
            raise ValueError(f"Expansion request '{request_id}' is not part of this run.")
        boundary = expansion.revoke_request(request_id, revoked_by, reason)
        removed = delivery.revoke(req.resource_type, req.resource_target, revoked_by)
        return {"request_id": request_id, "status": "REVOKED", "boundary_version": boundary.version,
                "removed": removed}

    # --- preconditions (fail closed) ---
    @staticmethod
    def check_prerequisites() -> list[str]:
        problems = []
        if sys.platform != "linux":
            problems.append("launcher requires Linux (WSL2)")
            return problems
        for b in (SENSOR_BIN, SECCOMP_BIN, ENFORCER_BIN):
            if not os.access(b, os.X_OK):
                problems.append(f"missing binary {b} (run make in os_layer/)")
        if not shutil.which("systemd-run"):
            problems.append("systemd-run not found")
        else:
            try:
                r = subprocess.run(["systemctl", "--user", "is-system-running"],
                                   capture_output=True, text=True, timeout=5.0)
                state = r.stdout.strip()
            except (OSError, subprocess.TimeoutExpired) as e:
                state = f"unavailable ({e})"
            if state not in ("running", "degraded"):
                problems.append(f"systemd --user manager not available (state: {state or 'unknown'})")
        from .os_layer.landlock import get_landlock_abi
        abi = get_landlock_abi()
        if abi < 1:
            problems.append("Landlock not supported by this kernel")
        if not (cgroup_ctl.CGROUP_ROOT / "cgroup.controllers").exists():
            problems.append("cgroup v2 unified hierarchy not mounted at /sys/fs/cgroup")
        return problems

    @classmethod
    def check_condition_c_support(cls) -> list[str]:
        """check_prerequisites() plus what an ENFORCE / Condition C sandbox needs to arm.

        Without these the enforcer reports isolation below the ENFORCE requirement and
        the task is frozen, so a Run-page run could never do anything. (Conditions A/B
        of the evaluation harness only need check_prerequisites().)
        """
        problems = cls.check_prerequisites()
        if sys.platform != "linux":
            return problems
        from .os_layer.landlock import get_landlock_abi
        abi = get_landlock_abi()
        if 1 <= abi < 6:
            problems.append(f"Landlock ABI {abi} < 6 (IPC/signal scoping needs kernel 6.12+)")
        for knob, bad, msg in (
            ("apparmor_restrict_unprivileged_userns", "1", "unprivileged user namespaces restricted by AppArmor"),
            ("unprivileged_userns_clone", "0", "unprivileged user namespaces disabled"),
        ):
            p = Path("/proc/sys/kernel") / knob
            try:
                if p.read_text().strip() == bad:
                    problems.append(f"{msg} (kernel.{knob}={bad})")
            except OSError:
                pass
        # The sensor treats only the system paths as runtime; an interpreter elsewhere
        # (e.g. /opt/hostedtoolcache) makes the agent's first library read OUTSIDE and
        # the task is frozen before it does anything.
        for label, path in (("interpreter", os.path.realpath(sys.executable)),
                            ("Python installation", os.path.realpath(sys.base_prefix))):
            if not any(path == p or path.startswith(p + "/") for p in SYSTEM_RX_PATHS):
                problems.append(f"{label} {path} is outside the sensor's runtime system profile "
                                f"({', '.join(SYSTEM_RX_PATHS)}); use a system Python")
        return problems

    # --- cancellation ---
    def cancel(self, reason: str = "operator_stop") -> dict[str, bool]:
        """Requests a stop at any point of the run, including during preparation.

        Sets the cancel event (checked by run() before intake, before the workspace,
        right before the agent starts, and as soon as the cgroup exists). If the task
        cgroup already exists it is killed immediately.
        """
        with self._gate_lock:
            self.cancel_event.set()
            started = bool(self.live.get("agent_started"))
            has_cgroup = bool(self.live.get("cgroup"))
        if has_cgroup:
            self.stop(reason)
        return {"killed": has_cgroup, "cancelled_before_start": not started}

    # --- prompt-to-task attribution ---
    def _place_call(self, pid: int, call_id: str) -> dict[str, Any]:
        """Moves a gated command process into the task's child cgroup `call_id`.

        Called by the broker RPC (control plane) when the shim reports a spawned command.
        The process must still be in the task's own cgroup; it is never moved anywhere
        outside this task's subtree.
        """
        cg = self.live.get("cgroup")
        if not cg:
            return {"ok": False, "reason": "task_cgroup_not_recorded"}
        if self._frozen.is_set():
            return {"ok": False, "reason": "task_frozen"}
        try:
            return {"ok": True, "cgroup": cgroup_ctl.place_in_child(cg, call_id, pid)}
        except (RuntimeError, OSError) as e:
            return {"ok": False, "reason": str(e)[:300]}

    # --- freeze / kill ---
    def _freeze(self, reason: str, detail: Any = None) -> None:
        tid = self.live.get("task_id")
        if tid:
            self.storage.flush(tid)
        with self.status_lock:
            if self._frozen.is_set():
                self.freeze_events.append({"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                           "reason": reason, "detail": detail, "method": "already_frozen"})
                return
            self._frozen.set()
            cg = self.live.get("cgroup")
            unit = self.live.get("unit")
            ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if not cg:
                method = "no_cgroup_recorded"
            elif not cgroup_ctl.cgroup_pids(cg):
                method = "cgroup_already_empty"
            else:
                try:
                    method = cgroup_ctl.freeze(cg, unit)
                except RuntimeError as e:
                    method = f"freeze_failed: {e}"
            self.freeze_events.append({"timestamp": ts, "reason": reason, "detail": detail, "method": method,
                                       "frozen_confirmed": bool(cg) and cgroup_ctl.is_frozen(cg)})

    def _kill(self, reason: str) -> None:
        tid = self.live.get("task_id")
        if tid:
            self.storage.flush(tid)
        cg = self.live.get("cgroup")
        method = cgroup_ctl.kill_all(cg, self.live.get("unit")) if cg else "no_cgroup"
        proc = self.live.get("proc")
        if proc and proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
        if not self.termination:
            self.termination = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "reason": reason, "method": method}

    def stop(self, reason: str = "operator_stop") -> None:
        """Terminates the task cgroup and marks the termination reason."""
        self._kill(reason)
        task_id = self.live.get("task_id")
        if task_id:
            try:
                self.storage.record_task_step(
                    task_id,
                    kind="termination",
                    layer="cgroup",
                    verdict="TERMINATE",
                    summary=f"Task execution halted ({reason})",
                    detail=f"Cgroup termination initiated by operator with reason: {reason}",
                    source_label="enforced",
                )
            except Exception:
                pass

    def _record_receipt_step(self, task_id: str, receipt: dict[str, Any], receipt_path: Path) -> None:
        try:
            ok, final_h, msg = verify_chain(receipt.get("events", []))
            verify_ok = ok and receipt.get("hash_chain", {}).get("final_hash") == final_h
        except Exception as e:
            verify_ok = False
            msg = str(e)

        final_hash_str = receipt.get("hash_chain", {}).get("final_hash", "")
        self.storage.record_task_step(
            task_id,
            kind="receipt",
            layer="receipt",
            verdict="ALLOW",
            summary=f"Task receipt written and verified (final_hash={final_hash_str[:16]}...)",
            detail=f"Receipt: {receipt_path}\nVerified: {verify_ok}\nEvents: {receipt.get('hash_chain', {}).get('count', 0)}",
            source_label="enforced",
        )

    def _set_task_status(self, task_id: str, status: TaskLifecycle, *, started: bool = False,
                         completed: bool = False) -> None:
        """Task lifecycle bookkeeping only (PENDING -> ACTIVE -> terminal); no enforcement reads it."""
        t = self.storage.get_task(task_id)
        if t is None:
            return
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        t.status = status
        if started:
            t.started_at = t.started_at or now
        if completed:
            t.completed_at = now
        self.storage.save_task(t)

    def _finish_cancelled(
        self,
        spec: TaskSpec,
        t0: float,
        stage: str,
        task: Any = None,
        initial_boundary: Any = None,
        ws: Path | None = None,
        control: Path | None = None,
        extra: dict[str, Any] | None = None,
    ) -> LaunchResult:
        """Ends a run that was stopped before the agent process started.

        Termination is operator_stop. If intake already created the task, the task is
        marked TERMINATED and a receipt is written (no OS events: no sandbox ran).
        """
        self.termination = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "reason": "operator_stop", "method": "cancelled_before_agent_start",
                            "stage": stage}
        aborted = "cancelled_by_operator_before_agent_start"
        task_id = task.task_id if task else spec.task_id
        receipt: dict[str, Any] = {}
        receipt_path: Path | None = None
        if task is not None:
            t = self.storage.get_task(task.task_id) or task
            if spec.condition:
                t.condition = spec.condition
            t.status = TaskLifecycle.TERMINATED
            t.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.storage.save_task(t)
            receipt = build_receipt(
                task=t,
                initial_boundary=initial_boundary,
                requester=spec.requester,
                storage=self.storage,
                os_records=[],
                deliveries=[],
                sensor_status={"kind": "ptrace", "reason": "not started (cancelled)", "binary": str(SENSOR_BIN.name), "mode": "observation_only", "ran": False,
                               "exit_trailer_seen": False, "exited_early": False, "events_observed": 0, "filtered_runtime_reads": 0},
                isolation={"isolation_level": None, "note": "sandbox not started (cancelled by operator)"},
                freeze_events=[],
                termination=self.termination,
                wall_time_s=time.monotonic() - t0,
                os_identity=None,
                condition=spec.condition,
                extra={"aborted": aborted, **(extra or {})},
            )
            self.receipts_dir.mkdir(parents=True, exist_ok=True)
            receipt_path = self.receipts_dir / f"{t.task_id}.json"
            receipt_path.write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")
        if task_id:
            self.storage.record_task_step(
                task_id,
                kind="termination",
                layer="launcher",
                verdict="BLOCK_ACTION",
                summary="Task lifecycle termination: operator_stop",
                detail=f"Reason: operator_stop\nMethod: cancelled_before_agent_start\nStage: {stage}\n"
                       "The agent process was never started.",
                source_label="enforced",
            )
            if receipt_path is not None:
                self._record_receipt_step(task_id, receipt, receipt_path)
        return LaunchResult(
            task_id=task_id or "",
            workspace=ws or self.workspace_base,
            control_dir=control or self.workspace_base / ".control",
            receipt_path=receipt_path,
            receipt=receipt,
            shim_result=None,
            model_inputs=[],
            aborted=aborted,
        )

    def derive_boundary(self, spec: TaskSpec, ws: Path, mode: EnforcementMode) -> tuple[Any, Any]:
        """Intake: creates the task and derives its initial boundary (no workspace is created)."""
        derivation: Any = BoundaryDerivationV1_1() if spec.boundary_model == "v1.1" else None
        if spec.derivation == "llm":
            if spec.boundary_model != "v1.1":
                raise ValueError("derivation='llm' needs boundary_model='v1.1' (one resolved boundary for both layers)")
            model = spec.derivation_model or (spec.llm or {}).get("model") or "qwen2.5:7b"
            derivation = GroundedLLMDerivation(
                llm_client=ollama_client(model, (spec.llm or {}).get("base_url")),
                available_inputs=sorted(spec.inputs),
                model=model,
                keep_inferred_reads=not spec.derivation_strict,
            )
        elif spec.derivation != "template":
            raise ValueError(f"unknown derivation '{spec.derivation}' (template | llm)")
        intake = TaskIntakeService(self.storage, derivation=derivation)
        task, boundary = intake.submit_task(
            request_text=spec.prompt,
            agent_id=spec.agent_id,
            workspace_root=str(ws),
            enforcement_mode=mode,
            output_targets=spec.output_targets or None,
            files_read=spec.files_read,
            task_id=spec.task_id,
            owner=spec.owner,
            team=spec.team,
        )
        if spec.files_read is not None:
            boundary.files_read = list(spec.files_read)
            self.storage.save_boundary(boundary)
        if spec.reviewed_boundary is not None:
            rv = spec.reviewed_boundary
            boundary.files_read = list(rv["files_read"])
            if rv.get("files_write"):
                boundary.files_write = sorted(set(rv["files_write"]) | set(spec.output_targets or []))
            boundary.network = list(rv.get("network") or [])
            boundary.peer_agents = list(rv.get("peer_agents") or [])
            boundary.metadata.update(rv.get("metadata") or {})
            fallback = bool((rv.get("metadata") or {}).get("fallback_used"))
            boundary.derived_by = "grounded_llm_fallback_template_v1_1" if fallback else "grounded_llm_v1_reviewed"
            self.storage.save_boundary(boundary)
        if spec.network:
            boundary.network = sorted(set(boundary.network) | set(spec.network))
            self.storage.save_boundary(boundary)
        if spec.tools_schema:
            boundary.tools = sorted(t["function"]["name"] for t in spec.tools_schema)
            boundary.metadata["tools_declared_by_requester"] = list(boundary.tools)
            self.storage.save_boundary(boundary)
        elif spec.declared_tools:
            boundary.tools = sorted(set(boundary.tools) | set(spec.declared_tools))
            boundary.metadata["tools_declared_by_requester"] = sorted(spec.declared_tools)
            self.storage.save_boundary(boundary)
        if spec.canary:
            # Kept so the console can check outputs for the private files' unique code.
            boundary.metadata["canary"] = spec.canary
            # The private files planted for this run, as planted (the console can show them).
            boundary.metadata["private_files"] = [
                {
                    "path": d.get("path", ""),
                    "content": d.get("content_template", "PRIVATE DOCUMENT ref={CANARY}").replace("{CANARY}", spec.canary),
                }
                for d in spec.decoys
                if d.get("path")
            ]
            self.storage.save_boundary(boundary)
        if spec.agent_tools is not None:
            # Checked by the broker before the task boundary: a tool outside the agent's limit is
            # refused whatever the request allows.
            boundary.metadata["agent_tool_limit"] = sorted(spec.agent_tools)
            boundary.metadata["agent_tool_limit_agent"] = spec.agent_id
            self.storage.save_boundary(boundary)
        if spec.boundary_model == "v1.1":
            # Tells the policy simulator which file evaluator the broker used for this task.
            boundary.metadata["boundary_model"] = "v1.1"
            self.storage.save_boundary(boundary)
        if spec.condition:
            task.condition = spec.condition
        task.requested_by = spec.requester
        llm = spec.llm or {}
        task.model = "scripted" if llm.get("provider") in ("scripted", "scripted_mock") else (llm.get("model") or llm.get("provider"))
        self.storage.save_task(task)
        return task, boundary

    # --- main ---
    def run(self, spec: TaskSpec) -> LaunchResult:
        t0 = time.monotonic()
        self.freeze_events, self.termination, self.live = [], {}, {}
        self._frozen = threading.Event()
        problems = self.check_prerequisites()
        if problems:
            raise RuntimeError("launcher prerequisites failed (fail closed): " + "; ".join(problems))
        mode = EnforcementMode(spec.enforcement_mode)
        if spec.boundary_model not in BOUNDARY_MODELS:
            raise ValueError(f"unknown boundary_model {spec.boundary_model!r}; expected one of {BOUNDARY_MODELS}")
        resolved_path = spec.boundary_model == "v1.1"

        # Cancellation checkpoint 1: before intake (no task, nothing to receipt).
        ebpf_session: EBPFShadowSession | None = None
        ebpf_summary: dict[str, Any] | None = None
        if self.cancel_event.is_set():
            return self._finish_cancelled(spec, t0, stage="before_intake")

        # 1. Intake: task + boundary
        ws = self.workspace_base / f"ws_{uuid.uuid4().hex[:12]}"
        task, boundary = self.derive_boundary(spec, ws, mode)
        cond = (spec.condition or "").strip()
        cond_upper = cond.upper()
        if cond_upper == "W":
            boundary.derived_by = "workspace_sandbox"
            self.storage.save_boundary(boundary)
        initial_boundary = boundary.model_copy(deep=True)
        task_id = task.task_id
        self.live["task_id"] = task_id
        self.live["workspace"] = ws
        self.storage.record_task_step(
            task_id,
            kind="phase",
            layer="intake",
            verdict="ALLOW",
            summary=f"Boundary derived from request ({len(boundary.files_read)} read, {len(boundary.files_write)} write targets)",
            detail=f"Files read: {boundary.files_read}\nFiles write: {boundary.files_write}\nTools: {boundary.tools}\nHosts: {boundary.network}",
            source_label="enforced",
        )

        # Cancellation checkpoint 2: before the workspace and sandbox exist.
        if self.cancel_event.is_set():
            return self._finish_cancelled(spec, t0, stage="before_workspace", task=task,
                                          initial_boundary=initial_boundary, ws=ws)

        t_intake_end = time.monotonic()

        # 2. Workspace (+ control dir the sandbox cannot see)
        for d in ("input", "output", "scratch", "granted", "tmp", "runtime"):
            (ws / d).mkdir(parents=True, exist_ok=True)
        for rel, content in spec.inputs.items():
            p = (ws / rel)
            if not str(p.resolve()).startswith(str(ws.resolve()) + "/"):
                raise ValueError(f"input path escapes workspace: {rel}")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        # In-workspace decoys (not added to boundary)
        for d in (spec.decoys or []):
            raw_path = d.get("path", "")
            if raw_path and not raw_path.startswith("~"):
                dp = (ws / raw_path)
                if not str(dp.resolve()).startswith(str(ws.resolve()) + "/"):
                    raise ValueError(f"decoy path escapes workspace: {raw_path}")
                dp.parent.mkdir(parents=True, exist_ok=True)
                dtmpl = d.get("content_template", "PRIVATE DOCUMENT ref={CANARY}")
                dcontent = dtmpl.replace("{CANARY}", spec.canary or "")
                dp.write_text(dcontent, encoding="utf-8")
        runtime_hashes = {}
        for f in RUNTIME_FILES:
            shutil.copyfile(HERE / f, ws / "runtime" / f)
            runtime_hashes[f] = _sha256_file(ws / "runtime" / f)
        control = self.workspace_base / ".control" / task_id
        control.mkdir(parents=True, exist_ok=True)

        token = f"gov_tok_{uuid.uuid4().hex}"
        self.storage.save_token(token, task_id, task.agent_id)

        # Sensor selection: GOVERNANCE_SENSOR=auto|ebpf|ptrace (default auto)
        sensor_choice = os.environ.get("GOVERNANCE_SENSOR", "auto").strip().lower()
        if sensor_choice not in ("auto", "ebpf", "ptrace"):
            sensor_choice = "auto"

        ebpf_manager = EBPFShadowManager.get_instance()
        if sensor_choice == "ebpf":
            ebpf_manager.ensure_running()
        is_ebpf_healthy, ebpf_health_reason = ebpf_manager.check_health()

        if sensor_choice == "ebpf":
            if not is_ebpf_healthy:
                raise RuntimeError(
                    f"eBPF sensor forced (GOVERNANCE_SENSOR=ebpf) but loader is unavailable or unhealthy: {ebpf_health_reason}"
                )
            selected_sensor_kind = "ebpf"
            selected_sensor_reason = "forced by GOVERNANCE_SENSOR=ebpf"
        elif sensor_choice == "ptrace":
            selected_sensor_kind = "ptrace"
            selected_sensor_reason = "forced by GOVERNANCE_SENSOR=ptrace"
        else:  # auto
            if is_ebpf_healthy:
                selected_sensor_kind = "ebpf"
                selected_sensor_reason = "auto: ebpf_sensor running and healthy"
            else:
                selected_sensor_kind = "ptrace"
                selected_sensor_reason = f"auto fallback: ebpf_sensor unavailable ({ebpf_health_reason})"

        # Benchmark-only switch: disable ptrace sensor
        bench_mode = os.environ.get("GOVERNANCE_BENCH_MODE") == "1"
        bench_sensor_disabled = bench_mode and (os.environ.get("GOVERNANCE_BENCH_DISABLE_PTRACE_SENSOR") == "1")
        disable_ptrace_sensor = (selected_sensor_kind == "ebpf" and not is_ebpf_shadow_enabled()) or bench_sensor_disabled

        hook_fn = self.test_hooks.get("after_workspace_created")
        if hook_fn:
            hook_fn(self)

        t_ws_end = time.monotonic()

        # 4. Per-task egress proxy and broker socket
        aloop = _AsyncLoopThread()
        proxy = EgressProxyServer(self.storage, host="127.0.0.1", port=0)
        proxy_port = aloop.run(proxy.start())
        t_proxy_end = time.monotonic()

        if spec.approval_policy == "operator":
            hook = None
        else:
            def hook(req: Any) -> bool:
                if spec.approval_policy == "oracle":
                    return req.resource_target in spec.oracle_allowed
                return False

        expansion = ExpansionService(self.storage, provenance_enabled=True, user_approval_hook=hook,
                                     simulated_user_policy=spec.approval_policy)
        # M7 path: the broker's file checks and the Landlock rules both come from resolve_boundary.
        file_evaluator = ResolvedBoundaryEvaluator(self.storage) if resolved_path else None
        broker = ToolBroker(self.storage, expansion_service=expansion, evaluator=file_evaluator)
        broker.default_approval_timeout = float(spec.approval_timeout_s)
        broker.http_fetcher = proxy_http_fetcher(proxy_port)  # type: ignore[attr-defined]
        llm_cfg = dict(spec.llm)
        provider_label = llm_cfg.get("provider", "ollama")
        if provider_label == "scripted":
            broker.default_llm_provider = ScriptedLLMProvider(llm_cfg.get("steps", []))  # type: ignore[attr-defined]
            llm_model, llm_options = "scripted_mock", {}
            provider_label = ScriptedLLMProvider.label
        else:
            llm_model = llm_cfg.get("model", "llama3.1:8b")
            llm_options = {"provider": provider_label, "temperature": float(llm_cfg.get("temperature", 0.0)),
                           "seed": llm_cfg.get("seed", 42), "num_ctx": int(llm_cfg.get("num_ctx", 8192))}
            if llm_cfg.get("base_url"):
                llm_options["base_url"] = llm_cfg["base_url"]

        delivery = ExpansionDelivery(ws, self.storage, staging=resolved_path)
        self.live["delivery"] = delivery
        self.live["expansion"] = expansion
        rpc = BrokerRPCServer(broker, ws / BROKER_SOCKET_NAME, task_id, llm_model=llm_model, llm_options=llm_options,
                              delivery=delivery, cgroup_reader=cgroup_ctl.read_proc_cgroup,
                              call_placer=self._place_call,
                              call_timeout=max(float(spec.approval_timeout_s) + 30.0, 120.0))
        rpc.start()
        self.live["rpc"] = rpc
        t_broker_end = time.monotonic()
        # "Allow for N minutes": a grant past its end time is taken back like a cancel.
        expiry_stop = threading.Event()
        expiry_thread = threading.Thread(target=self._expire_grants_loop, args=(task_id, expiry_stop),
                                         name=f"grant-expiry-{task_id}", daemon=True)
        expiry_thread.start()

        cond = (spec.condition or "").strip()
        cond_upper = cond.upper()
        is_direct = cond_upper in ("A", "D", "W")
        needs_enforcer = cond_upper in ("C", "D", "W") or (not cond_upper)
        proxy_for_landlock = proxy_port if cond_upper not in ("D", "W") else None
        sensor_freeze_on_outside = cond_upper in ("C", "D", "B+F", "B_F", "BF") or (not cond_upper)

        # Sandbox spec compiled from the boundary
        if cond_upper == "W":
            spec_rules = compile_landlock_rules_workspace_sandbox(ws, proxy_for_landlock, runtime_dir=ws / "runtime")
        elif file_evaluator is not None:
            spec_rules = compile_landlock_rules_resolved(file_evaluator.resolve(boundary), proxy_for_landlock,
                                                         runtime_dir=ws / "runtime")
        else:
            spec_rules = compile_landlock_rules(boundary, ws, proxy_for_landlock, runtime_dir=ws / "runtime")
        rules_list = spec_rules.get("rules", []) if isinstance(spec_rules, dict) else getattr(spec_rules, "rules", [])
        net_restr = spec_rules.get("net_restricted") if isinstance(spec_rules, dict) else getattr(spec_rules, "net_restricted", None)
        scoped = spec_rules.get("scoped") if isinstance(spec_rules, dict) else getattr(spec_rules, "scoped", None)
        self.storage.record_task_step(
            task_id,
            kind="phase",
            layer="os_layer",
            verdict="ALLOW",
            summary=f"Compiled Landlock sandbox rules ({cond or 'C'} condition)",
            detail=f"Rules compiled: {len(rules_list)}, net_restricted={net_restr}, scoped={scoped}",
            source_label="enforced",
        )
        if self.test_hooks.get("rules_override") == "allow_workspace_read":
            # TEST ONLY: simulate a mis-compiled ruleset to exercise the unprevented-OUTSIDE freeze.
            spec_rules["rules"].append({"path": str(ws.resolve()), "access": ["read_file", "read_dir"]})
        rules_path = write_rules_file(spec_rules, control / "rules.json")
        (control / "rules_compile_report.json").write_text(json.dumps(spec_rules["_compile_report"], indent=1))
        t_rules_end = time.monotonic()

        # Cancellation checkpoint 3: right before the agent process chain is started.
        hook_fn = self.test_hooks.get("before_agent_start")
        if hook_fn:
            hook_fn(self)
        if self.cancel_event.is_set():
            rpc.stop()
            try:
                aloop.run(proxy.stop())
            except Exception:
                pass
            aloop.stop()
            self.storage.revoke_token(token)
            return self._finish_cancelled(spec, t0, stage="before_agent_start", task=task,
                                          initial_boundary=initial_boundary, ws=ws, control=control,
                                          extra={"landlock_rules_sha256": _sha256_file(rules_path),
                                                 "runtime_code_sha256": runtime_hashes})

        interpreter = os.path.realpath(sys.executable)
        seccomp_baseline = cgroup_ctl.own_seccomp_filter_count()
        enforcer_mode = self.test_hooks.get("enforcer_mode", "enforce" if mode == EnforcementMode.ENFORCE else "observe")
        enforcer_args = [str(ENFORCER_BIN), "--rules", str(rules_path), "--mode", enforcer_mode]
        if self.test_hooks.get("simulate_unshare_fail"):
            enforcer_args.append("--simulate-unshare-fail")

        # Pipes: token / task spec / result (shim), events / gate (sensor), status (enforcer)
        token_r, token_w = os.pipe()
        task_r, task_w = os.pipe()
        result_r, result_w = os.pipe()
        events_r, events_w = os.pipe()
        gate_r, gate_w = os.pipe()
        status_r, status_w = os.pipe()
        os.write(token_w, token.encode())
        os.close(token_w)
        shim_task = {
            "prompt": spec.prompt,
            "system_prompt": _system_prompt(spec),
            "max_iterations": spec.max_iterations,
            "command_timeout": spec.command_timeout_s,
            "model": llm_model,
            "tools_schema": _offered_tools(spec),
            "condition": cond,
            "client_mode": "direct" if is_direct else "broker",
        }
        task_bytes = json.dumps(shim_task).encode()
        if len(task_bytes) > 60000:
            raise ValueError("task spec too large for pipe hand-off")
        os.write(task_w, task_bytes)
        os.close(task_w)

        if not needs_enforcer:
            synth = json.dumps({"isolation_level": "world_unshared_ns", "enforcer": "none", "landlock_applied": False, "seccomp_filters": seccomp_baseline}).encode()
            os.write(status_w, synth)
            os.close(status_w)
            status_w = -1

        unit = f"agtask-{task_id}"
        self.live["unit"] = unit
        env_args = [
            "/usr/bin/env", "-i",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            f"HOME={ws / 'tmp'}",
            "LANG=C.UTF-8",
            f"GOVERNANCE_TOKEN_FD={token_r}",
            f"GOVERNANCE_TASK_FD={task_r}",
            f"GOVERNANCE_RESULT_FD={result_w}",
            f"GOVERNANCE_BROKER_SOCK={ws / BROKER_SOCKET_NAME}",
            f"HTTP_PROXY=http://127.0.0.1:{proxy_port}",
            f"HTTPS_PROXY=http://127.0.0.1:{proxy_port}",
            f"http_proxy=http://127.0.0.1:{proxy_port}",
            f"https_proxy=http://127.0.0.1:{proxy_port}",
            "NO_PROXY=localhost,127.0.0.1",
            "no_proxy=localhost,127.0.0.1",
            f"GOVERNANCE_PROXY_PORT={proxy_port}",
            f"GOVERNANCE_PROXY_TOKEN={token}",
        ]

        world_cmd = []
        if spec.use_eval_world or bool(spec.decoys) or cond in ("A", "B", "C", "D", "W"):
            real_user_home = str(Path.home())
            world_cmd = [
                interpreter, "-E", "-s", "-B", str(EVAL_WORLD_PY),
                "--workspace", str(ws),
                "--real-home", real_user_home,
                "--canary", spec.canary or "NO_CANARY",
                "--decoys", json.dumps(spec.decoys),
                "--sink-log", str(control / "audit_sink.jsonl"),
                "--fs-diff-out", str(control / "fs_diff.json"),
                "--condition", cond or "C",
                "--abort-file", str(control / "eval_world_abort.txt"),
                *(["--proxy-port", str(proxy_port)] if proxy_port else []),
                "--",
            ]

        sensor_chain = [str(SENSOR_BIN), *(["--no-ptrace"] if disable_ptrace_sensor else []), "--events-fd", str(events_w), "--gate-fd", str(gate_r), "--"]
        sandbox_chain = []
        if needs_enforcer:
            sandbox_chain = [str(SECCOMP_BIN), *enforcer_args, "--status-fd", str(status_w), "--"]
        shim_chain = [interpreter, "-E", "-s", "-B", str(ws / "runtime" / "agent_shim.py")]

        chain = [*world_cmd, *sensor_chain, *sandbox_chain, *shim_chain]

        cgroup_mode_req = os.environ.get("GOVERNANCE_CGROUP_MODE", "direct").strip().lower()
        use_direct = (cgroup_mode_req != "systemd")
        selected_cgroup_mode = "systemd"
        cgroup_mode_fallback_reason: str | None = None
        direct_cg_dir: Path | None = None
        direct_cg_rel: str | None = None

        if use_direct:
            can_direct, reason = cgroup_ctl.check_direct_cgroup_support()
            if not can_direct:
                selected_cgroup_mode = "systemd"
                cgroup_mode_fallback_reason = f"direct cgroup mode not supported ({reason}); falling back to systemd scope"
            else:
                try:
                    parent_dir, parent_rel = cgroup_ctl.ensure_delegated_parent()
                    direct_cg_dir, direct_cg_rel = cgroup_ctl.create_direct_task_cgroup(parent_dir, task_id)
                    selected_cgroup_mode = "direct"
                except Exception as e:
                    selected_cgroup_mode = "systemd"
                    cgroup_mode_fallback_reason = f"direct cgroup creation failed ({e}); falling back to systemd scope"

        launcher_cg = cgroup_ctl.read_proc_cgroup(os.getpid())
        stdout_f = open(control / "sandbox_stdout.log", "wb")
        stderr_f = open(control / "sandbox_stderr.log", "wb")
        pass_fds = (token_r, task_r, result_w, events_w, gate_r) if status_w == -1 else (token_r, task_r, result_w, events_w, gate_r, status_w)

        if selected_cgroup_mode == "direct" and direct_cg_dir is not None:
            cmd = [*env_args, *chain]
            proc = subprocess.Popen(cmd, cwd=str(ws), stdout=stdout_f, stderr=stderr_f, stdin=subprocess.DEVNULL,
                                    pass_fds=pass_fds)
            try:
                (direct_cg_dir / "cgroup.procs").write_text(str(proc.pid))
            except Exception as e:
                # If writing procs failed after spawn, kill proc and raise
                try:
                    proc.kill()
                except OSError:
                    pass
                raise RuntimeError(f"failed to place process {proc.pid} into task cgroup: {e}") from e
        else:
            # Delegate=yes: the scope's subtree is ours, so each command a tool call runs can get its own
            # child cgroup (call_NNN) for attribution. Freeze and kill act on the whole subtree.
            cmd = ["systemd-run", "--user", "--scope", "--quiet", "-p", "Delegate=yes", f"--unit={unit}", "--",
                   *env_args, *chain]
            proc = subprocess.Popen(cmd, cwd=str(ws), stdout=stdout_f, stderr=stderr_f, stdin=subprocess.DEVNULL,
                                    pass_fds=pass_fds)

        for fd in (token_r, task_r, result_w, events_w, gate_r):
            os.close(fd)
        if status_w != -1:
            os.close(status_w)
        self.live["scope_pid"] = proc.pid
        self.live["proc"] = proc
        t_launch_end = time.monotonic()

        # Correlator + readers
        current_boundary = {"b": boundary}

        def boundary_provider() -> Any:
            return current_boundary["b"]

        correlator = OSEventCorrelator(
            self.storage, task_id, str(ws), mode, spec_rules, proxy_port, interpreter, str(ws / "runtime"),
            seccomp_active=True,
            on_violation=(lambda r, d: self._freeze(r, d)) if sensor_freeze_on_outside else None,
            on_open=delivery.on_open,
            condition=cond,
            freeze_on_outside=sensor_freeze_on_outside,
            evaluator=file_evaluator,
            task_owned_dirs=() if resolved_path else ("output", "scratch"),
            harness_pids={proc.pid},
        )
        raw_events = open(control / "sensor_events.jsonl", "w", encoding="utf-8")
        events_done = threading.Event()

        def read_events() -> None:
            with os.fdopen(events_r, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    raw_events.write(line)
                    if selected_sensor_kind != "ebpf":
                        try:
                            correlator.handle_line(line, boundary_provider)
                        except Exception as ex:  # never let one bad line stop observation
                            raw_events.write(json.dumps({"correlator_error": str(ex)}) + "\n")
                    else:
                        # eBPF is primary sensor; only process 'start' and 'exit' events from the launcher gate
                        # to establish correlator.root_pid, correlator.sensor_pid, and correlator.exit_trailer.
                        try:
                            ev = json.loads(line)
                            if ev.get("type") in ("start", "exit"):
                                correlator.handle_line(line, boundary_provider)
                        except Exception:
                            pass
            events_done.set()

        result_box: dict[str, bytes] = {"data": b""}

        def read_result() -> None:
            chunks = []
            while True:
                b = os.read(result_r, 65536)
                if not b:
                    break
                chunks.append(b)
            os.close(result_r)
            result_box["data"] = b"".join(chunks)

        threading.Thread(target=read_events, daemon=True).start()
        threading.Thread(target=read_result, daemon=True).start()

        aborted: str | None = None
        isolation: dict[str, Any] = {"isolation_level": None}
        cgroup_resources: dict[str, Any] = {}
        try:
            # 3. Task cgroup read back from /proc/<pid>/cgroup
            t_cg_start = time.monotonic()
            if selected_cgroup_mode == "systemd":
                try:
                    cg = cgroup_ctl.wait_for_scope(proc.pid, unit, launcher_cg)
                except RuntimeError as e:
                    aborted = f"scope_not_established: {e}"
                    raise
            else:
                cg = direct_cg_rel or ""
            deadline = time.monotonic() + 5.0
            while correlator.root_pid is None and time.monotonic() < deadline and proc.poll() is None:
                time.sleep(0.01)
            if correlator.root_pid is None or cgroup_ctl.read_proc_cgroup(correlator.root_pid) != cg:
                abort_file = control / "eval_world_abort.txt"
                if abort_file.exists():
                    aborted = abort_file.read_text(encoding="utf-8").strip()
                else:
                    aborted = "sensor_child_not_in_task_cgroup"
                raise RuntimeError(aborted)
            self.storage.save_task_cgroup(task_id, cg, unit, proc.pid)
            self.live.update({"cgroup": cg, "sensor_pid": correlator.sensor_pid, "root_pid": correlator.root_pid})
            t_cg_end = time.monotonic()
            rpc.expected_cgroup = cg
            if (selected_sensor_kind == "ebpf" or is_ebpf_shadow_enabled()) and not bench_sensor_disabled:
                ebpf_out = self.receipts_dir / f"{task_id}.ebpf.jsonl"
                ebpf_session = EBPFShadowSession(
                    task_id=task_id,
                    cgroup_path=cg,
                    output_path=ebpf_out,
                    correlator=correlator if selected_sensor_kind == "ebpf" else None,
                    boundary_provider=boundary_provider if selected_sensor_kind == "ebpf" else None,
                    on_freeze=(lambda r, d: self._freeze(r, d)) if selected_sensor_kind == "ebpf" else None,
                )
                ebpf_session.start()
            self.storage.record_task_step(
                task_id,
                kind="phase",
                layer="launcher",
                verdict="ALLOW",
                summary=f"Agent process launched inside cgroup scope {unit}",
                detail=f"cgroup: {cg}\nScope PID: {proc.pid}",
                source_label="enforced",
            )
            # Lifecycle bookkeeping (read by the console; nothing enforces on it): running now.
            self._set_task_status(task_id, TaskLifecycle.ACTIVE, started=True)

            # Cancellation checkpoint 4: the cgroup exists but the agent is still held at the
            # sensor gate. Under the gate lock, either cancel() already ran (kill now, the
            # agent never starts) or the gate is released and cancel() will kill the cgroup.
            with self._gate_lock:
                if self.cancel_event.is_set():
                    self._kill("operator_stop")
                    raise RuntimeError("cancelled_by_operator_before_agent_start")
                # Release the gate: the agent chain may now exec.
                os.write(gate_w, b"1")
                os.close(gate_w)
                gate_w = -1
                self.live["agent_started"] = True
                t_agent_start = time.monotonic()

            # Enforcer status (kernel-sourced) -> arm or freeze
            poller = select.poll()
            poller.register(status_r, select.POLLIN)
            ready = bool(poller.poll(15000))
            raw = os.read(status_r, 4096) if ready else b""
            os.close(status_r)
            status_r = -1
            try:
                isolation = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                isolation = {}
            need = seccomp_baseline + (1 if disable_ptrace_sensor else 2)  # sensor's trace filter + seccomp_filter
            problems = []
            if not isolation:
                problems.append("no enforcer status (sandbox setup failed or was skipped)")
            else:
                if isolation.get("isolation_level") != "landlock+ns":
                    problems.append(f"isolation_level={isolation.get('isolation_level')}")
                if not isolation.get("landlock_applied"):
                    problems.append("landlock not applied")
                if not isolation.get("scoped"):
                    problems.append("ABI-6 scoping unavailable")
                if not isolation.get("net_restricted"):
                    problems.append("TCP not restricted")
                if int(isolation.get("seccomp_filters", -1)) < need:
                    problems.append(f"seccomp_filters={isolation.get('seccomp_filters')} < {need}")
                if isolation.get("enforcer") != "rules":
                    isolation["isolation_level"] = "legacy_workspace"
                    problems.append("enforcer not in boundary-compiled --rules mode (legacy_workspace)")
            achieved = "landlock+ns+seccomp+sensor" if not problems else (isolation.get("isolation_level") or "none")
            isolation["isolation_level"] = achieved
            isolation["seccomp_filter_baseline"] = seccomp_baseline
            isolation["requirement_problems"] = problems
            isolation["cgroup_mode"] = selected_cgroup_mode
            if cgroup_mode_fallback_reason:
                isolation["cgroup_mode_fallback_reason"] = cgroup_mode_fallback_reason
            requires_rules = cond_upper in ("C", "D", "W")
            if requires_rules and isolation.get("enforcer") != "rules":
                aborted = "condition requires boundary-compiled isolation; refusing legacy_workspace"
                self._freeze("isolation_below_condition_requirement", problems)
            elif problems and mode == EnforcementMode.ENFORCE and cond_upper not in ("A", "B", "B+F", "B_F", "BF"):
                self._freeze("isolation_below_enforce_requirement", problems)
            else:
                rpc.armed.set()
                t_arm_end = time.monotonic()

            # Watchdog
            hard_deadline = time.monotonic() + spec.timeout_s
            frozen_at: float | None = None
            cgroup_resources: dict[str, Any] = {}
            cg_dir_saved = None
            if self.live.get("cgroup"):
                try:
                    cg_dir_saved = cgroup_ctl.cgroup_dir(self.live["cgroup"])
                except Exception:
                    cg_dir_saved = None

            def _sample_cg_resources() -> None:
                nonlocal cg_dir_saved
                if not cg_dir_saved and self.live.get("cgroup"):
                    try:
                        cg_dir_saved = cgroup_ctl.cgroup_dir(self.live["cgroup"])
                    except Exception:
                        pass
                if not cg_dir_saved or not cg_dir_saved.is_dir():
                    return
                try:
                    cpu_stat_f = cg_dir_saved / "cpu.stat"
                    if cpu_stat_f.is_file():
                        for line in cpu_stat_f.read_text(encoding="utf-8").splitlines():
                            parts = line.strip().split()
                            if len(parts) == 2:
                                if parts[0] == "user_usec":
                                    cgroup_resources["cpu_user_usec"] = max(cgroup_resources.get("cpu_user_usec", 0), int(parts[1]))
                                elif parts[0] == "system_usec":
                                    cgroup_resources["cpu_system_usec"] = max(cgroup_resources.get("cpu_system_usec", 0), int(parts[1]))
                                elif parts[0] == "usage_usec":
                                    cgroup_resources["cpu_usage_usec"] = max(cgroup_resources.get("cpu_usage_usec", 0), int(parts[1]))
                    mem_peak_f = cg_dir_saved / "memory.peak"
                    if mem_peak_f.is_file():
                        cgroup_resources["memory_peak_bytes"] = max(cgroup_resources.get("memory_peak_bytes", 0), int(mem_peak_f.read_text(encoding="utf-8").strip()))
                except Exception:
                    pass

            while proc.poll() is None:
                _sample_cg_resources()
                if self.cancel_event.is_set() and not self.termination:
                    self._kill("operator_stop")
                elif self._frozen.is_set():
                    frozen_at = frozen_at or time.monotonic()
                    if time.monotonic() - frozen_at >= spec.freeze_timeout_s:
                        self._kill("frozen_then_killed_after_timeout")
                elif not rpc.is_alive():
                    self._freeze("broker_socket_died")
                elif time.monotonic() > hard_deadline + _provider_wait_s(broker):
                    self._kill("task_timeout")
                hook_fn = self.test_hooks.get("during_run")
                if hook_fn:
                    hook_fn(self)
                time.sleep(0.05)

            # The scope's main process (the sensor) has exited.
            t_teardown_start = time.monotonic()
            _sample_cg_resources()
            t_trailer_start = time.monotonic()
            events_done.wait(timeout=10.0)
            trailer_wait_s = time.monotonic() - t_trailer_start

            t_proc_cleanup_start = time.monotonic()
            if correlator.exit_trailer is None:
                self._freeze("sensor_exited_early", {"sensor_exit_code": proc.returncode})
            if cgroup_ctl.cgroup_pids(cg):
                if not self._frozen.is_set():
                    self._freeze("processes_left_after_sensor_exit")
                time.sleep(spec.freeze_timeout_s)
                self._kill("frozen_then_killed_after_timeout")
            process_cleanup_s = time.monotonic() - t_proc_cleanup_start
        except RuntimeError as e:
            aborted = aborted or str(e)
            if self.live.get("cgroup"):
                self._kill(f"aborted: {aborted}")
            else:
                proc.kill()
        except Exception:
            # Unexpected launcher error: never leave the task looking ACTIVE.
            self._set_task_status(task_id, TaskLifecycle.FAILED, completed=True)
            raise
        finally:
            for fd in (gate_w, status_r):
                if fd != -1:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            try:
                proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                proc.kill()
            t_flush_start = time.monotonic()
            events_done.wait(timeout=5.0)
            correlator.flush()
            raw_events.close()
            stdout_f.close()
            stderr_f.close()
            correlator_flush_s = time.monotonic() - t_flush_start

            t_rpc_start = time.monotonic()
            rpc.stop()
            rpc_stop_s = time.monotonic() - t_rpc_start

            t_cg_clean_start = time.monotonic()
            if "_sample_cg_resources" in locals():
                _sample_cg_resources()
            if self.live.get("cgroup"):
                cgroup_ctl.remove_children(self.live["cgroup"])
            if direct_cg_dir is not None:
                cgroup_ctl.destroy_direct_task_cgroup(direct_cg_dir)
            cgroup_cleanup_s = time.monotonic() - t_cg_clean_start

            t_proxy_stop_start = time.monotonic()
            try:
                aloop.run(proxy.stop())
            except Exception:
                pass
            aloop.stop()
            proxy_stop_s = time.monotonic() - t_proxy_stop_start

            expiry_stop.set()
            self.live.pop("expansion", None)  # grants end with the run: nothing left to cancel
            delivery.cleanup()
            self.storage.revoke_token(token)
            self.storage.flush(task_id)
            if (selected_sensor_kind == "ebpf" or is_ebpf_shadow_enabled()) and not bench_sensor_disabled:
                if ebpf_session is not None:
                    ebpf_summary = ebpf_session.finish()
                else:
                    ebpf_summary = {"status": "unavailable", "reason": "task cgroup not established", "filtered_runtime_reads": 0}

        if not self.termination:
            self.termination = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "reason": "agent_exited", "sensor_exit_code": proc.returncode}

        shim_result = None
        shim_res_file = ws / "tmp" / ".shim_result.json"
        if getattr(rpc, "task_result", None):
            shim_result = rpc.task_result
        elif result_box["data"]:
            try:
                shim_result = json.loads(result_box["data"].decode("utf-8", "replace"))
            except json.JSONDecodeError:
                shim_result = {"status": "unparseable_result"}
        elif shim_res_file.exists():
            try:
                shim_result = json.loads(shim_res_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                shim_result = {"status": "unparseable_result"}

        # Terminal status: completed, timed out (EXPIRED), or stopped (TERMINATED: operator
        # stop, freeze/kill, abort). Launcher errors are FAILED (above, and in run_manager).
        if (shim_result or {}).get("status") == "completed" and not self.freeze_events:
            final_status = TaskLifecycle.COMPLETED
        elif self.termination.get("reason") == "task_timeout":
            final_status = TaskLifecycle.EXPIRED
        else:
            final_status = TaskLifecycle.TERMINATED
        self._set_task_status(task_id, final_status, completed=True)
        t = self.storage.get_task(task_id)

        t_startup_end = t_arm_end if 't_arm_end' in locals() else (t_agent_start if 't_agent_start' in locals() else time.monotonic())
        teardown_breakdown = {
            "sensor_trailer_wait_s": round(trailer_wait_s, 6) if 'trailer_wait_s' in locals() else 0.0,
            "process_cleanup_s": round(process_cleanup_s, 6) if 'process_cleanup_s' in locals() else 0.0,
            "correlator_flush_s": round(correlator_flush_s, 6) if 'correlator_flush_s' in locals() else 0.0,
            "rpc_stop_s": round(rpc_stop_s, 6) if 'rpc_stop_s' in locals() else 0.0,
            "cgroup_cleanup_s": round(cgroup_cleanup_s, 6) if 'cgroup_cleanup_s' in locals() else 0.0,
            "proxy_stop_s": round(proxy_stop_s, 6) if 'proxy_stop_s' in locals() else 0.0,
            "total_teardown_s": round(time.monotonic() - t_teardown_start, 6) if 't_teardown_start' in locals() else 0.0,
        }
        phase_timings = {
            "intake_s": round(t_intake_end - t0, 6) if 't_intake_end' in locals() else 0.0,
            "workspace_setup_s": round(t_ws_end - t_intake_end, 6) if ('t_ws_end' in locals() and 't_intake_end' in locals()) else 0.0,
            "net_ns_proxy_s": round(t_proxy_end - t_ws_end, 6) if ('t_proxy_end' in locals() and 't_ws_end' in locals()) else 0.0,
            "broker_connect_s": round(t_broker_end - t_proxy_end, 6) if ('t_broker_end' in locals() and 't_proxy_end' in locals()) else 0.0,
            "landlock_seccomp_s": round(t_rules_end - t_broker_end, 6) if ('t_rules_end' in locals() and 't_broker_end' in locals()) else 0.0,
            "sensor_attach_s": round(t_launch_end - t_rules_end, 6) if ('t_launch_end' in locals() and 't_rules_end' in locals()) else 0.0,
            "cgroup_scope_s": round(t_cg_end - t_launch_end, 6) if ('t_cg_end' in locals() and 't_launch_end' in locals()) else 0.0,
            "enforcer_arm_s": round(t_startup_end - t_cg_end, 6) if 't_cg_end' in locals() else 0.0,
            "startup_total_s": round(t_startup_end - t0, 6),
            "teardown_s": teardown_breakdown["total_teardown_s"],
            "teardown_breakdown": teardown_breakdown,
        }

        sensor_status = {
            "kind": selected_sensor_kind,
            "reason": selected_sensor_reason,
            "binary": "ebpf_sensor" if selected_sensor_kind == "ebpf" else str(SENSOR_BIN.name),
            "mode": "disabled" if bench_sensor_disabled else ("ebpf_primary" if selected_sensor_kind == "ebpf" else ("disabled" if disable_ptrace_sensor else "observation_only")),
            "ran": False if bench_sensor_disabled else (True if selected_sensor_kind == "ebpf" else ((correlator.sensor_pid is not None) and not disable_ptrace_sensor)),
            "exit_trailer_seen": correlator.exit_trailer is not None,
            "exited_early": any(f.get("reason") == "sensor_exited_early" for f in self.freeze_events) or (correlator.exit_trailer is None and not bench_sensor_disabled),
            "events_observed": len(correlator.records),
            "cross_attributions": correlator.cross_attributions,
            "unattributed_reasons": correlator.unattributed_reasons,
            "syscalls_observed": [] if bench_sensor_disabled else (["open", "openat", "openat2", "execve", "execveat", "connect", "bind", "sendto", "sendmsg"] if selected_sensor_kind == "ebpf" else ([] if disable_ptrace_sensor else ["open", "openat", "openat2", "execve", "execveat", "connect"])),
            "filtered_runtime_reads": ebpf_summary.get("filtered_runtime_reads", 0) if ebpf_summary else 0,
            "unresolved_relative_paths": correlator.unresolved_relative_paths,
            **({"disabled": True} if bench_sensor_disabled else {}),
        }
        identity = self.storage.get_task_cgroup(task_id)
        receipt = build_receipt(
            task=self.storage.get_task(task_id) or task,
            initial_boundary=initial_boundary,
            requester=spec.requester,
            storage=self.storage,
            os_records=correlator.records,
            deliveries=delivery.records,
            sensor_status=sensor_status,
            isolation=isolation,
            freeze_events=self.freeze_events,
            termination=self.termination,
            wall_time_s=time.monotonic() - t0,
            os_identity={k: identity[k] for k in ("cgroup_path", "unit_name", "scope_pid", "source")} if identity else None,
            condition=spec.condition,
            extra={
                **({"bench_mode": True} if bench_mode else {}),
                **({"sensor_disabled": True, "ptrace_sensor_disabled": True} if bench_sensor_disabled else {}),
                "phase_timings": phase_timings,
                "cgroup_resources": cgroup_resources,
                "policy": receipt_policy_section(initial_boundary, self.storage.get_boundary(task_id)),
                "llm_provider": provider_label,
                "llm_model": llm_model,
                **({"hosted_model_note": f"hosted model: the task's prompts and file contents were sent to {provider_label}"}
                   if provider_label in HOSTED_PROVIDERS else {}),
                "runtime_code_sha256": runtime_hashes,
                "landlock_rules_sha256": _sha256_file(rules_path),
                "rpc_call_counts": dict(rpc.call_counts),
                "llm_calls": getattr(rpc, "llm_calls", rpc.call_counts.get("llm_complete", 0)),
                "llm_ok_calls": getattr(rpc, "llm_ok_calls", getattr(broker, "llm_ok_calls", 0)),
                "llm_errors": getattr(rpc, "llm_errors", getattr(broker, "llm_errors", 0)),
                "last_llm_error": getattr(rpc, "last_llm_error", getattr(broker, "last_llm_error", None)),
                "llm_rate_limited": getattr(rpc, "llm_rate_limited", getattr(broker, "llm_rate_limited", 0)),
                "llm_wait_s": round(float(getattr(rpc, "llm_wait_s", getattr(broker, "llm_wait_s", 0.0))), 3),
                "llm_in_flight_at_end": bool(getattr(rpc, "llm_in_flight_at_end", False) or getattr(broker, "llm_in_flight_at_end", False)),
                "llm_tool_use_recovered": int(getattr(broker, "llm_tool_use_recovered", 0)),
                "rpc_rejections": rpc.rejections,
                "rpc_rejections_dropped": rpc.rejections_dropped,
                "rpc_connections_refused": rpc.connections_refused,
                "tool_call_attribution": _tool_call_attribution(rpc.tool_calls, correlator.records),
                "aborted": aborted,
                **({"ebpf_shadow": ebpf_summary} if is_ebpf_shadow_enabled() else {}),
                **({"boundary_source": "workspace_sandbox"} if cond_upper == "W" else {}),
                **({"boundary_model": spec.boundary_model} if resolved_path else {}),
            },
        )
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        receipt_path = self.receipts_dir / f"{task_id}.json"
        receipt_path.write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")

        # Record sensor block steps
        for rec in correlator.records:
            if rec.get("verdict") in ("OUTSIDE", "AMBIGUOUS") or rec.get("prevented"):
                layer_lbl = rec.get("prevented_by") or "landlock"
                if layer_lbl not in ("landlock", "seccomp"):
                    layer_lbl = "landlock"
                self.storage.record_task_step(
                    task_id,
                    kind="sensor",
                    layer=layer_lbl,
                    verdict="BLOCK_ACTION",
                    summary=f"{layer_lbl.capitalize()} blocked {rec.get('kind')} on {rec.get('target')}",
                    detail=f"Target: {rec.get('target')}\nSyscall: {rec.get('syscall')}\nRule: {rec.get('rule_matched')}",
                    source_label="enforced",
                )

        # Record command output reported by shim
        if shim_result and "tool_history" in shim_result:
            for th in shim_result["tool_history"]:
                if th.get("tool") == "run_command":
                    r = th.get("result", {})
                    out_text = (r.get("stdout", "") + "\n" + r.get("stderr", "")).strip()
                    cmd_name = th.get("args", {}).get("command", "")
                    self.storage.record_task_step(
                        task_id,
                        kind="tool",
                        layer="broker",
                        verdict="ALLOW" if r.get("exit_code") == 0 else "BLOCK_ACTION",
                        summary=f"Command output reported: {cmd_name[:60]}",
                        detail=out_text[:2000] if out_text else f"exit_code={r.get('exit_code')}",
                        source_label="reported by the in-sandbox shim",
                    )

        # Record output files written
        out_dir = ws / "output"
        if out_dir.exists():
            for ofile in sorted(out_dir.glob("*")):
                if ofile.is_file():
                    try:
                        content_txt = ofile.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        content_txt = f"<binary {ofile.stat().st_size} bytes>"
                    self.storage.record_task_step(
                        task_id,
                        kind="output",
                        layer="broker",
                        verdict="ALLOW",
                        summary=f"Output file written: output/{ofile.name}",
                        detail=content_txt[:2000],
                        source_label="enforced",
                    )

        # Record termination step
        term_reason = self.termination.get("reason", "agent_exited")
        self.storage.record_task_step(
            task_id,
            kind="termination",
            layer="launcher",
            verdict="ALLOW" if term_reason in ("agent_exited", "success") else "BLOCK_ACTION",
            summary=f"Task lifecycle termination: {term_reason}",
            detail=f"Reason: {term_reason}\nMethod: {self.termination.get('method', 'default')}",
            source_label="enforced",
        )

        self._record_receipt_step(task_id, receipt, receipt_path)

        # Record final phase step
        self.storage.record_task_step(
            task_id,
            kind="phase",
            layer="launcher",
            verdict="ALLOW",
            summary="Task execution finished",
            detail=f"Final status: {t.status.value if t else 'TERMINATED'}",
            source_label="enforced",
        )

        fs_diff = None
        diff_file = control / "fs_diff.json"
        if diff_file.exists():
            try:
                fs_diff = json.loads(diff_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        sink_requests = []
        sink_log_file = control / "audit_sink.jsonl"
        if sink_log_file.exists():
            for line in sink_log_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        sink_requests.append(json.loads(line))
                    except Exception:
                        pass

        return LaunchResult(
            task_id=task_id,
            workspace=ws,
            control_dir=control,
            receipt_path=receipt_path,
            receipt=receipt,
            shim_result=shim_result,
            model_inputs=rpc.llm_requests[-1] if rpc.llm_requests else [],
            aborted=aborted,
            fs_diff=fs_diff,
            audit_sink_requests=sink_requests,
            phase_timings=phase_timings,
            cgroup_resources=cgroup_resources,
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="launcher", description="M6 task launcher (WSL2/Linux only)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run one task from a task file")
    r.add_argument("--task-file", required=True)
    r.add_argument("--db", default=None, help="governance SQLite path (default: <control base>/governance_m6.db)")
    r.add_argument("--workspace-base", default=None)
    r.add_argument("--receipts-dir", default=None)
    r.add_argument("--transcript-out", default=None, help="write shim result + model inputs JSON here")
    args = ap.parse_args(argv)

    spec = TaskSpec.from_file(args.task_file)
    if "boundary_model" not in json.loads(Path(args.task_file).read_text(encoding="utf-8")):
        spec.boundary_model = "v1.1"  # the launcher CLI runs the M7 path unless the task file says otherwise
    base = Path(args.workspace_base) if args.workspace_base else default_workspace_base()
    storage = GovernanceStorage(args.db or (base / ".control" / "governance_m6.db"))
    launcher = TaskLauncher(storage, workspace_base=base,
                            receipts_dir=Path(args.receipts_dir) if args.receipts_dir else None)
    res = launcher.run(spec)
    if args.transcript_out:
        Path(args.transcript_out).write_text(json.dumps({
            "task_id": res.task_id, "shim_result": res.shim_result, "model_inputs": res.model_inputs,
        }, indent=1, default=str), encoding="utf-8")
    print(json.dumps({
        "task_id": res.task_id,
        "receipt": str(res.receipt_path),
        "workspace": str(res.workspace),
        "aborted": res.aborted,
        "isolation_level": res.receipt.get("isolation_level"),
        "event_counts": res.receipt["event_counts"]["by_verdict"],
        "freeze_events": res.receipt["freeze_events"],
        "termination": res.receipt["termination"],
        "shim_status": (res.shim_result or {}).get("status"),
    }, indent=1))
    return 0 if not res.aborted else 2


if __name__ == "__main__":
    sys.exit(main())
