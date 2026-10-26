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

from .broker import ToolBroker
from .broker_rpc import BrokerRPCServer
from .correlator import OSEventCorrelator
from .expansion import ExpansionService
from .intake import TaskIntakeService
from .models import EnforcementMode, ExpansionStatus, TaskLifecycle
from .os_layer import cgroup_ctl
from .os_layer.sandbox_spec import BROKER_SOCKET_NAME, compile_landlock_rules, write_rules_file
from .proxy import EgressProxyServer
from .receipt import build_receipt
from .storage import GovernanceStorage

HERE = Path(__file__).resolve().parent
OS_LAYER = HERE / "os_layer"
SENSOR_BIN = OS_LAYER / "sensor"
SECCOMP_BIN = OS_LAYER / "seccomp_filter"
ENFORCER_BIN = OS_LAYER / "landlock_enforcer"
EVAL_WORLD_PY = HERE / "eval_world.py"
RUNTIME_FILES = ("agent_shim.py", "llm_agent.py")
REPO_ROOT = HERE.parents[3]


def default_workspace_base() -> Path:
    return Path(os.environ.get("HOME", "/tmp")) / "agent_workspaces"


# ---------------------------------------------------------------------------
# Task specification
# ---------------------------------------------------------------------------

@dataclass
class TaskSpec:
    prompt: str
    requester: str = "local_user"
    agent_id: str = "m6_agent"
    inputs: dict[str, str] = field(default_factory=dict)        # workspace-relative path -> text
    output_targets: list[str] = field(default_factory=list)
    declared_tools: list[str] = field(default_factory=lambda: ["run_command"])
    enforcement_mode: str = "ENFORCE"
    llm: dict[str, Any] = field(default_factory=lambda: {"provider": "ollama", "model": "llama3.1:8b"})
    system_prompt: str | None = None
    max_iterations: int = 10
    timeout_s: float = 900.0
    command_timeout_s: float = 60.0
    freeze_timeout_s: float = 5.0
    approval_policy: str = "deny"                                # "deny" | "oracle"
    oracle_allowed: list[str] = field(default_factory=list)
    condition: str | None = None
    tools_schema: list[dict[str, Any]] | None = None
    decoys: list[dict[str, Any]] = field(default_factory=list)
    canary: str = ""
    use_eval_world: bool = False

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
    """

    def __init__(self, workspace: Path, storage: GovernanceStorage) -> None:
        self.ws = workspace.resolve()
        self.granted = self.ws / "granted"
        self.storage = storage
        self.records: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def _latest_request(self, task_id: str, rtype: str, target: str) -> Any:
        reqs = [r for r in self.storage.list_expansion_requests(task_id=task_id)
                if r.resource_type == rtype and r.resource_target == target]
        return reqs[-1] if reqs else None

    def deliver(self, task_id: str, rtype: str, target: str, granted: bool) -> dict[str, Any]:
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
        elif rtype == "file_read":
            rel = target.replace("\\", "/").lstrip("./")
            src = (self.ws / rel)
            try:
                real = Path(os.path.realpath(src))
                real.relative_to(self.ws)
                ok = real.is_file() and not str(real).startswith(str(self.granted))
            except ValueError:
                ok = False
            if not ok:
                rec.update({"type": "none", "reason": "source_missing_or_outside_workspace"})
            else:
                dst = self.granted / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(real, dst)
                os.chmod(dst, 0o444)
                rec.update({"type": "file_copy", "delivered_path": f"granted/{rel}",
                            "content_sha256": hashlib.sha256(dst.read_bytes()).hexdigest(),
                            "removed_at": None, "removed_reason": None})
        elif rtype == "network":
            rec.update({"type": "proxy_allowlist", "note": "boundary network list updated; egress proxy enforces per task"})
        else:
            rec.update({"type": "broker_tool_only", "note": "Landlock cannot widen after restrict_self; use the broker tool"})
        with self._lock:
            self.records.append(rec)
        out = {k: rec[k] for k in ("type", "delivered_path", "reason", "note") if k in rec}
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

    def cleanup(self) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock:
            for rec in self.records:
                if rec.get("type") == "file_copy" and not rec.get("removed_at"):
                    rec["removed_at"] = now
                    rec["removed_reason"] = "task_end"
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
    """Returns a broker http_fetcher that performs GETs through the per-task egress proxy."""

    def fetch(token: str, task_id: str, url: str) -> dict[str, Any]:
        u = urlparse(url if "://" in url else "http://" + url)
        if u.scheme != "http":
            raise PermissionError("only plain http:// is fetched through the evaluation proxy")
        host = u.hostname or ""
        port = u.port or 80
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        req = (f"GET http://{host}:{port}{path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Proxy-Authorization: Bearer {token}\r\nConnection: close\r\n\r\n").encode()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout) as s:
            s.sendall(req)
            data = b""
            while len(data) < max_body + 8192:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        try:
            status = int(head.split(b" ", 2)[1])
        except (IndexError, ValueError):
            status = 0
        if status == 403:
            raise PermissionError(f"egress proxy denied {url}")
        if status == 407:
            raise PermissionError("egress proxy authentication failed")
        return {"status": status, "body": body[:max_body].decode("utf-8", "replace")}

    return fetch


class _AsyncLoopThread:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def run(self, coro: Any, timeout: float = 10.0) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self) -> None:
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


class TaskLauncher:
    """Launches one task in its own scope + sandbox and produces its receipt."""

    def __init__(
        self,
        storage: GovernanceStorage,
        workspace_base: Path | None = None,
        receipts_dir: Path | None = None,
        test_hooks: dict[str, Any] | None = None,
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

    # --- preconditions (fail closed) ---
    @staticmethod
    def check_prerequisites() -> list[str]:
        problems = []
        if sys.platform != "linux":
            problems.append("launcher requires Linux (WSL2)")
        for b in (SENSOR_BIN, SECCOMP_BIN, ENFORCER_BIN):
            if not os.access(b, os.X_OK):
                problems.append(f"missing binary {b} (run make in os_layer/)")
        if not shutil.which("systemd-run"):
            problems.append("systemd-run not found")
        return problems

    # --- freeze / kill ---
    def _freeze(self, reason: str, detail: Any = None) -> None:
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
        cg = self.live.get("cgroup")
        method = cgroup_ctl.kill_all(cg, self.live.get("unit")) if cg else "no_cgroup"
        if not self.termination:
            self.termination = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "reason": reason, "method": method}

    # --- main ---
    def run(self, spec: TaskSpec) -> LaunchResult:
        t0 = time.monotonic()
        self.freeze_events, self.termination, self.live = [], {}, {}
        self._frozen = threading.Event()
        problems = self.check_prerequisites()
        if problems:
            raise RuntimeError("launcher prerequisites failed (fail closed): " + "; ".join(problems))
        mode = EnforcementMode(spec.enforcement_mode)

        # 1. Intake: task + boundary
        ws = self.workspace_base / f"ws_{uuid.uuid4().hex[:12]}"
        intake = TaskIntakeService(self.storage)
        task, boundary = intake.submit_task(
            request_text=spec.prompt,
            agent_id=spec.agent_id,
            workspace_root=str(ws),
            enforcement_mode=mode,
            output_targets=spec.output_targets or None,
        )
        if spec.declared_tools:
            boundary.tools = sorted(set(boundary.tools) | set(spec.declared_tools))
            boundary.metadata["tools_declared_by_requester"] = sorted(spec.declared_tools)
            self.storage.save_boundary(boundary)
        initial_boundary = boundary.model_copy(deep=True)
        task_id = task.task_id

        # 2. Workspace (+ control dir the sandbox cannot see)
        for d in ("input", "output", "scratch", "granted", "tmp", "runtime"):
            (ws / d).mkdir(parents=True, exist_ok=True)
        for rel, content in spec.inputs.items():
            p = (ws / rel)
            if not str(p.resolve()).startswith(str(ws.resolve()) + "/"):
                raise ValueError(f"input path escapes workspace: {rel}")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        runtime_hashes = {}
        for f in RUNTIME_FILES:
            shutil.copyfile(HERE / f, ws / "runtime" / f)
            runtime_hashes[f] = _sha256_file(ws / "runtime" / f)
        control = self.workspace_base / ".control" / task_id
        control.mkdir(parents=True, exist_ok=True)

        token = f"gov_tok_{uuid.uuid4().hex}"
        self.storage.save_token(token, task_id, task.agent_id)

        # 4. Per-task egress proxy and broker socket
        aloop = _AsyncLoopThread()
        proxy = EgressProxyServer(self.storage, host="127.0.0.1", port=0)
        proxy_port = aloop.run(proxy.start())

        def hook(req: Any) -> bool:
            if spec.approval_policy == "oracle":
                return req.resource_target in spec.oracle_allowed
            return False

        expansion = ExpansionService(self.storage, provenance_enabled=True, user_approval_hook=hook,
                                     simulated_user_policy=spec.approval_policy)
        broker = ToolBroker(self.storage, expansion_service=expansion)
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

        delivery = ExpansionDelivery(ws, self.storage)
        rpc = BrokerRPCServer(broker, ws / BROKER_SOCKET_NAME, task_id, llm_model=llm_model, llm_options=llm_options,
                              delivery=delivery, cgroup_reader=cgroup_ctl.read_proc_cgroup)
        rpc.start()
        self.live["rpc"] = rpc

        cond = (spec.condition or "").split("_")[0]
        is_direct = cond in ("A", "D")
        needs_enforcer = cond in ("C", "D") or (not cond)
        proxy_for_landlock = proxy_port if cond != "D" else None

        # Sandbox spec compiled from the boundary
        spec_rules = compile_landlock_rules(boundary, ws, proxy_for_landlock, runtime_dir=ws / "runtime")
        if self.test_hooks.get("rules_override") == "allow_workspace_read":
            # TEST ONLY: simulate a mis-compiled ruleset to exercise the unprevented-OUTSIDE freeze.
            spec_rules["rules"].append({"path": str(ws.resolve()), "access": ["read_file", "read_dir"]})
        rules_path = write_rules_file(spec_rules, control / "rules.json")
        (control / "rules_compile_report.json").write_text(json.dumps(spec_rules["_compile_report"], indent=1))

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
            "system_prompt": spec.system_prompt,
            "max_iterations": spec.max_iterations,
            "command_timeout": spec.command_timeout_s,
            "model": llm_model,
            "tools_schema": spec.tools_schema,
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
        ]

        world_cmd = []
        if spec.use_eval_world or bool(spec.decoys) or cond in ("A", "B", "C", "D"):
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
                "--",
            ]

        sensor_chain = [str(SENSOR_BIN), "--events-fd", str(events_w), "--gate-fd", str(gate_r), "--"]
        sandbox_chain = []
        if needs_enforcer:
            sandbox_chain = [str(SECCOMP_BIN), *enforcer_args, "--status-fd", str(status_w), "--"]
        shim_chain = [interpreter, "-E", "-s", "-B", str(ws / "runtime" / "agent_shim.py")]

        chain = [*world_cmd, *sensor_chain, *sandbox_chain, *shim_chain]
        cmd = ["systemd-run", "--user", "--scope", "--quiet", f"--unit={unit}", "--", *env_args, *chain]

        launcher_cg = cgroup_ctl.read_proc_cgroup(os.getpid())
        stdout_f = open(control / "sandbox_stdout.log", "wb")
        stderr_f = open(control / "sandbox_stderr.log", "wb")
        pass_fds = (token_r, task_r, result_w, events_w, gate_r) if status_w == -1 else (token_r, task_r, result_w, events_w, gate_r, status_w)
        proc = subprocess.Popen(cmd, cwd=str(ws), stdout=stdout_f, stderr=stderr_f, stdin=subprocess.DEVNULL,
                                pass_fds=pass_fds)
        for fd in (token_r, task_r, result_w, events_w, gate_r):
            os.close(fd)
        if status_w != -1:
            os.close(status_w)
        self.live["scope_pid"] = proc.pid

        # Correlator + readers
        current_boundary = {"b": boundary}

        def boundary_provider() -> Any:
            return current_boundary["b"]

        correlator = OSEventCorrelator(
            self.storage, task_id, str(ws), mode, spec_rules, proxy_port, interpreter, str(ws / "runtime"),
            seccomp_active=True, on_violation=lambda r, d: self._freeze(r, d), on_open=delivery.on_open,
        )
        raw_events = open(control / "sensor_events.jsonl", "w", encoding="utf-8")
        events_done = threading.Event()

        def read_events() -> None:
            with os.fdopen(events_r, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    raw_events.write(line)
                    try:
                        correlator.handle_line(line, boundary_provider)
                    except Exception as ex:  # never let one bad line stop observation
                        raw_events.write(json.dumps({"correlator_error": str(ex)}) + "\n")
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
        try:
            # 3. Task cgroup read back from /proc/<pid>/cgroup
            try:
                cg = cgroup_ctl.wait_for_scope(proc.pid, unit, launcher_cg)
            except RuntimeError as e:
                aborted = f"scope_not_established: {e}"
                raise
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
            rpc.expected_cgroup = cg

            # Release the gate: the agent chain may now exec.
            os.write(gate_w, b"1")
            os.close(gate_w)
            gate_w = -1

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
            need = seccomp_baseline + 2  # sensor's trace filter + seccomp_filter
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
            requires_rules = (spec.condition or "").split("_")[0] in ("C", "D")
            if requires_rules and isolation.get("enforcer") != "rules":
                aborted = "condition requires boundary-compiled isolation; refusing legacy_workspace"
                self._freeze("isolation_below_condition_requirement", problems)
            elif problems and mode == EnforcementMode.ENFORCE and cond not in ("A", "B"):
                self._freeze("isolation_below_enforce_requirement", problems)
            else:
                rpc.armed.set()

            # Watchdog
            hard_deadline = time.monotonic() + spec.timeout_s
            frozen_at: float | None = None
            while proc.poll() is None:
                if self._frozen.is_set():
                    frozen_at = frozen_at or time.monotonic()
                    if time.monotonic() - frozen_at >= spec.freeze_timeout_s:
                        self._kill("frozen_then_killed_after_timeout")
                elif not rpc.is_alive():
                    self._freeze("broker_socket_died")
                elif time.monotonic() > hard_deadline:
                    self._kill("task_timeout")
                hook_fn = self.test_hooks.get("during_run")
                if hook_fn:
                    hook_fn(self)
                time.sleep(0.05)

            # The scope's main process (the sensor) has exited.
            events_done.wait(timeout=10.0)
            if correlator.exit_trailer is None:
                self._freeze("sensor_exited_early", {"sensor_exit_code": proc.returncode})
            if cgroup_ctl.cgroup_pids(cg):
                if not self._frozen.is_set():
                    self._freeze("processes_left_after_sensor_exit")
                time.sleep(spec.freeze_timeout_s)
                self._kill("frozen_then_killed_after_timeout")
        except RuntimeError as e:
            aborted = aborted or str(e)
            if self.live.get("cgroup"):
                self._kill(f"aborted: {aborted}")
            else:
                proc.kill()
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
            events_done.wait(timeout=5.0)
            correlator.flush()
            raw_events.close()
            stdout_f.close()
            stderr_f.close()
            rpc.stop()
            try:
                aloop.run(proxy.stop())
            except Exception:
                pass
            aloop.stop()
            delivery.cleanup()
            self.storage.revoke_token(token)

        if not self.termination:
            self.termination = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "reason": "agent_exited", "sensor_exit_code": proc.returncode}

        shim_result = None
        if result_box["data"]:
            try:
                shim_result = json.loads(result_box["data"].decode("utf-8", "replace"))
            except json.JSONDecodeError:
                shim_result = {"status": "unparseable_result"}

        t = self.storage.get_task(task_id)
        if t:
            t.status = TaskLifecycle.COMPLETED if (shim_result or {}).get("status") == "completed" and not self.freeze_events else TaskLifecycle.TERMINATED
            t.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.storage.save_task(t)

        sensor_status = {
            "binary": str(SENSOR_BIN.name),
            "mode": "observation_only",
            "ran": correlator.sensor_pid is not None,
            "exit_trailer_seen": correlator.exit_trailer is not None,
            "exited_early": correlator.exit_trailer is None,
            "events_observed": len(correlator.records),
            "cross_attributions": correlator.cross_attributions,
            "unattributed_reasons": correlator.unattributed_reasons,
            "syscalls_observed": ["open", "openat", "openat2", "execve", "execveat", "connect"],
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
                "llm_provider": provider_label,
                "llm_model": llm_model,
                "runtime_code_sha256": runtime_hashes,
                "landlock_rules_sha256": _sha256_file(rules_path),
                "rpc_call_counts": dict(rpc.call_counts),
                "rpc_rejections": rpc.rejections,
                "aborted": aborted,
            },
        )
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        receipt_path = self.receipts_dir / f"{task_id}.json"
        receipt_path.write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")

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
