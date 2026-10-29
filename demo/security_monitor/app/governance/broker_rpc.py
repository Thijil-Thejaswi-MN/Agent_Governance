"""Agent-facing broker RPC over a per-task Unix domain socket (M6.1).

Exposes exactly seven endpoints to the sandboxed agent:
    read_file, write_file, http_get, call_agent, request_access,
    run_command_check, llm_complete
Dispatch is through an explicit table of handlers with whitelisted parameters;
there is no generic attribute lookup, so approve/deny/grant (or any other broker
or expansion-service method) are unreachable from this socket. Approval stays
with the user-facing control plane.

Each request is authenticated by the task token (which the shim received over a
pipe fd) and must belong to this socket's task. When the task's cgroup is known,
the connecting peer (SO_PEERCRED) must also be a process inside that cgroup.
Requests are size-limited and every call has a timeout.
"""
from __future__ import annotations

import datetime
import json
import os
import socket
import struct
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from .llm_agent import RPC_MAX_REQUEST_BYTES, rpc_recv_frame, rpc_send_frame
from .models import EventSource, EventVerdict, ExpansionRequest, ExpansionStatus, GovernanceEvent, RiskTier, TaskAction

AGENT_ENDPOINTS = (
    "read_file",
    "write_file",
    "http_get",
    "call_agent",
    "request_access",
    "run_command_check",
    "llm_complete",
)


def _peer_pid(conn: socket.socket) -> int | None:
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, _uid, _gid = struct.unpack("3i", creds)
        return pid
    except OSError:
        return None


def _str_param(params: dict[str, Any], name: str, max_len: int = 4096) -> str:
    v = params.get(name, "")
    if not isinstance(v, str):
        raise ValueError(f"parameter '{name}' must be a string")
    if len(v) > max_len:
        raise ValueError(f"parameter '{name}' exceeds {max_len} chars")
    return v


class BrokerRPCServer:
    """Threaded UDS server bridging the sandboxed agent to a ToolBroker."""

    def __init__(
        self,
        broker: Any,
        socket_path: str | Path,
        task_id: str,
        llm_model: str | None = None,
        llm_options: dict[str, Any] | None = None,
        delivery: Any | None = None,
        expected_cgroup: str | None = None,
        cgroup_reader: Callable[[int], str | None] | None = None,
        read_timeout: float = 30.0,
        call_timeout: float = 120.0,
        llm_timeout: float = 330.0,
        max_request_bytes: int = RPC_MAX_REQUEST_BYTES,
        arm_timeout: float = 15.0,
    ) -> None:
        self.broker = broker
        self.socket_path = Path(socket_path)
        self.task_id = task_id
        self.llm_model = llm_model
        self.llm_options = dict(llm_options or {})
        self.delivery = delivery
        self.expected_cgroup = expected_cgroup
        self.cgroup_reader = cgroup_reader
        self.read_timeout = read_timeout
        self.call_timeout = call_timeout
        self.llm_timeout = llm_timeout
        self.max_request_bytes = max_request_bytes
        self.arm_timeout = arm_timeout

        self.armed = threading.Event()
        self.llm_requests: list[list[dict[str, Any]]] = []  # messages sent to the model (evaluation ground truth)
        self.call_counts: dict[str, int] = {}
        self.rejections: list[dict[str, Any]] = []
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = False
        self._lock = threading.Lock()

        self._handlers: dict[str, Callable[[str, dict[str, Any]], Any]] = {
            "read_file": self._h_read_file,
            "write_file": self._h_write_file,
            "http_get": self._h_http_get,
            "call_agent": self._h_call_agent,
            "request_access": self._h_request_access,
            "run_command_check": self._h_run_command_check,
            "llm_complete": self._h_llm_complete,
        }
        assert tuple(self._handlers) == AGENT_ENDPOINTS

    # --- lifecycle ---
    def start(self) -> None:
        if self.socket_path.exists() or self.socket_path.is_symlink():
            self.socket_path.unlink()
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        s.listen(16)
        s.settimeout(0.5)
        self._sock = s
        self._thread = threading.Thread(target=self._accept_loop, name=f"broker-rpc-{self.task_id}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stopping = True
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
        try:
            if self.socket_path.exists():
                self.socket_path.unlink()
        except OSError:
            pass

    def is_alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and self.socket_path.exists())

    # --- server loop ---
    def _accept_loop(self) -> None:
        while not self._stopping:
            try:
                conn, _ = self._sock.accept()  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _reject(self, reason: str, method: str | None, peer: int | None) -> None:
        with self._lock:
            self.rejections.append({
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "method": method if method in AGENT_ENDPOINTS else (str(method)[:64] if method else None),
                "reason": reason,
                "peer_pid": peer,
            })
        evt = GovernanceEvent(
            event_id=f"evt_rpc_{uuid.uuid4().hex[:10]}",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=self.task_id,
            agent_id="agent_rpc_peer",
            pid=peer,
            kind="broker_rpc",
            target=str(method)[:64] if method else "unknown",
            details={"reason": reason, "channel": "broker_rpc"},
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.HIGH,
            action_taken=TaskAction.BLOCK_ACTION,
            prevented=True,
            rule_matched=f"broker rpc rejected: {reason}",
            boundary_version=None,
        )
        try:
            self.broker.storage.record_event(evt)
        except Exception:
            pass

    def _serve(self, conn: socket.socket) -> None:
        peer = _peer_pid(conn)
        method = None
        try:
            conn.settimeout(self.read_timeout)
            try:
                req = rpc_recv_frame(conn, self.max_request_bytes)
            except ValueError as ve:
                self._reject(f"malformed_or_oversized_request: {ve}", None, peer)
                rpc_send_frame(conn, {"ok": False, "error_type": "ValueError", "error": str(ve)})
                return
            method = req.get("method")
            token = req.get("token")
            params = req.get("params") or {}
            if not isinstance(method, str) or not isinstance(token, str) or not isinstance(params, dict):
                self._reject("bad_request_shape", method if isinstance(method, str) else None, peer)
                rpc_send_frame(conn, {"ok": False, "error_type": "ValueError", "error": "bad request"})
                return
            handler = self._handlers.get(method)
            if handler is None:
                self._reject("endpoint_not_exposed", method, peer)
                rpc_send_frame(conn, {"ok": False, "error_type": "PermissionError",
                                      "error": f"endpoint '{method[:64]}' is not exposed to agents"})
                return
            if not self.armed.wait(self.arm_timeout):
                self._reject("task_not_armed", method, peer)
                rpc_send_frame(conn, {"ok": False, "error_type": "RuntimeError", "error": "task sandbox not armed"})
                return
            owner = self.broker.storage.lookup_task_by_token(token)
            if not owner or owner[0] != self.task_id:
                self._reject("token_not_for_this_task", method, peer)
                rpc_send_frame(conn, {"ok": False, "error_type": "PermissionError", "error": "invalid task token"})
                return
            if self.expected_cgroup is not None:
                peer_cg = self.cgroup_reader(peer) if (self.cgroup_reader and peer) else None
                if peer_cg is None or not (peer_cg == self.expected_cgroup or peer_cg.startswith(self.expected_cgroup + "/")):
                    self._reject("peer_not_in_task_cgroup", method, peer)
                    rpc_send_frame(conn, {"ok": False, "error_type": "PermissionError",
                                          "error": "caller is not a process of this task"})
                    return

            with self._lock:
                self.call_counts[method] = self.call_counts.get(method, 0) + 1
            timeout = self.llm_timeout if method == "llm_complete" else self.call_timeout
            ok, value = self._run_with_timeout(handler, token, params, timeout)
            conn.settimeout(self.read_timeout)
            if ok:
                rpc_send_frame(conn, {"ok": True, "result": value})
            else:
                etype, msg = value
                rpc_send_frame(conn, {"ok": False, "error_type": etype, "error": msg})
        except (OSError, ConnectionError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _run_with_timeout(fn: Callable, token: str, params: dict[str, Any], timeout: float) -> tuple[bool, Any]:
        box: dict[str, Any] = {}

        def work() -> None:
            try:
                box["value"] = fn(token, params)
            except PermissionError as pe:
                box["error"] = ("PermissionError", str(pe))
            except ValueError as ve:
                box["error"] = ("ValueError", str(ve))
            except Exception as ex:
                box["error"] = ("RuntimeError", f"{type(ex).__name__}: {ex}")

        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            return False, ("RuntimeError", f"broker call timed out after {timeout}s")
        if "error" in box:
            return False, box["error"]
        return True, box.get("value")

    # --- handlers (whitelisted parameters only) ---
    def _h_read_file(self, token: str, p: dict[str, Any]) -> Any:
        file_path = _str_param(p, "file_path")
        try:
            res = self.broker.read_file(token, file_path)
            self.broker.storage.record_task_step(
                self.task_id,
                kind="tool",
                layer="broker",
                verdict="ALLOW",
                summary=f"read_file allowed: {file_path}",
                detail=f"Read {len(res)} characters from {file_path}",
                source_label="enforced",
            )
            return res
        except Exception as err:
            self.broker.storage.record_task_step(
                self.task_id,
                kind="tool",
                layer="broker",
                verdict="BLOCK_ACTION",
                summary=f"read_file blocked: {file_path}",
                detail=str(err),
                source_label="enforced",
            )
            raise

    def _h_write_file(self, token: str, p: dict[str, Any]) -> Any:
        file_path = _str_param(p, "file_path")
        content = p.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        try:
            res = self.broker.write_file(token, file_path, content)
            self.broker.storage.record_task_step(
                self.task_id,
                kind="tool",
                layer="broker",
                verdict="ALLOW",
                summary=f"write_file allowed: {file_path}",
                detail=f"Wrote {len(content)} characters to {file_path}",
                source_label="enforced",
            )
            if file_path.startswith("output/") or file_path.startswith("./output/"):
                self.broker.storage.record_task_step(
                    self.task_id,
                    kind="output",
                    layer="broker",
                    verdict="ALLOW",
                    summary=f"Output file written: {file_path}",
                    detail=content[:2000],
                    source_label="enforced",
                )
            return res
        except Exception as err:
            self.broker.storage.record_task_step(
                self.task_id,
                kind="tool",
                layer="broker",
                verdict="BLOCK_ACTION",
                summary=f"write_file blocked: {file_path}",
                detail=str(err),
                source_label="enforced",
            )
            raise

    def _h_http_get(self, token: str, p: dict[str, Any]) -> Any:
        return self.broker.http_get(token, _str_param(p, "url"))

    def _h_call_agent(self, token: str, p: dict[str, Any]) -> Any:
        msg = p.get("message", {})
        if not isinstance(msg, dict):
            msg = {"text": str(msg)}
        return self.broker.call_agent(token, _str_param(p, "target_agent", 256), msg)

    def _h_request_access(self, token: str, p: dict[str, Any]) -> Any:
        rtype = _str_param(p, "resource_type", 64)
        target = _str_param(p, "resource_target")
        just = _str_param(p, "justification", 2000)

        # 1. Reject targets containing ".." or absolute paths before any lookup
        is_repeat_granted = False
        deliv = None
        prev_req = None

        if self.delivery is not None and rtype == "file_read":
            raw = target.strip().replace("\\", "/")
            parts = [part for part in raw.split("/") if part]
            has_traversal = (
                ".." in parts
                or raw.startswith("/")
                or (len(parts) > 0 and len(parts[0]) == 2 and parts[0][1] == ":")
            )

            if not has_traversal:
                rel = raw
                if rel.startswith("granted/"):
                    rel = rel[len("granted/"):]
                rel = rel.lstrip("./")

                try:
                    granted_dir = self.delivery.granted.resolve()
                    dst = (self.delivery.granted / rel).resolve()
                    # Resolve and require the path to stay strictly inside granted/
                    dst.relative_to(granted_dir)
                    path_inside_granted = True
                except (ValueError, Exception):
                    path_inside_granted = False

                if path_inside_granted and dst.is_file():
                    prev_req = self.delivery._latest_request(self.task_id, rtype, target)
                    if prev_req and prev_req.status == ExpansionStatus.APPROVED:
                        candidate_deliv = self.delivery.deliver(self.task_id, rtype, target, True)
                        # 2. Only return granted=True if deliver() returned type == "file_copy"
                        if candidate_deliv.get("type") == "file_copy":
                            is_repeat_granted = True
                            deliv = candidate_deliv

        if is_repeat_granted and prev_req is not None and deliv is not None:
            # 3. Still record the repeat request (broker/storage audit event, e.g. status "duplicate_of:<request_id>") so it appears in the receipt
            now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
            dup_req_id = f"exp_req_dup_{uuid.uuid4().hex[:8]}"
            dup_req = ExpansionRequest(
                request_id=dup_req_id,
                task_id=self.task_id,
                agent_id=prev_req.agent_id,
                resource_type=rtype,
                resource_target=target,
                justification=just,
                baseline_risk_tier=prev_req.baseline_risk_tier,
                effective_risk_tier=prev_req.effective_risk_tier,
                escalated_by_provenance=prev_req.escalated_by_provenance,
                status=ExpansionStatus.APPROVED,
                created_at=now_utc,
                resolved_at=now_utc,
                resolved_by=f"duplicate_of:{prev_req.request_id}",
                single_use=False,
                used_count=prev_req.used_count + 1,
                timeout_seconds=0.0,
            )
            self.broker.storage.save_expansion_request(dup_req)

            try:
                bnd = self.broker.storage.get_boundary(self.task_id)
                bnd_ver = bnd.version if bnd else None
            except Exception:
                bnd_ver = None

            ev_id = self.broker._generate_event_id() if hasattr(self.broker, "_generate_event_id") else f"gov_ev_{uuid.uuid4().hex[:12]}"
            ev = GovernanceEvent(
                event_id=ev_id,
                timestamp=now_utc,
                source=EventSource.TOOL_BROKER,
                task_id=self.task_id,
                agent_id=prev_req.agent_id,
                kind="request_access",
                target=target,
                details={
                    "resource_type": rtype,
                    "justification": just,
                    "status": f"duplicate_of:{prev_req.request_id}",
                    "granted": True,
                },
                verdict=EventVerdict.INSIDE,
                risk_tier=prev_req.effective_risk_tier,
                action_taken=TaskAction.ALLOW,
                prevented=False,
                rule_matched=f"duplicate_of:{prev_req.request_id}",
                boundary_version=bnd_ver,
            )
            self.broker.storage.record_event(ev)

            deliv_dup = dict(deliv)
            deliv_dup["request_id"] = dup_req_id

            return {
                "granted": True,
                "status": f"duplicate_of:{prev_req.request_id}",
                "resource_type": rtype,
                "resource_target": target,
                "baseline_risk": prev_req.baseline_risk_tier.value,
                "effective_risk": prev_req.effective_risk_tier.value,
                "baseline_risk_tier": prev_req.baseline_risk_tier.value,
                "effective_risk_tier": prev_req.effective_risk_tier.value,
                "escalated_by_provenance": prev_req.escalated_by_provenance,
                "delivery": deliv_dup,
            }

        timeout_s = getattr(self.broker, "default_approval_timeout", None)
        if timeout_s is not None:
            res = self.broker.request_access(token, rtype, target, just, timeout_seconds=timeout_s)
        else:
            res = self.broker.request_access(token, rtype, target, just)
        if self.delivery is not None:
            res["delivery"] = self.delivery.deliver(self.task_id, rtype, target, bool(res.get("granted")))
        status_val = res.get("status") or ("APPROVED" if res.get("granted") else "DENIED")
        approver_val = res.get("approved_by") or ("operator" if res.get("granted") else "policy")
        reason_val = res.get("reason") or ("Granted" if res.get("granted") else "Denied")
        self.broker.storage.record_task_step(
            self.task_id,
            kind="expansion",
            layer="broker",
            verdict="APPROVED" if res.get("granted") else "BLOCK_ACTION",
            summary=f"Expansion {target} {str(status_val).lower()} by {approver_val}",
            detail=f"Reason: {reason_val}\nStatus: {status_val}",
            source_label="enforced",
        )
        return res

    def _h_run_command_check(self, token: str, p: dict[str, Any]) -> Any:
        cmd = _str_param(p, "command", 8192)
        try:
            res = self.broker.run_command_check(token, cmd)
            self.broker.storage.record_task_step(
                self.task_id,
                kind="tool",
                layer="broker",
                verdict="ALLOW",
                summary=f"run_command check allowed: {cmd[:60]}",
                detail=f"Command: {cmd}",
                source_label="enforced",
            )
            return res
        except Exception as err:
            self.broker.storage.record_task_step(
                self.task_id,
                kind="tool",
                layer="broker",
                verdict="BLOCK_ACTION",
                summary=f"run_command check blocked: {cmd[:60]}",
                detail=str(err),
                source_label="enforced",
            )
            raise

    def _h_llm_complete(self, token: str, p: dict[str, Any]) -> Any:
        messages = p.get("messages")
        tools = p.get("tools")
        if not isinstance(messages, list) or not all(isinstance(m, dict) for m in messages):
            raise ValueError("messages must be a list of objects")
        if tools is not None and not isinstance(tools, list):
            raise ValueError("tools must be a list")
        with self._lock:
            self.llm_requests.append(messages)
            turn_idx = len(self.llm_requests)
        # The model, provider and options are fixed by the launcher, never by the agent.
        res = self.broker.llm_complete(token=token, messages=messages, tools=tools, model=self.llm_model, **self.llm_options)
        content = res.get("content") or ""
        tool_calls = res.get("tool_calls") or []
        summary = f"Model turn {turn_idx}: response generated"
        if tool_calls:
            names = [tc.get("function", {}).get("name", "tool") for tc in tool_calls]
            summary += f" (invoking {', '.join(names)})"
        detail_text = content[:2000] if content else json.dumps(tool_calls, indent=2)[:2000]
        self.broker.storage.record_task_step(
            self.task_id,
            kind="model",
            layer="broker",
            verdict="ALLOW",
            summary=summary,
            detail=detail_text,
            source_label="model output (untrusted)",
        )
        return {k: res.get(k) for k in ("role", "content", "tool_calls", "provider", "model", "model_digest")}
