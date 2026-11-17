"""Agent-facing broker RPC over a per-task Unix domain socket (M6.1).

Exposes exactly eight endpoints to the sandboxed agent:
    read_file, write_file, http_get, call_agent, request_access,
    run_command_check, run_command_begin, llm_complete
Dispatch is through an explicit table of handlers with whitelisted parameters;
there is no generic attribute lookup, so approve/deny/grant (or any other broker
or expansion-service method) are unreachable from this socket. Approval stays
with the user-facing control plane.

Each request is authenticated by the task token (which the shim received over a
pipe fd) and must belong to this socket's task. When the task's cgroup is known,
the connecting peer (SO_PEERCRED) must also be a process inside that cgroup.
Requests are size-limited and every call has a timeout. At most MAX_CONNECTIONS are
served at once, and the per-task lists kept in memory are bounded (audit finding A7).
"""
from __future__ import annotations

import collections
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

from .pathnorm import strip_dot_slash
from .llm_agent import RPC_MAX_REQUEST_BYTES, rpc_recv_frame, rpc_send_frame
from .staged_writes import normalize_write_target
from .models import EventSource, EventVerdict, ExpansionRequest, ExpansionStatus, GovernanceEvent, RiskTier, TaskAction

AGENT_ENDPOINTS = (
    "read_file",
    "write_file",
    "http_get",
    "call_agent",
    "request_access",
    "run_command_check",
    "run_command_begin",
    "llm_complete",
)

MAX_PENDING_CALLS = 64
MAX_CONNECTIONS = 32  # served at once; more are closed straight away and counted
MAX_REJECTIONS_KEPT = 200  # rejected requests kept for the receipt; the rest are only counted


def _proc_ppid(pid: int) -> int | None:
    """Parent pid from /proc/<pid>/stat (the field after the parenthesised command name)."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        return int(stat.rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return None


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
        call_placer: Callable[[int, str], dict[str, Any]] | None = None,
        ppid_reader: Callable[[int], int | None] | None = None,
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
        self.call_placer = call_placer
        self.ppid_reader = ppid_reader or _proc_ppid
        self.read_timeout = read_timeout
        self.call_timeout = call_timeout
        self.llm_timeout = llm_timeout
        self.max_request_bytes = max_request_bytes
        self.arm_timeout = arm_timeout

        self.armed = threading.Event()
        # Messages sent to the model (evaluation ground truth uses the last); only the latest few are
        # kept, the turn count is separate.
        self.llm_requests: collections.deque[list[dict[str, Any]]] = collections.deque(maxlen=4)
        self.llm_turns = 0
        self.rejections_dropped = 0
        self.connections_refused = 0
        self._conn_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.call_counts: dict[str, int] = {}
        self.rejections: list[dict[str, Any]] = []
        # Prompt-to-task attribution: one entry per command a tool call ran, and the
        # child cgroup (call_NNN) it ran in. Checked commands wait here for their spawn.
        self.tool_calls: list[dict[str, Any]] = []
        self._pending_calls: dict[str, dict[str, Any]] = {}
        self._call_seq = 0
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
            "run_command_begin": self._h_run_command_begin,
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
            if not self._conn_slots.acquire(blocking=False):
                with self._lock:
                    self.connections_refused += 1
                try:
                    conn.close()
                except OSError:
                    pass
                continue

            def serve(c: socket.socket = conn) -> None:
                try:
                    self._serve(c)
                finally:
                    self._conn_slots.release()

            threading.Thread(target=serve, daemon=True).start()

    def _reject(self, reason: str, method: str | None, peer: int | None) -> None:
        with self._lock:
            if len(self.rejections) >= MAX_REJECTIONS_KEPT:
                self.rejections_dropped += 1
                return  # counted only: no further list entry or stored event for a flood
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
            params = {k: v for k, v in params.items() if k != "_peer_pid"}
            if method == "run_command_begin":
                params["_peer_pid"] = peer  # from SO_PEERCRED, never from the agent
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
        except ValueError as err:
            # A malformed call (no path): an error for the model, not a blocked attempt.
            self.broker.storage.record_task_step(
                self.task_id,
                kind="tool",
                layer="broker",
                verdict="ERROR",
                summary=f"read_file failed: {err}",
                detail=str(err),
                source_label="enforced",
            )
            raise
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
        except ValueError as err:
            # A malformed call (no path): an error for the model, not a blocked attempt.
            self.broker.storage.record_task_step(
                self.task_id,
                kind="tool",
                layer="broker",
                verdict="ERROR",
                summary=f"write_file failed: {err}",
                detail=str(err),
                source_label="enforced",
            )
            raise
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

    def _step(self, verdict: str, summary: str, detail: str) -> None:
        self.broker.storage.record_task_step(
            self.task_id, kind="tool", layer="broker", verdict=verdict,
            summary=summary, detail=detail, source_label="enforced",
        )

    def _h_http_get(self, token: str, p: dict[str, Any]) -> Any:
        url = _str_param(p, "url")
        try:
            res = self.broker.http_get(token, url)
        except Exception as err:
            # Shown on the run page like a refused file read (it was only in the event log before).
            self._step("BLOCK_ACTION", f"http_get blocked: {url}", str(err))
            raise
        self._step("ALLOW", f"http_get allowed: {url}", f"Fetched {url}")
        return res

    def _h_call_agent(self, token: str, p: dict[str, Any]) -> Any:
        msg = p.get("message", {})
        if not isinstance(msg, dict):
            msg = {"text": str(msg)}
        target = _str_param(p, "target_agent", 256)
        try:
            res = self.broker.call_agent(token, target, msg)
        except Exception as err:
            self._step("BLOCK_ACTION", f"call_agent blocked: {target}", str(err))
            raise
        self._step("ALLOW", f"call_agent allowed: {target}", f"Message sent to {target}")
        return res

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
                rel = strip_dot_slash(rel)

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

        if rtype == "file_write" and self.delivery is not None and getattr(self.delivery, "staging", False):
            target = normalize_write_target(target) or target  # "staged/output/x.txt" asks for output/x.txt

        # A decision already made in this run is not asked again: a block stays a block, and an
        # approved file that does not exist in the task folder is reported as missing.
        repeat = self._repeat_decision(rtype, target, just)
        if repeat is not None:
            return repeat
        already = self._already_allowed(rtype, target)
        if already is not None:
            return already

        # Content-reviewed writes: a file the agent was not given is staged first, and the
        # snapshot taken now (not the file as it is later) is what the person reviews and what lands.
        if rtype == "file_write" and self.delivery is not None and getattr(self.delivery, "staging", False):
            staged = self._stage_for_review(target)
            if staged is not None:
                return staged

        timeout_s = getattr(self.broker, "default_approval_timeout", None)
        if timeout_s is not None:
            res = self.broker.request_access(token, rtype, target, just, timeout_seconds=timeout_s)
        else:
            res = self.broker.request_access(token, rtype, target, just)
        if self.delivery is not None:
            res["delivery"] = self.delivery.deliver(self.task_id, rtype, target, bool(res.get("granted")))
            if res.get("granted") and res["delivery"].get("reason") == "source_missing_or_outside_workspace":
                res["message"] = f"'{target}' was approved, but no such file exists in the task folder."
            if rtype == "file_write" and getattr(self.delivery, "staging", False) and res.get("granted"):
                d = res["delivery"]
                if d.get("type") == "file_land":
                    res["message"] = (f"Approved. The reviewed content was saved to '{d['landed_path']}' "
                                      f"(SHA-256 {d['content_sha256'][:12]}...). You cannot change that file yourself.")
                else:
                    res["granted"] = False
                    res["message"] = f"Approved, but '{target}' was not saved: {str(d.get('reason', 'unknown')).replace('_', ' ')}."
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

    def _stage_for_review(self, target: str) -> dict[str, Any] | None:
        """Snapshots staged/<target>. Returns a reply when there is nothing to review, else None."""
        snap = self.delivery.stage_snapshot(target)
        if not snap.get("ok"):
            reason = snap.get("reason", "not_staged")
            where = snap.get("staged_path") or f"staged/{target}"
            if reason == "not_staged":
                message = (f"To create '{target}', first write the full content to '{where}' "
                           f"(with write_file or the shell), then call request_access again with resource_type "
                           f"'file_write' and resource_target '{target}'. A person will review that exact content.")
            elif reason == "invalid_target":
                message = f"'{target}' is not a file path inside the task folder."
            else:
                message = f"'{where}' cannot be reviewed ({reason.replace('_', ' ')}). Write it as a plain file."
            self._step("BLOCK_ACTION", f"Write request {target}: nothing to review", message)
            return {"granted": False, "status": "STAGE_FIRST" if reason == "not_staged" else "REFUSED",
                    "resource_type": "file_write", "resource_target": target, "reason": reason, "message": message}
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            bnd = self.broker.storage.get_boundary(self.task_id)
            bnd_ver = bnd.version if bnd else None
        except Exception:
            bnd_ver = None
        details = {k: snap[k] for k in ("staged_path", "size_bytes", "content_sha256", "binary", "preview", "truncated")}
        details["resource_type"] = "file_write"
        self.broker.storage.record_event(GovernanceEvent(
            event_id=self.broker._generate_event_id() if hasattr(self.broker, "_generate_event_id") else f"gov_ev_{uuid.uuid4().hex[:12]}",
            timestamp=now_utc, source=EventSource.TOOL_BROKER, task_id=self.task_id,
            agent_id=getattr(self.broker.storage.get_task(self.task_id), "agent_id", "agent") or "agent",
            kind="staged_write", target=snap["target"], details=details,
            verdict=EventVerdict.INSIDE, risk_tier=RiskTier.LOW, action_taken=TaskAction.LOG, prevented=False,
            rule_matched="staged_for_review", boundary_version=bnd_ver,
        ))
        self._step("ALLOW", f"Staged {snap['target']} for review ({snap['size_bytes']} bytes)",
                   f"SHA-256 {snap['content_sha256']}")
        return None

    @staticmethod
    def _norm_target(target: str) -> str:
        t = str(target).strip().replace("\\", "/")
        if t.startswith("granted/"):
            t = t[len("granted/"):]
        while t.startswith("./"):
            t = t[2:]
        return t

    def _already_allowed(self, rtype: str, target: str) -> dict[str, Any] | None:
        """A file read the boundary already allows, asked for by a shorter name
        (e.g. "system_audit.txt" for "input/system_audit.txt"), is answered with the allowed path
        instead of asking the person about a file the task already has."""
        if rtype != "file_read":
            return None
        norm = self._norm_target(target)
        if not norm or norm.startswith("/") or ".." in norm.split("/"):
            return None
        boundary = self.broker.storage.get_boundary(self.task_id)
        if not boundary:
            return None
        allowed = [f for f in boundary.files_read if "*" not in f and "?" not in f]
        if norm in allowed:
            match = norm
        else:
            hits = [f for f in allowed if f.endswith("/" + norm)]
            if len(hits) != 1:
                return None
            match = hits[0]
        self.broker.storage.record_task_step(
            self.task_id, kind="expansion", layer="broker", verdict="ALLOW",
            summary=f"Not asked: {target} is already allowed as {match}",
            detail="The request named a file the boundary already allows, so no approval was needed.",
            source_label="enforced",
        )
        return {
            "granted": True,
            "status": "already_in_boundary",
            "message": f"'{target}' is already allowed for this task. Read it as '{match}'.",
            "resource_type": rtype,
            "resource_target": match,
            "delivery": {"type": "none", "reason": "already_in_boundary", "path": match},
        }

    def _repeat_decision(self, rtype: str, target: str, just: str) -> dict[str, Any] | None:
        """Returns an immediate answer when this run already decided on the same resource.

        DENIED (by a person, a rule or the fail-closed timeout) stays denied for the rest of
        the run, so a blocked request is never shown to the person again. An approved file read
        whose file does not exist in the task folder is answered "not found" instead of creating
        a new pending request. Single-use approvals are not reused."""
        norm = self._norm_target(target)
        prior = sorted(
            (r for r in self.broker.storage.list_expansion_requests(task_id=self.task_id)
             if r.resource_type == rtype and self._norm_target(r.resource_target) == norm
             and r.status in (ExpansionStatus.APPROVED, ExpansionStatus.DENIED, ExpansionStatus.REVOKED)
             and not str(r.resolved_by or "").startswith(("duplicate_of:", "repeat_of:"))),
            key=lambda r: r.created_at,
        )
        if not prior:
            return None
        last = prior[-1]  # the most recent decision on this resource
        if last.status == ExpansionStatus.REVOKED:
            granted, status = False, f"repeat_of:{last.request_id}:revoked"
            message = ("A person cancelled this access earlier in this run. "
                       "You will not be asked again; continue without this resource.")
            step = f"Not asked again: access to {target} was cancelled in this run"
        elif last.status == ExpansionStatus.DENIED:
            granted, status = False, f"repeat_of:{last.request_id}:denied"
            message = (f"Already denied earlier in this run (by {last.resolved_by}). "
                       "You will not be asked again; continue without this resource.")
            step = f"Not asked again: {target} was already blocked in this run"
        elif (last.status == ExpansionStatus.APPROVED and rtype == "file_read" and not last.single_use
              and self.delivery is not None and ".." not in norm.split("/") and not norm.startswith("/")
              and not (self.delivery.ws / norm).is_file() and not (self.delivery.granted / norm).is_file()):
            granted, status = False, f"repeat_of:{last.request_id}:not_found"
            message = f"'{target}' was approved, but no such file exists in the task folder."
            step = f"Not asked again: {target} was approved but does not exist in the task folder"
        else:
            return None

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # Audited like any other request (it appears in the receipt), but resolved at once.
        self.broker.storage.save_expansion_request(ExpansionRequest(
            request_id=f"exp_req_rep_{uuid.uuid4().hex[:8]}",
            task_id=self.task_id,
            agent_id=last.agent_id,
            resource_type=rtype,
            resource_target=target,
            justification=just,
            baseline_risk_tier=last.baseline_risk_tier,
            effective_risk_tier=last.effective_risk_tier,
            escalated_by_provenance=last.escalated_by_provenance,
            status=ExpansionStatus.DENIED,
            created_at=now_utc,
            resolved_at=now_utc,
            resolved_by=f"repeat_of:{last.request_id}",
            reason=message,
            single_use=False,
            timeout_seconds=0.0,
        ))
        self.broker.storage.record_event(GovernanceEvent(
            event_id=f"gov_ev_{uuid.uuid4().hex[:12]}",
            timestamp=now_utc,
            source=EventSource.TOOL_BROKER,
            task_id=self.task_id,
            agent_id=last.agent_id,
            kind="request_access",
            target=target,
            details={"resource_type": rtype, "justification": just, "status": status, "granted": granted},
            verdict=EventVerdict.OUTSIDE,
            risk_tier=last.effective_risk_tier,
            action_taken=TaskAction.BLOCK_ACTION,
            prevented=True,
            rule_matched=status,
            boundary_version=None,
        ))
        self.broker.storage.record_task_step(
            self.task_id, kind="expansion", layer="broker", verdict="BLOCK_ACTION",
            summary=step, detail=f"Earlier decision: {last.request_id} ({last.status.value} by {last.resolved_by})",
            source_label="enforced",
        )
        return {
            "granted": False,
            "status": status,
            "message": message,
            "resource_type": rtype,
            "resource_target": target,
            "baseline_risk": last.baseline_risk_tier.value,
            "effective_risk": last.effective_risk_tier.value,
            "baseline_risk_tier": last.baseline_risk_tier.value,
            "effective_risk_tier": last.effective_risk_tier.value,
            "escalated_by_provenance": last.escalated_by_provenance,
            "delivery": {"type": "none", "reason": status.split(":")[-1]},
        }

    def _h_run_command_check(self, token: str, p: dict[str, Any]) -> Any:
        cmd = _str_param(p, "command", 8192)
        try:
            res = self.broker.run_command_check(token, cmd)
            call_id = self._new_call(cmd)
            self.broker.storage.record_task_step(
                self.task_id,
                kind="tool",
                layer="broker",
                verdict="ALLOW",
                summary=f"run_command check allowed ({call_id}): {cmd[:60]}",
                detail=f"Command: {cmd}\nTool call: {call_id}",
                source_label="enforced",
            )
            return {**res, "call_id": call_id} if isinstance(res, dict) else res
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

    # --- prompt-to-task attribution (roadmap item 3) ---
    def _new_call(self, command: str) -> str:
        from .redaction import redact_command

        with self._lock:
            self._call_seq += 1
            call_id = f"call_{self._call_seq:03d}"
            entry = {
                "call_id": call_id,
                "tool": "run_command",
                "command": redact_command(command)[:300],
                "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "started_at": None,
                "pid": None,
                "placed": False,
                "cgroup": None,
                "reason": "not_started",
            }
            self.tool_calls.append(entry)
            self._pending_calls[call_id] = entry
            while len(self._pending_calls) > MAX_PENDING_CALLS:  # checked but never spawned
                stale = next(iter(self._pending_calls))
                self._pending_calls.pop(stale)["reason"] = "never_started"
        return call_id

    def _h_run_command_begin(self, token: str, p: dict[str, Any]) -> Any:
        """The shim has spawned an allowed command (held at a gate) and reports its pid.

        The control plane, not the agent, moves that process into the task's child cgroup
        call_NNN before the command runs. The pid must be a direct child of the calling
        process, and each call_id is good for one spawn only. Attribution falls back to the
        task root (never to another task) if the move is not possible.
        """
        call_id = _str_param(p, "call_id", 32)
        pid = p.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
            raise ValueError("pid must be a positive integer")
        peer = p.get("_peer_pid")
        with self._lock:
            entry = self._pending_calls.pop(call_id, None)
        if entry is None:
            raise PermissionError(f"unknown or already used call_id '{call_id[:32]}'")
        entry["started_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry["pid"] = pid
        if not peer or self.ppid_reader(pid) != peer:
            entry["reason"] = "pid_not_a_child_of_caller"
            raise PermissionError("pid is not a child of the calling process")
        if self.call_placer is None:
            entry["reason"] = "no_placer"
        else:
            try:
                out = self.call_placer(pid, call_id) or {}
            except Exception as ex:  # attribution only: the command still runs, labelled task_root
                out = {"ok": False, "reason": f"{type(ex).__name__}: {ex}"}
            entry["placed"] = bool(out.get("ok"))
            entry["cgroup"] = out.get("cgroup")
            entry["reason"] = None if entry["placed"] else str(out.get("reason") or "placer_failed")[:300]
        self._step("ALLOW",
                   f"{call_id} started" + ("" if entry["placed"] else " (not placed in its own cgroup)"),
                   f"Command: {entry['command']}\nPID: {pid}\n"
                   + (f"cgroup: {entry['cgroup']}" if entry["placed"] else f"Reason: {entry['reason']}"))
        return {"call_id": call_id, "placed": entry["placed"]}

    def _h_llm_complete(self, token: str, p: dict[str, Any]) -> Any:
        messages = p.get("messages")
        tools = p.get("tools")
        if not isinstance(messages, list) or not all(isinstance(m, dict) for m in messages):
            raise ValueError("messages must be a list of objects")
        if tools is not None and not isinstance(tools, list):
            raise ValueError("tools must be a list")
        with self._lock:
            self.llm_requests.append(messages)
            self.llm_turns += 1
            turn_idx = self.llm_turns
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
