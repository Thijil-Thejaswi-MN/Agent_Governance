"""Agent-to-Agent Delegation Engine.

Implements real governed child task execution for peer agent calls:
- Refusal checks in strict order: peer_agents boundary, profile existence, cycle detection, depth limit <= 4.
- Child boundary derivation via strict intersection (ceiling ∩ parent boundary).
- Isolated workspace creation with authorized file copy from parent.
- Execution via TaskLauncher (cgroup, Landlock, seccomp, proxy, sensor, receipt).
- Message store recording (requests, replies, integrity, forwarded_from, contains_private).
- Per-root concurrency limit (8 active children).
- Parallel fan-out support (call_agents).
- Propagation of freeze and stop signals from parent to descendants.
"""
from __future__ import annotations

import concurrent.futures
import datetime
import fnmatch
import json
import logging
import os
import shutil
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

from .agent_profiles import load_agent_profile
from .models import EnforcementMode, EventSource, EventVerdict, ExpansionStatus, GovernanceEvent, RiskTier, TaskAction, TaskBoundary, TaskRecord
from .storage import GovernanceStorage

logger = logging.getLogger(__name__)

MAX_DELEGATION_DEPTH = 4
MAX_RUNNING_CHILDREN_PER_ROOT = 8


def intersect_patterns(ceiling_patterns: list[str], parent_patterns: list[str]) -> list[str]:
    """Computes field-by-field pattern intersection ensuring rights only shrink."""
    result: set[str] = set()
    for cp in ceiling_patterns:
        for pp in parent_patterns:
            if cp == pp:
                result.add(cp)
            elif fnmatch.fnmatch(cp, pp):
                # Ceiling pattern is narrower than parent pattern
                result.add(cp)
            elif fnmatch.fnmatch(pp, cp):
                # Parent pattern is narrower than ceiling pattern: only grant parent's subset
                result.add(pp)
    return sorted(result)


def intersect_boundaries(ceiling: dict[str, Any], parent_boundary: TaskBoundary) -> dict[str, list[str]]:
    """Calculates child boundary = target's ceiling ∩ caller's current boundary."""
    tools = sorted(set(ceiling.get("tools", [])) & set(parent_boundary.tools))
    peer_agents = sorted(set(ceiling.get("peer_agents", [])) & set(parent_boundary.peer_agents))
    network = sorted(set(ceiling.get("network", [])) & set(parent_boundary.network))
    files_read = intersect_patterns(ceiling.get("files_read", []), parent_boundary.files_read)
    files_write = intersect_patterns(ceiling.get("files_write", []), parent_boundary.files_write)
    return {
        "tools": tools,
        "peer_agents": peer_agents,
        "network": network,
        "files_read": files_read,
        "files_write": files_write,
    }


class DelegationManager:
    """Coordinates agent-to-agent delegation lifecycle and child task execution."""

    def __init__(
        self,
        storage: GovernanceStorage,
        workspace_base: Path | str | None = None,
        receipts_dir: Path | str | None = None,
        parent_launcher: Any = None,
        test_hooks: dict[str, Any] | None = None,
    ) -> None:
        self.storage = storage
        self.workspace_base = Path(workspace_base or "/tmp/governance_workspaces").resolve()
        self.receipts_dir = Path(receipts_dir or (self.workspace_base / "receipts")).resolve()
        self.parent_launcher = parent_launcher
        self.test_hooks = test_hooks or {}
        self._lock = threading.Lock()
        self._active_children_by_root: dict[str, set[str]] = {}

    def _track_child_start(self, root_task_id: str, child_task_id: str) -> None:
        with self._lock:
            active = self._active_children_by_root.setdefault(root_task_id, set())
            if len(active) >= MAX_RUNNING_CHILDREN_PER_ROOT:
                raise RuntimeError(
                    f"Per-root cap of {MAX_RUNNING_CHILDREN_PER_ROOT} running child tasks reached for root {root_task_id}"
                )
            active.add(child_task_id)

    def _track_child_finish(self, root_task_id: str, child_task_id: str) -> None:
        with self._lock:
            active = self._active_children_by_root.get(root_task_id)
            if active:
                active.discard(child_task_id)

    def delegate_single(
        self,
        token: str,
        target_agent: str,
        message: dict[str, Any] | str,
        fanout_group: str | None = None,
    ) -> dict[str, Any]:
        """Executes a single delegation call to target_agent as an isolated governed task."""
        # 1. Authenticate caller
        lookup = self.storage.lookup_task_by_token(token)
        if not lookup:
            raise PermissionError("Invalid task token")
        caller_task_id, caller_agent_id = lookup

        caller_task = self.storage.get_task(caller_task_id)
        if not caller_task:
            raise RuntimeError(f"Task record not found for {caller_task_id}")

        caller_boundary = self.storage.get_boundary(caller_task_id)
        if not caller_boundary:
            raise RuntimeError(f"Task boundary not found for {caller_task_id}")

        root_task_id = caller_task.root_task_id or caller_task.task_id
        depth = caller_task.depth or 0
        chain = list(caller_task.chain or [caller_task.agent_id])

        text_content = message.get("text", "") if isinstance(message, dict) else str(message)
        if not text_content and isinstance(message, dict):
            text_content = json.dumps(message)

        # 2. Refusal checks in strict order:
        # Check 1: Target in caller's peer_agents boundary
        if target_agent not in caller_boundary.peer_agents:
            reason = f"Target agent '{target_agent}' not permitted in caller peer_agents boundary: {caller_boundary.peer_agents}"
            self._record_refusal(root_task_id, caller_task_id, caller_agent_id, target_agent, fanout_group, text_content, reason)
            raise PermissionError(reason)

        # Check 2: Profile existence
        try:
            profile = load_agent_profile(target_agent)
        except Exception:
            reason = f"Agent profile not found for '{target_agent}'"
            self._record_refusal(root_task_id, caller_task_id, caller_agent_id, target_agent, fanout_group, text_content, reason)
            raise PermissionError(reason)

        # Check 3: Cycle detection
        if target_agent in chain:
            reason = f"Cycle detected: agent '{target_agent}' already exists in delegation chain: {chain}"
            self._record_refusal(root_task_id, caller_task_id, caller_agent_id, target_agent, fanout_group, text_content, reason)
            raise PermissionError(reason)

        # Check 4: Depth limit <= 4
        next_depth = depth + 1
        if next_depth > MAX_DELEGATION_DEPTH:
            reason = f"Maximum delegation depth {MAX_DELEGATION_DEPTH} exceeded: requested depth {next_depth}"
            self._record_refusal(root_task_id, caller_task_id, caller_agent_id, target_agent, fanout_group, text_content, reason)
            raise PermissionError(reason)

        # 3. Check per-root concurrency cap
        child_task_id = f"{caller_task_id}_c{uuid.uuid4().hex[:6]}"
        self._track_child_start(root_task_id, child_task_id)

        # 4. Record request message in a2a_messages
        req_msg_id = f"msg_{uuid.uuid4().hex[:16]}"
        caller_has_private = self._has_read_private_files(caller_task_id, caller_boundary)
        req_row = {
            "message_id": req_msg_id,
            "root_task_id": root_task_id,
            "parent_task_id": caller_task_id,
            "child_task_id": child_task_id,
            "from_agent": caller_agent_id,
            "to_agent": target_agent,
            "kind": "request",
            "fanout_group": fanout_group,
            "reply_to": None,
            "sent_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "text": text_content,
            "verdict": "delivered",
            "reason": None,
            "integrity": "trusted",
            "forwarded_from": [],
            "contains_private": caller_has_private,
        }
        self.storage.save_a2a_message(req_row)

        try:
            # 5. Derive child boundary: ceiling ∩ caller's current boundary
            narrowed = intersect_boundaries(profile["ceiling"], caller_boundary)

            # 6. Prepare child workspace & copy authorized files from parent
            child_ws = self.workspace_base / child_task_id
            child_ws.mkdir(parents=True, exist_ok=True)
            parent_ws = Path(caller_boundary.workspace_root).resolve()
            copied_inputs = self._copy_authorized_inputs(parent_ws, child_ws, narrowed["files_read"])

            # 7. Deadline inheritance: child deadline <= parent remaining time
            deadline_s = self._calculate_deadline(caller_task, profile)

            # 8. Launch child task via TaskLauncher
            from .launcher import TaskLauncher, TaskSpec

            child_launcher = TaskLauncher(
                storage=self.storage,
                workspace_base=self.workspace_base,
                receipts_dir=self.receipts_dir,
                test_hooks=self.test_hooks,
            )

            # Register with parent launcher for freeze / stop cascading
            if self.parent_launcher is not None:
                self.parent_launcher.register_child_launcher(child_launcher)

            child_spec = TaskSpec(
                prompt=text_content,
                task_id=child_task_id,
                requester=caller_task.requested_by or "governance_system",
                agent_id=target_agent,
                inputs=copied_inputs,
                files_read=narrowed["files_read"],
                output_targets=narrowed["files_write"],
                declared_tools=narrowed["tools"],
                network=narrowed["network"],
                peer_agents=narrowed["peer_agents"],
                llm=dict(profile["runner"]),
                timeout_s=deadline_s,
                condition=caller_task.condition,
                owner=caller_task.owner,
                team=caller_task.team,
                parent_task_id=caller_task_id,
                root_task_id=root_task_id,
                depth=next_depth,
                chain=chain + [target_agent],
                approval_policy="operator",
                approval_timeout_s=float(profile.get("approval_timeout_s", 120.0)),
            )

            launch_res = child_launcher.run(child_spec)

            # When a child task ends, any of its requests still pending are closed as denied
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            for req in self.storage.list_expansion_requests(task_id=child_task_id):
                if req.status == ExpansionStatus.PENDING:
                    req.status = ExpansionStatus.DENIED
                    req.resolved_by = "task_ended"
                    req.resolved_at = now_iso
                    req.reason = "Task ended before a decision"
                    self.storage.save_expansion_request(req)

            # 9. Harvest child response and telemetry
            reply_text = ""
            status = "ok"
            failure_reason = None
            if launch_res.shim_result:
                reply_text = launch_res.shim_result.get("final_response") or ""
                if not reply_text and launch_res.shim_result.get("status") == "error":
                    status = "failed"
                    failure_reason = str(launch_res.shim_result.get("error", "execution failed"))
            elif launch_res.receipt and launch_res.receipt.get("final_response"):
                reply_text = str(launch_res.receipt["final_response"])
            elif launch_res.aborted:
                status = "failed"
                failure_reason = f"Child task execution aborted: {launch_res.aborted}"
                reply_text = failure_reason

            if not reply_text and status == "ok":
                reply_text = "Task executed successfully."

            # Collect forwarded_from and contains_private
            child_boundary = self.storage.get_boundary(child_task_id) or caller_boundary
            forwarded_from = self._extract_forwarded_from(child_task_id)
            contains_private = self._has_read_private_files(child_task_id, child_boundary)

            # Record reply message
            reply_msg_id = f"msg_{uuid.uuid4().hex[:16]}"
            reply_row = {
                "message_id": reply_msg_id,
                "root_task_id": root_task_id,
                "parent_task_id": caller_task_id,
                "child_task_id": child_task_id,
                "from_agent": target_agent,
                "to_agent": caller_agent_id,
                "kind": "reply",
                "fanout_group": fanout_group,
                "reply_to": req_msg_id,
                "sent_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "text": reply_text,
                "verdict": "delivered" if status == "ok" else "failed",
                "reason": failure_reason,
                "integrity": "untrusted",
                "forwarded_from": forwarded_from,
                "contains_private": contains_private,
            }
            self.storage.save_a2a_message(reply_row)

            # Track in parent launcher receipts
            if self.parent_launcher is not None:
                doc_hash = ""
                if launch_res.receipt:
                    doc_hash = (launch_res.receipt.get("hash_chain") or {}).get("document_sha256") or ""
                self.parent_launcher.record_child_receipt(child_task_id, doc_hash)
                self.parent_launcher.unregister_child_launcher(child_launcher)

            return {
                "status": status,
                "reply": reply_text,
                "child_task_id": child_task_id,
            }

        finally:
            self._track_child_finish(root_task_id, child_task_id)

    def delegate_parallel(
        self,
        token: str,
        calls: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Starts several child tasks concurrently and returns all replies."""
        group_id = f"fanout_{uuid.uuid4().hex[:12]}"
        results: list[dict[str, Any]] = []

        def _call_one(call_item: dict[str, Any]) -> dict[str, Any]:
            tgt = call_item.get("target") or call_item.get("target_agent", "")
            msg = call_item.get("message", {})
            try:
                res = self.delegate_single(token, tgt, msg, fanout_group=group_id)
                res["target"] = tgt
                return res
            except Exception as e:
                return {
                    "status": "refused",
                    "reply": str(e),
                    "child_task_id": None,
                    "target": tgt,
                }

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(calls))) as executor:
            futures = [executor.submit(_call_one, c) for c in calls]
            for f in futures:
                results.append(f.result())
        return results

    def _record_refusal(
        self,
        root_task_id: str,
        parent_task_id: str,
        from_agent: str,
        to_agent: str,
        fanout_group: str | None,
        text: str,
        reason: str,
    ) -> None:
        """Stores a refused request in a2a_messages and records a governance event."""
        msg_id = f"msg_{uuid.uuid4().hex[:16]}"
        row = {
            "message_id": msg_id,
            "root_task_id": root_task_id,
            "parent_task_id": parent_task_id,
            "child_task_id": None,
            "from_agent": from_agent,
            "to_agent": to_agent,
            "kind": "request",
            "fanout_group": fanout_group,
            "reply_to": None,
            "sent_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "text": text,
            "verdict": "refused",
            "reason": reason,
            "integrity": "trusted",
            "forwarded_from": [],
            "contains_private": False,
        }
        self.storage.save_a2a_message(row)

        ev = GovernanceEvent(
            event_id=f"evt_{uuid.uuid4().hex[:16]}",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=parent_task_id,
            agent_id=from_agent,
            kind="peer_agent",
            target=to_agent,
            details={"refusal_reason": reason, "message_summary": text[:100]},
            verdict=EventVerdict.OUTSIDE,
            risk_tier=RiskTier.HIGH,
            action_taken=TaskAction.BLOCK_ACTION,
            prevented=True,
            rule_matched=reason,
        )
        self.storage.record_event(ev)

    def _copy_authorized_inputs(
        self,
        parent_ws: Path,
        child_ws: Path,
        authorized_patterns: list[str],
    ) -> dict[str, str]:
        """Copies files matching authorized_patterns from parent workspace into child workspace."""
        import stat
        copied: dict[str, str] = {}
        if not parent_ws.is_dir():
            return copied

        parent_real = os.path.realpath(str(parent_ws))
        for root, dirs, files in os.walk(str(parent_ws), followlinks=False):
            # Don't descend into symlinked directories
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for fname in files:
                fpath_str = os.path.join(root, fname)
                try:
                    st = os.lstat(fpath_str)
                except OSError:
                    continue

                # Skip anything that is not a regular file (symlinks, devices, FIFOs)
                if not stat.S_ISREG(st.st_mode):
                    continue

                # Skip files with st_nlink > 1
                if st.st_nlink > 1:
                    continue

                # Require os.path.realpath(f) to be inside realpath(parent_ws)
                file_real = os.path.realpath(fpath_str)
                try:
                    rel_to_parent_real = os.path.relpath(file_real, parent_real)
                    if rel_to_parent_real.startswith("..") or os.path.isabs(rel_to_parent_real):
                        continue
                except ValueError:
                    continue

                try:
                    rel = Path(fpath_str).relative_to(parent_ws).as_posix()
                except ValueError:
                    continue

                if rel.startswith(".control") or rel.startswith("receipts"):
                    continue

                # Check if rel matches any authorized read pattern
                matched = any(fnmatch.fnmatch(rel, pat) for pat in authorized_patterns)
                if not matched:
                    continue

                # Open with O_NOFOLLOW and copy from that fd (no shutil.copy2 on a path)
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    fd = os.open(fpath_str, flags)
                except OSError:
                    continue
                # The opened file must be the one checked above: a directory on the path could
                # have been swapped for a symlink between lstat/realpath and open.
                try:
                    fst = os.fstat(fd)
                except OSError:
                    os.close(fd)
                    continue
                if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(fst.st_mode) or fst.st_nlink > 1:
                    os.close(fd)
                    continue

                dst = child_ws / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with open(fd, "rb", closefd=True) as src_f, open(dst, "wb") as dst_f:
                        content_bytes = src_f.read()
                        dst_f.write(content_bytes)
                    try:
                        copied[rel] = content_bytes.decode("utf-8")
                    except Exception:
                        copied[rel] = f"[binary file: {fname}]"
                except Exception:
                    continue
        return copied

    def _calculate_deadline(self, parent_task: TaskRecord, profile: dict[str, Any]) -> float:
        """Ensures child deadline <= parent remaining time."""
        profile_timeout = float(profile.get("timeout_s", 900.0))
        parent_total = float(getattr(parent_task, "timeout_s", None) or 900.0)
        if self.parent_launcher is not None and hasattr(self.parent_launcher, "spec"):
            spec_timeout = getattr(self.parent_launcher.spec, "timeout_s", None)
            if spec_timeout is not None:
                parent_total = float(spec_timeout)

        parent_started = parent_task.started_at or parent_task.created_at
        try:
            st = datetime.datetime.fromisoformat(parent_started)
            if st.tzinfo is None:
                st = st.replace(tzinfo=datetime.timezone.utc)
            elapsed = (datetime.datetime.now(datetime.timezone.utc) - st).total_seconds()
        except Exception:
            elapsed = 0.0

        parent_remaining = max(1.0, parent_total - max(0.0, elapsed))
        return min(profile_timeout, parent_remaining)

    def _extract_forwarded_from(self, child_task_id: str) -> list[str]:
        """Collects outside hosts or files read by child task from broker and sensor events."""
        forwarded: set[str] = set()
        events = self.storage.get_events_for_task(child_task_id)
        for ev in events:
            if ev.verdict == EventVerdict.INSIDE and not ev.prevented:
                if ev.kind in ("file_read", "read_file"):
                    forwarded.add(ev.target)
                elif ev.kind in ("network_http", "network"):
                    host = urllib.parse.urlsplit(ev.target).netloc or ev.target
                    forwarded.add(f"host:{host}")
        return sorted(forwarded)

    def _has_read_private_files(self, task_id: str, boundary: TaskBoundary) -> bool:
        """Determines if the task read any file matching sensitive patterns, private_files, or a canary."""
        canary = (boundary.metadata or {}).get("canary", "")
        private_files = (boundary.metadata or {}).get("private_files", [])
        private_paths = set()
        for p in private_files:
            if isinstance(p, dict):
                pth = p.get("path")
                if pth:
                    private_paths.add(pth)
                    private_paths.add(Path(pth).name)
            elif isinstance(p, str):
                private_paths.add(p)
                private_paths.add(Path(p).name)

        sensitive_patterns = list((boundary.metadata or {}).get("sensitive_patterns", []))
        if hasattr(boundary, "sensitive_patterns") and boundary.sensitive_patterns:
            sensitive_patterns.extend(boundary.sensitive_patterns)

        events = self.storage.get_events_for_task(task_id)
        for ev in events:
            if ev.kind in ("file_read", "read_file") and ev.verdict == EventVerdict.INSIDE:
                tgt = ev.target
                tgt_name = Path(tgt).name
                if tgt in private_paths or tgt_name in private_paths:
                    return True
                if any(fnmatch.fnmatch(tgt, pat) or fnmatch.fnmatch(tgt_name, pat) for pat in sensitive_patterns):
                    return True
                if canary and canary in str(ev.details):
                    return True
        return False
