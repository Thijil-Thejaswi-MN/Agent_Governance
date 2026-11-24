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


_GLOBAL_ROOT_CHILDREN_LOCK = threading.Lock()
_GLOBAL_RUNNING_CHILDREN_BY_ROOT: dict[str, set[str]] = {}


def intersect_patterns(ceiling_patterns: list[str], parent_patterns: list[str]) -> list[str]:
    """Computes field-by-field pattern intersection ensuring rights only shrink."""
    from .delegation_token import is_single_pattern_subset

    result: set[str] = set()
    for cp in ceiling_patterns:
        for pp in parent_patterns:
            if is_single_pattern_subset(cp, pp):
                result.add(cp)
            elif is_single_pattern_subset(pp, cp):
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

    def _track_child_start(self, root_task_id: str, child_task_id: str) -> None:
        with _GLOBAL_ROOT_CHILDREN_LOCK:
            active = _GLOBAL_RUNNING_CHILDREN_BY_ROOT.setdefault(root_task_id, set())
            if len(active) >= MAX_RUNNING_CHILDREN_PER_ROOT:
                raise RuntimeError(
                    f"Per-root cap of {MAX_RUNNING_CHILDREN_PER_ROOT} running child tasks reached for root {root_task_id}"
                )
            active.add(child_task_id)

    def _track_child_finish(self, root_task_id: str, child_task_id: str) -> None:
        with _GLOBAL_ROOT_CHILDREN_LOCK:
            active = _GLOBAL_RUNNING_CHILDREN_BY_ROOT.get(root_task_id)
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

        if hasattr(self.storage, "is_task_frozen") and self.storage.is_task_frozen(caller_task_id):
            reason = f"Caller task {caller_task_id} is frozen"
            self._record_refusal(root_task_id, caller_task_id, caller_agent_id, target_agent, fanout_group, text_content, reason)
            raise PermissionError(reason)

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

        # Check 5: Delegation token verification and chain validation
        from .delegation_token import (
            decode_delegation_token,
            mint_delegation_token,
            normalize_scope,
            compute_intent_hash,
            compute_token_hash,
            is_scope_subset,
            verify_chain_tokens,
        )
        with self._lock:
            parent_token_text = self.storage.get_delegation_token_by_task_id(caller_task_id)
            if not parent_token_text and (depth != 0 or caller_task.parent_task_id):
                reason = f"No delegation token on record for {caller_task_id}"
                self._record_refusal(root_task_id, caller_task_id, caller_agent_id, target_agent, fanout_group, text_content, reason)
                raise PermissionError(reason)
            if not parent_token_text:
                # A root task started outside the launcher (no token yet): mint its root token now.
                parent_token_text = self._mint_root_token(caller_task, caller_boundary, caller_task_id, caller_agent_id, root_task_id, chain, depth)

        curr_tok = parent_token_text
        chain_tokens = [curr_tok]
        while True:
            _, p_obj, _ = decode_delegation_token(curr_tok)
            p_hash = p_obj.get("par_hash")
            if not p_hash:
                break
            prev_tok = self.storage.get_delegation_token_by_hash(p_hash)
            if not prev_tok:
                break
            chain_tokens.insert(0, prev_tok)
            curr_tok = prev_tok

        chain_ok, chain_err = verify_chain_tokens(chain_tokens, storage=self.storage)
        if chain_ok:
            # The verified token must be the caller's own, and the signed chain must agree with
            # the task record (the record-based cycle and depth checks above).
            _, leaf, _ = decode_delegation_token(chain_tokens[-1])
            if leaf.get("task") != caller_task_id or leaf.get("agent") != caller_agent_id:
                chain_ok, chain_err = False, f"Delegation token belongs to task {leaf.get('task')}, not {caller_task_id}"
            elif list(leaf.get("chain") or []) != chain or int(leaf.get("depth", -1)) != depth:
                chain_ok, chain_err = False, "Delegation token chain does not match the task record"
            elif target_agent in (leaf.get("chain") or []):
                chain_ok, chain_err = False, f"Cycle detected in signed chain: '{target_agent}' already in {leaf.get('chain')}"
            elif int(leaf.get("depth", 0)) + 1 > int(leaf.get("max_depth", MAX_DELEGATION_DEPTH)):
                chain_ok, chain_err = False, f"Maximum delegation depth {leaf.get('max_depth')} in the signed token reached"
            elif target_agent not in ((leaf.get("scope") or {}).get("peer_agents") or []):
                chain_ok, chain_err = False, f"Target agent '{target_agent}' is not in the caller's signed scope"
        if not chain_ok:
            self._record_refusal(root_task_id, caller_task_id, caller_agent_id, target_agent, fanout_group, text_content, chain_err)
            raise PermissionError(chain_err)

        # 3. Check per-root concurrency cap
        child_task_id = f"{caller_task_id}_c{uuid.uuid4().hex[:6]}"
        self._track_child_start(root_task_id, child_task_id)

        # 4. Record request message in a2a_messages as pending
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
            "verdict": "pending",
            "reason": None,
            "integrity": "trusted",
            "forwarded_from": [],
            "contains_private": caller_has_private,
        }
        self.storage.save_a2a_message(req_row)

        try:
            # 5. Derive child boundary: ceiling ∩ caller's current boundary
            narrowed = intersect_boundaries(profile["ceiling"], caller_boundary)
            child_scope = normalize_scope(narrowed)
            parent_scope = normalize_scope(caller_boundary)
            if not is_scope_subset(child_scope, parent_scope):
                reason = "Child scope widens caller scope"
                self._record_refusal(root_task_id, caller_task_id, caller_agent_id, target_agent, fanout_group, text_content, reason)
                req_row["verdict"] = "failed"
                req_row["reason"] = reason
                self.storage.save_a2a_message(req_row)
                raise PermissionError(reason)

            # 6. Register child launcher before copying inputs
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
                if getattr(self.parent_launcher, "_frozen", None) and self.parent_launcher._frozen.is_set():
                    child_launcher._freeze_now("parent_already_frozen")

            if hasattr(self.storage, "is_task_frozen") and self.storage.is_task_frozen(caller_task_id):
                child_launcher._freeze_now(f"parent_frozen:{caller_task_id}")
                reason = f"Task {caller_task_id} in delegation chain is frozen"
                req_row["verdict"] = "failed"
                req_row["reason"] = reason
                self.storage.save_a2a_message(req_row)
                raise PermissionError(reason)

            # Copy authorized files from parent workspace
            parent_ws = Path(caller_boundary.workspace_root).resolve()
            copied_inputs = self._copy_authorized_inputs(
                parent_ws,
                None,
                narrowed["files_read"],
                child_launcher=child_launcher,
            )

            if getattr(child_launcher, "_frozen", None) and child_launcher._frozen.is_set():
                reason = "Child launcher was frozen during input copy"
                req_row["verdict"] = "failed"
                req_row["reason"] = reason
                self.storage.save_a2a_message(req_row)
                raise PermissionError(reason)

            # 7. Deadline inheritance: child deadline <= parent remaining time
            deadline_s = self._calculate_deadline(caller_task, profile)

            # Mint child delegation token server-side (agent never holds token)
            _, parent_payload, _ = decode_delegation_token(parent_token_text)
            now_ts = int(time.time())
            child_exp = min(int(parent_payload.get("exp", now_ts + 900)), now_ts + int(deadline_s))
            par_hash = compute_token_hash(parent_token_text)
            child_tok = mint_delegation_token(
                org_id=parent_payload.get("iss", "default"),
                sub=parent_payload.get("sub", "local_user"),
                txn=parent_payload.get("txn", root_task_id),
                task_id=child_task_id,
                agent_id=target_agent,
                chain=parent_payload.get("chain", []) + [target_agent],
                depth=parent_payload.get("depth", 0) + 1,
                scope=child_scope,
                par_hash=par_hash,
                intent=parent_payload.get("intent", ""),
                iat=now_ts,
                exp=child_exp,
            )
            self.storage.save_delegation_token(child_task_id, child_tok, parent_token_hash=par_hash)
            # The child starts with the label of what it is given: the caller's context at the
            # moment of sending (a message from a task that read secret or untrusted data may carry it).
            sent_integ, sent_conf = self.storage.get_task_context_label(caller_task_id)
            self.storage.update_task_context_label(child_task_id, integrity=sent_integ, confidentiality=sent_conf)

            # 8. Launch child task via TaskLauncher
            parent_meta = caller_boundary.metadata or {}
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
                agent_tools=profile["ceiling"].get("tools"),
                boundary_model=parent_meta.get("boundary_model", "v1.1"),
                canary=parent_meta.get("canary") or "",
                private_files=parent_meta.get("private_files"),
                sensitive_patterns=parent_meta.get("sensitive_patterns") or getattr(caller_boundary, "sensitive_patterns", None),
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

            # Update request message to delivered or failed
            req_row["verdict"] = "delivered" if status == "ok" else "failed"
            req_row["reason"] = failure_reason
            self.storage.save_a2a_message(req_row)

            # Collect forwarded_from and contains_private
            child_boundary = self.storage.get_boundary(child_task_id) or caller_boundary
            forwarded_from = self._extract_forwarded_from(child_task_id)
            contains_private = self._has_read_private_files(child_task_id, child_boundary)
            canary_val = parent_meta.get("canary") or ""
            if canary_val and canary_val in reply_text:
                contains_private = True

            # Record reply message
            child_integ, child_conf = self.storage.get_task_context_label(child_task_id)
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
                "integrity": child_integ,
                "confidentiality": child_conf,
                "forwarded_from": forwarded_from,
                "contains_private": contains_private,
            }
            self.storage.save_a2a_message(reply_row)

            # Receiving child reply raises parent's labels
            self.storage.update_task_context_label(caller_task_id, integrity="untrusted", confidentiality=child_conf)

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
                "confidentiality": child_conf,
                "integrity": child_integ,
            }

        except Exception as e:
            req_row["verdict"] = "failed"
            req_row["reason"] = str(e)
            self.storage.save_a2a_message(req_row)
            raise

        finally:
            self._track_child_finish(root_task_id, child_task_id)

    def delegate_parallel(
        self,
        token: str,
        calls: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Starts several child tasks concurrently and returns all replies."""
        if len(calls) > 8:
            calls = calls[:8]
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

    def _mint_root_token(self, caller_task, caller_boundary, caller_task_id, caller_agent_id, root_task_id, chain, depth) -> str:
        from .delegation_token import compute_intent_hash, mint_delegation_token, normalize_scope

        caller_scope = normalize_scope(caller_boundary)
        intent_hash = compute_intent_hash(caller_task.request_text, caller_scope)
        now_ts = int(time.time())
        tok = mint_delegation_token(
            org_id=caller_task.org or "default",
            sub=caller_task.requested_by or caller_task.owner or "local_user",
            txn=root_task_id,
            task_id=caller_task_id,
            agent_id=caller_agent_id,
            chain=chain,
            depth=depth,
            scope=caller_scope,
            par_hash=None,
            intent=intent_hash,
            iat=now_ts,
            exp=now_ts + int(caller_task.timeout_s or 900),
        )
        self.storage.save_delegation_token(caller_task_id, tok, parent_token_hash=None)
        return tok

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
        child_ws: Path | None,
        authorized_patterns: list[str],
        child_launcher: Any = None,
    ) -> dict[str, str]:
        """Copies files matching authorized_patterns from parent workspace using openat(dir_fd, name, O_NOFOLLOW).
        Caps each file at 1 MB and 50 files total.
        Never leaves a folder on disk."""
        import stat
        copied: dict[str, str] = {}
        if not parent_ws.is_dir():
            return copied

        copy_hook = (self.test_hooks or {}).get("during_input_copy")

        try:
            parent_fd = os.open(str(parent_ws), os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return copied

        try:
            for root, dirs, files in os.walk(str(parent_ws), followlinks=False):
                if copy_hook:
                    copy_hook()
                if child_launcher and getattr(child_launcher, "_frozen", None) and child_launcher._frozen.is_set():
                    break

                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                for fname in sorted(files):
                    if len(copied) >= 50:
                        break
                    fpath_str = os.path.join(root, fname)
                    try:
                        rel = Path(fpath_str).relative_to(parent_ws).as_posix()
                    except ValueError:
                        continue

                    if rel.startswith(".control") or rel.startswith("receipts") or rel.startswith("granted"):
                        continue

                    matched = any(fnmatch.fnmatch(rel, pat) for pat in authorized_patterns)
                    if not matched:
                        continue

                    # Open each path one component at a time with openat(dir_fd, name, O_NOFOLLOW)
                    parts = [p for p in rel.split("/") if p and p != "."]
                    if any(p == ".." for p in parts):
                        continue

                    cur_fd = None
                    try:
                        cur_fd = os.dup(parent_fd)
                        flags = os.O_RDONLY
                        if hasattr(os, "O_NOFOLLOW"):
                            flags |= os.O_NOFOLLOW

                        failed = False
                        for idx, part in enumerate(parts):
                            is_last = (idx == len(parts) - 1)
                            comp_flags = flags if is_last else (flags | os.O_DIRECTORY)
                            try:
                                next_fd = os.open(part, comp_flags, dir_fd=cur_fd)
                            except OSError:
                                failed = True
                                break
                            os.close(cur_fd)
                            cur_fd = next_fd

                        if failed or cur_fd is None:
                            continue

                        fst = os.fstat(cur_fd)
                        if not stat.S_ISREG(fst.st_mode) or fst.st_nlink > 1:
                            continue
                        if fst.st_size > 1048576:  # 1 MB cap
                            continue

                        with open(cur_fd, "rb", closefd=True) as src_f:
                            cur_fd = None  # open took ownership
                            content_bytes = src_f.read(1048576)

                        try:
                            copied[rel] = content_bytes.decode("utf-8")
                        except Exception:
                            copied[rel] = f"[binary file: {fname}]"

                        if child_ws is not None:
                            dst = child_ws / rel
                            dst.parent.mkdir(parents=True, exist_ok=True)
                            with open(dst, "wb") as dst_f:
                                dst_f.write(content_bytes)

                    except Exception:
                        continue
                    finally:
                        if cur_fd is not None:
                            try:
                                os.close(cur_fd)
                            except OSError:
                                pass
        finally:
            try:
                os.close(parent_fd)
            except OSError:
                pass

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
        """Collects outside hosts or files read by child task from broker events only."""
        forwarded: set[str] = set()
        events = self.storage.get_events_for_task(child_task_id)
        child_task = self.storage.get_task(child_task_id)
        ws_root = Path(child_task.workspace_root).resolve() if child_task and child_task.workspace_root else None

        for ev in events:
            # Only the child's own tool calls from the broker, never sensor events
            source_val = ev.source.value if hasattr(ev.source, "value") else str(ev.source)
            if source_val not in (EventSource.TOOL_BROKER.value, "tool_broker"):
                continue
            if ev.verdict != EventVerdict.INSIDE or ev.prevented:
                continue

            if ev.kind in ("read_file", "file_read"):
                tgt = str(ev.target).strip()
                # Exclude runtime, proc, dev, interpreter, library paths
                if any(tgt.startswith(p) for p in ("/proc", "/dev", "/usr", "/bin", "/lib", "/etc", "/var", "/tmp/pytest")):
                    continue
                if ws_root:
                    try:
                        p = Path(tgt)
                        if not p.is_absolute():
                            p = (ws_root / p).resolve()
                        else:
                            p = p.resolve()
                        # Must be inside the child workspace
                        rel = p.relative_to(ws_root).as_posix()
                        forwarded.add(rel)
                    except ValueError:
                        # Outside child workspace
                        continue
                else:
                    if not tgt.startswith("/"):
                        forwarded.add(tgt)
            elif ev.kind in ("network_http", "network"):
                host = urllib.parse.urlsplit(ev.target).netloc or ev.target
                forwarded.add(f"host:{host}")

        return sorted(forwarded)[:10]

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
