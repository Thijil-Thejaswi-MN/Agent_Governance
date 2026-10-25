"""OS event correlator (M6.1): sensor events -> task -> verdict -> graduated response.

Attribution: each sensor event carries the cgroup path the sensor read from
/proc/<pid>/cgroup at event time. That path is mapped to a task through the
task_os_identity table (attribution_method="cgroup"). Events whose cgroup maps to
no task are UNATTRIBUTED. The sensor instance that emitted the event is kept as
`tracer_task_hint` (tracer lineage) only to measure cross-attribution; it is
never used to attribute.

Classification is against the current Task Boundary plus the sandbox runtime
profile (system read/exec paths, task tmp, granted/, runtime code, broker socket).

prevented_by is decided from the syscall's return value and the compiled
Landlock rules: an EACCES/EPERM on an access the rules do not permit is
`landlock`; any other failure (ENOENT, ECONNREFUSED, or EACCES on an access the
rules *do* permit) is `none` - the action failed, but not because of governance.
"""
from __future__ import annotations

import datetime
import fnmatch
import json
import os
import re
import threading
from typing import Any, Callable

from .evaluator import SENSITIVE_FILE_PATTERNS, BoundaryEvaluator
from .models import EnforcementMode, EventSource, EventVerdict, GovernanceEvent, RiskTier, TaskAction
from .os_layer.sandbox_spec import (
    BROKER_SOCKET_NAME,
    SYSTEM_RO_PATHS,
    SYSTEM_RW_FILES,
    SYSTEM_RX_PATHS,
    is_access_permitted,
    is_port_permitted,
)
from .storage import GovernanceStorage

O_DIRECTORY = 0o200000
O_PATH = 0o10000000
PROC_PID_RE = re.compile(r"^/proc/(\d+)(/|$)")
DENIAL_RESULTS = ("EACCES", "EPERM")


def _under(path: str, prefix: str) -> bool:
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def _iso_from_ms(ms: int | None) -> str:
    if not ms:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()
    return datetime.datetime.fromtimestamp(ms / 1000.0, tz=datetime.timezone.utc).isoformat()


class OSEventCorrelator:
    """Consumes one task's sensor stream; thread-safe for a single reader."""

    def __init__(
        self,
        storage: GovernanceStorage,
        task_id: str,
        workspace_root: str,
        enforcement_mode: EnforcementMode,
        landlock_spec: dict[str, Any] | None,
        proxy_port: int | None,
        interpreter_path: str,
        runtime_dir: str | None,
        seccomp_active: bool,
        on_violation: Callable[[str, dict[str, Any]], None] | None = None,
        on_open: Callable[[str], None] | None = None,
        evaluator: BoundaryEvaluator | None = None,
        flush_every: int = 200,
    ) -> None:
        self.storage = storage
        self.task_id = task_id
        self.ws = os.path.realpath(workspace_root)
        self.mode = enforcement_mode
        self.spec = landlock_spec
        self.proxy_port = proxy_port
        self.interpreter = os.path.realpath(interpreter_path)
        self.runtime_dir = os.path.realpath(runtime_dir) if runtime_dir else None
        self.seccomp_active = seccomp_active
        self.on_violation = on_violation
        self.on_open = on_open
        self.evaluator = evaluator or BoundaryEvaluator()
        self.flush_every = flush_every

        self.sensor_pid: int | None = None
        self.root_pid: int | None = None
        self.setup_done = False
        self.exit_trailer: dict[str, Any] | None = None
        self.records: list[dict[str, Any]] = []
        self.counts = {v.value: 0 for v in EventVerdict}
        self.cross_attributions = 0
        self.unattributed_reasons: dict[str, int] = {}
        self._pending: list[GovernanceEvent] = []
        self._cg_table: dict[str, str] = {}
        self._lock = threading.Lock()
        self._n = 0

    # --- attribution ---
    def _attribute(self, cg: str, cg_status: str) -> tuple[str | None, str | None]:
        if cg_status != "ok" or not cg:
            return None, f"cgroup_{cg_status or 'missing'}"
        for attempt in (0, 1):
            if attempt == 1 or not self._cg_table:
                self._cg_table = self.storage.list_task_cgroups()
            for path, tid in self._cg_table.items():
                if cg == path or cg.startswith(path.rstrip("/") + "/"):
                    return tid, None
        return None, "cgroup_not_in_task_table"

    # --- classification ---
    def _rel(self, path: str) -> str | None:
        if _under(path, self.ws):
            return os.path.relpath(path, self.ws).replace(os.sep, "/")
        return None

    def _classify_path(self, boundary: Any, path: str, is_write: bool, pid: int | None = None) -> tuple[EventVerdict, RiskTier, str]:
        rel = self._rel(path)
        if rel is not None:
            top = rel.split("/")[0]
            if rel == BROKER_SOCKET_NAME:
                return EventVerdict.INSIDE, RiskTier.LOW, "broker socket"
            if top == "tmp":
                return EventVerdict.INSIDE, RiskTier.LOW, "task tmp dir"
            if top == "runtime" and not is_write:
                return EventVerdict.INSIDE, RiskTier.LOW, "agent runtime code (read-only)"
            if top == "granted" and not is_write:
                return EventVerdict.INSIDE, RiskTier.LOW, "expansion delivery dir (granted/)"
            if rel == ".":
                return EventVerdict.INSIDE, RiskTier.LOW, "workspace root directory handle"
            if not is_write and boundary is not None:
                # Read-back of a granted write target is allowed by the compiled profile.
                wr = self.evaluator.evaluate_file_access(boundary, rel, is_write=True)
                if wr.verdict == EventVerdict.INSIDE:
                    return EventVerdict.INSIDE, RiskTier.LOW, f"read-back of write target: {wr.rule_matched}"
            if boundary is None:
                return EventVerdict.AMBIGUOUS, RiskTier.MEDIUM, "no boundary available"
            res = self.evaluator.evaluate_file_access(boundary, rel, is_write=is_write)
            return res.verdict, res.risk_tier, res.rule_matched
        if self.runtime_dir and _under(path, self.runtime_dir) and not is_write:
            return EventVerdict.INSIDE, RiskTier.LOW, "agent runtime code (read-only)"

        m = PROC_PID_RE.match(path)
        if m:
            if pid is not None and int(m.group(1)) == pid:
                return EventVerdict.INSIDE, RiskTier.LOW, "own /proc entry"
            return EventVerdict.AMBIGUOUS, RiskTier.MEDIUM, "per-process /proc entry of another pid"
        if path.startswith("/proc/self") or path.startswith("/proc/thread-self"):
            return EventVerdict.INSIDE, RiskTier.LOW, "own /proc entry"
        sys_ro = SYSTEM_RX_PATHS + SYSTEM_RO_PATHS
        if any(_under(path, p) for p in SYSTEM_RW_FILES):
            return EventVerdict.INSIDE, RiskTier.LOW, "runtime device file"
        if any(_under(path, p) for p in sys_ro):
            if is_write:
                return EventVerdict.OUTSIDE, RiskTier.HIGH, "write to system path"
            name = os.path.basename(path).lower()
            # Sensitive-name check only where credentials live (/etc); under /usr it
            # matches library files such as tokenize.pyc.
            if _under(path, "/etc") and any(fnmatch.fnmatch(name, pat.lower()) for pat in SENSITIVE_FILE_PATTERNS):
                return EventVerdict.AMBIGUOUS, RiskTier.HIGH, "sensitive file inside runtime system profile"
            return EventVerdict.INSIDE, RiskTier.LOW, "runtime system path (sandbox profile)"
        return EventVerdict.OUTSIDE, RiskTier.HIGH, "path outside task boundary and runtime profile"

    def _classify(self, ev: dict[str, Any], boundary: Any) -> tuple[EventVerdict, RiskTier, str, str, list[str] | None]:
        """Returns verdict, risk, rule, op, and the Landlock rights the access needs."""
        sc = ev.get("syscall", "")
        tgt = ev.get("abs_target") or ""
        if sc in ("open", "openat", "openat2"):
            flags = int(ev.get("flags", 0) or 0)
            if not tgt:
                return EventVerdict.AMBIGUOUS, RiskTier.MEDIUM, "relative path could not be resolved", "file_open", None
            path = os.path.normpath(tgt)
            access = ev.get("access", "read")
            is_write = access in ("write", "read_write") or bool(ev.get("creat"))
            if flags & O_PATH:
                rights: list[str] = []
            elif flags & O_DIRECTORY:
                rights = ["read_dir"]
            else:
                rights = {"read": ["read_file"], "write": ["write_file"], "read_write": ["read_file", "write_file"]}.get(access, ["read_file"])
            v, r, rule = self._classify_path(boundary, path, is_write, ev.get("pid"))
            return v, r, rule, "file_write" if is_write else "file_read", rights
        if sc in ("execve", "execveat"):
            path = os.path.normpath(tgt) if tgt else ""
            if path and any(_under(path, p) for p in SYSTEM_RX_PATHS):
                if boundary is not None and "run_command" in boundary.tools:
                    return EventVerdict.INSIDE, RiskTier.LOW, "exec of system binary (run_command granted)", "process_exec", ["execute"]
                return EventVerdict.OUTSIDE, RiskTier.HIGH, "process exec without run_command in boundary", "process_exec", ["execute"]
            return EventVerdict.OUTSIDE, RiskTier.HIGH, "exec of non-system binary", "process_exec", ["execute"]
        if sc == "connect":
            if tgt == f"unix:{os.path.join(self.ws, BROKER_SOCKET_NAME)}":
                return EventVerdict.INSIDE, RiskTier.LOW, "broker socket", "network_connect", None
            m = re.match(r"^tcp6?:(?:\[([^\]]+)\]|([^:]+)):(\d+)$", tgt)
            if m:
                port = int(m.group(3))
                if self.proxy_port and port == self.proxy_port and (m.group(2) or m.group(1)) in ("127.0.0.1", "::1"):
                    return EventVerdict.INSIDE, RiskTier.LOW, "egress proxy", "network_connect", None
                return EventVerdict.OUTSIDE, RiskTier.HIGH, f"direct TCP connect bypassing proxy: {tgt}", "network_connect", None
            return EventVerdict.OUTSIDE, RiskTier.MEDIUM, f"socket connect outside boundary: {tgt}", "network_connect", None
        return EventVerdict.AMBIGUOUS, RiskTier.LOW, f"unclassified syscall {sc}", sc, None

    def _prevented_by(self, ev: dict[str, Any], rights: list[str] | None) -> str:
        result = ev.get("result", "ok")
        if result == "ok":
            return "none"
        if result not in DENIAL_RESULTS:
            return "none"
        sc = ev.get("syscall", "")
        tgt = ev.get("abs_target") or ""
        if sc == "connect":
            m = re.match(r"^tcp6?:.*:(\d+)$", tgt)
            if m and is_port_permitted(self.spec, int(m.group(1))) is False:
                return "landlock"
            if tgt.startswith("unix-abstract:") and self.spec is not None:
                return "landlock"  # ABI-6 abstract unix socket scoping
            return "none"
        if rights is None or not tgt:
            return "none"
        permitted = is_access_permitted(self.spec, os.path.normpath(tgt), rights)
        if permitted is False:
            return "landlock"
        return "none"

    # --- main entry ---
    def handle_line(self, line: str, boundary_provider: Callable[[], Any]) -> dict[str, Any] | None:
        line = line.strip()
        if not line.startswith('{"source":"os_sensor"'):
            return None
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            return None
        typ = ev.get("type")
        if typ == "start":
            self.sensor_pid = ev.get("sensor_pid")
            self.root_pid = ev.get("child_pid")
            return None
        if typ == "exit":
            self.exit_trailer = ev
            self.flush()
            return None
        if typ != "syscall":
            return None

        with self._lock:
            return self._handle_syscall(ev, boundary_provider)

    def _handle_syscall(self, ev: dict[str, Any], boundary_provider: Callable[[], Any]) -> dict[str, Any]:
        self._n += 1
        pid = ev.get("pid")
        sc = ev.get("syscall")
        attributed, unattr_reason = self._attribute(ev.get("cgroup_id", ""), ev.get("cgroup_status", ""))

        phase = "agent"
        if not self.setup_done:
            phase = "launch_chain_setup"
            if (pid == self.root_pid and sc in ("execve", "execveat") and ev.get("result") == "ok"
                    and os.path.realpath(ev.get("abs_target") or "") == self.interpreter):
                self.setup_done = True

        boundary = boundary_provider()
        if attributed is None:
            verdict, risk, rule, op, rights = EventVerdict.UNATTRIBUTED, RiskTier.MEDIUM, f"unattributed: {unattr_reason}", sc, None
            self.unattributed_reasons[unattr_reason] = self.unattributed_reasons.get(unattr_reason, 0) + 1
            _, _, _, op, rights = self._classify(ev, boundary)
        elif phase == "launch_chain_setup":
            verdict, risk, rule = EventVerdict.INSIDE, RiskTier.LOW, "launch chain setup before agent exec (pre-sandbox)"
            _, _, _, op, rights = self._classify(ev, boundary)
        else:
            verdict, risk, rule, op, rights = self._classify(ev, boundary)
        if attributed is not None and attributed != self.task_id:
            self.cross_attributions += 1

        prevented_by = self._prevented_by(ev, rights) if verdict != EventVerdict.INSIDE else "none"
        result = ev.get("result", "ok")
        prevented = prevented_by != "none"
        channel = "agent_process" if pid == self.root_pid else "shell"

        # Graduated response for OS events (the sensor only observes; Landlock/seccomp enforce).
        action = TaskAction.ALLOW
        if verdict == EventVerdict.OUTSIDE:
            if prevented:
                action = TaskAction.ALERT if risk == RiskTier.HIGH else TaskAction.LOG
            elif result == "ok":
                if self.mode == EnforcementMode.ENFORCE:
                    action = TaskAction.PAUSE_TASK  # an OUTSIDE access succeeded under ENFORCE: freeze
                else:
                    action = TaskAction.ALERT
            else:
                action = TaskAction.LOG
        elif verdict in (EventVerdict.AMBIGUOUS, EventVerdict.UNATTRIBUTED):
            action = TaskAction.LOG

        rec = {
            "seq": ev.get("seq"),
            "timestamp": _iso_from_ms(ev.get("ts_ms")),
            "source": EventSource.OS_SENSOR.value,
            "kind": op,
            "syscall": sc,
            "target": ev.get("abs_target") or ev.get("target"),
            "result": result,
            "pid": pid,
            "ppid": ev.get("ppid"),
            "cgroup_path": ev.get("cgroup_id"),
            "attribution_method": "cgroup",
            "attributed_task_id": attributed,
            "tracer_task_hint": self.task_id,
            "phase": phase,
            "channel": channel,
            "verdict": verdict.value,
            "risk_tier": risk.value,
            "rule_matched": rule,
            "action_taken": action.value,
            "prevented": prevented,
            "prevented_by": prevented_by,
            "observed_by": ["os_sensor"],
        }
        self.records.append(rec)
        self.counts[verdict.value] += 1

        gov = GovernanceEvent(
            event_id=f"evt_os_{self.task_id}_{ev.get('seq', self._n):06d}",
            timestamp=rec["timestamp"],
            source=EventSource.OS_SENSOR,
            task_id=attributed,
            agent_id="os_process",
            pid=pid,
            kind=op,
            target=str(rec["target"])[:4096],
            details={k: rec[k] for k in ("syscall", "result", "ppid", "cgroup_path", "attribution_method",
                                         "tracer_task_hint", "phase", "channel", "prevented_by", "observed_by")},
            verdict=verdict,
            risk_tier=risk,
            action_taken=action,
            prevented=prevented,
            rule_matched=f"os_sensor: {rule}",
            boundary_version=getattr(boundary, "version", None),
        )
        self._pending.append(gov)
        if len(self._pending) >= self.flush_every:
            self._flush_locked()

        if self.on_open and sc in ("open", "openat", "openat2") and result == "ok" and rec["target"]:
            self.on_open(os.path.normpath(rec["target"]))
        if action == TaskAction.PAUSE_TASK and self.on_violation:
            self._flush_locked()
            self.on_violation("unprevented_outside_os_event", rec)
        return rec

    def _flush_locked(self) -> None:
        if self._pending:
            self.storage.record_events(self._pending)
            self._pending = []

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()
