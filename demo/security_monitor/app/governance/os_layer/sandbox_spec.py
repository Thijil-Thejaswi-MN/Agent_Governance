"""Sandbox spec compiled from the Task Boundary (M6.1).

Turns a TaskBoundary into the JSON rules file consumed by
`landlock_enforcer --rules`. Rules come from the boundary, not from the
workspace layout:

- files_read  -> per-file READ_FILE rules (globs are expanded against the files
                 present at launch; sensitive-pattern matches are excluded, the
                 same way BoundaryEvaluator ranks them above glob grants).
- output/, scratch/ -> directory-level read-write (task-owned; temp-file + rename
                 and sed -i work there).
- files_write -> outside the task-owned dirs: per-file READ_FILE|WRITE_FILE|TRUNCATE
                 on exact targets (pre-created empty because Landlock can only
                 attach a rule to an existing inode); directory rules for glob
                 write patterns. Bare names aliasing an output/ target are skipped.
- task tmp dir, the pre-authorised read-only granted/ dir, the runtime code
  dir and the broker socket.
- the system read/exec paths already used in M4.
- TCP connect only to the egress proxy port.

`is_access_permitted` answers "would these rules allow this access?" so the
correlator can say an EACCES was caused by Landlock (prevented_by=landlock)
rather than by ordinary file permissions.
"""
from __future__ import annotations

import fnmatch
import json
import os
import sys
from pathlib import Path
from typing import Any

from demo.security_monitor.app.governance.evaluator import SENSITIVE_FILE_PATTERNS
from demo.security_monitor.app.governance.models import TaskBoundary

RX = ["execute", "read_file", "read_dir"]
RO_DIR = ["read_file", "read_dir"]
RO_FILE = ["read_file"]
RW_FILE = ["read_file", "write_file", "truncate"]
RW_DIR = [
    "read_file", "read_dir", "write_file", "make_reg", "make_dir",
    "remove_file", "remove_dir", "truncate", "refer",
]

SYSTEM_RX_PATHS = ["/usr", "/lib", "/lib64", "/bin", "/sbin"]
SYSTEM_RO_PATHS = ["/etc", "/proc", "/dev/urandom", "/dev/zero"]
SYSTEM_RW_FILES = ["/dev/null"]

WORKSPACE_DIRS = ("input", "output", "scratch", "granted", "tmp", "runtime")
TASK_OWNED_RW_DIRS = ("output", "scratch")
BROKER_SOCKET_NAME = "broker.sock"


def _is_glob(p: str) -> bool:
    return any(c in p for c in "*?[")


def _is_sensitive(name: str) -> bool:
    low = name.lower()
    return any(fnmatch.fnmatch(low, pat.lower()) for pat in SENSITIVE_FILE_PATTERNS)


def _inside(root: Path, rel: str) -> Path | None:
    """Resolves a boundary-relative path, rejecting anything escaping the workspace."""
    rel_norm = rel.replace("\\", "/").strip()
    if not rel_norm or rel_norm.startswith("/") or ".." in Path(rel_norm).parts:
        return None
    cand = (root / rel_norm)
    try:
        resolved = Path(os.path.realpath(cand))
        resolved.relative_to(root)
    except ValueError:
        return None
    return resolved


def compile_landlock_rules(
    boundary: TaskBoundary,
    workspace_root: str | Path,
    proxy_port: int | None,
    runtime_dir: str | Path | None = None,
    extra_ro_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Compiles the Landlock rules dict for a task. Creates exact write targets (empty)."""
    root = Path(os.path.realpath(workspace_root))
    rules: list[dict[str, Any]] = []
    provenance: list[dict[str, Any]] = []  # why each workspace rule exists
    by_path: dict[str, dict[str, Any]] = {}

    def add(path: str | Path, access: list[str], optional: bool = False, why: str = "") -> None:
        key = str(path)
        if key in by_path:
            # Same inode from two boundary entries (e.g. read and write): union the rights.
            r = by_path[key]
            r["access"] = sorted(set(r["access"]) | set(access))
            if not optional:
                r.pop("optional", None)
        else:
            r = {"path": key, "access": list(access)}
            if optional:
                r["optional"] = True
            by_path[key] = r
            rules.append(r)
        if why:
            provenance.append({"path": key, "access": list(access), "from": why})

    for p in SYSTEM_RX_PATHS:
        add(p, RX, optional=not os.path.exists(p))
    for p in SYSTEM_RO_PATHS:
        add(p, RO_DIR if os.path.isdir(p) else RO_FILE, optional=not os.path.exists(p))
    for p in SYSTEM_RW_FILES:
        add(p, ["read_file", "write_file"], optional=not os.path.exists(p))
    for p in extra_ro_paths or []:
        add(p, RO_DIR if os.path.isdir(p) else RO_FILE, why="extra_ro")

    # Interpreter and runtime virtualenv (if outside /usr system paths)
    interp = os.path.realpath(sys.executable)
    if not any(interp.startswith(p) for p in SYSTEM_RX_PATHS):
        add(interp, RX if os.path.isdir(interp) else ["execute", "read_file"], why="runtime_interpreter")
        venv_prefix = getattr(sys, "base_prefix", None) or getattr(sys, "prefix", None)
        if venv_prefix and venv_prefix != "/usr" and os.path.exists(venv_prefix):
            add(venv_prefix, RO_DIR, why="runtime_venv")

    tmp_dir = root / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    add(tmp_dir, RW_DIR, why="task_tmp")

    granted = root / "granted"
    granted.mkdir(parents=True, exist_ok=True)
    add(granted, RO_DIR, why="expansion_delivery_dir")

    if runtime_dir:
        add(Path(os.path.realpath(runtime_dir)), RO_DIR, why="agent_runtime_code")

    sock = root / BROKER_SOCKET_NAME
    # connect() to a pathname socket is not mediated by Landlock FS rights on
    # this kernel; the rule documents intent and is harmless if the inode is absent.
    add(sock, ["read_file", "write_file"], optional=True, why="broker_socket")

    skipped: list[dict[str, str]] = []

    # files_read: per-file rules
    for pat in boundary.files_read:
        if _is_glob(pat):
            base = pat.replace("\\", "/")
            matched = False
            for f in sorted(root.rglob("*")):
                if not f.is_file():
                    continue
                rel = f.relative_to(root).as_posix()
                if rel.split("/")[0] in ("tmp", "granted", "runtime"):
                    continue
                if fnmatch.fnmatch(rel.lower(), base.lower()):
                    if _is_sensitive(f.name):
                        skipped.append({"pattern": pat, "path": rel, "reason": "sensitive_pattern_excluded_from_glob"})
                        continue
                    add(f, RO_FILE, why=f"files_read:{pat}")
                    matched = True
            if not matched:
                skipped.append({"pattern": pat, "reason": "glob_matched_no_files_at_launch"})
            continue
        target = _inside(root, pat)
        if target is None:
            skipped.append({"pattern": pat, "reason": "escapes_workspace"})
            continue
        if target.is_file():
            add(target, RO_FILE, why=f"files_read:{pat}")
        elif target.is_dir():
            add(target, RO_DIR, why=f"files_read:{pat}")
        else:
            skipped.append({"pattern": pat, "reason": "not_present_at_launch"})

    # Task-owned output/ and scratch/: directory-level read-write so temp-file + rename
    # and in-place editors (sed -i) work. Writes there to names not in files_write are
    # recorded INSIDE with a note by the correlator.
    for owned in TASK_OWNED_RW_DIRS:
        d = root / owned
        d.mkdir(parents=True, exist_ok=True)
        add(d, RW_DIR, why=f"task_owned_dir:{owned}/")

    # files_write: other exact targets pre-created (per-file rule); glob patterns become directory rules
    write_set = {w.replace("\\", "/") for w in boundary.files_write}
    for pat in boundary.files_write:
        norm = pat.replace("\\", "/")
        if norm.split("/")[0] in TASK_OWNED_RW_DIRS and "/" in norm:
            continue  # covered by the task-owned directory rule
        if "/" not in norm and f"output/{norm}" in write_set:
            skipped.append({"pattern": pat, "reason": "bare_alias_of_output_target"})
            continue
        if _is_glob(norm):
            prefix = norm.split("*")[0].split("?")[0].split("[")[0].rstrip("/")
            d = _inside(root, prefix) if prefix else None
            if d is None:
                skipped.append({"pattern": pat, "reason": "glob_without_safe_directory_prefix"})
                continue
            d.mkdir(parents=True, exist_ok=True)
            add(d, RW_DIR, why=f"files_write:{pat}")
            continue
        target = _inside(root, norm)
        if target is None:
            skipped.append({"pattern": pat, "reason": "escapes_workspace"})
            continue
        if target.is_dir():
            add(target, RW_DIR, why=f"files_write:{pat}")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.touch()
        add(target, RW_FILE, why=f"files_write:{pat}")

    return {
        "version": 1,
        "task_tmp": str(tmp_dir),
        "tcp_connect_ports": [int(proxy_port)] if proxy_port else [],
        "rules": rules,
        "_compile_report": {"workspace_rules": provenance, "skipped": skipped},
    }


def write_rules_file(spec: dict[str, Any], path: str | Path) -> Path:
    """Writes the enforcer-consumable rules (without the compile report) as ASCII JSON."""
    out = {k: v for k, v in spec.items() if not k.startswith("_")}
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, ensure_ascii=True, indent=1), encoding="ascii")
    return p


def is_access_permitted(spec: dict[str, Any] | None, abs_path: str, rights: list[str]) -> bool | None:
    """Would the compiled Landlock rules allow `rights` on `abs_path`?

    Returns None when no Landlock spec was applied (condition without Landlock).
    Landlock rights accumulate across all rules that are a parent of (or equal
    to) the path, so the check unions them.
    """
    if spec is None:
        return None
    p = os.path.normpath(abs_path)
    have: set[str] = set()
    for r in spec.get("rules", []):
        rp = os.path.normpath(r["path"])
        if p == rp or p.startswith(rp.rstrip("/") + "/"):
            have.update(r["access"])
    return all(x in have for x in rights)


def is_port_permitted(spec: dict[str, Any] | None, port: int) -> bool | None:
    if spec is None:
        return None
    return int(port) in spec.get("tcp_connect_ports", [])
