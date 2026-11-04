"""Resolved boundary (M7): one canonical list of filesystem entries for both layers.

`resolve_boundary(boundary, workspace)` turns a TaskBoundary's files_read and
files_write into one list of `ResolvedEntry(path, kind, access)`. The tool layer
(`ResolvedBoundaryEvaluator`, used by the ToolBroker) and the kernel layer
(`sandbox_spec.compile_landlock_rules_resolved`) both take the ResolvedBoundary
and nothing else, so they cannot disagree about a path in the task boundary.

Resolution rules (each one is at least as strict as the stricter of the two M6
layers on the same path):

- Every entry is made absolute against the workspace (its realpath). An entry
  must already be a canonical relative path: absolute entries, '..' components
  and non-normalised spellings ('./x', 'a//b', 'x/') are rejected, because the M6
  tool layer compared them literally and never matched them. Entries under the
  runtime-support names tmp/, runtime/, granted/, broker.sock, entries with a
  symlink anywhere below the workspace root, and entries below a non-directory
  are rejected too. Entries therefore name canonical, symlink-free paths, and a
  probe path is canonicalised the same way (realpath) before it is looked up.
- ALIAS RULE: a bare name n (no '/') is an alias, and is dropped, when the same
  list also holds the scoped name: input/n in files_read, output/n in
  files_write. It is never a second grant. Every other entry denotes exactly the
  one path it names; entries that resolve to the same path are merged (union of
  access).
- files_read: an exact entry is a file entry {read} if it is a regular file at
  resolve time. Globs are expanded once, case-insensitively, to the regular
  files present at resolve time, minus SENSITIVE_FILE_PATTERNS names.
- files_write: an exact entry is a file entry {read, write, create}; "create"
  means only this one name may be brought into existence (the kernel compiler
  pre-creates it, because Landlock attaches rules to existing inodes). A glob of
  the form D/* or D/** is a dir entry D {read, write, create, remove} (fnmatch's
  '*' crosses '/', so both mean "anything beneath D"). Any other write glob is
  narrowed to the existing files it matches beneath its literal directory
  prefix, without create; a glob with no literal prefix ('*') grants nothing.
- Always present: output/ {read} and granted/ {read} (dir entries). Nothing else
  in output/ is writable unless named, and scratch/ is not granted at all.
- Expansion grants: an approved file_read grant for T is reachable only at its
  delivered copy granted/<T>, which the granted/ entry covers; T itself is not
  added (Landlock cannot widen after restrict_self). An approved file_write grant
  is dropped for the same reason.

Kernel-only runtime support (system paths, interpreter, runtime/ code, tmp/,
broker socket) is added by the kernel compiler and is never a boundary entry,
so the broker refuses all of it.
"""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .evaluator import SENSITIVE_FILE_PATTERNS, BoundaryEvaluator, EvaluationResult
from .models import EventVerdict, RiskTier, TaskBoundary

ACCESS_KINDS = ("read", "write", "create", "remove")
RESERVED_NAMES = ("tmp", "runtime", "granted", "broker.sock")
FILE_WRITE = frozenset({"read", "write", "create"})
DIR_WRITE = frozenset({"read", "write", "create", "remove"})
READ = frozenset({"read"})
RESOLVER_VERSION = "resolved_v1"

_DIR_GLOB = re.compile(r"^([^*?\[]+?)/\*{1,2}$")


def _is_glob(p: str) -> bool:
    return any(c in p for c in "*?[")


def _is_sensitive(name: str) -> bool:
    low = name.lower()
    return any(fnmatch.fnmatch(low, pat.lower()) for pat in SENSITIVE_FILE_PATTERNS)


def _under(p: str, root: str) -> bool:
    return p == root or p.startswith(root.rstrip("/") + "/")


@dataclass(frozen=True)
class ResolvedEntry:
    path: str                 # absolute, normalised, symlink-free
    kind: str                 # "file" | "dir"
    access: frozenset[str]    # subset of ACCESS_KINDS
    sources: tuple[str, ...]  # boundary entries / rules this came from
    exclude_sensitive_writes: bool = False

    def covers(self, p: str) -> bool:
        return p == self.path or (self.kind == "dir" and p.startswith(self.path + "/"))

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"path": self.path, "kind": self.kind, "access": sorted(self.access),
                             "sources": list(self.sources)}
        if self.exclude_sensitive_writes:
            d["exclude_sensitive_writes"] = True
        return d


@dataclass(frozen=True)
class ResolvedBoundary:
    workspace: str
    task_id: str
    boundary_version: int
    entries: tuple[ResolvedEntry, ...]
    skipped: tuple[tuple[str, str], ...]  # (boundary entry, reason)

    # --- the one decision function both layers are compiled to agree with ---
    def allows(self, abs_path: str, access: str) -> tuple[bool, str]:
        """Is `access` on canonical absolute `abs_path` granted? Returns (allowed, rule)."""
        if access not in ACCESS_KINDS:
            raise ValueError(f"unknown access kind: {access}")
        covering = [e for e in self.entries if e.covers(abs_path)]
        exact = [e for e in covering if e.path == abs_path and access in e.access]
        if exact:
            return True, f"{access} via {exact[0].kind} entry {exact[0].sources[0]}"
        for e in covering:
            if access not in e.access:
                continue
            if (e.exclude_sensitive_writes and access in ("write", "create")
                    and _is_sensitive(os.path.basename(abs_path))):
                continue
            return True, f"{access} via {e.kind} entry {e.sources[0]}"
        return False, f"no resolved entry grants {access}"

    def canonical(self, path_str: str, world_home: str | None = None) -> str:
        """Canonicalises a tool-supplied path exactly as the broker always has (realpath)."""
        cleaned = path_str.strip().rstrip(". ")
        home = world_home or str(Path.home())
        if cleaned.startswith("~/"):
            raw = os.path.join(home, cleaned[2:])
        elif cleaned.startswith("~"):
            raw = os.path.join(home, cleaned.lstrip("~").lstrip("/\\"))
        else:
            raw = cleaned
        if not os.path.isabs(raw):
            raw = os.path.join(self.workspace, raw)
        return os.path.realpath(raw)

    def evaluate(self, path_str: str, is_write: bool, world_home: str | None = None) -> EvaluationResult:
        """Tool-layer verdict for read_file / write_file (write = open('w'): write if it exists, else create)."""
        if not path_str.strip().rstrip(". "):
            return EvaluationResult(verdict=EventVerdict.OUTSIDE, risk_tier=RiskTier.HIGH,
                                    rule_matched="empty or invalid path target", resolved_path="")
        p = self.canonical(path_str, world_home)
        if not _under(p, self.workspace):
            return EvaluationResult(verdict=EventVerdict.OUTSIDE, risk_tier=RiskTier.HIGH,
                                    rule_matched="path escapes task workspace_root (canonical target outside boundary)",
                                    resolved_path=p)
        access = ("write" if os.path.exists(p) else "create") if is_write else "read"
        ok, rule = self.allows(p, access)
        if ok:
            return EvaluationResult(verdict=EventVerdict.INSIDE, risk_tier=RiskTier.LOW,
                                    rule_matched=f"resolved boundary: {rule}", resolved_path=p)
        if _is_sensitive(os.path.basename(p)):
            return EvaluationResult(verdict=EventVerdict.OUTSIDE, risk_tier=RiskTier.HIGH,
                                    rule_matched="prohibited sensitive credential pattern (not in resolved boundary)",
                                    resolved_path=p)
        rel = os.path.relpath(p, self.workspace)
        return EvaluationResult(verdict=EventVerdict.OUTSIDE, risk_tier=RiskTier.MEDIUM,
                                rule_matched=f"not in resolved boundary ({access}): {rel}", resolved_path=p)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolver": RESOLVER_VERSION,
            "workspace": self.workspace,
            "boundary_version": self.boundary_version,
            "entries": [e.to_dict() for e in self.entries],
            "skipped": [{"entry": s, "reason": r} for s, r in self.skipped],
        }


def resolve_boundary(
    boundary: TaskBoundary,
    workspace: str | Path | None = None,
    grants: Iterable[tuple[str, str]] = (),
) -> ResolvedBoundary:
    """Resolves files_read / files_write into canonical entries (rules in the module docstring).

    `grants` are approved expansion requests as (resource_type, resource_target).
    Reads the filesystem (realpath, glob expansion) but never writes to it.
    """
    root = os.path.realpath(workspace if workspace is not None else boundary.workspace_root)
    merged: dict[str, dict[str, Any]] = {}
    skipped: list[tuple[str, str]] = []

    def add(path: str, kind: str, access: frozenset[str], source: str, excl: bool = False) -> None:
        m = merged.get(path)
        if m is None:
            merged[path] = {"kind": kind, "access": set(access), "sources": [source], "excl": excl}
            return
        if m["kind"] != kind:
            skipped.append((source, f"kind_conflict_with_{m['kind']}_entry"))
            return
        m["access"] |= access
        m["sources"].append(source)
        m["excl"] = m["excl"] and excl

    def canon(entry: str) -> tuple[str | None, str]:
        if not entry:
            return None, "empty_entry"
        if os.path.isabs(entry):
            return None, "absolute_entry"
        if ".." in entry.split("/"):
            return None, "dotdot_component"
        if os.path.normpath(entry) != entry:
            return None, "non_canonical_spelling"
        p = os.path.join(root, entry)
        if entry.split("/")[0] in RESERVED_NAMES:
            return None, "reserved_runtime_path"
        if os.path.realpath(p) != p:
            return None, "symlink_in_path"
        anc = os.path.dirname(p)
        while anc != root:
            if os.path.lexists(anc) and not os.path.isdir(anc):
                return None, "parent_not_a_directory"
            anc = os.path.dirname(anc)
        return p, ""

    def files_matching(pattern: str) -> list[str]:
        out = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            rel_dir = os.path.relpath(dirpath, root)
            if rel_dir == ".":
                dirnames[:] = [d for d in dirnames if d not in RESERVED_NAMES]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, root)
                if rel in RESERVED_NAMES or os.path.islink(full) or not os.path.isfile(full):
                    continue
                if fnmatch.fnmatch(rel.lower(), pattern.lower()):
                    out.append(full)
        return sorted(out)

    def norm(e: str) -> str:
        return e.replace("\\", "/").strip()

    grant_reads = {norm(t) for rt, t in grants if rt == "file_read"}
    grant_writes = {norm(t) for rt, t in grants if rt == "file_write"}
    reads = [norm(e) for e in boundary.files_read]
    writes = [norm(e) for e in boundary.files_write]
    read_set, write_set = set(reads), set(writes)

    for e in reads:
        if "/" not in e and f"input/{e}" in read_set:
            skipped.append((e, f"bare_alias_of:input/{e}"))
            continue
        if e in grant_reads:
            skipped.append((e, "grant_resolved_to_delivered_copy:granted/"))
            continue
        if _is_glob(e):
            matched = False
            for f in files_matching(e):
                if _is_sensitive(os.path.basename(f)):
                    skipped.append((e, f"sensitive_pattern_excluded_from_glob:{os.path.relpath(f, root)}"))
                    continue
                p, why = canon(os.path.relpath(f, root))
                if p is None:
                    skipped.append((e, why))
                    continue
                add(p, "file", READ, f"files_read:{e}")
                matched = True
            if not matched:
                skipped.append((e, "glob_matched_no_files_at_resolve"))
            continue
        p, why = canon(e)
        if p is None:
            skipped.append((e, why))
        elif os.path.isfile(p):
            add(p, "file", READ, f"files_read:{e}")
        elif os.path.isdir(p):
            skipped.append((e, "directory_named_in_files_read"))
        else:
            skipped.append((e, "not_present_at_resolve"))

    for e in writes:
        if "/" not in e and f"output/{e}" in write_set:
            skipped.append((e, f"bare_alias_of:output/{e}"))
            continue
        if e in grant_writes:
            skipped.append((e, "write_grant_not_enforceable_in_kernel"))
            continue
        if _is_glob(e):
            m = _DIR_GLOB.match(e)
            if m:
                p, why = canon(m.group(1))
                if p is None:
                    skipped.append((e, why))
                elif os.path.exists(p) and not os.path.isdir(p):
                    skipped.append((e, "glob_prefix_is_not_a_directory"))
                else:
                    add(p, "dir", DIR_WRITE, f"files_write:{e}", excl=True)
                continue
            prefix = e.split("*")[0].split("?")[0].split("[")[0].rstrip("/")
            pdir, why = canon(prefix) if prefix else (None, "glob_without_directory_prefix")
            if pdir is None:
                skipped.append((e, why))
                continue
            matched = False
            for f in files_matching(e):
                p, _ = canon(os.path.relpath(f, root))
                if p is not None and p.startswith(pdir + "/"):
                    add(p, "file", READ | {"write"}, f"files_write:{e}")
                    matched = True
            skipped.append((e, "write_glob_narrowed_to_existing_files" if matched else "glob_matched_no_files_at_resolve"))
            continue
        p, why = canon(e)
        if p is None:
            skipped.append((e, why))
        elif os.path.isdir(p):
            skipped.append((e, "directory_named_in_files_write"))
        else:
            add(p, "file", FILE_WRITE, f"files_write:{e}")

    add(os.path.join(root, "output"), "dir", READ, "task_output_dir")
    add(os.path.join(root, "granted"), "dir", READ, "expansion_delivery_dir")

    entries = tuple(
        ResolvedEntry(path=p, kind=m["kind"], access=frozenset(m["access"]), sources=tuple(m["sources"]),
                      exclude_sensitive_writes=bool(m["excl"]))
        for p, m in sorted(merged.items())
    )
    return ResolvedBoundary(workspace=root, task_id=boundary.task_id, boundary_version=boundary.version,
                            entries=entries, skipped=tuple(skipped))


def approved_file_grants(storage: Any, task_id: str) -> list[tuple[str, str]]:
    """Approved file_read / file_write expansions of a task that added an entry, as resolver grants.

    A target already in boundary version 1 was granted at launch (and is in the
    kernel ruleset); approving it again adds nothing, so it is not a grant.
    """
    if storage is None:
        return []
    from .models import ExpansionStatus
    base = storage.get_boundary(task_id, version=1)
    at_launch = {"file_read": set(base.files_read), "file_write": set(base.files_write)} if base else {}
    return sorted({(r.resource_type, r.resource_target)
                   for r in storage.list_expansion_requests(task_id=task_id)
                   if r.status == ExpansionStatus.APPROVED and r.resource_type in ("file_read", "file_write")
                   and r.resource_target not in at_launch.get(r.resource_type, set())})


class ResolvedBoundaryEvaluator(BoundaryEvaluator):
    """Tool-layer file checks against the ResolvedBoundary (the M7 path).

    Network, peer-agent, command and tool checks are BoundaryEvaluator's own.
    File checks never read files_read / files_write: they resolve the current
    boundary (with the task's approved grants) and ask ResolvedBoundary.evaluate.
    """

    def __init__(self, storage: Any = None, world_home: str | None = None) -> None:
        super().__init__(world_home=world_home)
        self.storage = storage

    def resolve(self, boundary: TaskBoundary) -> ResolvedBoundary:
        return resolve_boundary(boundary, boundary.workspace_root,
                                grants=approved_file_grants(self.storage, boundary.task_id))

    def evaluate_file_access(self, boundary: TaskBoundary, path_str: str, is_write: bool) -> EvaluationResult:
        return self.resolve(boundary).evaluate(path_str, is_write, self.world_home)
