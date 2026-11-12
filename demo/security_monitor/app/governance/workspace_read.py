"""Read-only helpers over one task's workspace (Console v4: approval preview, incidents).

Every path is resolved (symlinks followed) and must stay inside that task's workspace
root; anything else is reported as unknown. Nothing here writes, and nothing here is
used by enforcement.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from typing import Any

MAX_SEARCH_FILE_BYTES = 2 * 1024 * 1024
MAX_LINE_CHARS = 300


def resolve_inside(workspace_root: str | Path | None, rel: str | None) -> Path | None:
    """`rel` resolved under `workspace_root`, or None if it is empty, absolute, uses '..',
    or (after following symlinks) lands outside the workspace."""
    if not workspace_root or not rel:
        return None
    raw = str(rel).strip().replace("\\", "/")
    if not raw or "\x00" in raw:
        return None
    if raw.startswith("/") or raw.startswith("~") or (len(raw) > 1 and raw[1] == ":"):
        return None
    parts = [p for p in PurePosixPath(raw).parts if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    try:
        root = Path(workspace_root).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not root.is_dir():
        return None
    try:
        candidate = root.joinpath(*parts).resolve(strict=False)
        candidate.relative_to(root)
    except (ValueError, OSError, RuntimeError):
        return None
    return candidate


def file_preview(workspace_root: str | Path | None, resource_type: str, target: str) -> dict[str, Any]:
    """Name, folder and size of a requested file, without reading it."""
    norm = str(target or "").strip().replace("\\", "/")
    p = PurePosixPath(norm) if norm else PurePosixPath(".")
    out: dict[str, Any] = {
        "kind": "file" if resource_type in ("file_read", "file_write") else
                "address" if resource_type == "network" else
                "agent" if resource_type == "peer_agent" else "other",
        "name": p.name or norm,
        "folder": str(p.parent) if str(p.parent) not in (".", "") else None,
        "size_bytes": None,
        "exists": None,
        "inside_workspace": None,
    }
    if out["kind"] != "file":
        return out
    try:
        root_ok = bool(workspace_root) and Path(workspace_root).resolve(strict=True).is_dir()
    except (OSError, RuntimeError):
        root_ok = False
    if not root_ok:
        return out  # the workspace is gone: everything stays unknown
    resolved = resolve_inside(workspace_root, norm)
    out["inside_workspace"] = resolved is not None
    if resolved is None:
        return out
    try:
        st = os.stat(resolved)
    except OSError:
        out["exists"] = False
        return out
    if resolved.is_file():
        out["exists"] = True
        out["size_bytes"] = st.st_size
    else:
        out["exists"] = False
    return out


def find_mention(workspace_root: str | Path | None, files: list[str], target: str) -> dict[str, Any] | None:
    """The first line, in the given workspace files (in order), that mentions `target`
    by its path or its file name. None when no such line is found."""
    norm = str(target or "").strip().replace("\\", "/").lstrip("./")
    if not norm:
        return None
    name = PurePosixPath(norm).name
    needles = [n.lower() for n in dict.fromkeys([norm, name]) if n and len(n) >= 3]
    if not needles:
        return None
    seen: set[Path] = set()
    for rel in files:
        path = resolve_inside(workspace_root, rel)
        if path is None or path in seen:
            continue
        seen.add(path)
        try:
            if not path.is_file() or path.stat().st_size > MAX_SEARCH_FILE_BYTES:
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    low = line.lower()
                    if any(n in low for n in needles):
                        text = line.rstrip("\r\n")
                        if len(text) > MAX_LINE_CHARS:
                            text = text[:MAX_LINE_CHARS] + "…"
                        return {"file": str(PurePosixPath(rel.replace("\\", "/"))), "line_number": lineno, "line": text}
        except OSError:
            continue
    return None
