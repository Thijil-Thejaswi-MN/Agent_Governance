"""Content-reviewed writes: the agent stages a file, a person approves those exact bytes, the system lands them.

Landlock cannot widen after restrict_self, so an approved file_write never makes
the target writable for the agent. Instead (roadmap item 4):

1. The agent writes the file it was not given to staged/<target>. staged/ is a
   resolved dir entry, writable at both layers (resolved_boundary.STAGED_DIR).
2. When the agent asks (request_access file_write <target>), the control plane
   snapshots staged/<target> from outside the sandbox: every path component is
   opened with O_NOFOLLOW, the file must be a regular file with one link and at
   most MAX_STAGED_BYTES. The bytes are read once and hashed.
3. The person sees a preview of those bytes on the approval card.
4. On approval the control plane writes the snapshot (never the staged file as
   it is now) to <target>, created exclusively: an existing target is refused.

Nothing here runs inside the sandbox; these functions are called by the
launcher's ExpansionDelivery (control plane).
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

STAGED_DIR = "staged"
MAX_STAGED_BYTES = 1024 * 1024
PREVIEW_CHARS = 2000
# Top-level names a write target may never be under (runtime support and the expansion folders).
RESERVED_TOP = ("tmp", "runtime", "granted", STAGED_DIR, "broker.sock")


def normalize_write_target(target: str) -> str | None:
    """The canonical relative target, or None when it is not a plain path inside the workspace."""
    t = str(target or "").strip().replace("\\", "/")
    while t.startswith("./"):
        t = t[2:]
    if t.startswith(STAGED_DIR + "/"):
        t = t[len(STAGED_DIR) + 1:]
    if not t or t.startswith("/") or t.endswith("/"):
        return None
    parts = t.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    if len(parts[0]) == 2 and parts[0][1] == ":":
        return None
    if parts[0] in RESERVED_TOP or any(c in t for c in ("*", "?", "[", "]", "\x00")):
        return None
    return t


def _open_nofollow_chain(root: Path, rel_parts: list[str], create_dirs: bool = False) -> int:
    """An O_DIRECTORY fd for root/rel_parts, refusing a symlink at any component."""
    fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in rel_parts:
            if create_dirs:
                try:
                    os.mkdir(part, 0o755, dir_fd=fd)
                except FileExistsError:
                    pass
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def snapshot_staged(workspace: str | Path, target: str) -> dict[str, Any]:
    """Reads staged/<target> once, safely. Returns {ok, ...}; on success `data` holds the bytes."""
    t = normalize_write_target(target)
    if t is None:
        return {"ok": False, "reason": "invalid_target", "target": str(target)}
    ws = Path(workspace).resolve()
    parts = t.split("/")
    staged_rel = f"{STAGED_DIR}/{t}"
    try:
        dfd = _open_nofollow_chain(ws, [STAGED_DIR, *parts[:-1]])
    except FileNotFoundError:
        return {"ok": False, "reason": "not_staged", "target": t, "staged_path": staged_rel}
    except OSError:
        return {"ok": False, "reason": "staged_path_not_a_plain_folder", "target": t, "staged_path": staged_rel}
    try:
        try:
            ffd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except FileNotFoundError:
            return {"ok": False, "reason": "not_staged", "target": t, "staged_path": staged_rel}
        except OSError:
            return {"ok": False, "reason": "staged_file_is_a_link", "target": t, "staged_path": staged_rel}
        try:
            st = os.fstat(ffd)
            if not stat.S_ISREG(st.st_mode):
                return {"ok": False, "reason": "staged_file_not_regular", "target": t, "staged_path": staged_rel}
            if st.st_nlink != 1:
                return {"ok": False, "reason": "staged_file_has_links", "target": t, "staged_path": staged_rel}
            if st.st_size > MAX_STAGED_BYTES:
                return {"ok": False, "reason": "staged_file_too_large", "target": t, "staged_path": staged_rel,
                        "size_bytes": st.st_size}
            chunks: list[bytes] = []
            total = 0
            while True:
                b = os.read(ffd, 65536)
                if not b:
                    break
                total += len(b)
                if total > MAX_STAGED_BYTES:
                    return {"ok": False, "reason": "staged_file_too_large", "target": t, "staged_path": staged_rel}
                chunks.append(b)
            data = b"".join(chunks)
        finally:
            os.close(ffd)
    finally:
        os.close(dfd)
    binary = b"\x00" in data
    text = "" if binary else data.decode("utf-8", errors="replace")
    return {
        "ok": True,
        "target": t,
        "staged_path": staged_rel,
        "size_bytes": len(data),
        "content_sha256": hashlib.sha256(data).hexdigest(),
        "binary": binary,
        "preview": text[:PREVIEW_CHARS],
        "truncated": len(text) > PREVIEW_CHARS,
        "data": data,
    }


def land_snapshot(workspace: str | Path, target: str, data: bytes) -> dict[str, Any]:
    """Writes the reviewed bytes to <target>, created exclusively and never through a link."""
    t = normalize_write_target(target)
    if t is None:
        return {"ok": False, "reason": "invalid_target"}
    ws = Path(workspace).resolve()
    parts = t.split("/")
    try:
        dfd = _open_nofollow_chain(ws, parts[:-1], create_dirs=True)
    except OSError:
        return {"ok": False, "reason": "target_folder_not_a_plain_folder"}
    try:
        try:
            ffd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
        except FileExistsError:
            return {"ok": False, "reason": "target_exists"}
        except OSError:
            return {"ok": False, "reason": "target_not_writable"}
        try:
            view = memoryview(data)
            while view:
                n = os.write(ffd, view)
                view = view[n:]
            os.fsync(ffd)
        finally:
            os.close(ffd)
    finally:
        os.close(dfd)
    return {"ok": True, "landed_path": t, "content_sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
