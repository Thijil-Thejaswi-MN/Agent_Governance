"""One rule for "./" in front of a workspace path.

`str.lstrip("./")` removes any leading "." and "/" characters, so ".reference/a.csv"
became "reference/a.csv": the person approved one name and the control plane delivered a
different file (independent audit, finding A2). Only whole leading "./" segments are
removed here; a name that starts with a dot keeps it.
"""
from __future__ import annotations


def strip_dot_slash(path: str) -> str:
    p = path
    while p.startswith("./"):
        p = p[2:]
    return p
