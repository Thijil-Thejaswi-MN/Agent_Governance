"""Scale-Adaptive Map and Demo Data (Console v4).

layout_mode(count):
- <= 20 active agents: "individual" (one node per agent on the map, and cards below)
- 20 < count <= 500: "teams" (the map shows teams as nodes sized by agent count, sortable virtualised table)
- > 500: "canvas" (teams as nodes, <canvas> above 1500 elements, exceptions only: stopped, waiting)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def layout_mode(active_agent_count: int) -> str:
    """Returns the scale-adaptive display mode according to active agent count."""
    if active_agent_count <= 20:
        return "individual"
    elif active_agent_count <= 500:
        return "teams"
    else:
        return "canvas"


def is_demo_data_enabled() -> bool:
    """Returns True if GOVERNANCE_DEMO_DATA=1 is set."""
    return os.getenv("GOVERNANCE_DEMO_DATA", "0").strip() in ("1", "true", "True")


def get_demo_db_path() -> Path:
    """Returns the path to the separate demo database file."""
    return Path(os.getenv("GOVERNANCE_DEMO_DB_PATH", "/tmp/governance_demo.db"))


def get_demo_size() -> int:
    """Returns the demo size configured in GOVERNANCE_DEMO_SIZE (default 200)."""
    try:
        return int(os.getenv("GOVERNANCE_DEMO_SIZE", "200").strip())
    except (ValueError, TypeError):
        return 200
