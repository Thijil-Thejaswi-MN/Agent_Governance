"""Agent Profile Loader and Validation.

Loads admin-configured agent profiles defining delegation ceilings and execution runners.
Ceilings are immutable boundaries configured by administrators, never by calling agents.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_AGENTS_DIR = Path(__file__).resolve().parent / "agents"

REQUIRED_FIELDS = ("id", "name", "owner", "description", "ceiling", "runner")
CEILING_FIELDS = ("tools", "files_read", "files_write", "network", "peer_agents")


def validate_agent_profile(data: dict[str, Any]) -> dict[str, Any]:
    """Validates structure and types of an agent profile."""
    if not isinstance(data, dict):
        raise ValueError("Agent profile must be a dictionary")

    for f in REQUIRED_FIELDS:
        if f not in data:
            raise ValueError(f"Agent profile missing required field: {f}")

    if not isinstance(data["id"], str) or not data["id"].strip():
        raise ValueError("Agent profile id must be a non-empty string")
    if not isinstance(data["name"], str):
        raise ValueError("Agent profile name must be a string")
    if not isinstance(data["owner"], str):
        raise ValueError("Agent profile owner must be a string")
    if not isinstance(data["description"], str):
        raise ValueError("Agent profile description must be a string")

    ceiling = data["ceiling"]
    if not isinstance(ceiling, dict):
        raise ValueError("Agent profile ceiling must be a dictionary")

    for cf in CEILING_FIELDS:
        if cf not in ceiling:
            raise ValueError(f"Agent profile ceiling missing field: {cf}")
        if not isinstance(ceiling[cf], list):
            raise ValueError(f"Agent profile ceiling.{cf} must be a list of strings")
        for item in ceiling[cf]:
            if not isinstance(item, str):
                raise ValueError(f"Agent profile ceiling.{cf} elements must be strings, got {type(item)}")

    runner = data["runner"]
    if not isinstance(runner, dict):
        raise ValueError("Agent profile runner must be a dictionary")
    if "provider" not in runner or not isinstance(runner["provider"], str):
        raise ValueError("Agent profile runner must specify a string provider")

    if runner["provider"] == "scripted":
        steps = runner.get("steps")
        if not isinstance(steps, list):
            raise ValueError("Scripted runner must define a list of steps")
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ValueError(f"Scripted runner step {idx} must be a dictionary")
            if "tool" not in step and "final" not in step:
                raise ValueError(f"Scripted runner step {idx} must have 'tool' or 'final'")

    return data


_PROFILE_CACHE: dict[str, dict[str, Any]] = {}


def clear_profile_cache() -> None:
    _PROFILE_CACHE.clear()


def load_agent_profile(agent_id: str, agents_dir: Path | str | None = None) -> dict[str, Any]:
    """Loads a validated agent profile by identifier from JSON disk storage."""
    base = Path(agents_dir) if agents_dir else DEFAULT_AGENTS_DIR
    cache_key = f"{base}:{agent_id}"
    if cache_key in _PROFILE_CACHE:
        return _PROFILE_CACHE[cache_key]

    fpath = base / f"{agent_id}.json"
    if not fpath.is_file():
        raise FileNotFoundError(f"Agent profile not found for '{agent_id}' at {fpath}")

    with open(fpath, "r", encoding="utf-8") as f:
        data = json.load(f)

    validated = validate_agent_profile(data)
    _PROFILE_CACHE[cache_key] = validated
    return validated


def load_all_agent_profiles(agents_dir: Path | str | None = None) -> dict[str, dict[str, Any]]:
    """Loads and validates all agent profiles in the agents directory."""
    base = Path(agents_dir) if agents_dir else DEFAULT_AGENTS_DIR
    if not base.is_dir():
        return {}

    out: dict[str, dict[str, Any]] = {}
    for fpath in sorted(base.glob("*.json")):
        aid = fpath.stem
        try:
            out[aid] = load_agent_profile(aid, base)
        except Exception:
            pass
    return out
