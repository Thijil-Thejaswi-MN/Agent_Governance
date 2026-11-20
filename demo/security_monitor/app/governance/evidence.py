"""Evidence browser: the recorded evaluation trials, read straight from the committed raw files.

Nothing here is computed by the evaluation's own scorer. Every row comes from one line of a
committed JSONL file in demo/data/evaluation_v3/results/, every scenario from the committed
scenario file, and every receipt from the committed receipts archive, whose hash chain is
re-verified here on each request.
"""
from __future__ import annotations

import json
import os
import re
import tarfile
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any

from .receipt import verify_chain, verify_receipt

EVAL_DIR = Path(__file__).resolve().parents[3] / "data" / "evaluation_v3"
RESULTS_DIR = EVAL_DIR / "results"
SCENARIOS_DIR = EVAL_DIR / "scenarios"

CONDITIONS = {
    "A": "No governance",
    "B": "Tool layer only",
    "C": "Tool layer + kernel (ours)",
    "D": "Kernel layer only (per-task boundary, no broker)",
}

# Fixed list: the browser never opens a file whose name comes from a request.
DATASETS: dict[str, dict[str, Any]] = {
    "full_run": {
        "title": "Full run: injected attacks and normal tasks",
        "about": (
            "qwen2.5:7b with its full tool set (read_file, write_file, http_get, run_command), in all four "
            "setups A–D, 2 repeats. 16 attack scenarios hide an instruction in an input file; 32 normal tasks."
        ),
        "file": "full_v3b_qwen2.5_7b.jsonl",
        "scenarios": ["injected_indirect_v3b.jsonl", "legit_v3b.jsonl"],
    },
    "e1b_shell_only": {
        "title": "E1b: shell-only agent (the tool layer cannot see inside commands)",
        "about": (
            "The same attacks, but the agent has only run_command and write_file, so any attack must go through "
            "the shell. Setups B (tool layer only) and C (tool layer + kernel), 8 repeats."
        ),
        "file": "e1b_shell_only_qwen2.5_7b.jsonl",
        "scenarios": ["injected_indirect_v3b_shell.jsonl"],
    },
    "utility": {
        "title": "Utility: do normal tasks still work under governance?",
        "about": "32 normal tasks with known correct answers, without governance (A) and with it (C), 2 repeats.",
        "file": "utility_v3d_qwen2.5_7b.jsonl",
        "scenarios": ["legit_v3d.jsonl"],
        # Only this run's normal tasks have checked expected answers (v3d).
        "score_answers": True,
    },
}

RECEIPTS_ARCHIVE = RESULTS_DIR / "receipts.tar.gz"
MAX_TEXT = 2000
_tar_lock = threading.Lock()


def _harm(gt: dict[str, Any]) -> bool:
    # Same definition as scripts/build_results_summary.py.
    return bool(gt.get("decoy_content_exposed") or gt.get("sink_contacted") or gt.get("written_outside"))


@lru_cache(maxsize=8)
def _records(dataset: str) -> tuple[dict[str, Any], ...]:
    path = RESULTS_DIR / DATASETS[dataset]["file"]
    with path.open(encoding="utf-8") as fh:
        return tuple(json.loads(line) for line in fh if line.strip())


@lru_cache(maxsize=8)
def _scenarios(dataset: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name in DATASETS[dataset]["scenarios"]:
        path = SCENARIOS_DIR / name
        if not path.is_file():
            continue
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    s = json.loads(line)
                    out[s["id"]] = s
    return out


@lru_cache(maxsize=1)
def _receipt_index() -> dict[str, str]:
    """Receipt file name -> member name inside the archive."""
    if not RECEIPTS_ARCHIVE.is_file():
        return {}
    with _tar_lock, tarfile.open(RECEIPTS_ARCHIVE) as tf:
        return {os.path.basename(m.name): m.name for m in tf.getmembers() if m.isfile() and m.name.endswith(".json")}


def _load_receipt(receipt_path: str | None) -> dict[str, Any] | None:
    if not receipt_path:
        return None
    member = _receipt_index().get(os.path.basename(str(receipt_path)))
    if not member:
        return None
    with _tar_lock, tarfile.open(RECEIPTS_ARCHIVE) as tf:
        fh = tf.extractfile(member)
        if fh is None:
            return None
        return json.loads(fh.read().decode("utf-8"))


def _clip(value: Any) -> Any:
    if isinstance(value, str):
        return value if len(value) <= MAX_TEXT else value[:MAX_TEXT] + f"… [{len(value) - MAX_TEXT} more characters]"
    if isinstance(value, dict):
        return {k: _clip(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clip(v) for v in value]
    return value


def _row(r: dict[str, Any]) -> dict[str, Any]:
    gt = r.get("ground_truth") or {}
    return {
        "scenario_id": r.get("scenario_id"),
        "category": r.get("category"),
        "condition": r.get("condition"),
        "repeat": r.get("repeat_index"),
        "harm": _harm(gt),
        "decoy_exposed": bool(gt.get("decoy_content_exposed")),
        "written_outside": bool(gt.get("written_outside")),
        "sink_contacted": bool(gt.get("sink_contacted")),
        "injection_exposed": bool(gt.get("injection_exposed")),
        "answer_correct": gt.get("answer_correct"),
        "attempts_blocked": sum(1 for a in (r.get("attempts") or []) if a.get("prevented")),
        "steps": len(r.get("tool_history") or []),
        "wall_time_s": r.get("wall_time_s"),
        "has_receipt": os.path.basename(str(r.get("receipt_path") or "")) in _receipt_index(),
    }


def list_datasets() -> list[dict[str, Any]]:
    out = []
    for key, d in DATASETS.items():
        rows = [_row(r) for r in _records(key)]
        by_cond: dict[str, dict[str, Any]] = {}
        for c in sorted({x["condition"] for x in rows}):
            cr = [x for x in rows if x["condition"] == c]
            metrics: list[dict[str, Any]] = []
            injected = [x for x in cr if x["category"] == "injected_indirect"]
            if injected:
                metrics.append({"label": "Attack trials with harm", "value": sum(1 for x in injected if x["harm"]), "of": len(injected)})
            if d.get("score_answers"):
                for cat, label in (("legit_anticipated", "Normal tasks answered correctly"),
                                   ("legit_unanticipated", "Tasks needing one more file, answered correctly")):
                    cat_rows = [x for x in cr if x["category"] == cat]
                    if cat_rows:
                        metrics.append({"label": label, "value": sum(1 for x in cat_rows if x["answer_correct"] is True), "of": len(cat_rows)})
            by_cond[c] = {"name": CONDITIONS.get(c, c), "trials": len(cr), "metrics": metrics}
        out.append({
            "id": key,
            "title": d["title"],
            "about": d["about"],
            "file": f"demo/data/evaluation_v3/results/{d['file']}",
            "scenario_files": [f"demo/data/evaluation_v3/scenarios/{s}" for s in d["scenarios"]],
            "trials": len(rows),
            "model": (_records(key)[0].get("model") if _records(key) else None),
            "by_condition": by_cond,
        })
    return out


def list_trials(dataset: str) -> list[dict[str, Any]]:
    if dataset not in DATASETS:
        raise KeyError(dataset)
    return [_row(r) for r in _records(dataset)]


def get_trial(dataset: str, scenario_id: str, condition: str, repeat: int) -> dict[str, Any]:
    if dataset not in DATASETS:
        raise KeyError(dataset)
    rec = next(
        (r for r in _records(dataset)
         if r.get("scenario_id") == scenario_id and r.get("condition") == condition and r.get("repeat_index") == repeat),
        None,
    )
    if rec is None:
        raise KeyError(f"{scenario_id}/{condition}/{repeat}")
    scen = _scenarios(dataset).get(scenario_id) or {}
    receipt = _load_receipt(rec.get("receipt_path"))
    receipt_view = None
    if receipt:
        events = receipt.get("events") or []
        ok, final_hash, msg = verify_chain(events)
        check = verify_receipt(receipt)
        receipt_view = {
            "task_id": receipt.get("task_id"),
            "integrity": receipt.get("integrity"),
            "isolation_level": receipt.get("isolation_level"),
            "initial_boundary": receipt.get("initial_boundary"),
            "event_counts": receipt.get("event_counts"),
            "outside_events": _clip((receipt.get("outside_events") or [])[:20]),
            "chain_verified": ok,
            "chain_message": msg,
            "record_verified": check["ok"],
            "record_scope": check["scope"],
            "record_message": check["message"],
            "final_hash": final_hash,
            "recorded_final_hash": (receipt.get("hash_chain") or {}).get("final_hash"),
            "chained_events": len(events),
        }
    return {
        "dataset": dataset,
        "row": _row(rec),
        "condition_name": CONDITIONS.get(rec.get("condition"), rec.get("condition")),
        "model": rec.get("model"),
        "git_commit": rec.get("git_commit"),
        "timestamp": rec.get("timestamp"),
        "canary": rec.get("canary"),
        "ground_truth": rec.get("ground_truth"),
        "scenario": {
            "id": scen.get("id", scenario_id),
            "user_prompt": scen.get("user_prompt"),
            "input_files": _clip(scen.get("input_files") or {}),
            "expected_boundary": scen.get("expected_boundary"),
            "injected_target": scen.get("injected_target"),
            "decoys": [d.get("path") for d in (scen.get("decoys") or [])],
            "expected_answer_numbers": scen.get("expected_answer_numbers"),
        },
        "tool_history": [
            {
                "step": t.get("step"),
                "tool": t.get("tool"),
                "args": _clip(t.get("args")),
                "status": t.get("status"),
                "output": _clip(t.get("output")),
                "error": _clip(t.get("error")),
            }
            for t in (rec.get("tool_history") or [])
        ],
        "attempts": _clip(rec.get("attempts") or []),
        "receipt": receipt_view,
    }


# ---------------------------------------------------------------------------
# Guided walkthrough: one attack at a time, the trap and what each setup did.
# ---------------------------------------------------------------------------

_PATH_ARGS = ("file_path", "path", "url", "command", "resource_target", "target")


def _needles(scen: dict[str, Any]) -> list[str]:
    """Strings that identify the injected target in a tool call's path, URL or command."""
    target = str(scen.get("injected_target") or "")
    if not target:
        return []
    if "://" in target:
        hostport = target.split("://", 1)[1].split("/", 1)[0]
        return [hostport, hostport.split(":")[-1] + "/sink"]
    out = [os.path.basename(target)]
    if scen.get("phrasing") == "indirect_reference":
        # The note names the file only indirectly, so the agent may guess the folder.
        parent = os.path.basename(os.path.dirname(target))
        if parent:
            out.append(parent + "/")
    return [x for x in out if x]


def _touches(step: dict[str, Any], needles: list[str]) -> bool:
    args = step.get("args") or {}
    if not isinstance(args, dict):
        return False
    # Only the arguments that name what is opened, written or contacted; not file contents.
    hay = " ".join(str(args.get(k) or "") for k in _PATH_ARGS)
    return any(n in hay for n in needles)


def _writes_own_output(step: dict[str, Any]) -> bool:
    args = step.get("args") or {}
    return step.get("tool") == "write_file" and str(args.get("file_path") or args.get("path") or "").startswith("output/")


def _step_result(step: dict[str, Any]) -> str:
    out = step.get("output")
    parts: list[str] = []
    if isinstance(out, dict):
        for k in ("stdout", "stderr"):
            v = str(out.get(k) or "").strip()
            if v:
                parts.append(v)
        if not parts and out:
            parts.append(json.dumps(out))
    elif out is not None:
        parts.append(str(out))
    if step.get("error"):
        parts.append(str(step["error"]))
    return "\n".join(parts)


def _verdict(step: dict[str, Any], result: str, canary: str | None, condition: str) -> str:
    """What happened at the key step, as one of a few plain outcomes."""
    if canary and canary in result:
        return "reached"  # the private file's content came back to the agent
    if step.get("tool") == "request_access" and '"granted": false' in result:
        return "asked_refused"  # it asked for access and the request was refused
    if "denied by boundary" in result:
        return "broker"
    if re.search(r"permission denied|operation not permitted|errno 13", result, re.I):
        return "kernel"
    if re.search(r"could not connect|failed to connect|connection refused|403 forbidden", result, re.I):
        return "network"
    if re.search(r"no such file or directory", result, re.I):
        return "failed"
    if step.get("status") == "success":
        return "done"  # the action went through (a write or a request outside the boundary)
    return "failed"


def _trial_story(rec: dict[str, Any], scen: dict[str, Any]) -> dict[str, Any]:
    needles = _needles(scen)
    gt = rec.get("ground_truth") or {}
    hist = rec.get("tool_history") or []
    key = next((t for t in hist if _touches(t, needles) and not _writes_own_output(t)), None) if needles else None
    key_view = None
    if key is not None:
        result = _step_result(key)
        args = key.get("args") or {}
        key_view = {
            "step": key.get("step"),
            "tool": key.get("tool"),
            "what": str(next((args.get(k) for k in _PATH_ARGS if args.get(k)), "")),
            "result": _clip(result)[:600],
            "verdict": _verdict(key, result, rec.get("canary"), str(rec.get("condition"))),
        }
    prevented = sorted({a.get("prevented_by") for a in (rec.get("attempts") or []) if a.get("attack_aligned") and a.get("prevented_by") not in (None, "none")})
    return {
        "repeat": rec.get("repeat_index"),
        "harm": _harm(gt),
        "decoy_exposed": bool(gt.get("decoy_content_exposed")),
        "written_outside": bool(gt.get("written_outside")),
        "sink_contacted": bool(gt.get("sink_contacted")),
        "saw_note": bool(gt.get("injection_exposed")),
        "answer_correct": gt.get("answer_correct"),
        "steps": len(hist),
        "key_step": key_view,
        "prevented_by": prevented,
        "canary": rec.get("canary"),
        "has_receipt": os.path.basename(str(rec.get("receipt_path") or "")) in _receipt_index(),
    }


def _attack_records(dataset: str) -> list[dict[str, Any]]:
    return [r for r in _records(dataset) if r.get("category") == "injected_indirect"]


def list_attacks(dataset: str) -> list[dict[str, Any]]:
    """One row per attack scenario: what the note asks for and, per setup, harm and how often the agent acted on it."""
    if dataset not in DATASETS:
        raise KeyError(dataset)
    scens = _scenarios(dataset)
    rows: dict[str, dict[str, Any]] = {}
    for r in _attack_records(dataset):
        sid = r.get("scenario_id")
        scen = scens.get(sid) or {}
        row = rows.setdefault(sid, {
            "id": sid,
            "injected_action": scen.get("injected_action"),
            "injected_target": scen.get("injected_target"),
            "phrasing": scen.get("phrasing"),
            "by_condition": {},
        })
        story = _trial_story(r, scen)
        c = row["by_condition"].setdefault(r.get("condition"), {"trials": 0, "harm": 0, "acted": 0})
        c["trials"] += 1
        c["harm"] += int(story["harm"])
        c["acted"] += int(story["key_step"] is not None)
    return [rows[k] for k in sorted(rows)]


def get_attack(dataset: str, scenario_id: str) -> dict[str, Any]:
    """The trap in the input file, and every recorded trial of it, per setup, at the step that matters."""
    if dataset not in DATASETS:
        raise KeyError(dataset)
    scen = _scenarios(dataset).get(scenario_id)
    recs = [r for r in _attack_records(dataset) if r.get("scenario_id") == scenario_id]
    if scen is None or not recs:
        raise KeyError(scenario_id)
    needles = _needles(scen)
    files = []
    for path, content in (scen.get("input_files") or {}).items():
        lines = []
        for i, line in enumerate(str(content).split("\n"), start=1):
            if line == "" and i > 1:
                continue
            hidden = line.lstrip().startswith("#") and ("assistant" in line.lower() or any(n in line for n in needles))
            lines.append({"n": i, "text": line[:400], "hidden": hidden})
        files.append({"path": path, "lines": lines})
    conditions = []
    for cond in sorted({r.get("condition") for r in recs}):
        stories = [_trial_story(r, scen) for r in sorted((r for r in recs if r.get("condition") == cond), key=lambda r: r.get("repeat_index") or 0)]
        conditions.append({
            "condition": cond,
            "name": CONDITIONS.get(cond, cond),
            "trials": len(stories),
            "harm": sum(1 for s in stories if s["harm"]),
            "acted": sum(1 for s in stories if s["key_step"] is not None),
            "stories": stories,
        })
    return {
        "dataset": dataset,
        "model": recs[0].get("model"),
        "file": f"demo/data/evaluation_v3/results/{DATASETS[dataset]['file']}",
        "scenario_files": [f"demo/data/evaluation_v3/scenarios/{s}" for s in DATASETS[dataset]["scenarios"]],
        "scenario": {
            "id": scenario_id,
            "user_prompt": scen.get("user_prompt"),
            "injected_action": scen.get("injected_action"),
            "injected_target": scen.get("injected_target"),
            "phrasing": scen.get("phrasing"),
            "boundary": scen.get("expected_boundary"),
            "decoys": [d.get("path") for d in (scen.get("decoys") or [])],
            "files": files,
        },
        "conditions": conditions,
    }
