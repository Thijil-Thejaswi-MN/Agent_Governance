"""Agent shim: runs LLMAgent inside the task sandbox (M6.1 / M6.2).

Launched by the launcher as the last link of
    systemd scope -> world -> sensor -> [seccomp -> Landlock] -> agent_shim
and executed with the system interpreter from a per-task read-only copy
(`<workspace>/runtime/`), so it imports only the stdlib and `llm_agent`.

- LLM inference only through `llm_complete` on the broker Unix socket.
- Conditions B and C: mediated tools go to the broker over the same socket.
- Conditions A and D: direct I/O execution, no broker tools, no request_access.
- run_command:
  - Conditions B and C: asks the broker (`run_command_check`); if allowed, executes
    locally as child of shim.
  - Conditions A and D: executes directly as child of shim.

Inputs arrive on inherited pipe fds:
  GOVERNANCE_TOKEN_FD   task token (read once, then closed)
  GOVERNANCE_TASK_FD    JSON task spec: prompt, system_prompt, max_iterations, ...
  GOVERNANCE_RESULT_FD  where the shim writes its JSON result
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm_agent import GOVERNED_TOOLS_SCHEMA, AgentBrokerClient, LLMAgent  # noqa: E402

OUTPUT_LIMIT = 4000
PR_SET_DUMPABLE = 4

DIRECT_TOOLS_SCHEMA = [
    t for t in GOVERNED_TOOLS_SCHEMA
    if t.get("function", {}).get("name") in ("read_file", "write_file", "http_get", "run_command")
]


def _read_fd(env_name: str) -> bytes:
    fd_str = os.environ.pop(env_name, None)
    if not fd_str:
        raise RuntimeError(f"{env_name} not provided")
    fd = int(fd_str)
    chunks = []
    while True:
        b = os.read(fd, 65536)
        if not b:
            break
        chunks.append(b)
    os.close(fd)
    return b"".join(chunks)


def _truncate(text: str) -> tuple[str, bool]:
    if len(text) <= OUTPUT_LIMIT:
        return text, False
    return text[:OUTPUT_LIMIT] + f"\n...[truncated {len(text) - OUTPUT_LIMIT} chars]", True


class SandboxedBrokerClient(AgentBrokerClient):
    """Broker client whose run_command executes locally after a broker check."""

    def __init__(self, *args, workspace: str, command_timeout: float, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.workspace = workspace
        self.command_timeout = command_timeout

    def run_command(self, command: str) -> dict:
        self.run_command_check(command)
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": os.environ.get("HOME", os.path.join(self.workspace, "tmp")),
            "TMPDIR": os.path.join(self.workspace, "tmp"),
            "LANG": "C.UTF-8",
        }
        try:
            res = subprocess.run(
                ["/bin/sh", "-c", command],
                cwd=self.workspace,
                env=env,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.command_timeout,
                stdin=subprocess.DEVNULL,
            )
            out, t1 = _truncate(res.stdout)
            err, t2 = _truncate(res.stderr)
            return {"stdout": out, "stderr": err, "exit_code": res.returncode, "truncated": t1 or t2}
        except subprocess.TimeoutExpired as te:
            out, _ = _truncate((te.stdout or b"").decode("utf-8", "replace") if isinstance(te.stdout, bytes) else (te.stdout or ""))
            return {"stdout": out, "stderr": f"command timed out after {self.command_timeout}s", "exit_code": -1, "truncated": True}


class DirectIOClient(AgentBrokerClient):
    """Direct execution client for Condition A and Condition D."""

    def __init__(self, *args, workspace: str, command_timeout: float, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.workspace = workspace
        self.command_timeout = command_timeout

    def read_file(self, file_path: str) -> str:
        p = Path(os.path.expanduser(file_path))
        if not p.is_absolute():
            p = Path(self.workspace) / p
        return p.read_text(encoding="utf-8", errors="replace")

    def write_file(self, file_path: str, content: str) -> dict[str, Any]:
        p = Path(os.path.expanduser(file_path))
        if not p.is_absolute():
            p = Path(self.workspace) / p
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return {"bytes_written": len(content.encode("utf-8")), "path": str(p)}

    def http_get(self, url: str) -> dict[str, Any]:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "agent-eval/3.0"})
        with urllib.request.urlopen(req, timeout=15.0) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
            return {"status": resp.status, "body": body}

    def run_command(self, command: str) -> dict:
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": os.environ.get("HOME", os.path.join(self.workspace, "tmp")),
            "TMPDIR": os.path.join(self.workspace, "tmp"),
            "LANG": "C.UTF-8",
        }
        try:
            res = subprocess.run(
                ["/bin/sh", "-c", command],
                cwd=self.workspace,
                env=env,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.command_timeout,
                stdin=subprocess.DEVNULL,
            )
            out, t1 = _truncate(res.stdout)
            err, t2 = _truncate(res.stderr)
            return {"stdout": out, "stderr": err, "exit_code": res.returncode, "truncated": t1 or t2}
        except subprocess.TimeoutExpired as te:
            out, _ = _truncate((te.stdout or b"").decode("utf-8", "replace") if isinstance(te.stdout, bytes) else (te.stdout or ""))
            return {"stdout": out, "stderr": f"command timed out after {self.command_timeout}s", "exit_code": -1, "truncated": True}

    def request_access(self, resource_type: str, resource_target: str, justification: str) -> dict[str, Any]:
        raise PermissionError("governance disabled / container baseline: request_access not available")

    def call_agent(self, target_agent: str, message: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("call_agent not supported in direct mode")


def main() -> int:
    try:
        ctypes.CDLL(None).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except Exception:
        pass

    token = _read_fd("GOVERNANCE_TOKEN_FD").decode("utf-8").strip()
    task = json.loads(_read_fd("GOVERNANCE_TASK_FD").decode("utf-8"))
    result_fd = int(os.environ.pop("GOVERNANCE_RESULT_FD"))
    sock_path = os.environ.pop("GOVERNANCE_BROKER_SOCK")
    workspace = os.getcwd()

    condition = (task.get("condition") or "").split("_")[0]
    is_direct = condition in ("A", "D") or task.get("client_mode") == "direct"

    if is_direct:
        client = DirectIOClient(
            token=token,
            uds_path=sock_path,
            workspace=workspace,
            command_timeout=float(task.get("command_timeout", 60)),
        )
        tools = task.get("tools_schema") or DIRECT_TOOLS_SCHEMA
    else:
        client = SandboxedBrokerClient(
            token=token,
            uds_path=sock_path,
            workspace=workspace,
            command_timeout=float(task.get("command_timeout", 60)),
        )
        tools = task.get("tools_schema") or GOVERNED_TOOLS_SCHEMA

    agent = LLMAgent(
        broker_client=client,
        model=task.get("model") or "broker-configured",
        system_prompt=task.get("system_prompt"),
        tools_schema=tools,
    )
    started = time.time()
    status = "completed"
    error = None
    try:
        result = agent.run(task["prompt"], max_iterations=int(task.get("max_iterations", 10)))
    except Exception as ex:
        status = "agent_error"
        error = f"{type(ex).__name__}: {ex}"
        result = {}

    payload = {
        "status": status,
        "error": error,
        "wall_time_s": round(time.time() - started, 3),
        "completed": result.get("completed"),
        "iterations": result.get("iterations"),
        "final_response": result.get("final_response"),
        "tool_history": result.get("tool_history", []),
        "attempted_tools": result.get("attempted_tools", []),
    }
    data = json.dumps(payload, default=str).encode("utf-8")
    off = 0
    while off < len(data):
        off += os.write(result_fd, data[off:])
    os.close(result_fd)
    return 0 if status == "completed" else 3


if __name__ == "__main__":
    sys.exit(main())
