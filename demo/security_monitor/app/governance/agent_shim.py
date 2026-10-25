"""Agent shim: runs LLMAgent inside the task sandbox (M6.1).

Launched by the launcher as the last link of
    systemd scope -> sensor -> seccomp -> Landlock -> agent_shim
and executed with the system interpreter from a per-task read-only copy
(`<workspace>/runtime/`), so it imports only the stdlib and `llm_agent`.

- LLM inference only through `llm_complete` on the broker Unix socket. The shim
  has no network rule other than the proxy port and holds no API keys.
- Mediated tools go to the broker over the same socket.
- run_command: asks the broker (`run_command_check`); if allowed, executes the
  command locally as a child of the shim, inside the sandbox, so the OS layer is
  what limits its effects. stdout/stderr are truncated to a fixed size.

Inputs arrive on inherited pipe fds (never argv/env values):
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm_agent import GOVERNED_TOOLS_SCHEMA, AgentBrokerClient, LLMAgent  # noqa: E402

OUTPUT_LIMIT = 4000
PR_SET_DUMPABLE = 4


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
        # Raises PermissionError when run_command is outside the boundary.
        self.run_command_check(command)
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": os.path.join(self.workspace, "tmp"),
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


def main() -> int:
    # Our memory holds the task token: make /proc/<shim>/mem etc. inaccessible
    # to the commands this shim spawns.
    try:
        ctypes.CDLL(None).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except Exception:
        pass

    token = _read_fd("GOVERNANCE_TOKEN_FD").decode("utf-8").strip()
    task = json.loads(_read_fd("GOVERNANCE_TASK_FD").decode("utf-8"))
    result_fd = int(os.environ.pop("GOVERNANCE_RESULT_FD"))
    sock_path = os.environ.pop("GOVERNANCE_BROKER_SOCK")
    workspace = os.getcwd()

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
    except Exception as ex:  # broker socket died, malformed LLM output, ...
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
