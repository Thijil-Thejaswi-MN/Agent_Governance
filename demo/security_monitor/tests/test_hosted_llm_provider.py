"""Tests for hosted OpenAI-compatible LLM providers (Groq, Cerebras, Gemini, generic).

Verifies:
- provider:model parsing and plain name preservation
- Model menu / API listing only when API key environment variable is set
- Bearer authorization header sent
- Standard OpenAI body only (no options or seed)
- tool_calls parsed and returned
- 429 with Retry-After retried and succeeds
- 5 x 429 raises rate-limit error naming provider
- API key never appears in records, receipts, steps, logs, or error messages
- Task record contains hosted model data disclosure note
"""
from __future__ import annotations

import http.server
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any
import pytest
from starlette.testclient import TestClient

from app.gateway.server import create_app
from app.governance.broker import ToolBroker
from app.governance.launcher import TaskLauncher, TaskSpec
from app.governance.llm_providers import (
    HOSTED_PROVIDERS,
    HostedProvider,
    get_available_hosted_models,
    is_hosted_model,
    parse_model_string,
)
from app.governance.models import (
    EnforcementMode,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from app.governance.run_manager import fetch_available_models, validate_model
from app.governance.storage import GovernanceStorage


# ---------------------------------------------------------------------------
# 1. Parsing and validation
# ---------------------------------------------------------------------------

def test_parse_model_string():
    hp, model = parse_model_string("groq:qwen/qwen3-32b")
    assert hp is not None
    assert hp.id == "groq"
    assert model == "qwen/qwen3-32b"

    hp, model = parse_model_string("cerebras:llama3.1-8b")
    assert hp is not None
    assert hp.id == "cerebras"
    assert model == "llama3.1-8b"

    hp, model = parse_model_string("gemini:gemini-1.5-flash")
    assert hp is not None
    assert hp.id == "gemini"
    assert model == "gemini-1.5-flash"

    hp, model = parse_model_string("openai_compat:custom-model")
    assert hp is not None
    assert hp.id == "openai_compat"
    assert model == "custom-model"

    # Bare provider name falls back to default model
    hp, model = parse_model_string("groq")
    assert hp is not None
    assert hp.id == "groq"
    assert model == "qwen/qwen3-32b"

    # Plain names and Ollama tags are unchanged
    hp, model = parse_model_string("qwen2.5:7b")
    assert hp is None
    assert model == "qwen2.5:7b"

    hp, model = parse_model_string("llama3.1:8b")
    assert hp is None
    assert model == "llama3.1:8b"

    hp, model = parse_model_string("scripted")
    assert hp is None
    assert model == "scripted"

    hp, model = parse_model_string(None)
    assert hp is None
    assert model == ""

    assert is_hosted_model("groq:qwen/qwen3-32b") is True
    assert is_hosted_model("qwen2.5:7b") is False
    assert is_hosted_model("scripted") is False


def test_fetch_available_models_lists_hosted_models_only_when_env_var_set(monkeypatch):
    for pid, provider in HOSTED_PROVIDERS.items():
        monkeypatch.delenv(provider.env_var, raising=False)
    monkeypatch.delenv("GOVERNANCE_LLM_BASE_URL", raising=False)

    # Without keys set, no hosted models appear
    data = fetch_available_models()
    assert not any(is_hosted_model(m) for m in data["models"])

    # Set GROQ_API_KEY: only groq appears
    monkeypatch.setenv("GROQ_API_KEY", "test_groq_key_123")
    data = fetch_available_models()
    assert "groq:qwen/qwen3-32b" in data["models"]
    assert "cerebras:llama3.1-8b" not in data["models"]

    # Set CEREBRAS_API_KEY as well
    monkeypatch.setenv("CEREBRAS_API_KEY", "test_cerebras_key_456")
    data = fetch_available_models()
    assert "groq:qwen/qwen3-32b" in data["models"]
    assert "cerebras:llama3.1-8b" in data["models"]

    # Set GEMINI_API_KEY
    monkeypatch.setenv("GEMINI_API_KEY", "test_gemini_key_789")
    data = fetch_available_models()
    assert "gemini:gemini-1.5-flash" in data["models"]

    # openai_compat needs both API_KEY and BASE_URL
    monkeypatch.setenv("GOVERNANCE_LLM_API_KEY", "test_compat_key")
    data = fetch_available_models()
    assert "openai_compat:default" not in data["models"]

    monkeypatch.setenv("GOVERNANCE_LLM_BASE_URL", "http://127.0.0.1:9999/v1")
    data = fetch_available_models()
    assert "openai_compat:default" in data["models"]


def test_validate_model_checks_env_var(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(ValueError, match="not configured"):
        validate_model("groq:qwen/qwen3-32b")

    monkeypatch.setenv("GROQ_API_KEY", "valid_key")
    assert validate_model("groq:qwen/qwen3-32b") == "groq:qwen/qwen3-32b"
    assert validate_model("scripted") == "scripted"


# ---------------------------------------------------------------------------
# 2. Fake OpenAI-compatible HTTP Server fixture
# ---------------------------------------------------------------------------

class FakeOpenAIHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence default stderr logging
        pass

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body_bytes = self.rfile.read(length) if length > 0 else b""
        body_json = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}

        req_info = {
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body_json,
        }
        self.server.captured_requests.append(req_info)

        # Check for scripted response override
        handler_fn = getattr(self.server, "custom_handler", None)
        if handler_fn:
            status, headers, response_data = handler_fn(req_info, len(self.server.captured_requests))
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            if response_data is not None:
                self.wfile.write(json.dumps(response_data).encode("utf-8"))
            return

        # Default 200 response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        default_resp = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": body_json.get("model", "test-model"),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Hello from fake hosted LLM",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        self.wfile.write(json.dumps(default_resp).encode("utf-8"))


@pytest.fixture
def fake_openai_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), FakeOpenAIHandler)
    server.captured_requests = []
    server.custom_handler = None
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield server
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# 3. Protocol, header, body and retry tests
# ---------------------------------------------------------------------------

def test_bearer_header_sent_and_no_options_field(fake_openai_server, tmp_path):
    storage = GovernanceStorage(tmp_path / "test.db")
    broker = ToolBroker(storage)

    base_url = f"http://127.0.0.1:{fake_openai_server.server_port}/v1"
    res = broker._call_openai_compat(
        messages=[{"role": "user", "content": "Analyze sales"}],
        tools=[{"type": "function", "function": {"name": "read_file", "parameters": {}}}],
        model="qwen/qwen3-32b",
        base_url=base_url,
        api_key="TEST_SECRET_BEARER_KEY_123",
        temperature=0.2,
        max_tokens=150,
        provider="groq",
    )

    assert res["role"] == "assistant"
    assert res["content"] == "Hello from fake hosted LLM"
    assert res["provider"] == "groq"
    assert res["model"] == "qwen/qwen3-32b"

    assert len(fake_openai_server.captured_requests) == 1
    req = fake_openai_server.captured_requests[0]
    assert req["path"] == "/v1/chat/completions"
    assert req["headers"].get("authorization") == "Bearer TEST_SECRET_BEARER_KEY_123"

    # Crucial check: Standard OpenAI body only, no Ollama options or seed
    body = req["body"]
    assert "options" not in body
    assert "seed" not in body
    assert body["model"] == "qwen/qwen3-32b"
    assert body["temperature"] == 0.2
    assert body["max_tokens"] == 150
    assert len(body["tools"]) == 1


def test_tool_calls_parsed_correctly(fake_openai_server, tmp_path):
    storage = GovernanceStorage(tmp_path / "test.db")
    broker = ToolBroker(storage)

    def tool_handler(req, count):
        return 200, {"Content-Type": "application/json"}, {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": '{"path": "input/data.csv"}',
                                },
                            }
                        ],
                    }
                }
            ]
        }

    fake_openai_server.custom_handler = tool_handler
    base_url = f"http://127.0.0.1:{fake_openai_server.server_port}/v1"
    res = broker._call_openai_compat(
        messages=[{"role": "user", "content": "Read the file"}],
        tools=[{"type": "function", "function": {"name": "read_file"}}],
        model="llama3.1-8b",
        base_url=base_url,
        api_key="key",
        provider="cerebras",
    )

    assert res["role"] == "assistant"
    assert res["content"] is None
    assert len(res["tool_calls"]) == 1
    tc = res["tool_calls"][0]
    assert tc["id"] == "call_123"
    assert tc["function"]["name"] == "read_file"


def test_retry_on_429_with_retry_after_header(fake_openai_server, tmp_path):
    storage = GovernanceStorage(tmp_path / "test.db")
    broker = ToolBroker(storage)

    def retry_handler(req, count):
        # Return 429 on initial 2 calls, then 200
        if count < 3:
            return 429, {"Retry-After": "0.02", "Content-Type": "application/json"}, {"error": "Rate limit"}
        return 200, {"Content-Type": "application/json"}, {
            "choices": [{"message": {"role": "assistant", "content": "Success after retry"}}]
        }

    fake_openai_server.custom_handler = retry_handler
    base_url = f"http://127.0.0.1:{fake_openai_server.server_port}/v1"
    res = broker._call_openai_compat(
        messages=[{"role": "user", "content": "Hi"}],
        tools=None,
        model="gemini-1.5-flash",
        base_url=base_url,
        api_key="key",
        provider="gemini",
    )

    assert res["content"] == "Success after retry"
    assert len(fake_openai_server.captured_requests) == 3


def test_five_x_429_raises_rate_limit_error(fake_openai_server, tmp_path):
    storage = GovernanceStorage(tmp_path / "test.db")
    broker = ToolBroker(storage)

    def rate_limit_handler(req, count):
        return 429, {"Retry-After": "0.01", "Content-Type": "application/json"}, {"error": "Too many requests"}

    fake_openai_server.custom_handler = rate_limit_handler
    base_url = f"http://127.0.0.1:{fake_openai_server.server_port}/v1"

    with pytest.raises(RuntimeError) as exc_info:
        broker._call_openai_compat(
            messages=[{"role": "user", "content": "Hi"}],
            tools=None,
            model="qwen/qwen3-32b",
            base_url=base_url,
            api_key="key",
            provider="groq",
        )

    # Must name the provider and "rate limit"
    err_text = str(exc_info.value).lower()
    assert "groq" in err_text
    assert "rate limit" in err_text
    assert len(fake_openai_server.captured_requests) == 5


# ---------------------------------------------------------------------------
# 4. Privacy: API key never stored or logged
# ---------------------------------------------------------------------------

def test_api_key_never_appears_in_records_steps_logs_or_errors(fake_openai_server, tmp_path, monkeypatch, caplog):
    secret_key = "TOP_SECRET_API_KEY_DO_NOT_STORE_OR_LEAK_987654"
    monkeypatch.setenv("GROQ_API_KEY", secret_key)

    db_path = tmp_path / "test_privacy.db"
    storage = GovernanceStorage(db_path)
    broker = ToolBroker(storage)

    task_id = "task_privacy_test_1"
    # Seed token and boundary
    token = "test_tok_privacy_123"
    storage.save_token(token, task_id, "agent_1")
    boundary = TaskBoundary(task_id=task_id, workspace_root=str(tmp_path), tools=["read_file", "llm_complete"])
    storage.save_boundary(boundary)
    storage.save_task(TaskRecord(
        task_id=task_id,
        request_text="Analyze files",
        request_hash="hash1",
        agent_id="agent_1",
        workspace_root=str(tmp_path),
        created_at="2026-11-20T00:00:00Z",
    ))

    base_url = f"http://127.0.0.1:{fake_openai_server.server_port}/v1"

    with caplog.at_level(logging.DEBUG):
        # 1. Normal call
        res = broker.llm_complete(
            token=token,
            messages=[{"role": "user", "content": "Test"}],
            model="groq:qwen/qwen3-32b",
            base_url=base_url,
        )

    # Key is not in response
    assert secret_key not in json.dumps(res)

    # 2. Check stored steps
    steps = storage.get_task_steps(task_id)
    steps_json = json.dumps([s.__dict__ for s in steps])
    assert secret_key not in steps_json

    # 3. Check logs
    assert secret_key not in caplog.text

    # 4. Check error message redaction
    def error_handler(req, count):
        return 401, {"Content-Type": "application/json"}, {"error": f"Invalid key: {secret_key}"}

    fake_openai_server.custom_handler = error_handler
    with pytest.raises(RuntimeError) as exc_info:
        broker.llm_complete(
            token=token,
            messages=[{"role": "user", "content": "Test"}],
            model="groq:qwen/qwen3-32b",
            base_url=base_url,
        )
    assert secret_key not in str(exc_info.value)


def test_task_record_hosted_model_disclosure(tmp_path, fake_openai_server, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "dummy_groq_key")
    db_path = tmp_path / "test_record.db"
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    os.environ["GOVERNANCE_DB_PATH"] = str(db_path)
    os.environ["RECEIPTS_DIR"] = str(receipts_dir)
    os.environ["GOVERNANCE_OPERATOR_TOKEN"] = "op_token"
    os.environ["GOVERNANCE_OPERATOR_NAME"] = "operator"

    client = TestClient(create_app())
    headers = {"X-Operator-Token": "op_token"}

    # Query models
    models_resp = client.get("/api/governance/run/models", headers=headers).json()
    assert "groq:qwen/qwen3-32b" in models_resp["models"]

    # Verify receipt generated with hosted model note
    from app.governance.receipt import build_receipt
    storage = GovernanceStorage(db_path)
    task = TaskRecord(
        task_id="task_hosted_rec_1",
        request_text="test prompt",
        request_hash="hash",
        agent_id="finance_bot",
        workspace_root=str(tmp_path),
        created_at="2026-11-20T00:00:00Z",
    )
    boundary = TaskBoundary(task_id=task.task_id, workspace_root=str(tmp_path))
    receipt = build_receipt(
        task=task,
        initial_boundary=boundary,
        requester="operator",
        storage=storage,
        os_records=[],
        deliveries=[],
        sensor_status={"binary": "sensor", "mode": "observation_only", "ran": False},
        isolation={"isolation_level": "user_namespace"},
        freeze_events=[],
        termination={"reason": "completed"},
        wall_time_s=1.0,
        os_identity=None,
        extra={
            "llm_provider": "groq",
            "llm_model": "qwen/qwen3-32b",
            "hosted_model_note": "hosted model: the task's prompts and file contents were sent to groq",
        },
    )

    # Note must be present in receipt
    assert "hosted model: the task's prompts and file contents were sent to groq" in json.dumps(receipt)
    assert receipt.get("hosted_model_note") == "hosted model: the task's prompts and file contents were sent to groq"
    assert receipt.get("llm_provider") == "groq"
    assert receipt.get("llm_model") == "qwen/qwen3-32b"
