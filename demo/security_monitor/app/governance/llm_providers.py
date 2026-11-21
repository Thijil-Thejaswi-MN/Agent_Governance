"""Hosted OpenAI-compatible LLM providers (Groq, Cerebras, Gemini, generic).

Maintains base URLs, API key environment variables, default models,
and model string parsing for governed agent inference.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class HostedProvider:
    id: str
    name: str
    base_url: str
    env_var: str
    fallback_model: str

    @property
    def default_model(self) -> str:
        """The model shown in the console. Hosted model names change often, so each provider's
        model can be set with <ID>_MODEL (e.g. GROQ_MODEL); the built-in name is only a fallback."""
        env = "GOVERNANCE_LLM_MODEL" if self.id == "openai_compat" else f"{self.id.upper()}_MODEL"
        return (os.environ.get(env) or self.fallback_model).strip()

    def get_base_url(self) -> str:
        if self.id == "openai_compat":
            return os.environ.get("GOVERNANCE_LLM_BASE_URL", self.base_url)
        return self.base_url

    def get_api_key(self) -> str | None:
        return os.environ.get(self.env_var)

    def is_available(self) -> bool:
        key = self.get_api_key()
        if not key:
            return False
        if self.id == "openai_compat":
            return bool(self.get_base_url())
        return True


HOSTED_PROVIDERS: dict[str, HostedProvider] = {
    "groq": HostedProvider(
        id="groq",
        name="Groq",
        base_url="https://api.groq.com/openai/v1",
        env_var="GROQ_API_KEY",
        fallback_model="qwen/qwen3.8-27b",
    ),
    "cerebras": HostedProvider(
        id="cerebras",
        name="Cerebras",
        base_url="https://api.cerebras.ai/v1",
        env_var="CEREBRAS_API_KEY",
        fallback_model="gpt-oss-120b",
    ),
    "gemini": HostedProvider(
        id="gemini",
        name="Gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        env_var="GEMINI_API_KEY",
        fallback_model="gemini-3.8-flash",
    ),
    "openai_compat": HostedProvider(
        id="openai_compat",
        name="OpenAI-compatible",
        base_url="",
        env_var="GOVERNANCE_LLM_API_KEY",
        fallback_model="default",
    ),
}


def parse_model_string(model: str | None) -> tuple[HostedProvider | None, str]:
    """Parses a model string into a HostedProvider (if prefixed) and model name.

    'groq:qwen/qwen3.8-27b' -> (HostedProvider(id='groq', ...), 'qwen/qwen3.8-27b')
    'cerebras:gpt-oss-120b' -> (HostedProvider(id='cerebras', ...), 'gpt-oss-120b')
    'qwen2.5:7b' -> (None, 'qwen2.5:7b')  (Ollama plain tag, not a hosted provider)
    'scripted' -> (None, 'scripted')
    """
    if not model:
        return None, ""
    name = model.strip()
    if ":" in name:
        prefix, rest = name.split(":", 1)
        prefix_lower = prefix.lower()
        if prefix_lower in HOSTED_PROVIDERS:
            hp = HOSTED_PROVIDERS[prefix_lower]
            actual = rest.strip() or hp.default_model
            return hp, actual
    if name.lower() in HOSTED_PROVIDERS:
        hp = HOSTED_PROVIDERS[name.lower()]
        return hp, hp.default_model
    return None, name


def is_hosted_model(model: str | None) -> bool:
    """True if the model string selects a hosted provider."""
    hp, _ = parse_model_string(model)
    return hp is not None


def get_available_hosted_models() -> list[dict[str, str]]:
    """Returns hosted models whose API key is set on the server."""
    available: list[dict[str, str]] = []
    for pid, provider in HOSTED_PROVIDERS.items():
        if provider.is_available():
            available.append({
                "id": f"{pid}:{provider.default_model}",
                "provider": pid,
                "model": provider.default_model,
                "label": f"{pid}: {provider.default_model} (hosted)",
            })
    return available


def redact_llm_error(error: Any, max_chars: int | None = 300) -> str | None:
    """Redacts tokens, query keys, and environment API keys from error messages."""
    if error is None:
        return None
    s = str(error)
    # 1. Remove Bearer values
    s = re.sub(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', '[REDACTED_AUTH]', s, flags=re.IGNORECASE)
    s = re.sub(r'Bearer\b[^\s,]*', '[REDACTED_AUTH]', s, flags=re.IGNORECASE)

    # 2. Remove key=... and api_key=... query/url/json parameters
    s = re.sub(r'([?&]api[_-]?key=)[^&\s]+', r'\1[REDACTED_KEY]', s, flags=re.IGNORECASE)
    s = re.sub(r'(\bapi[_-]?key=)[^&\s,]+', r'\1[REDACTED_KEY]', s, flags=re.IGNORECASE)
    s = re.sub(r'([?&]key=)[^&\s]+', r'\1[REDACTED_KEY]', s, flags=re.IGNORECASE)
    s = re.sub(r'(\bkey=)[^&\s,]+', r'\1[REDACTED_KEY]', s, flags=re.IGNORECASE)
    s = re.sub(r'("(?:api[_-]?key|key|token|secret)"\s*:\s*")[^"]+(")', r'\1[REDACTED_KEY]\2', s, flags=re.IGNORECASE)

    # 3. Remove values of configured environment variables if set
    for env_var, val in os.environ.items():
        if (env_var.endswith("_API_KEY") or env_var.endswith("_KEY")) and val and len(val.strip()) >= 4:
            s = s.replace(val.strip(), "[REDACTED_KEY]")

    for env_var in (
        "GROQ_API_KEY",
        "CEREBRAS_API_KEY",
        "GEMINI_API_KEY",
        "GOVERNANCE_LLM_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ):
        val = os.environ.get(env_var)
        if val and len(val.strip()) >= 4:
            s = s.replace(val.strip(), "[REDACTED_KEY]")

    if max_chars is not None and len(s) > max_chars:
        s = s[:max_chars]

    return s
