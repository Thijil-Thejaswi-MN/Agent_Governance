"""Redaction of secret-looking strings for receipts and audit targets (M6).

Applied to command lines before they are stored in receipts. Never a substitute
for not collecting data: receipts hold paths, operations and results only.
"""
from __future__ import annotations

import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # HTTP auth headers
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    # key=value / key: value style assignments of secret-ish names
    (re.compile(r"(?i)\b([A-Za-z0-9_]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|auth(?:orization)?|credential)[A-Za-z0-9_]*)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1\2[REDACTED]"),
    # well-known token shapes
    (re.compile(r"\bgov_tok_[A-Za-z0-9_-]+"), "[REDACTED_TASK_TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{12,}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bCANARY[-_][A-Za-z0-9_-]{6,}"), "[REDACTED_CANARY]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), "[REDACTED_PRIVATE_KEY]"),
    # long opaque blobs (hex/base64/url-safe) of 32+ chars
    (re.compile(r"(?<![A-Za-z0-9/._-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9/._-])"), "[REDACTED_BLOB]"),
]


def redact_command(text: str, max_len: int = 1000) -> str:
    """Redacts secret-looking substrings and caps length."""
    out = str(text)
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    if len(out) > max_len:
        out = out[:max_len] + f"...[truncated {len(out) - max_len} chars]"
    return out
