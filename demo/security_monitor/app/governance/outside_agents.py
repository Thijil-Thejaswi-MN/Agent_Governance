"""Outbound A2A v1.0 registry, JWS/JCS card verification, and governed JSON-RPC client.

Handles:
1. Admin registration of outside agents with pinned JWK trust anchors and attested ceilings.
2. Fetching Agent Cards over CONNECT through EgressProxyServer and verifying RFC 7515 JWS
   signatures computed over RFC 8785 JCS canonicalized cards strictly against pinned anchors.
3. Outbound JSON-RPC calls (SendMessage, GetTask polling, CancelTask on freeze/revoke/deadline)
   using official a2a-sdk==1.3.1 with header `A2A-Version: 1.0`.
"""
from __future__ import annotations

import asyncio
import copy
import datetime
import hashlib
import json
import logging
import ssl
import threading
import time
import typing
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx
import jwt
from jwt.api_jwk import PyJWK
from jwt.exceptions import PyJWTError
from jwt.utils import base64url_decode, base64url_encode

from a2a.client.card_resolver import parse_agent_card
from a2a.client.client import ClientCallContext
from a2a.client.errors import A2AClientError, A2AClientTimeoutError
from a2a.client.transports.jsonrpc import JsonRpcTransport
from a2a.types.a2a_pb2 import (
    AgentCard,
    CancelTaskRequest,
    GetTaskRequest,
    Message,
    Part,
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
    Task,
    TaskState,
)
from a2a.utils._jcs import CanonicalizationError, canonicalize
from a2a.utils.constants import TERMINAL_TASK_STATES, VERSION_HEADER, PROTOCOL_VERSION_1_0
from a2a.utils.signing import _canonicalize_agent_card
from google.protobuf import struct_pb2
from google.protobuf.json_format import MessageToDict

from .models import EventSource, EventVerdict, GovernanceEvent, RiskTier, TaskAction
from .proxy import EgressProxyServer
from .storage import GovernanceStorage

logger = logging.getLogger(__name__)

LABEL_ORDER: dict[str, int] = {"public": 0, "internal": 1, "secret": 2}
ALLOWED_OUTSIDE_MAX_LABELS = ("public", "internal")
ALLOWED_JWS_ALGORITHMS = ("EdDSA", "ES256", "ES384", "ES512", "RS256", "PS256")
POLL_INTERVAL_SECONDS = 0.15

_REPO_ROOT = Path(__file__).resolve().parents[4]


class OutsideAgentError(PermissionError):
    """Raised when an outside agent card or call violates security policy or fails."""


@dataclass
class VerifiedCardResult:
    card: AgentCard
    raw_card: dict[str, Any]
    card_hash: str
    card_kid: str
    interface_url: str
    card_skills: list[str]
    description: str
    name: str


def _canonical_url_host_port(url: str) -> tuple[str, str, int]:
    """Validates remote URL scheme/host and returns (scheme, host, port).

    Plain http:// is refused except for 127.0.0.1 in tests.
    """
    raw = str(url or "").strip()
    if not raw:
        raise OutsideAgentError("URL cannot be empty")
    parsed = urlsplit(raw)
    scheme = (parsed.scheme or "").lower()
    if parsed.username or parsed.password:
        raise OutsideAgentError("URL must not contain embedded userinfo credentials")
    if scheme not in ("https", "http"):
        raise OutsideAgentError(f"Unsupported URL scheme '{scheme}'; only https:// (or http://127.0.0.1 in tests) is allowed")
    host = (parsed.hostname or "").strip().strip("[]").lower()
    if not host:
        raise OutsideAgentError(f"URL missing host: {raw}")
    if scheme == "http" and host != "127.0.0.1":
        raise OutsideAgentError(f"Plain http:// is refused for non-loopback host '{host}'; use https://")
    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    return scheme, host, int(port)


def validate_jwk_anchor(anchor: dict[str, Any]) -> dict[str, Any]:
    """Validates a pinned public JWK anchor dict."""
    if not isinstance(anchor, dict):
        raise ValueError("jwk_anchor must be a JSON object")
    private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth"}
    present_priv = private_fields.intersection(anchor.keys())
    if present_priv:
        raise ValueError(f"jwk_anchor must be a public JWK; private key fields not permitted: {sorted(present_priv)}")
    kid = str(anchor.get("kid") or "").strip()
    if not kid:
        raise ValueError("jwk_anchor must include a non-empty 'kid' field")
    kty = str(anchor.get("kty") or "").strip()
    if not kty:
        raise ValueError("jwk_anchor must include a 'kty' field")
    try:
        PyJWK.from_dict(anchor)
    except Exception as exc:
        raise ValueError(f"Invalid jwk_anchor: {exc}") from exc
    return dict(anchor)


def validate_max_label(max_label: str) -> str:
    label = str(max_label or "internal").strip().lower()
    if label == "secret":
        raise ValueError("Outside agent max_label cannot be 'secret'; highest allowed label is 'internal'")
    if label not in ALLOWED_OUTSIDE_MAX_LABELS:
        raise ValueError(f"Invalid max_label '{max_label}'; must be one of {ALLOWED_OUTSIDE_MAX_LABELS}")
    return label


def validate_auth_config(auth_type: str | None, auth_token_path: str | None) -> tuple[str, str | None]:
    kind = str(auth_type or "none").strip().lower()
    if kind not in ("none", "bearer"):
        raise ValueError("auth_type must be 'none' or 'bearer'")
    if kind == "none":
        if auth_token_path:
            raise ValueError("auth_token_path must be omitted when auth_type is 'none'")
        return "none", None
    path_str = str(auth_token_path or "").strip()
    if not path_str:
        raise ValueError("auth_token_path is required when auth_type is 'bearer'")
    resolved = Path(path_str).expanduser().resolve()
    try:
        is_in_repo = resolved.is_relative_to(_REPO_ROOT.resolve())
    except Exception:
        is_in_repo = False
    if is_in_repo:
        raise ValueError("auth_token_path must reference a file outside the repository")
    return "bearer", str(resolved)


def read_partner_bearer_token(auth_type: str, auth_token_path: str | None) -> str | None:
    if (auth_type or "none") != "bearer":
        return None
    if not auth_token_path:
        raise OutsideAgentError("Partner bearer auth configured without auth_token_path")
    _, checked_path = validate_auth_config("bearer", auth_token_path)
    assert checked_path is not None
    p = Path(checked_path)
    if not p.is_file():
        raise OutsideAgentError(f"Partner bearer token file not found: {checked_path}")
    tok = p.read_text(encoding="utf-8").strip()
    if not tok:
        raise OutsideAgentError(f"Partner bearer token file is empty: {checked_path}")
    return tok


def card_status_summary(rec: dict[str, Any] | None) -> str:
    if not rec:
        return "not registered"
    if rec.get("disabled"):
        return rec.get("failure_reason") or "disabled by administrator"
    status = rec.get("status")
    if status == "verified":
        kid = rec.get("card_kid") or (rec.get("jwk_anchor") or {}).get("kid") or "unknown"
        return f"signature verified (key {kid})"
    return rec.get("failure_reason") or str(status or "unverified")


def _extract_jsonrpc_interface_url(card: AgentCard) -> str:
    if not card.supported_interfaces:
        raise OutsideAgentError("Agent card missing supportedInterfaces")
    chosen: str | None = None
    for iface in card.supported_interfaces:
        binding = (iface.protocol_binding or "").strip().upper()
        pver = (iface.protocol_version or "").strip()
        if binding in ("", "JSONRPC"):
            if pver and not pver.startswith("1."):
                continue
            if iface.url:
                chosen = iface.url
                break
    if not chosen:
        raise OutsideAgentError("Agent card has no supportedInterfaces entry for A2A v1.0 JSONRPC binding")
    _canonical_url_host_port(chosen)
    return chosen


def _decode_jws_protected(protected_b64: str) -> dict[str, Any]:
    raw_bytes = base64url_decode(protected_b64.encode("utf-8"))
    obj = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Protected header is not a JSON object")
    return obj


def _verify_single_signature(
    *,
    protected_b64: str,
    signature_b64: str,
    canonical_payload: str,
    anchor: dict[str, Any],
    anchor_key: PyJWK,
    card_url: str,
) -> str | None:
    """Returns None on success or a descriptive refusal string on failure."""
    try:
        hdr = _decode_jws_protected(protected_b64)
    except Exception:
        return "malformed JWS protected header"

    jku = hdr.get("jku")
    if jku is not None and str(jku).strip():
        jku_parsed = urlsplit(str(jku).strip())
        card_parsed = urlsplit(card_url)
        if (
            jku_parsed.scheme.lower() != card_parsed.scheme.lower()
            or jku_parsed.netloc.lower() != card_parsed.netloc.lower()
        ):
            return "jku points elsewhere; only pinned trust anchors are allowed"

    alg = str(hdr.get("alg") or "").strip()
    if not alg or alg not in ALLOWED_JWS_ALGORITHMS:
        return f"disallowed or missing JWS algorithm '{alg}'"

    sig_kid = hdr.get("kid")
    anchor_kid = anchor.get("kid")
    if not sig_kid or sig_kid != anchor_kid:
        return f"unknown kid '{sig_kid}' (expected '{anchor_kid}')"

    encoded_payload = base64url_encode(canonical_payload.encode("utf-8")).decode("utf-8")
    token = f"{protected_b64}.{encoded_payload}.{signature_b64}"
    try:
        jwt.decode(jwt=token, key=anchor_key, algorithms=[alg])
        return None
    except PyJWTError:
        return "bad signature"


def verify_card_payload(
    card_data: dict[str, Any],
    card_url: str,
    anchor: dict[str, Any],
) -> VerifiedCardResult:
    """Validates AgentCard structure, interface URL, and RFC 7515 JWS over RFC 8785 JCS."""
    if not isinstance(card_data, dict):
        raise OutsideAgentError("Agent card response is not a JSON object")

    validated_anchor = validate_jwk_anchor(anchor)
    anchor_key = PyJWK.from_dict(validated_anchor)

    if not card_data.get("supportedInterfaces"):
        raise OutsideAgentError("Agent card missing supportedInterfaces (A2A v1.0 required)")

    try:
        card = parse_agent_card(copy.deepcopy(card_data))
    except Exception as exc:
        raise OutsideAgentError(f"Invalid A2A AgentCard structure: {exc}") from exc

    interface_url = _extract_jsonrpc_interface_url(card)

    if not card.signatures:
        raise OutsideAgentError("unsigned card")

    try:
        canonical_sdk_payload = _canonicalize_agent_card(card)
    except CanonicalizationError as exc:
        raise OutsideAgentError(f"Agent card cannot be canonicalized: {exc}") from exc

    raw_unsigned = {k: v for k, v in card_data.items() if k != "signatures"}
    try:
        canonical_raw_payload = canonicalize(raw_unsigned)
    except CanonicalizationError:
        canonical_raw_payload = canonical_sdk_payload

    reasons: list[str] = []
    verified_payload: str | None = None
    matched_kid: str | None = None

    for sig in card.signatures:
        if not sig.protected or not sig.signature:
            reasons.append("bad signature")
            continue
        err = _verify_single_signature(
            protected_b64=sig.protected,
            signature_b64=sig.signature,
            canonical_payload=canonical_sdk_payload,
            anchor=validated_anchor,
            anchor_key=anchor_key,
            card_url=card_url,
        )
        if err is None:
            verified_payload = canonical_sdk_payload
            matched_kid = validated_anchor["kid"]
            break
        if canonical_raw_payload != canonical_sdk_payload:
            err_raw = _verify_single_signature(
                protected_b64=sig.protected,
                signature_b64=sig.signature,
                canonical_payload=canonical_raw_payload,
                anchor=validated_anchor,
                anchor_key=anchor_key,
                card_url=card_url,
            )
            if err_raw is None:
                verified_payload = canonical_raw_payload
                matched_kid = validated_anchor["kid"]
                break
        reasons.append(err)

    if verified_payload is None or matched_kid is None:
        # Surface specific refusal cause (unknown kid / jku / bad signature)
        for pref in ("jku", "unknown kid", "bad signature"):
            for r in reasons:
                if pref in r:
                    raise OutsideAgentError(r)
        raise OutsideAgentError(reasons[0] if reasons else "bad signature")

    card_hash = hashlib.sha256(verified_payload.encode("utf-8")).hexdigest()
    skill_ids = [s.id for s in card.skills if getattr(s, "id", None)]
    return VerifiedCardResult(
        card=card,
        raw_card=card_data,
        card_hash=card_hash,
        card_kid=matched_kid,
        interface_url=interface_url,
        card_skills=skill_ids,
        description=card.description or "",
        name=card.name or "",
    )


class _BufferedNetworkStream(httpcore.AsyncNetworkStream):
    def __init__(self, inner: httpcore.AsyncNetworkStream, initial_buf: bytes) -> None:
        self._inner = inner
        self._buf = initial_buf

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        if self._buf:
            chunk = self._buf[:max_bytes]
            self._buf = self._buf[max_bytes:]
            return chunk
        return await self._inner.read(max_bytes, timeout=timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._inner.write(buffer, timeout=timeout)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        tls_stream = await self._inner.start_tls(
            ssl_context=ssl_context,
            server_hostname=server_hostname,
            timeout=timeout,
        )
        return _BufferedNetworkStream(tls_stream, self._buf) if self._buf else tls_stream

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class _ConnectProxyBackend(httpcore.AsyncNetworkBackend):
    """Routes every outbound TCP stream via HTTP CONNECT through EgressProxyServer."""

    def __init__(self, proxy_host: str, proxy_port: int, proxy_token: str) -> None:
        self._proxy_host = proxy_host
        self._proxy_port = int(proxy_port)
        self._proxy_token = proxy_token
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._inner.connect_tcp(
            self._proxy_host,
            self._proxy_port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        req = (
            f"CONNECT {target} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Proxy-Authorization: Bearer {self._proxy_token}\r\n"
            f"\r\n"
        ).encode("utf-8")
        try:
            await stream.write(req, timeout=timeout)
            buf = bytearray()
            while b"\r\n\r\n" not in buf:
                chunk = await stream.read(4096, timeout=timeout)
                if not chunk:
                    raise httpx.ProxyError(f"Egress proxy closed connection during CONNECT {target}")
                buf.extend(chunk)
                if len(buf) > 32768:
                    raise httpx.ProxyError(f"Egress proxy CONNECT response exceeded limit for {target}")
        except Exception:
            await stream.aclose()
            raise

        hdr_bytes, _, rest = bytes(buf).partition(b"\r\n\r\n")
        status_line = hdr_bytes.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        parts = status_line.split(" ", 2)
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if code != 200:
            body = rest.decode("utf-8", errors="replace").strip()
            await stream.aclose()
            raise httpx.ProxyError(f"Egress proxy refused CONNECT {target} ({status_line}): {body}")
        return _BufferedNetworkStream(stream, rest) if rest else stream


def build_proxy_httpx_client(
    *,
    proxy_host: str,
    proxy_port: int,
    proxy_token: str,
    timeout: float,
) -> httpx.AsyncClient:
    """Builds an httpx.AsyncClient routed strictly via proxy CONNECT with system CA TLS verification."""
    transport = httpx.AsyncHTTPTransport(verify=True, trust_env=False)
    transport._pool = httpcore.AsyncConnectionPool(  # type: ignore[attr-defined]
        ssl_context=ssl.create_default_context(),
        max_connections=10,
        max_keepalive_connections=4,
        retries=0,
        network_backend=_ConnectProxyBackend(proxy_host, proxy_port, proxy_token),
    )
    return httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        trust_env=False,
    )


def _format_network_error(exc: Exception, url: str) -> OutsideAgentError:
    if isinstance(exc, OutsideAgentError):
        return exc
    msg = str(exc) or type(exc).__name__
    low = msg.lower()
    if "certificate" in low or "ssl" in low or "tls" in low or "verify failed" in low:
        return OutsideAgentError(f"TLS certificate verification failed for {url}: {msg}")
    if isinstance(exc, (httpx.TimeoutException, asyncio.TimeoutError, A2AClientTimeoutError, TimeoutError)):
        return OutsideAgentError(f"Outside agent request timed out for {url}: {msg}")
    if isinstance(exc, httpx.ProxyError) or "proxy" in low:
        return OutsideAgentError(f"Proxy egress refused for {url}: {msg}")
    return OutsideAgentError(f"Failed contacting outside agent at {url}: {msg}")


class _EphemeralProxyRunner:
    """Runs an EgressProxyServer in a dedicated background asyncio thread when needed."""

    def __init__(self, storage: GovernanceStorage) -> None:
        self.storage = storage
        self.proxy = EgressProxyServer(storage=storage, host="127.0.0.1", port=0)
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="outside-a2a-proxy", daemon=True)
        self._thread.start()
        fut = asyncio.run_coroutine_threadsafe(self.proxy.start(), self._loop)
        self.port = fut.result(timeout=5.0)

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def stop(self) -> None:
        try:
            asyncio.run_coroutine_threadsafe(self.proxy.stop(), self._loop).result(timeout=3.0)
        except Exception:
            pass
        try:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=2.0)
        except Exception:
            pass


def fetch_and_verify_card_via_proxy(
    *,
    storage: GovernanceStorage,
    card_url: str,
    anchor: dict[str, Any],
    proxy: EgressProxyServer | None = None,
    proxy_port: int | None = None,
    task_id: str | None = None,
    caller_agent_id: str = "admin_registry",
    timeout: float = 10.0,
) -> VerifiedCardResult:
    """Fetches card_url through the egress proxy (CONNECT) and verifies JWS over JCS."""
    _, host, port = _canonical_url_host_port(card_url)

    ephemeral: _EphemeralProxyRunner | None = None
    active_proxy = proxy
    active_port = proxy_port
    if active_proxy is None:
        ephemeral = _EphemeralProxyRunner(storage)
        active_proxy = ephemeral.proxy
        active_port = ephemeral.port
    elif not active_port:
        active_port = getattr(active_proxy, "listening_port", 0) or getattr(active_proxy, "port", 0)
        if not active_port:
            raise OutsideAgentError("EgressProxyServer has no listening port")

    scope_token = f"oa_card_{uuid.uuid4().hex}"
    active_proxy.grant_scoped_egress(
        scope_token,
        task_id=task_id,
        agent_id=caller_agent_id,
        allowed_host=host,
        allowed_port=port,
        require_connect=True,
    )

    async def _fetch() -> dict[str, Any]:
        async with build_proxy_httpx_client(
            proxy_host="127.0.0.1",
            proxy_port=int(active_port),
            proxy_token=scope_token,
            timeout=timeout,
        ) as client:
            resp = await client.get(
                card_url,
                headers={VERSION_HEADER: PROTOCOL_VERSION_1_0, "Accept": "application/json"},
            )
            if resp.status_code != 200:
                raise OutsideAgentError(f"Agent card fetch returned HTTP {resp.status_code} from {card_url}")
            return resp.json()

    try:
        try:
            asyncio.get_running_loop()
            in_running_loop = True
        except RuntimeError:
            in_running_loop = False

        if in_running_loop:
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                card_data = pool.submit(lambda: asyncio.run(_fetch())).result(timeout=timeout + 2.0)
        else:
            card_data = asyncio.run(_fetch())
    except Exception as exc:
        raise _format_network_error(exc, card_url) from exc
    finally:
        active_proxy.revoke_scoped_egress(scope_token)
        if ephemeral is not None:
            ephemeral.stop()

    return verify_card_payload(card_data, card_url=card_url, anchor=anchor)


def validate_and_build_outgoing_parts(message: dict[str, Any] | str) -> tuple[list[Part], str]:
    """Validates outgoing payload allows only text and data parts (no raw, url, tokens, or history)."""
    if isinstance(message, str):
        return [Part(text=message)], message

    if not isinstance(message, dict):
        raise OutsideAgentError("Outgoing outside A2A message must be a string or dict")

    forbidden_top = {"raw", "url", "file", "file_path", "history", "chat_history", "delegation_token", "token", "keys", "private_key"}
    for fk in forbidden_top:
        if fk in message and message[fk] is not None:
            if fk in ("raw", "url", "file", "file_path"):
                raise OutsideAgentError(f"Outside A2A calls only allow text and data parts; '{fk}' is refused")
            raise OutsideAgentError(f"Outside A2A calls must not include '{fk}'")

    parts: list[Part] = []
    summaries: list[str] = []

    raw_parts = message.get("parts")
    if raw_parts is not None:
        if not isinstance(raw_parts, list) or not raw_parts:
            raise OutsideAgentError("Message 'parts' must be a non-empty list of text or data parts")
        for idx, p in enumerate(raw_parts):
            if not isinstance(p, dict):
                raise OutsideAgentError(f"Message part[{idx}] must be an object")
            if "raw" in p or "url" in p or str(p.get("kind") or "").lower() in ("file", "raw", "url"):
                raise OutsideAgentError("Outside A2A calls only permit text and data parts; raw and url parts are refused")
            has_text = "text" in p and p["text"] is not None
            has_data = "data" in p and p["data"] is not None
            if not has_text and not has_data:
                raise OutsideAgentError(f"Message part[{idx}] must contain 'text' or 'data'")
            if has_text and not isinstance(p["text"], str):
                raise OutsideAgentError(f"Message part[{idx}].text must be a string")
            if has_data and not isinstance(p["data"], dict):
                raise OutsideAgentError(f"Message part[{idx}].data must be a JSON object")
            if has_text:
                parts.append(Part(text=p["text"]))
                summaries.append(p["text"])
            if has_data:
                val = struct_pb2.Value()
                val.struct_value.update(p["data"])
                parts.append(Part(data=val))
                summaries.append(json.dumps(p["data"], sort_keys=True))
    else:
        if "text" in message and message["text"] is not None:
            if not isinstance(message["text"], str):
                raise OutsideAgentError("Message 'text' must be a string")
            parts.append(Part(text=message["text"]))
            summaries.append(message["text"])
        if "data" in message and message["data"] is not None:
            if not isinstance(message["data"], dict):
                raise OutsideAgentError("Message 'data' must be a JSON object")
            val = struct_pb2.Value()
            val.struct_value.update(message["data"])
            parts.append(Part(data=val))
            summaries.append(json.dumps(message["data"], sort_keys=True))

    if not parts:
        raise OutsideAgentError("Outgoing message must contain at least one text or data part")
    return parts, "\n".join(summaries)


def _extract_reply_text_from_task(task: Task) -> str:
    texts: list[str] = []
    if task.artifacts:
        for art in task.artifacts:
            for p in art.parts:
                which = p.WhichOneof("content")
                if which == "text" and p.text:
                    texts.append(p.text)
                elif which == "data":
                    texts.append(json.dumps(MessageToDict(p).get("data", {})))
    if not texts and task.HasField("status") and task.status.HasField("message"):
        for p in task.status.message.parts:
            which = p.WhichOneof("content")
            if which == "text" and p.text:
                texts.append(p.text)
            elif which == "data":
                texts.append(json.dumps(MessageToDict(p).get("data", {})))
    if not texts and task.history:
        for msg in reversed(task.history):
            if msg.role == Role.ROLE_AGENT:
                for p in msg.parts:
                    which = p.WhichOneof("content")
                    if which == "text" and p.text:
                        texts.append(p.text)
                    elif which == "data":
                        texts.append(json.dumps(MessageToDict(p).get("data", {})))
                if texts:
                    break
    return "\n".join(texts).strip()


def _extract_reply_text_from_message(msg: Message) -> str:
    texts: list[str] = []
    for p in msg.parts:
        which = p.WhichOneof("content")
        if which == "text" and p.text:
            texts.append(p.text)
        elif which == "data":
            texts.append(json.dumps(MessageToDict(p).get("data", {})))
    return "\n".join(texts).strip()


class OutsideAgentRegistry:
    """Admin-controlled registry and verification service for outside A2A v1.0 agents."""

    def __init__(
        self,
        storage: GovernanceStorage,
        proxy: EgressProxyServer | None = None,
        proxy_port: int | None = None,
    ) -> None:
        self.storage = storage
        self.proxy = proxy
        self.proxy_port = proxy_port

    def _record_extra_skills_event(
        self,
        agent_id: str,
        extra_skills: list[str],
        allowed_skills: list[str],
        task_id: str | None = None,
    ) -> None:
        if not extra_skills:
            return
        evt = GovernanceEvent(
            event_id=f"evt_{uuid.uuid4().hex[:16]}",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source=EventSource.TOOL_BROKER,
            task_id=task_id,
            agent_id=agent_id,
            pid=None,
            kind="outside_a2a_card_skills",
            target=agent_id,
            details={
                "extra_skills": list(extra_skills),
                "allowed_skills": list(allowed_skills),
            },
            verdict=EventVerdict.INSIDE,
            risk_tier=RiskTier.MEDIUM,
            action_taken=TaskAction.ALERT,
            prevented=False,
            rule_matched="card claims skills the admin did not allow",
            boundary_version=None,
        )
        self.storage.record_event(evt)

    def register(
        self,
        *,
        agent_id: str,
        card_url: str,
        jwk_anchor: dict[str, Any],
        allowed_callers: list[str],
        allowed_skills: list[str],
        max_label: str = "internal",
        auth_type: str = "none",
        auth_token_path: str | None = None,
        name: str | None = None,
        proxy: EgressProxyServer | None = None,
        proxy_port: int | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        aid = str(agent_id or "").strip()
        if not aid:
            raise ValueError("agent_id cannot be empty")
        _canonical_url_host_port(card_url)
        validated_anchor = validate_jwk_anchor(jwk_anchor)
        validated_label = validate_max_label(max_label)
        validated_auth_type, validated_auth_path = validate_auth_config(auth_type, auth_token_path)
        callers = [str(c).strip() for c in (allowed_callers or []) if str(c).strip()]
        skills = [str(s).strip() for s in (allowed_skills or []) if str(s).strip()]

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        existing = self.storage.get_outside_agent(aid)
        rec: dict[str, Any] = {
            "agent_id": aid,
            "name": (name or (existing or {}).get("name") or aid),
            "description": (existing or {}).get("description") or "",
            "card_url": card_url,
            "interface_url": None,
            "jwk_anchor": validated_anchor,
            "allowed_callers": callers,
            "allowed_skills": skills,
            "max_label": validated_label,
            "auth_type": validated_auth_type,
            "auth_token_path": validated_auth_path,
            "card": None,
            "card_hash": None,
            "card_kid": None,
            "card_skills": [],
            "extra_skills": [],
            "status": "refused",
            "failure_reason": None,
            "verified_at": None,
            "disabled": False,
            "created_at": (existing or {}).get("created_at") or now_utc,
            "updated_at": now_utc,
        }

        try:
            verified = fetch_and_verify_card_via_proxy(
                storage=self.storage,
                card_url=card_url,
                anchor=validated_anchor,
                proxy=proxy or self.proxy,
                proxy_port=proxy_port if proxy_port is not None else self.proxy_port,
                timeout=timeout,
            )
            extra = [s for s in verified.card_skills if s not in skills]
            rec.update({
                "name": name or verified.name or aid,
                "description": verified.description,
                "interface_url": verified.interface_url,
                "card": verified.raw_card,
                "card_hash": verified.card_hash,
                "card_kid": verified.card_kid,
                "card_skills": verified.card_skills,
                "extra_skills": extra,
                "status": "verified",
                "failure_reason": None,
                "verified_at": now_utc,
            })
            self.storage.save_outside_agent(rec)
            self._record_extra_skills_event(aid, extra, skills)
        except Exception as exc:
            rec["status"] = "refused"
            rec["failure_reason"] = str(exc)
            self.storage.save_outside_agent(rec)

        stored = self.storage.get_outside_agent(aid) or rec
        stored["card_status_label"] = card_status_summary(stored)
        return stored

    def reverify(
        self,
        agent_id: str,
        *,
        proxy: EgressProxyServer | None = None,
        proxy_port: int | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any] | None:
        existing = self.storage.get_outside_agent(agent_id)
        if not existing:
            return None
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        rec = dict(existing)
        rec["updated_at"] = now_utc
        try:
            verified = fetch_and_verify_card_via_proxy(
                storage=self.storage,
                card_url=existing["card_url"],
                anchor=existing["jwk_anchor"],
                proxy=proxy or self.proxy,
                proxy_port=proxy_port if proxy_port is not None else self.proxy_port,
                timeout=timeout,
            )
            allowed_skills = list(existing.get("allowed_skills") or [])
            extra = [s for s in verified.card_skills if s not in allowed_skills]
            rec.update({
                "name": verified.name or existing.get("name") or agent_id,
                "description": verified.description,
                "interface_url": verified.interface_url,
                "card": verified.raw_card,
                "card_hash": verified.card_hash,
                "card_kid": verified.card_kid,
                "card_skills": verified.card_skills,
                "extra_skills": extra,
                "status": "disabled" if existing.get("disabled") else "verified",
                "failure_reason": "disabled by administrator" if existing.get("disabled") else None,
                "verified_at": now_utc,
            })
            self.storage.save_outside_agent(rec)
            self._record_extra_skills_event(agent_id, extra, allowed_skills)
        except Exception as exc:
            rec["status"] = "disabled" if existing.get("disabled") else "refused"
            rec["failure_reason"] = str(exc)
            self.storage.save_outside_agent(rec)

        stored = self.storage.get_outside_agent(agent_id) or rec
        stored["card_status_label"] = card_status_summary(stored)
        return stored

    def disable(self, agent_id: str, disabled: bool = True, reason: str | None = None) -> dict[str, Any] | None:
        updated = self.storage.set_outside_agent_disabled(
            agent_id,
            disabled=disabled,
            reason=reason or ("disabled by administrator" if disabled else None),
        )
        if updated:
            updated["card_status_label"] = card_status_summary(updated)
        return updated

    def list(self, include_disabled: bool = True) -> list[dict[str, Any]]:
        rows = self.storage.list_outside_agents(include_disabled=include_disabled)
        for r in rows:
            r["card_status_label"] = card_status_summary(r)
        return rows

    def get(self, agent_id: str) -> dict[str, Any] | None:
        r = self.storage.get_outside_agent(agent_id)
        if r:
            r["card_status_label"] = card_status_summary(r)
        return r


def execute_outside_a2a_call(
    *,
    storage: GovernanceStorage,
    caller_task: Any,
    caller_agent_id: str,
    outside_record: dict[str, Any],
    message: dict[str, Any] | str,
    deadline_epoch: float,
    caller_token: str | None = None,
    proxy: EgressProxyServer | None = None,
    proxy_port: int | None = None,
    fanout_group: str | None = None,
    should_cancel: typing.Callable[[], str | None] | None = None,
) -> dict[str, Any]:
    """Performs the live verified outside A2A v1.0 JSON-RPC call over EgressProxyServer."""
    target_agent = outside_record["agent_id"]
    caller_task_id = caller_task.task_id
    root_task_id = getattr(caller_task, "root_task_id", None) or caller_task_id
    _, caller_conf = storage.get_task_context_label(caller_task_id)
    parts, outgoing_summary = validate_and_build_outgoing_parts(message)

    def _record_broker_evt(kind: str, verdict: EventVerdict, risk: RiskTier, action: TaskAction, prevented: bool, rule: str, extra_details: dict[str, Any]) -> None:
        storage.record_event(
            GovernanceEvent(
                event_id=f"evt_{uuid.uuid4().hex[:16]}",
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                source=EventSource.TOOL_BROKER,
                task_id=caller_task_id,
                agent_id=caller_agent_id,
                pid=None,
                kind=kind,
                target=target_agent,
                details=extra_details,
                verdict=verdict,
                risk_tier=risk,
                action_taken=action,
                prevented=prevented,
                rule_matched=rule,
                boundary_version=None,
            )
        )

    # 1. Live card re-fetch & change check through proxy
    ephemeral: _EphemeralProxyRunner | None = None
    active_proxy = proxy
    active_port = proxy_port
    if active_proxy is None:
        ephemeral = _EphemeralProxyRunner(storage)
        active_proxy = ephemeral.proxy
        active_port = ephemeral.port
    elif not active_port:
        active_port = getattr(active_proxy, "listening_port", 0) or getattr(active_proxy, "port", 0)
        if not active_port:
            raise OutsideAgentError("EgressProxyServer has no listening port")

    stored_hash = outside_record.get("card_hash")
    req_msg_id = f"msg_{uuid.uuid4().hex[:16]}"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    base_req_row: dict[str, Any] = {
        "message_id": req_msg_id,
        "root_task_id": root_task_id,
        "parent_task_id": caller_task_id,
        "child_task_id": None,
        "from_agent": caller_agent_id,
        "to_agent": target_agent,
        "kind": "request",
        "fanout_group": fanout_group,
        "reply_to": None,
        "sent_at": now_iso,
        "text": outgoing_summary[:8192],
        "verdict": "refused",
        "reason": None,
        "integrity": "trusted",
        "forwarded_from": [],
        "contains_private": caller_conf == "secret",
        "confidentiality": caller_conf,
        "transport": "a2a_v1",
        "remote_task_id": None,
        "card_hash": stored_hash,
    }

    try:
        try:
            card_remaining = max(0.5, min(10.0, deadline_epoch - time.time()))
            verified_card = fetch_and_verify_card_via_proxy(
                storage=storage,
                card_url=outside_record["card_url"],
                anchor=outside_record["jwk_anchor"],
                proxy=active_proxy,
                proxy_port=int(active_port),
                task_id=caller_task_id,
                caller_agent_id=caller_agent_id,
                timeout=card_remaining,
            )
        except Exception as exc:
            reason = str(exc)
            updated = dict(outside_record)
            updated["status"] = "refused"
            updated["failure_reason"] = reason
            updated["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            storage.save_outside_agent(updated)
            base_req_row["verdict"] = "refused"
            base_req_row["reason"] = reason
            storage.save_a2a_message(base_req_row)
            _record_broker_evt(
                "outside_a2a_request",
                EventVerdict.OUTSIDE,
                RiskTier.HIGH,
                TaskAction.BLOCK_ACTION,
                True,
                reason,
                {"transport": "a2a_v1", "card_hash": stored_hash},
            )
            raise OutsideAgentError(reason) from exc

        if verified_card.card_hash != stored_hash:
            reason = "Agent card changed since admin approval; re-verification required"
            updated = dict(outside_record)
            updated["status"] = "changed"
            updated["failure_reason"] = reason
            updated["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            storage.save_outside_agent(updated)
            base_req_row["verdict"] = "refused"
            base_req_row["reason"] = reason
            storage.save_a2a_message(base_req_row)
            _record_broker_evt(
                "outside_a2a_request",
                EventVerdict.OUTSIDE,
                RiskTier.HIGH,
                TaskAction.BLOCK_ACTION,
                True,
                reason,
                {"transport": "a2a_v1", "card_hash": verified_card.card_hash, "card_kid": verified_card.card_kid},
            )
            raise OutsideAgentError(reason)

        # Record any extra skills claimed beyond admin ceiling
        allowed_skills = list(outside_record.get("allowed_skills") or [])
        extra_skills = [s for s in verified_card.card_skills if s not in allowed_skills]
        if extra_skills:
            OutsideAgentRegistry(storage)._record_extra_skills_event(
                target_agent, extra_skills, allowed_skills, task_id=caller_task_id
            )

        bearer_token = read_partner_bearer_token(
            outside_record.get("auth_type") or "none",
            outside_record.get("auth_token_path"),
        )

        interface_url = verified_card.interface_url
        _, iface_host, iface_port = _canonical_url_host_port(interface_url)
        context_id = str(uuid.uuid5(uuid.NAMESPACE_OID, f"agent-governance-a2a:{root_task_id}"))
        rpc_msg = Message(
            message_id=f"a2amsg_{uuid.uuid4().hex}",
            context_id=context_id,
            role=Role.ROLE_USER,
            parts=parts,
        )

        # 2. Open egress ONLY to the interface host for this call
        call_proxy_token = f"oa_call_{uuid.uuid4().hex}"
        active_proxy.grant_scoped_egress(
            call_proxy_token,
            task_id=caller_task_id,
            agent_id=caller_agent_id,
            allowed_host=iface_host,
            allowed_port=iface_port,
            require_connect=True,
        )

        def _is_aborted() -> str | None:
            if should_cancel is not None:
                why = should_cancel()
                if why:
                    return why
            if caller_token and not storage.lookup_task_by_token(caller_token):
                return "task token revoked"
            if hasattr(storage, "is_task_frozen") and storage.is_task_frozen(caller_task_id):
                return "parent task frozen"
            if root_task_id != caller_task_id and hasattr(storage, "is_task_frozen") and storage.is_task_frozen(root_task_id):
                return "root task frozen"
            t_cur = storage.get_task(caller_task_id)
            if t_cur is not None:
                st_val = t_cur.status.value if hasattr(t_cur.status, "value") else str(t_cur.status)
                if st_val in ("FROZEN", "TERMINATED", "FAILED", "EXPIRED"):
                    return f"task is {st_val.lower()}"
            return None

        async def _drive_rpc() -> tuple[str | None, str]:
            svc_params: dict[str, str] = {VERSION_HEADER: PROTOCOL_VERSION_1_0}
            if bearer_token:
                svc_params["Authorization"] = f"Bearer {bearer_token}"

            async with build_proxy_httpx_client(
                proxy_host="127.0.0.1",
                proxy_port=int(active_port),
                proxy_token=call_proxy_token,
                timeout=max(1.0, deadline_epoch - time.time()),
            ) as httpx_client:
                transport = JsonRpcTransport(
                    httpx_client=httpx_client,
                    agent_card=verified_card.card,
                    url=interface_url,
                    is_shared_httpx=True,
                )

                async def _run_with_watch(coro: typing.Coroutine[Any, Any, Any]) -> Any:
                    task_obj = asyncio.create_task(coro)
                    try:
                        while not task_obj.done():
                            abort_why = _is_aborted()
                            if abort_why:
                                task_obj.cancel()
                                raise OutsideAgentError(f"Outside call aborted ({abort_why})")
                            rem = deadline_epoch - time.time()
                            if rem <= 0:
                                task_obj.cancel()
                                raise TimeoutError(f"Inherited task deadline exceeded calling '{target_agent}'")
                            done, _ = await asyncio.wait({task_obj}, timeout=min(0.1, rem))
                            if done:
                                return task_obj.result()
                        return task_obj.result()
                    except BaseException:
                        if not task_obj.done():
                            task_obj.cancel()
                        raise

                abort_initial = _is_aborted()
                if abort_initial:
                    raise OutsideAgentError(f"Outside call aborted ({abort_initial})")
                rem0 = deadline_epoch - time.time()
                if rem0 <= 0:
                    raise TimeoutError(f"Inherited task deadline exceeded calling '{target_agent}'")

                ctx = ClientCallContext(service_parameters=svc_params, timeout=rem0)
                send_req = SendMessageRequest(
                    message=rpc_msg,
                    configuration=SendMessageConfiguration(return_immediately=True),
                )
                send_resp = await _run_with_watch(
                    transport.send_message(send_req, context=ctx)
                )

                if send_resp.HasField("message") and not send_resp.HasField("task"):
                    return None, _extract_reply_text_from_message(send_resp.message)

                if not send_resp.HasField("task"):
                    raise OutsideAgentError("Outside agent returned neither task nor message")

                remote_task = send_resp.task
                r_tid = remote_task.id
                base_req_row["remote_task_id"] = r_tid

                async def _send_cancel() -> None:
                    try:
                        c_ctx = ClientCallContext(service_parameters=svc_params, timeout=2.0)
                        await transport.cancel_task(CancelTaskRequest(id=r_tid), context=c_ctx)
                    except Exception as cancel_exc:
                        logger.debug("Best-effort CancelTask failed for %s: %s", r_tid, cancel_exc)

                while True:
                    cur_state = remote_task.status.state
                    if cur_state == TaskState.TASK_STATE_COMPLETED:
                        return r_tid, _extract_reply_text_from_task(remote_task)
                    if cur_state in TERMINAL_TASK_STATES:
                        state_name = TaskState.Name(cur_state)
                        raise OutsideAgentError(f"Outside agent task {r_tid} ended with state {state_name}")

                    abort_why = _is_aborted()
                    if abort_why:
                        await _send_cancel()
                        raise OutsideAgentError(f"Outside call canceled ({abort_why}); CancelTask sent")

                    rem = deadline_epoch - time.time()
                    if rem <= 0:
                        await _send_cancel()
                        raise TimeoutError(f"Inherited task deadline exceeded waiting for '{target_agent}'; CancelTask sent")

                    await asyncio.sleep(min(POLL_INTERVAL_SECONDS, max(0.01, rem)))

                    abort_why2 = _is_aborted()
                    if abort_why2:
                        await _send_cancel()
                        raise OutsideAgentError(f"Outside call canceled ({abort_why2}); CancelTask sent")

                    rem2 = deadline_epoch - time.time()
                    if rem2 <= 0:
                        await _send_cancel()
                        raise TimeoutError(f"Inherited task deadline exceeded waiting for '{target_agent}'; CancelTask sent")

                    poll_ctx = ClientCallContext(service_parameters=svc_params, timeout=min(5.0, rem2))
                    try:
                        remote_task = await _run_with_watch(
                            transport.get_task(GetTaskRequest(id=r_tid), context=poll_ctx)
                        )
                    except (OutsideAgentError, TimeoutError):
                        await _send_cancel()
                        raise

        try:
            try:
                asyncio.get_running_loop()
                in_loop = True
            except RuntimeError:
                in_loop = False

            if in_loop:
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    remote_task_id, reply_text = pool.submit(lambda: asyncio.run(_drive_rpc())).result()
            else:
                remote_task_id, reply_text = asyncio.run(_drive_rpc())
        except Exception as exc:
            err_reason = str(_format_network_error(exc, interface_url)) if not isinstance(exc, (OutsideAgentError, TimeoutError)) else str(exc)
            base_req_row["verdict"] = "failed"
            base_req_row["reason"] = err_reason
            storage.save_a2a_message(base_req_row)
            _record_broker_evt(
                "outside_a2a_request",
                EventVerdict.OUTSIDE,
                RiskTier.HIGH,
                TaskAction.BLOCK_ACTION,
                True,
                err_reason,
                {
                    "transport": "a2a_v1",
                    "remote_task_id": base_req_row.get("remote_task_id"),
                    "card_hash": verified_card.card_hash,
                    "card_kid": verified_card.card_kid,
                },
            )
            if isinstance(exc, (OutsideAgentError, TimeoutError)):
                raise
            raise _format_network_error(exc, interface_url) from exc
        finally:
            active_proxy.revoke_scoped_egress(call_proxy_token)

        # Success: record delivered request & reply rows + broker events
        base_req_row["verdict"] = "delivered"
        base_req_row["remote_task_id"] = remote_task_id
        base_req_row["card_hash"] = verified_card.card_hash
        storage.save_a2a_message(base_req_row)
        _record_broker_evt(
            "outside_a2a_request",
            EventVerdict.INSIDE,
            RiskTier.LOW,
            TaskAction.ALLOW,
            False,
            f"outside A2A v1.0 SendMessage to {target_agent}",
            {
                "transport": "a2a_v1",
                "remote_task_id": remote_task_id,
                "card_hash": verified_card.card_hash,
                "card_kid": verified_card.card_kid,
            },
        )

        rep_msg_id = f"msg_{uuid.uuid4().hex[:16]}"
        rep_row = {
            "message_id": rep_msg_id,
            "root_task_id": root_task_id,
            "parent_task_id": caller_task_id,
            "child_task_id": None,
            "from_agent": target_agent,
            "to_agent": caller_agent_id,
            "kind": "reply",
            "fanout_group": fanout_group,
            "reply_to": req_msg_id,
            "sent_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "text": reply_text[:8192],
            "verdict": "delivered",
            "reason": None,
            "integrity": "untrusted",
            "forwarded_from": [],
            "contains_private": False,
            "confidentiality": "public",
            "transport": "a2a_v1",
            "remote_task_id": remote_task_id,
            "card_hash": verified_card.card_hash,
        }
        storage.save_a2a_message(rep_row)
        _record_broker_evt(
            "outside_a2a_reply",
            EventVerdict.INSIDE,
            RiskTier.MEDIUM,
            TaskAction.ALLOW,
            False,
            f"outside A2A v1.0 reply from {target_agent} labelled untrusted",
            {
                "transport": "a2a_v1",
                "remote_task_id": remote_task_id,
                "card_hash": verified_card.card_hash,
                "card_kid": verified_card.card_kid,
            },
        )

        return {
            "status": "completed",
            "reply": reply_text,
            "child_task_id": None,
            "remote_task_id": remote_task_id,
            "card_hash": verified_card.card_hash,
            "card_kid": verified_card.card_kid,
            "transport": "a2a_v1",
            "integrity": "untrusted",
            "confidentiality": "public",
            "outside_a2a": True,
        }
    finally:
        if ephemeral is not None:
            ephemeral.stop()
