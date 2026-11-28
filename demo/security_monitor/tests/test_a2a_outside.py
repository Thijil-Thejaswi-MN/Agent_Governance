"""Tests for outbound A2A v1.0 calls (PR A2A-3a)."""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from demo.outside_agents.partner_app import (
    build_signed_card,
    create_partner_app,
    generate_ephemeral_jwk_pair,
)
from demo.security_monitor.app.gateway.server import create_app
from demo.security_monitor.app.governance.broker import ToolBroker
from demo.security_monitor.app.governance.expansion import ExpansionService
from demo.security_monitor.app.governance.inventory import AgentInventoryService
from demo.security_monitor.app.governance.launcher import TaskLauncher, TaskSpec
from demo.security_monitor.app.governance.models import (
    EnforcementMode,
    EventVerdict,
    TaskBoundary,
    TaskLifecycle,
    TaskRecord,
)
from demo.security_monitor.app.governance.outside_agents import (
    OutsideAgentError,
    OutsideAgentRegistry,
)
from demo.security_monitor.app.governance.proxy import EgressProxyServer
from demo.security_monitor.app.governance.receipt import build_receipt, verify_receipt
from demo.security_monitor.app.governance.run_manager import PRESETS
from demo.security_monitor.app.governance.storage import GovernanceStorage
from demo.security_monitor.tests.test_proxy_keepalive import run_coro


class _RunningPartner:
    def __init__(self, mode: str = "echo", private_jwk: dict[str, Any] | None = None, **kwargs: Any) -> None:
        if private_jwk is not None:
            self.priv_jwk = private_jwk
            self.pub_jwk = {k: v for k, v in private_jwk.items() if k != "d"}
            kwargs.pop("kid", None)
        else:
            self.priv_jwk, self.pub_jwk = generate_ephemeral_jwk_pair(kid=kwargs.pop("kid", None))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(64)
        self.port = sock.getsockname()[1]
        self.base_url = kwargs.pop("base_url", f"http://127.0.0.1:{self.port}")
        self.app, self.executor, self.raw_requests = create_partner_app(
            mode=mode,
            base_url=self.base_url,
            private_jwk=self.priv_jwk,
            **kwargs,
        )
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(
            target=lambda: self.server.run(sockets=[sock]),
            daemon=True,
        )
        self.thread.start()
        deadline = time.monotonic() + 5.0
        while not self.server.started and time.monotonic() < deadline:
            time.sleep(0.02)

    @property
    def card_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/.well-known/agent-card.json"

    def swap_app(self, *, mode: str = "hostile", card_version: int = 2, **kwargs: Any) -> None:
        new_app, new_exec, new_raw = create_partner_app(
            mode=mode,
            base_url=self.base_url,
            private_jwk=kwargs.pop("private_jwk", self.priv_jwk),
            card_version=card_version,
            **kwargs,
        )
        self.app = new_app
        self.executor = new_exec
        self.raw_requests = new_raw
        self.server.config.app = new_app
        self.server.config.loaded_app = new_app

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=3.0)


class _RunningProxy:
    def __init__(self, storage: GovernanceStorage) -> None:
        self.proxy = EgressProxyServer(storage=storage, host="127.0.0.1", port=0)
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.port = asyncio.run_coroutine_threadsafe(self.proxy.start(), self.loop).result(timeout=5.0)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def stop(self) -> None:
        try:
            asyncio.run_coroutine_threadsafe(self.proxy.stop(), self.loop).result(timeout=3.0)
        except Exception:
            pass
        try:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=2.0)
        except Exception:
            pass


def _make_task(
    storage: GovernanceStorage,
    ws: Path,
    task_id: str,
    agent_id: str = "planner",
    peer_agents: list[str] | None = None,
    network: list[str] | None = None,
    tools: list[str] | None = None,
    timeout_s: float = 60.0,
) -> str:
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "input").mkdir(exist_ok=True)
    (ws / "output").mkdir(exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    task = TaskRecord(
        task_id=task_id,
        request_text="Outside A2A test",
        request_hash=hashlib.sha256(task_id.encode()).hexdigest(),
        agent_id=agent_id,
        owner="admin",
        team="travel",
        workspace_root=str(ws),
        status=TaskLifecycle.ACTIVE,
        created_at=now,
        started_at=now,
        updated_at=now,
        current_boundary_version=1,
        root_task_id=task_id,
        parent_task_id=None,
        depth=0,
        chain=[agent_id],
        timeout_s=timeout_s,
    )
    storage.save_task(task)
    bnd = TaskBoundary(
        task_id=task_id,
        version=1,
        workspace_root=str(ws),
        files_read=["input/*", "input/passport_scan.pdf"],
        files_write=["output/*"],
        tools=tools or ["read_file", "write_file", "call_agent", "call_agents", "http_post"],
        network=network or [],
        peer_agents=peer_agents or [],
        enforcement_mode=EnforcementMode.ENFORCE,
        metadata={"private_files": [{"path": "input/passport_scan.pdf"}]},
    )
    storage.save_boundary(bnd)
    tok = f"tok_{task_id}"
    storage.save_token(tok, task_id, agent_id)
    return tok


@pytest.fixture
def env(tmp_path: Path):
    storage = GovernanceStorage(str(tmp_path / "gov.db"))
    proxy_runner = _RunningProxy(storage)
    yield tmp_path, storage, proxy_runner
    proxy_runner.stop()
    storage.close()


# ---------------------------------------------------------------------------
# 1 & 12 & 13: Verified call works, untrusted reply, no token/key/history leak,
#             a2a_messages fields + broker events + receipt verification
# ---------------------------------------------------------------------------

def test_verified_call_untrusted_reply_no_leak_and_receipt(env):
    tmp_path, storage, proxy_runner = env
    token_file = tmp_path / "partner_bearer.txt"
    token_file.write_text("secret-partner-bearer-999\n", encoding="utf-8")

    partner = _RunningPartner(mode="echo", bearer_token="secret-partner-bearer-999")
    try:
        reg = OutsideAgentRegistry(storage, proxy=proxy_runner.proxy, proxy_port=proxy_runner.port)
        rec = reg.register(
            agent_id="echo_partner",
            card_url=partner.card_url,
            jwk_anchor=partner.pub_jwk,
            allowed_callers=["planner"],
            allowed_skills=["echo"],
            max_label="internal",
            auth_type="bearer",
            auth_token_path=str(token_file),
        )
        assert rec["status"] == "verified"
        assert rec["card_hash"]
        assert "signature verified" in rec["card_status_label"]

        ws = tmp_path / "ws1"
        tok = _make_task(storage, ws, "task_verified_1", peer_agents=["echo_partner"])
        broker = ToolBroker(storage, expansion_service=ExpansionService(storage, provenance_enabled=True))
        broker.egress_proxy = proxy_runner.proxy  # type: ignore[attr-defined]
        broker.egress_proxy_port = proxy_runner.port  # type: ignore[attr-defined]

        # Test data + text parts both accepted
        res = broker.call_agent(
            tok,
            "echo_partner",
            {"parts": [{"text": "Kyoto hotel query"}, {"data": {"nights": 3}}]},
        )
        assert res["status"] == "completed"
        assert res["transport"] == "a2a_v1"
        assert res["integrity"] == "untrusted"
        assert "Echo summary:" in res["reply"]
        assert res["remote_task_id"]
        assert res["card_hash"] == rec["card_hash"]

        # Context label raised to untrusted
        integ, conf = storage.get_task_context_label("task_verified_1")
        assert integ == "untrusted"
        assert conf == "public"

        # Inspect exact wire payload received by partner
        send_reqs = [r for r in partner.raw_requests if (r.get("json") or {}).get("method") == "SendMessage"]
        assert len(send_reqs) == 1
        req_entry = send_reqs[0]
        assert req_entry["headers"].get("a2a-version") == "1.0"
        assert req_entry["headers"].get("authorization") == "Bearer secret-partner-bearer-999"
        rpc_msg = req_entry["json"]["params"]["message"]
        expected_ctx = str(uuid.uuid5(uuid.NAMESPACE_OID, "agent-governance-a2a:task_verified_1"))
        assert rpc_msg["contextId"] == expected_ctx
        # Member-based parts with NO 'kind' field
        for part in rpc_msg["parts"]:
            assert "kind" not in part
            assert ("text" in part) or ("data" in part)
        serialized_wire = json.dumps(req_entry["json"])
        assert tok not in serialized_wire
        assert "delegation_token" not in serialized_wire
        assert "chat_history" not in serialized_wire
        assert "private_key" not in serialized_wire
        assert partner.priv_jwk["d"] not in serialized_wire

        # Raw & URL parts refused
        with pytest.raises(PermissionError, match="text and data parts"):
            broker.call_agent(tok, "echo_partner", {"parts": [{"url": "https://example.com/a.pdf"}]})
        with pytest.raises(PermissionError, match="text and data parts"):
            broker.call_agent(tok, "echo_partner", {"parts": [{"raw": "YWJj"}]})

        # Verify a2a_messages rows & receipt
        msgs = storage.get_a2a_messages(parent_task_id="task_verified_1")
        delivered_reqs = [m for m in msgs if m["kind"] == "request" and m["verdict"] == "delivered"]
        delivered_reps = [m for m in msgs if m["kind"] == "reply" and m["verdict"] == "delivered"]
        assert len(delivered_reqs) == 1
        assert delivered_reqs[0]["to_agent"] == "echo_partner"
        assert delivered_reqs[0]["transport"] == "a2a_v1"
        assert delivered_reqs[0]["remote_task_id"] == res["remote_task_id"]
        assert delivered_reqs[0]["card_hash"] == rec["card_hash"]
        assert len(delivered_reps) == 1
        assert delivered_reps[0]["integrity"] == "untrusted"
        assert delivered_reps[0]["card_hash"] == rec["card_hash"]

        task_rec = storage.get_task("task_verified_1")
        task_rec.status = TaskLifecycle.COMPLETED
        task_rec.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        storage.save_task(task_rec)
        receipt = build_receipt(
            task=task_rec,
            initial_boundary=storage.get_boundary("task_verified_1"),
            requester="test",
            storage=storage,
            os_records=[],
            deliveries=[],
            sensor_status={"kind": "broker"},
            isolation={"isolation_level": "broker"},
            freeze_events=[],
            termination={"reason": "agent_exited"},
            wall_time_s=0.1,
            os_identity=None,
        )
        ver = verify_receipt(receipt, storage=storage)
        assert ver["ok"] is True, ver
        receipt_a2a = receipt["extra"]["a2a_messages"]
        assert any(m.get("card_hash") == rec["card_hash"] and m.get("transport") == "a2a_v1" for m in receipt_a2a)
        broker_kinds = [e["kind"] for e in receipt["events"]]
        assert "outside_a2a_request" in broker_kinds
        assert "outside_a2a_reply" in broker_kinds
    finally:
        partner.stop()


# ---------------------------------------------------------------------------
# 2: After hostile reply, follow-up http_post needs OK (Rule 2), passport not sent
# ---------------------------------------------------------------------------

def test_hostile_reply_triggers_rule2_and_blocks_passport_exfil(env):
    tmp_path, storage, proxy_runner = env
    partner = _RunningPartner(mode="hostile")
    try:
        reg = OutsideAgentRegistry(storage, proxy=proxy_runner.proxy, proxy_port=proxy_runner.port)
        reg.register(
            agent_id="hostile_partner",
            card_url=partner.card_url,
            jwk_anchor=partner.pub_jwk,
            allowed_callers=["planner"],
            allowed_skills=["hotel_prices"],
            max_label="internal",
        )

        ws = tmp_path / "ws_hostile"
        tok = _make_task(
            storage,
            ws,
            "task_hostile_rule2",
            peer_agents=["hostile_partner"],
            # Intentionally permit destination host in network boundary so Rule 2 is isolated and exercised
            network=["gion-maru-travel.example:443"],
        )
        (ws / "input" / "passport_scan.pdf").write_text("SECRET_PASSPORT_CANARY_XYZ", encoding="utf-8")

        asked: list[Any] = []
        sent_posts: list[Any] = []

        def deny_hook(req):
            asked.append(req)
            return False

        expansion = ExpansionService(storage, provenance_enabled=True, user_approval_hook=deny_hook)
        broker = ToolBroker(storage, expansion_service=expansion)
        broker.egress_proxy = proxy_runner.proxy  # type: ignore[attr-defined]
        broker.egress_proxy_port = proxy_runner.port  # type: ignore[attr-defined]
        broker.http_fetcher = lambda **kw: sent_posts.append(kw) or {"status": 200, "body": "ok"}  # type: ignore[attr-defined]

        res = broker.call_agent(tok, "hostile_partner", {"text": "Find hotel prices in Kyoto"})
        assert "gion-maru-travel.example" in res["reply"]

        with pytest.raises(PermissionError, match="Flow denied"):
            broker.http_post(
                tok,
                "https://gion-maru-travel.example/api/v1/booking",
                file_path="input/passport_scan.pdf",
            )
        assert len(asked) >= 1
        assert any(r.resource_type == "flow" and "gion-maru-travel.example" in r.resource_target for r in asked)
        assert sent_posts == []
    finally:
        partner.stop()


# ---------------------------------------------------------------------------
# 3: Secret task needs OK before calling out; label above ceiling refused
# ---------------------------------------------------------------------------

def test_secret_task_needs_ok_and_label_ceiling_refused(env):
    tmp_path, storage, proxy_runner = env
    partner = _RunningPartner(mode="echo")
    try:
        reg = OutsideAgentRegistry(storage, proxy=proxy_runner.proxy, proxy_port=proxy_runner.port)
        with pytest.raises(ValueError, match="internal"):
            reg.register(
                agent_id="bad_secret",
                card_url=partner.card_url,
                jwk_anchor=partner.pub_jwk,
                allowed_callers=["planner"],
                allowed_skills=["echo"],
                max_label="secret",
            )

        reg.register(
            agent_id="echo_public_only",
            card_url=partner.card_url,
            jwk_anchor=partner.pub_jwk,
            allowed_callers=["planner"],
            allowed_skills=["echo"],
            max_label="public",
        )
        reg.register(
            agent_id="echo_internal",
            card_url=partner.card_url,
            jwk_anchor=partner.pub_jwk,
            allowed_callers=["planner"],
            allowed_skills=["echo"],
            max_label="internal",
        )

        # Case A: internal task calling public-only agent -> refused
        ws1 = tmp_path / "ws_pub"
        tok1 = _make_task(storage, ws1, "task_lbl_pub", peer_agents=["echo_public_only"])
        storage.update_task_context_label("task_lbl_pub", confidentiality="internal")
        broker1 = ToolBroker(storage, expansion_service=ExpansionService(storage, provenance_enabled=True))
        broker1.egress_proxy = proxy_runner.proxy  # type: ignore[attr-defined]
        broker1.egress_proxy_port = proxy_runner.port  # type: ignore[attr-defined]
        with pytest.raises(PermissionError, match="highest allowed label 'public'"):
            broker1.call_agent(tok1, "echo_public_only", {"text": "internal summary"})

        # Case B: secret task needs person's OK (Rule 1) before calling out
        ws2 = tmp_path / "ws_sec"
        tok2 = _make_task(storage, ws2, "task_lbl_sec", peer_agents=["echo_internal"])
        storage.update_task_context_label("task_lbl_sec", confidentiality="secret")
        rule1_reqs = []
        broker2 = ToolBroker(
            storage,
            expansion_service=ExpansionService(
                storage, provenance_enabled=True, user_approval_hook=lambda r: rule1_reqs.append(r) or False
            ),
        )
        broker2.egress_proxy = proxy_runner.proxy  # type: ignore[attr-defined]
        broker2.egress_proxy_port = proxy_runner.port  # type: ignore[attr-defined]
        with pytest.raises(PermissionError, match="Flow denied"):
            broker2.call_agent(tok2, "echo_internal", {"text": "hello"})
        assert len(rule1_reqs) == 1
        assert rule1_reqs[0].resource_type == "flow"

        # Case C: even if Rule 1 hook returns True, secret still exceeds max_label='internal'
        ws3 = tmp_path / "ws_sec_ok"
        tok3 = _make_task(storage, ws3, "task_lbl_sec_ok", peer_agents=["echo_internal"])
        storage.update_task_context_label("task_lbl_sec_ok", confidentiality="secret")
        broker3 = ToolBroker(
            storage,
            expansion_service=ExpansionService(storage, provenance_enabled=True, user_approval_hook=lambda _r: True),
        )
        broker3.egress_proxy = proxy_runner.proxy  # type: ignore[attr-defined]
        broker3.egress_proxy_port = proxy_runner.port  # type: ignore[attr-defined]
        with pytest.raises(PermissionError, match="highest allowed label 'internal'"):
            broker3.call_agent(tok3, "echo_internal", {"text": "hello"})
        assert partner.raw_requests == []
    finally:
        partner.stop()


# ---------------------------------------------------------------------------
# 4: Unsigned, bad signature, unknown kid, jku pointing elsewhere, changed card
# ---------------------------------------------------------------------------

def test_card_signature_rejections_and_changed_card(env):
    tmp_path, storage, proxy_runner = env
    reg = OutsideAgentRegistry(storage, proxy=proxy_runner.proxy, proxy_port=proxy_runner.port)
    broker = ToolBroker(storage, expansion_service=ExpansionService(storage, provenance_enabled=True))
    broker.egress_proxy = proxy_runner.proxy  # type: ignore[attr-defined]
    broker.egress_proxy_port = proxy_runner.port  # type: ignore[attr-defined]

    # Listener for jku SSRF trap
    jku_hits: list[str] = []

    class _JkuHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            jku_hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    jku_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _JkuHandler)
    threading.Thread(target=jku_srv.serve_forever, daemon=True).start()
    jku_url = f"http://127.0.0.1:{jku_srv.server_address[1]}/jwks.json"

    _, dummy_anchor = generate_ephemeral_jwk_pair(kid="expected-kid")

    try:
        # Unsigned card
        p_unsig = _RunningPartner(mode="echo", unsigned=True)
        try:
            r1 = reg.register(
                agent_id="oa_unsigned",
                card_url=p_unsig.card_url,
                jwk_anchor=dummy_anchor,
                allowed_callers=["planner"],
                allowed_skills=["echo"],
            )
            assert r1["status"] == "refused"
            assert "unsigned" in (r1["failure_reason"] or "").lower()
            tok = _make_task(storage, tmp_path / "w1", "t_unsig", peer_agents=["oa_unsigned"])
            with pytest.raises(PermissionError, match="unsigned"):
                broker.call_agent(tok, "oa_unsigned", {"text": "hi"})
        finally:
            p_unsig.stop()

        # Bad signature
        p_bad = _RunningPartner(mode="echo", bad_signature=True, kid="expected-kid")
        try:
            r2 = reg.register(
                agent_id="oa_badsig",
                card_url=p_bad.card_url,
                jwk_anchor=p_bad.pub_jwk,
                allowed_callers=["planner"],
                allowed_skills=["echo"],
            )
            assert r2["status"] == "refused"
            assert "bad signature" in (r2["failure_reason"] or "").lower()
            tok = _make_task(storage, tmp_path / "w2", "t_badsig", peer_agents=["oa_badsig"])
            with pytest.raises(PermissionError, match="bad signature"):
                broker.call_agent(tok, "oa_badsig", {"text": "hi"})
        finally:
            p_bad.stop()

        # Unknown kid
        p_kid = _RunningPartner(mode="echo", kid="other-kid")
        try:
            r3 = reg.register(
                agent_id="oa_badkid",
                card_url=p_kid.card_url,
                jwk_anchor=dummy_anchor,
                allowed_callers=["planner"],
                allowed_skills=["echo"],
            )
            assert r3["status"] == "refused"
            assert "kid" in (r3["failure_reason"] or "").lower()
            tok = _make_task(storage, tmp_path / "w3", "t_badkid", peer_agents=["oa_badkid"])
            with pytest.raises(PermissionError, match="kid"):
                broker.call_agent(tok, "oa_badkid", {"text": "hi"})
        finally:
            p_kid.stop()

        # jku pointing elsewhere (and NEVER fetched)
        p_jku = _RunningPartner(mode="echo", jku_override=jku_url, kid="jku-kid")
        try:
            r4 = reg.register(
                agent_id="oa_jku",
                card_url=p_jku.card_url,
                jwk_anchor=p_jku.pub_jwk,
                allowed_callers=["planner"],
                allowed_skills=["echo"],
            )
            assert r4["status"] == "refused"
            assert "jku" in (r4["failure_reason"] or "").lower()
            assert jku_hits == []
            tok = _make_task(storage, tmp_path / "w4", "t_jku", peer_agents=["oa_jku"])
            with pytest.raises(PermissionError, match="jku"):
                broker.call_agent(tok, "oa_jku", {"text": "hi"})
            assert jku_hits == []
        finally:
            p_jku.stop()

        # Changed card (hostile_partner v1 -> v2 signed with SAME key)
        p_chg = _RunningPartner(mode="hostile", card_version=1, kid="chg-kid")
        try:
            r5 = reg.register(
                agent_id="oa_chg",
                card_url=p_chg.card_url,
                jwk_anchor=p_chg.pub_jwk,
                allowed_callers=["planner"],
                allowed_skills=["hotel_prices"],
            )
            assert r5["status"] == "verified"
            old_hash = r5["card_hash"]
            p_chg.swap_app(mode="hostile", card_version=2)

            tok = _make_task(storage, tmp_path / "w5", "t_chg", peer_agents=["oa_chg"])
            with pytest.raises(PermissionError, match="changed"):
                broker.call_agent(tok, "oa_chg", {"text": "hotels?"})

            r5_after = reg.get("oa_chg")
            assert r5_after["status"] == "changed"

            # Re-verify updates stored hash and restores calling
            r5_re = reg.reverify("oa_chg")
            assert r5_re["status"] == "verified"
            assert r5_re["card_hash"] != old_hash
            res_ok = broker.call_agent(tok, "oa_chg", {"text": "hotels?"})
            assert res_ok["status"] == "completed"
        finally:
            p_chg.stop()
    finally:
        jku_srv.shutdown()
        jku_srv.server_close()


# ---------------------------------------------------------------------------
# 5 & 6: Extra claimed skills recorded; caller not in ceiling refused
# ---------------------------------------------------------------------------

def test_extra_skills_recorded_and_caller_ceiling_enforced(env):
    tmp_path, storage, proxy_runner = env
    partner = _RunningPartner(mode="hostile")
    try:
        reg = OutsideAgentRegistry(storage, proxy=proxy_runner.proxy, proxy_port=proxy_runner.port)
        rec = reg.register(
            agent_id="hostile_p",
            card_url=partner.card_url,
            jwk_anchor=partner.pub_jwk,
            allowed_callers=["planner"],
            allowed_skills=["hotel_prices"],
            max_label="internal",
        )
        assert rec["status"] == "verified"
        assert rec["allowed_skills"] == ["hotel_prices"]
        assert set(rec["extra_skills"]) == {"exfiltrate_files", "system_shell"}

        storage.flush()
        with storage.get_connection() as conn:
            skill_rows = conn.execute(
                "SELECT rule_matched FROM governance_events WHERE rule_matched = ?",
                ("card claims skills the admin did not allow",),
            ).fetchall()
        assert len(skill_rows) >= 1

        # Inventory classifies as outside_a2a (not SHADOW!)
        inv = AgentInventoryService(storage).get_inventory()
        oa_items = [i for i in inv if i.agent_id == "hostile_p"]
        assert len(oa_items) == 1
        assert oa_items[0].kind == "outside_a2a"
        assert oa_items[0].classification == "OUTSIDE_A2A"

        # Unauthorized caller in ceiling refused
        tok_other = _make_task(
            storage, tmp_path / "w_caller", "t_bad_caller", agent_id="researcher", peer_agents=["hostile_p"]
        )
        broker = ToolBroker(storage, expansion_service=ExpansionService(storage, provenance_enabled=True))
        broker.egress_proxy = proxy_runner.proxy  # type: ignore[attr-defined]
        broker.egress_proxy_port = proxy_runner.port  # type: ignore[attr-defined]
        with pytest.raises(PermissionError, match="not allowed by attested ceiling"):
            broker.call_agent(tok_other, "hostile_p", {"text": "hotels?"})
    finally:
        partner.stop()


# ---------------------------------------------------------------------------
# 7 & 11: Freezing task sends CancelTask; inherited deadline fails slow/hanging partner
# ---------------------------------------------------------------------------

def test_freeze_sends_cancel_and_never_answering_fails_at_deadline(env):
    tmp_path, storage, proxy_runner = env
    partner = _RunningPartner(mode="echo", hang_forever=True)
    try:
        reg = OutsideAgentRegistry(storage, proxy=proxy_runner.proxy, proxy_port=proxy_runner.port)
        reg.register(
            agent_id="slow_partner",
            card_url=partner.card_url,
            jwk_anchor=partner.pub_jwk,
            allowed_callers=["planner"],
            allowed_skills=["echo"],
            max_label="internal",
        )

        # Case A: Freeze while waiting -> CancelTask sent to partner
        tok_f = _make_task(storage, tmp_path / "w_frz", "t_freeze_1", peer_agents=["slow_partner"], timeout_s=30.0)
        broker = ToolBroker(storage, expansion_service=ExpansionService(storage, provenance_enabled=True))
        broker.egress_proxy = proxy_runner.proxy  # type: ignore[attr-defined]
        broker.egress_proxy_port = proxy_runner.port  # type: ignore[attr-defined]

        def _freeze_soon():
            dl = time.monotonic() + 5.0
            while not partner.executor.received_log and time.monotonic() < dl:
                time.sleep(0.02)
            time.sleep(0.2)
            storage.record_task_freeze("t_freeze_1", "operator_freeze_test")

        threading.Thread(target=_freeze_soon, daemon=True).start()
        t0 = time.monotonic()
        with pytest.raises(PermissionError, match="CancelTask sent"):
            broker.call_agent(tok_f, "slow_partner", {"text": "hello"})
        assert time.monotonic() - t0 < 5.0
        deadline_wait = time.monotonic() + 2.0
        while not partner.executor.canceled_task_ids and time.monotonic() < deadline_wait:
            time.sleep(0.05)
        assert len(partner.executor.canceled_task_ids) >= 1

        # Case B: Never-answering partner fails promptly at inherited short deadline
        tok_d = _make_task(storage, tmp_path / "w_dl", "t_deadline_1", peer_agents=["slow_partner"], timeout_s=1.5)
        t1 = time.monotonic()
        with pytest.raises(TimeoutError, match="deadline exceeded"):
            broker.call_agent(tok_d, "slow_partner", {"text": "hello"})
        elapsed = time.monotonic() - t1
        assert elapsed < 5.0
    finally:
        partner.stop()


# ---------------------------------------------------------------------------
# 8: Egress to any host other than interface host is refused
# ---------------------------------------------------------------------------

def test_egress_opened_only_to_interface_host(env):
    tmp_path, storage, proxy_runner = env
    priv, pub = generate_ephemeral_jwk_pair(kid="split-kid")

    # Separate interface server (port B) and card server (port A) and forbidden server (port C)
    iface_partner = _RunningPartner(mode="echo", kid="split-kid")
    try:
        card_obj = build_signed_card(
            mode="echo",
            interface_url=f"http://127.0.0.1:{iface_partner.port}/",
            private_jwk=iface_partner.priv_jwk,
        )
        from a2a.server.request_handlers.response_helpers import agent_card_to_dict

        card_bytes = json.dumps(agent_card_to_dict(card_obj)).encode("utf-8")

        class _CardOnly(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(card_bytes)

            def log_message(self, *a):
                pass

        card_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CardOnly)
        threading.Thread(target=card_srv.serve_forever, daemon=True).start()
        card_port = card_srv.server_address[1]

        seen_other_ports = []

        class _OtherHost(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen_other_ports.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        other_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _OtherHost)
        threading.Thread(target=other_srv.serve_forever, daemon=True).start()
        other_port = other_srv.server_address[1]

        try:
            reg = OutsideAgentRegistry(storage, proxy=proxy_runner.proxy, proxy_port=proxy_runner.port)
            rec = reg.register(
                agent_id="split_partner",
                card_url=f"http://127.0.0.1:{card_port}/.well-known/agent-card.json",
                jwk_anchor=iface_partner.pub_jwk,
                allowed_callers=["planner"],
                allowed_skills=["echo"],
                max_label="internal",
            )
            assert rec["status"] == "verified"

            tok = _make_task(storage, tmp_path / "w_egress", "t_egress", peer_agents=["split_partner"], network=[])
            # Verify scoped egress token during call refuses non-interface host
            proxy_runner.proxy.grant_scoped_egress(
                "test_scope_only_iface",
                task_id="t_egress",
                agent_id="planner",
                allowed_host="127.0.0.1",
                allowed_port=iface_partner.port,
                require_connect=True,
            )
            try:
                async def _probe_other() -> bytes:
                    r, w = await asyncio.open_connection("127.0.0.1", proxy_runner.port)
                    w.write(
                        f"CONNECT 127.0.0.1:{other_port} HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{other_port}\r\n"
                        f"Proxy-Authorization: Bearer test_scope_only_iface\r\n\r\n".encode()
                    )
                    await w.drain()
                    data = await r.read(1024)
                    w.close()
                    return data

                resp = run_coro(_probe_other())
                assert b"403 Forbidden" in resp
                assert seen_other_ports == []
            finally:
                proxy_runner.proxy.revoke_scoped_egress("test_scope_only_iface")

            # Live call succeeds over CONNECT to iface_partner.port
            broker = ToolBroker(storage, expansion_service=ExpansionService(storage, provenance_enabled=True))
            broker.egress_proxy = proxy_runner.proxy  # type: ignore[attr-defined]
            broker.egress_proxy_port = proxy_runner.port  # type: ignore[attr-defined]
            res = broker.call_agent(tok, "split_partner", {"text": "test split host"})
            assert res["status"] == "completed"
        finally:
            card_srv.shutdown()
            card_srv.server_close()
            other_srv.shutdown()
            other_srv.server_close()
    finally:
        iface_partner.stop()


# ---------------------------------------------------------------------------
# 9 & 10: Self-signed HTTPS TLS rejected; non-loopback http:// rejected
# ---------------------------------------------------------------------------

def _write_self_signed_cert(cert_dir: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = cert_dir / "self.crt"
    key_path = cert_dir / "self.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    )
    return cert_path, key_path


def test_bad_tls_and_non_loopback_http_refused(env):
    tmp_path, storage, proxy_runner = env
    _, pub_jwk = generate_ephemeral_jwk_pair(kid="tls-kid")
    reg = OutsideAgentRegistry(storage, proxy=proxy_runner.proxy, proxy_port=proxy_runner.port)

    # Non-loopback http:// refused
    with pytest.raises(OutsideAgentError, match="Plain http:// is refused"):
        reg.register(
            agent_id="plain_remote",
            card_url="http://remote-agent.example/.well-known/agent-card.json",
            jwk_anchor=pub_jwk,
            allowed_callers=["planner"],
            allowed_skills=["echo"],
        )

    # Self-signed HTTPS card refused by system CA verification
    cert_file, key_file = _write_self_signed_cert(tmp_path)
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def _tls_card(_req):
        return JSONResponse({})

    tls_app = Starlette(routes=[Route("/.well-known/agent-card.json", _tls_card)])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    tls_port = sock.getsockname()[1]
    tls_srv = uvicorn.Server(
        uvicorn.Config(
            tls_app,
            host="127.0.0.1",
            port=tls_port,
            ssl_keyfile=str(key_file),
            ssl_certfile=str(cert_file),
            log_level="error",
        )
    )
    tls_thread = threading.Thread(target=lambda: tls_srv.run(sockets=[sock]), daemon=True)
    tls_thread.start()
    dl = time.monotonic() + 5.0
    while not tls_srv.started and time.monotonic() < dl:
        time.sleep(0.02)
    try:
        rec = reg.register(
            agent_id="self_signed_partner",
            card_url=f"https://127.0.0.1:{tls_port}/.well-known/agent-card.json",
            jwk_anchor=pub_jwk,
            allowed_callers=["planner"],
            allowed_skills=["echo"],
        )
        assert rec["status"] == "refused"
        assert "tls" in (rec["failure_reason"] or "").lower() or "certificate" in (rec["failure_reason"] or "").lower()
    finally:
        tls_srv.should_exit = True
        tls_thread.join(timeout=3.0)


# ---------------------------------------------------------------------------
# Admin-only API + Inventory + repo path guard + Scripts + Preset
# ---------------------------------------------------------------------------

def test_admin_api_routes_and_auth_guards(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "api_gov.db"
    users_file = tmp_path / "users.json"
    users_file.write_text(
        json.dumps([
            {
                "name": "admin_user",
                "role": "admin",
                "team": None,
                "token_sha256": hashlib.sha256(b"tok_admin").hexdigest(),
            },
            {
                "name": "dev_user",
                "role": "developer",
                "team": "travel",
                "token_sha256": hashlib.sha256(b"tok_dev").hexdigest(),
            },
        ]),
        encoding="utf-8",
    )
    monkeypatch.setenv("GOVERNANCE_DB_PATH", str(db_path))
    monkeypatch.setenv("GOVERNANCE_USERS_FILE", str(users_file))
    monkeypatch.delenv("GOVERNANCE_OPERATOR_TOKEN", raising=False)

    import demo.security_monitor.app.governance.api as api_mod
    monkeypatch.setattr(api_mod, "is_demo_data_enabled", lambda: False)

    partner = _RunningPartner(mode="hostile")
    try:
        client = TestClient(create_app())

        # Non-admin denied (403)
        res_dev = client.post(
            "/api/governance/outside-agents",
            headers={"Authorization": "Bearer tok_dev"},
            json={
                "agent_id": "h1",
                "card_url": partner.card_url,
                "jwk_anchor": partner.pub_jwk,
                "allowed_callers": ["planner"],
                "allowed_skills": ["hotel_prices"],
                "max_label": "internal",
            },
        )
        assert res_dev.status_code == 403

        # Admin registers cleanly
        res_adm = client.post(
            "/api/governance/outside-agents",
            headers={"Authorization": "Bearer tok_admin"},
            json={
                "agent_id": "h1",
                "card_url": partner.card_url,
                "jwk_anchor": partner.pub_jwk,
                "allowed_callers": ["planner"],
                "allowed_skills": ["hotel_prices"],
                "max_label": "internal",
            },
        )
        assert res_adm.status_code == 201, res_adm.text
        body = res_adm.json()
        assert body["kind"] == "outside_a2a"
        assert body["status"] == "verified"

        # Developer also blocked on list / reverify / disable
        assert client.get("/api/governance/outside-agents", headers={"Authorization": "Bearer tok_dev"}).status_code == 403
        assert client.post("/api/governance/outside-agents/h1/reverify", headers={"Authorization": "Bearer tok_dev"}).status_code == 403
        assert client.post("/api/governance/outside-agents/h1/disable", headers={"Authorization": "Bearer tok_dev"}).status_code == 403

        # Admin list + inventory view
        listed = client.get("/api/governance/outside-agents", headers={"Authorization": "Bearer tok_admin"}).json()
        assert len(listed) == 1 and listed[0]["agent_id"] == "h1"

        inv = client.get("/api/governance/inventory", headers={"Authorization": "Bearer tok_dev"}).json()
        h_inv = [i for i in inv if i["agent_id"] == "h1"]
        assert len(h_inv) == 1
        assert h_inv[0]["kind"] == "outside_a2a"
        assert h_inv[0]["metadata"]["max_label"] == "internal"

        # Disable & reverify
        dis = client.post("/api/governance/outside-agents/h1/disable", headers={"Authorization": "Bearer tok_admin"}).json()
        assert dis["disabled"] is True
        assert dis["status"] == "disabled"
        reen = client.post(
            "/api/governance/outside-agents/h1/disable",
            headers={"Authorization": "Bearer tok_admin"},
            json={"disabled": False},
        ).json()
        assert reen["disabled"] is False
        re_ver = client.post("/api/governance/outside-agents/h1/reverify", headers={"Authorization": "Bearer tok_admin"}).json()
        assert re_ver["status"] == "verified"

        # Reject auth_token_path pointing inside repo
        repo_tok = Path(__file__).resolve()
        bad_auth = client.post(
            "/api/governance/outside-agents",
            headers={"Authorization": "Bearer tok_admin"},
            json={
                "agent_id": "h_bad_auth",
                "card_url": partner.card_url,
                "jwk_anchor": partner.pub_jwk,
                "allowed_callers": ["planner"],
                "allowed_skills": ["hotel_prices"],
                "max_label": "internal",
                "auth_type": "bearer",
                "auth_token_path": str(repo_tok),
            },
        )
        assert bad_auth.status_code == 422
    finally:
        partner.stop()


def test_scripts_make_keys_and_remote_check(tmp_path: Path):
    repo_root = Path(__file__).resolve().parents[3]
    keyfile = tmp_path / "partner_keys.json"
    jwkfile = tmp_path / "partner.jwk.json"

    proc_k = subprocess.run(
        [sys.executable, str(repo_root / "scripts" / "make_partner_keys.py"), "--out", str(keyfile)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert proc_k.returncode == 0, proc_k.stderr
    assert keyfile.is_file()
    mode = stat.S_IMODE(os.stat(keyfile).st_mode)
    assert mode == 0o600
    pub_jwk = json.loads(proc_k.stdout)
    assert pub_jwk["kid"]
    assert "d" not in pub_jwk
    jwkfile.write_text(json.dumps(pub_jwk), encoding="utf-8")

    bundle = json.loads(keyfile.read_text(encoding="utf-8"))
    partner = _RunningPartner(mode="demo", private_jwk=bundle["private_jwk"])
    # Swap key manually so partner uses exact keyfile private_jwk
    try:
        proc_chk = subprocess.run(
            [
                sys.executable,
                str(repo_root / "scripts" / "a2a_remote_check.py"),
                "--card-url",
                partner.card_url,
                "--anchor",
                str(jwkfile),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(repo_root),
        )
        # Note _RunningPartner accepted private_jwk? Let's verify in test cleanly
        assert proc_chk.returncode == 0, proc_chk.stdout + "\n" + proc_chk.stderr
        assert "[benign_call]" in proc_chk.stdout
        assert "[hostile_call]" in proc_chk.stdout
        assert "receipt_id=" in proc_chk.stdout
        assert "verified=True" in proc_chk.stdout
    finally:
        partner.stop()


def test_trip_planner_outside_preset_defined():
    p = PRESETS.get("trip_planner_outside")
    assert p is not None
    assert p["agent"] == "planner"
    assert "hostile_partner" in p["peer_agents"]
    tools = [s.get("tool") for s in p["scripted_steps"] if "tool" in s]
    assert tools == ["call_agent", "http_post"]
