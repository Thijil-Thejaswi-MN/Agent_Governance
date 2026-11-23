"""Unit tests for eBPF discovery v2: DNS parsing, unit grouping, MCP detection, rate limiting, and secret redaction."""
from __future__ import annotations

import struct
import pytest

from demo.security_monitor.app.governance.discovery.ebpf_signals import (
    EBPFDiscoveryProcessor,
    match_exec_agent,
    match_llm_connect,
    match_llm_dns,
    match_mcp_child,
    parse_cgroup_identity,
    parse_dns_question_name,
    sanitize_ebpf_argv,
)
from demo.security_monitor.app.governance.discovery.models import DiscoveredAgent


def craft_dns_query(domain: str) -> bytes:
    """Builds a raw DNS query packet for domain."""
    # 12-byte DNS header: ID=0x1234, Flags=0x0100 (standard query), QDCOUNT=1, others=0
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    labels = b""
    for part in domain.split("."):
        encoded = part.encode("ascii")
        labels += bytes([len(encoded)]) + encoded
    labels += b"\x00"
    # QTYPE=1 (A), QCLASS=1 (IN)
    footer = struct.pack("!HH", 1, 1)
    return header + labels + footer


class TestDNSQuestionParsing:
    """Tests for parse_dns_question_name."""

    def test_parse_valid_dns_queries(self) -> None:
        for dom in ["api.openai.com", "generativelanguage.googleapis.com", "api.anthropic.com", "local-test_domain.internal"]:
            pkt = craft_dns_query(dom)
            parsed = parse_dns_question_name(pkt)
            assert parsed == dom.lower()

    def test_parse_empty_or_truncated(self) -> None:
        assert parse_dns_question_name(b"") is None
        assert parse_dns_question_name(b"short") is None
        assert parse_dns_question_name(b"\x00" * 12) is None  # qdcount=0

    def test_parse_malformed_packets(self) -> None:
        # Header specifies qdcount=1, but payload ends abruptly
        hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        assert parse_dns_question_name(hdr) is None

        # Label length points beyond packet length
        bad_len = hdr + b"\x20openai\x03com\x00"
        assert parse_dns_question_name(bad_len) is None

        # Label length exceeds 63
        oversized = hdr + bytes([64]) + (b"a" * 64) + b"\x00"
        assert parse_dns_question_name(oversized) is None

        # Invalid characters in DNS label (e.g. spaces, control chars, nulls)
        invalid_char = hdr + b"\x03a b\x03com\x00"
        assert parse_dns_question_name(invalid_char) is None

    def test_compression_loop_safeguard(self) -> None:
        # Compression pointer that points to itself or loops
        hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        # Offset 12 has pointer 0xC00C (points to offset 12)
        loop_pkt = hdr + b"\xc0\x0c"
        assert parse_dns_question_name(loop_pkt) is None

        # Pointer pointing beyond packet boundary
        oob_ptr = hdr + b"\xc0\xff"
        assert parse_dns_question_name(oob_ptr) is None


class TestUnitAndCgroupGrouping:
    """Tests for parse_cgroup_identity and unit/container grouping."""

    def test_parse_systemd_unit(self) -> None:
        cg = "/user.slice/user-1000.slice/user@1000.service/app.slice/agent-worker.service"
        key, name, unit = parse_cgroup_identity(cg, unit="agent-worker.service")
        assert key == "unit:agent-worker.service"
        assert name == "Systemd Unit agent-worker.service"
        assert unit == "agent-worker.service"

    def test_parse_container_id(self) -> None:
        cont_hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        key, name, unit = parse_cgroup_identity("", container_id=cont_hex)
        assert key == "container:abcdef012345"
        assert name == "Container abcdef012345"
        assert unit is None

    def test_parse_container_from_cgroup_path(self) -> None:
        cont_hex = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
        cg = f"/docker/{cont_hex}"
        key, name, unit = parse_cgroup_identity(cg)
        assert key == "container:112233445566"
        assert name == "Container 112233445566"

    def test_grouping_merges_multiple_signals_into_one_agent(self) -> None:
        proc = EBPFDiscoveryProcessor(host_name="test-host")

        # Event 1: Execve of claude in unit my-agent.service
        ev1 = {
            "mode": "discovery",
            "op": "exec",
            "target": "/usr/local/bin/claude",
            "argv": ["claude", "--model", "claude-3-opus"],
            "pid": 5001,
            "ppid": 100,
            "cgroup_path": "/user.slice/my-agent.service",
            "unit": "my-agent.service",
        }
        a1 = proc.process_event(ev1)
        assert a1 is not None
        assert a1.name == "claude"
        assert a1.kind == "coding_agent"
        assert len(a1.evidence) == 1
        assert a1.evidence[0].signal == "ebpf_exec_agent"

        # Event 2: DNS lookup for api.anthropic.com in same unit
        ev2 = {
            "mode": "discovery",
            "op": "send",
            "dns_question": "api.anthropic.com",
            "pid": 5001,
            "ppid": 100,
            "cgroup_path": "/user.slice/my-agent.service",
            "unit": "my-agent.service",
        }
        a2 = proc.process_event(ev2)
        assert a2 is not None
        # Must be merged into the same DiscoveredAgent
        assert a2.discovery_id == a1.discovery_id
        assert len(a2.evidence) == 2
        signals = {e.signal for e in a2.evidence}
        assert signals == {"ebpf_exec_agent", "ebpf_llm_dns"}


class TestMCPChildDetection:
    """Tests for match_mcp_child."""

    def test_npx_modelcontextprotocol(self) -> None:
        argv = ["npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/db"]
        matched, detail = match_mcp_child("exec", "/usr/bin/npx", argv)
        assert matched is True
        assert "@modelcontextprotocol" in detail

    def test_uvx_mcp_server(self) -> None:
        argv = ["uvx", "mcp-server-git", "--repository", "/tmp/repo"]
        matched, detail = match_mcp_child("exec", "/usr/bin/uvx", argv)
        assert matched is True
        assert "mcp-server-git" in detail

    def test_standalone_mcp_binary(self) -> None:
        matched, detail = match_mcp_child("exec", "/opt/tools/mcp-server-filesystem", [])
        assert matched is True
        assert "mcp-server-filesystem" in detail

    def test_child_of_agent_process(self) -> None:
        # Child process of an agent running a custom mcp script
        argv = ["python", "custom_mcp_bridge.py"]
        matched, detail = match_mcp_child("exec", "/usr/bin/python", argv, is_child_of_agent=True)
        assert matched is True
        assert "custom_mcp_bridge.py" in detail

    def test_normal_command_not_mcp(self) -> None:
        matched, _ = match_mcp_child("exec", "/bin/ls", ["ls", "-la"])
        assert matched is False


class TestRateLimitTracking:
    """Tests for rate limiting tracking."""

    def test_rate_limit_counter_updates(self) -> None:
        proc = EBPFDiscoveryProcessor()
        assert proc.get_rate_limited_count() == 0

        proc.process_event({"op": "send", "rate_limited": 42})
        assert proc.get_rate_limited_count() == 42

        # Monotonic update
        proc.process_event({"op": "send", "rate_limited": 85})
        assert proc.get_rate_limited_count() == 85

        # Does not decrease
        proc.process_event({"op": "send", "rate_limited": 20})
        assert proc.get_rate_limited_count() == 85


class TestPlantedSecretRedaction:
    """Tests ensuring secrets in command lines are redacted."""

    def test_secret_in_argv_is_redacted(self) -> None:
        argv = [
            "python3",
            "agent_launcher.py",
            "--api-key",
            "sk-proj-supersecretkey1234567890abcdef",
            "--auth-token=secrettoken998877",
            "--workspace",
            "/tmp/work",
        ]
        sanitized = sanitize_ebpf_argv(argv)

        # Neither raw secret must appear
        assert "sk-proj-supersecretkey1234567890abcdef" not in sanitized
        assert "secrettoken998877" not in sanitized
        assert "[REDACTED" in sanitized
        assert len(sanitized) <= 300

    def test_excessively_long_argv_is_capped_at_300(self) -> None:
        argv = ["python3", "worker.py", "--param", "x" * 500]
        sanitized = sanitize_ebpf_argv(argv)
        assert len(sanitized) <= 300


class TestLiveEBPFDiscovery:
    """Live eBPF discovery tests. Skipped automatically if CAP_BPF / privileges are absent."""

    def test_live_short_lived_process_discovered_v2_missed_v1(self, tmp_path) -> None:
        from demo.security_monitor.app.governance.os_layer.ebpf_shadow import EBPF_SENSOR_BIN
        from demo.security_monitor.app.governance.discovery.host_scan import HostScanner
        import json
        import os
        import socket as py_socket
        import subprocess
        import time
        import uuid

        if not EBPF_SENSOR_BIN.exists():
            pytest.skip("ebpf_sensor binary not compiled")

        sock_path = tmp_path / f"ebpf_disc_{uuid.uuid4().hex[:6]}.sock"
        cmd = [str(EBPF_SENSOR_BIN), "--socket", str(sock_path), "--discovery"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        except OSError as e:
            pytest.skip(f"Cannot execute ebpf_sensor: {e}")

        try:
            for _ in range(20):
                if proc.poll() is not None:
                    _, err = proc.communicate()
                    pytest.skip(f"ebpf_sensor lacks required privileges: {err.strip()}")
                if sock_path.exists():
                    break
                time.sleep(0.05)

            if not sock_path.exists():
                proc.kill()
                pytest.skip("ebpf_sensor socket did not appear")

            # Connect client socket to receive events
            s = py_socket.socket(py_socket.AF_UNIX, py_socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(str(sock_path))
            sock_file = s.makefile("r", encoding="utf-8", errors="replace")

            # Create and run a short-lived process (<1s) named 'aider'
            script_path = tmp_path / "aider"
            script_path.write_text("#!/bin/sh\nexit 0\n")
            os.chmod(script_path, 0o755)

            # Run process: it exits almost instantly
            subprocess.run([str(script_path)], check=True)

            # 1. Check v1 host scan: process has exited, so /proc scan cannot see it
            v1_scanner = HostScanner(proc_root="/proc")
            v1_agents, _ = v1_scanner._scan_processes("default", "2026-01-01T00:00:00Z", {}, [])
            v1_names = [a.name.lower() for a in v1_agents]
            assert "aider" not in v1_names, "v1 scan should not detect exited short-lived process"

            # 2. Check v2 eBPF stream: captured exec event in ring buffer
            processor = EBPFDiscoveryProcessor(host_name="test-host")
            found_agent = None
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                line = sock_file.readline()
                if not line:
                    break
                try:
                    ev = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue
                if ev.get("mode") == "discovery" and "aider" in str(ev.get("target", "")):
                    found_agent = processor.process_event(ev)
                    break

            sock_file.close()
            s.close()

            assert found_agent is not None, "eBPF discovery v2 captured the short-lived process"
            assert found_agent.name == "aider"
            assert any(e.signal == "ebpf_exec_agent" for e in found_agent.evidence)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    proc.kill()

    def test_live_dns_query_openai_caught_v2(self, tmp_path) -> None:
        from demo.security_monitor.app.governance.os_layer.ebpf_shadow import EBPF_SENSOR_BIN
        import json
        import socket as py_socket
        import subprocess
        import time
        import uuid

        if not EBPF_SENSOR_BIN.exists():
            pytest.skip("ebpf_sensor binary not compiled")

        # Pick an arbitrary local test port for DNS
        target_port = 15353
        sock_path = tmp_path / f"ebpf_disc_dns_{uuid.uuid4().hex[:6]}.sock"
        cmd = [
            str(EBPF_SENSOR_BIN),
            "--socket", str(sock_path),
            "--discovery",
            "--dns-port", str(target_port),
        ]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        except OSError as e:
            pytest.skip(f"Cannot execute ebpf_sensor: {e}")

        try:
            for _ in range(20):
                if proc.poll() is not None:
                    _, err = proc.communicate()
                    pytest.skip(f"ebpf_sensor lacks required privileges: {err.strip()}")
                if sock_path.exists():
                    break
                time.sleep(0.05)

            if not sock_path.exists():
                proc.kill()
                pytest.skip("ebpf_sensor socket did not appear")

            s = py_socket.socket(py_socket.AF_UNIX, py_socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(str(sock_path))
            sock_file = s.makefile("r", encoding="utf-8", errors="replace")

            # Ensure client is fully registered in sensor before firing UDP packet
            s.sendall(b"PING\n")
            for _ in range(10):
                l = sock_file.readline()
                if "pong" in l:
                    break

            # Send crafted DNS packet to local UDP port
            dns_pkt = craft_dns_query("api.openai.com")
            udp_sender = py_socket.socket(py_socket.AF_INET, py_socket.SOCK_DGRAM)
            udp_sender.sendto(dns_pkt, ("127.0.0.1", target_port))
            udp_sender.close()

            processor = EBPFDiscoveryProcessor(host_name="test-host")
            found_dns_agent = None
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                line = sock_file.readline()
                if not line:
                    break
                try:
                    ev = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue
                if ev.get("mode") == "discovery" and ev.get("dns_question") == "api.openai.com":
                    found_dns_agent = processor.process_event(ev)
                    break

            sock_file.close()
            s.close()

            assert found_dns_agent is not None, "eBPF discovery caught DNS query for api.openai.com"
            assert any(e.signal == "ebpf_llm_dns" for e in found_dns_agent.evidence)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
