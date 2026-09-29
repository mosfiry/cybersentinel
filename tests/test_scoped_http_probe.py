from __future__ import annotations

import hashlib
import json
import socket
import ssl
import time
from pathlib import Path

import pytest

from owner_session_testutils import allow_owner_sessions
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.execution_boundary import OwnerDirectBoundary
from security.owner_policy import authenticate_owner, capture_policy_snapshot
from security.scope import ProgramAuthorization, TargetIdentity, make_snapshot
import security.scope_store as scope_store
from security.scope_store import init_scope_store, save_snapshot
import tools.scoped_http_probe as probe
from tools.registry import execute, get_tool, tool_definitions


PUBLIC_IP = "93.184.216.34"


class FakeSocket:
    def __init__(self, response: bytes = b"", *, timeout_after_response: bool = False, connect_timeout: bool = False):
        self.response = bytearray(response)
        self.timeout_after_response = timeout_after_response
        self.connect_timeout = connect_timeout
        self.connected_to = None
        self.sent = bytearray()
        self.closed = False
        self.timeouts: list[float] = []

    def settimeout(self, value: float):
        self.timeouts.append(value)

    def connect(self, address):
        if self.connect_timeout:
            raise socket.timeout()
        self.connected_to = address

    def sendall(self, data: bytes):
        self.sent.extend(data)

    def recv(self, size: int) -> bytes:
        if self.response:
            count = min(size, len(self.response))
            value = bytes(self.response[:count])
            del self.response[:count]
            return value
        if self.timeout_after_response:
            raise socket.timeout()
        return b""

    def close(self):
        self.closed = True


class FakeTLSContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True

    def __init__(self):
        self.server_names: list[str] = []

    def wrap_socket(self, sock, *, server_hostname):
        self.server_names.append(server_hostname)
        return sock


@pytest.fixture
def persisted_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    allow_owner_sessions(monkeypatch, "probe-owner")
    init_scope_store()
    authorization = ProgramAuthorization(
        program_id="probe-program",
        platform="test",
        scope_version="v1",
        retrieved_at="2026-09-21T00:00:00+00:00",
        in_scope_assets=({"host": "target.example.com", "schemes": ["https"], "ports": [443], "paths": ["/api"]},),
        out_of_scope_assets=({"host": "target.example.com", "paths": ["/admin"]},),
        allowed_methods=("GET",),
        prohibited_methods=("POST", "PUT", "PATCH", "DELETE"),
        rate_limits={"requests_per_minute": 2},
    )
    target = TargetIdentity(
        "probe-target", "probe-program", "target.example.com",
        allowed_ports=(443,), allowed_paths=("/api",), excluded_paths=("/api/private",),
    )
    return save_snapshot(make_snapshot("probe-snapshot", authorization, [target]), owner_session_token="probe-owner")


def scope_context(url: str = "https://target.example.com/api/v1") -> dict[str, str]:
    return {
        "program_id": "probe-program",
        "target_id": "probe-target",
        "scope_snapshot_id": "probe-snapshot",
        "url": url,
    }


def owner_context(snapshot, request_id: str = "probe-request") -> AuthorizationContext:
    evidence = authenticate_owner("probe-owner", request_id)
    return AuthorizationContext(
        request_id,
        evidence,
        capture_policy_snapshot(request_id, evidence),
        scope_snapshot=snapshot,
        session_id=evidence.session_id,
    )


def fake_dns(monkeypatch, addresses=(PUBLIC_IP,)):
    calls: list[tuple[str, int]] = []

    def getaddrinfo(host, port, *_args):
        calls.append((host, port))
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))
            for address in addresses
        ]

    monkeypatch.setattr(probe.socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(probe.ssl, "create_default_context", lambda: FakeTLSContext())
    return calls


def install_fake_socket(monkeypatch, response: bytes, *, timeout_after_response: bool = False, connect_timeout: bool = False):
    created: list[FakeSocket] = []

    def make_socket(*_args):
        result = FakeSocket(response, timeout_after_response=timeout_after_response, connect_timeout=connect_timeout)
        created.append(result)
        return result

    monkeypatch.setattr(probe.socket, "socket", make_socket)
    return created


def test_registry_exposes_only_the_bounded_scoped_get_contract():
    spec = get_tool("scoped_http_probe")
    assert spec is not None and spec.available
    assert spec.scope_required and spec.requires_owner
    assert spec.network_access == "scope_authorized_http_get"
    assert spec.credential_access == "none"
    assert spec.scope_requirements == ("persisted_scope_snapshot", "program_id", "target_id", "GET")
    definition = next(item for item in tool_definitions() if item["name"] == "scoped_http_probe")
    assert definition["parameters"]["additionalProperties"] is False
    assert definition["parameters"]["required"] == ["query"]


def test_exact_scope_context_rejects_missing_and_extra_fields():
    with pytest.raises(PermissionError, match="scope_context_missing_required_fields"):
        probe.validate_scope_context_fields({"program_id": "p"})
    with pytest.raises(PermissionError, match="scope_context_has_unexpected_fields"):
        probe.validate_scope_context_fields({**scope_context(), "method": "POST"})
    with pytest.raises(PermissionError, match="scope_context_fields_must_be_non_empty_strings"):
        probe.validate_scope_context_fields({**scope_context(), "target_id": ""})


def test_probe_rejects_out_of_scope_wrong_identity_exclusions_and_noncanonical_paths(persisted_scope, monkeypatch):
    calls = fake_dns(monkeypatch)
    ctx = scope_context()
    with pytest.raises(PermissionError):
        probe.scoped_http_probe("https://outside.example/api", scope_context=ctx)
    with pytest.raises(PermissionError):
        probe.scoped_http_probe("https://target.example.com/api/private", scope_context=ctx)
    with pytest.raises(PermissionError):
        probe.scoped_http_probe("https://target.example.com/api/%2e%2e/admin", scope_context=ctx)
    with pytest.raises(PermissionError):
        probe.scoped_http_probe("https://target.example.com:0/api", scope_context=ctx)
    with pytest.raises(PermissionError):
        probe.scoped_http_probe("https://target.example.com/api", scope_context={**ctx, "program_id": "other-program"})
    with pytest.raises(PermissionError):
        probe.scoped_http_probe("https://target.example.com/api", scope_context={**ctx, "target_id": "other-target"})
    with pytest.raises(PermissionError):
        probe.scoped_http_probe("https://target.example.com/api", scope_context={**ctx, "method": "POST"})
    assert calls == []
    from security.scope_resolver import resolve
    port_zero = resolve("probe-snapshot", "probe-target", "https://target.example.com:0/api", consume_rate=False)
    assert port_zero.allowed is False and port_zero.reason == "asset_not_in_scope"


def test_probe_requires_target_specific_get_authorization(tmp_path, monkeypatch):
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    allow_owner_sessions(monkeypatch, "probe-owner")
    init_scope_store()
    authorization = ProgramAuthorization(
        "head-only-program", "test", "v1", "2026-09-21T00:00:00+00:00",
        ({"host": "target.example.com", "schemes": ["https"], "ports": [443], "paths": ["/api"]},),
        allowed_methods=("HEAD",), prohibited_methods=("POST",),
    )
    target = TargetIdentity("head-only-target", "head-only-program", "target.example.com", allowed_ports=(443,), allowed_paths=("/api",))
    save_snapshot(make_snapshot("head-only-snapshot", authorization, [target]), owner_session_token="probe-owner")
    ctx = {"program_id": "head-only-program", "target_id": "head-only-target", "scope_snapshot_id": "head-only-snapshot", "url": "https://target.example.com/api"}
    with pytest.raises(PermissionError, match="scope denied"):
        probe.scoped_http_probe("https://target.example.com/api", scope_context=ctx)


def test_dns_rejects_private_and_mixed_answer_sets(monkeypatch):
    for answer_set in (("127.0.0.1",), (PUBLIC_IP, "10.0.0.7")):
        def getaddrinfo(host, port, *_args, _answers=answer_set):
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (item, port)) for item in _answers]
        monkeypatch.setattr(probe.socket, "getaddrinfo", getaddrinfo)
        with pytest.raises(probe._ProbeFailure, match="dns_non_public_address"):
            probe._resolve_public_addresses("target.example.com", 443, time.monotonic() + 2)


def test_mocked_dns_is_resolved_once_and_socket_is_pinned_to_that_ip(persisted_scope, monkeypatch):
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nhello world"
    lookups = fake_dns(monkeypatch)
    sockets = install_fake_socket(monkeypatch, response)

    result = probe.scoped_http_probe("https://target.example.com/api/v1?x=1", scope_context=scope_context())

    assert result["success"] is True
    assert result["observation_only"] is True
    assert result["status"] == 200
    assert result["content_type"] == "text/plain"
    assert result["byte_count"] == 11
    assert result["sha256"] == hashlib.sha256(b"hello world").hexdigest()
    assert "hello world" not in json.dumps(result)
    assert lookups == [("target.example.com", 443)]
    assert sockets[0].connected_to == (PUBLIC_IP, 443)
    request = bytes(sockets[0].sent).decode("ascii")
    assert request.startswith("GET /api/v1?x=1 HTTP/1.1\r\n")
    assert "Host: target.example.com\r\n" in request
    assert "Authorization:" not in request and "Cookie:" not in request
    assert sockets[0].closed


def test_https_preserves_hostname_for_verified_tls_sni(persisted_scope, monkeypatch):
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    fake_dns(monkeypatch)
    sockets = install_fake_socket(monkeypatch, response)
    tls = FakeTLSContext()
    monkeypatch.setattr(probe.ssl, "create_default_context", lambda: tls)

    result = probe.scoped_http_probe("https://target.example.com/api", scope_context=scope_context())

    assert result["success"] is True
    assert tls.server_names == ["target.example.com"]
    assert tls.verify_mode == ssl.CERT_REQUIRED and tls.check_hostname is True
    assert sockets[0].connected_to == (PUBLIC_IP, 443)


def test_expired_total_deadline_fails_before_dns_or_socket(persisted_scope, monkeypatch):
    lookups = fake_dns(monkeypatch)
    sockets = install_fake_socket(monkeypatch, b"HTTP/1.1 200 OK\r\n\r\n")
    monkeypatch.setattr(probe, "TOTAL_TIMEOUT_SECONDS", -1.0)

    result = probe.scoped_http_probe("https://target.example.com/api", scope_context=scope_context())

    assert result["success"] is False
    assert result["error_code"] == "total_timeout"
    assert lookups == [] and sockets == []


def test_connect_timeout_sends_no_request_bytes(persisted_scope, monkeypatch):
    fake_dns(monkeypatch)
    sockets = install_fake_socket(monkeypatch, b"", connect_timeout=True)

    result = probe.scoped_http_probe("https://target.example.com/api", scope_context=scope_context())

    assert result["success"] is False
    assert result["error_code"] == "connect_timeout"
    assert sockets[0].sent == b""
    assert sockets[0].closed


def test_redirect_is_reported_as_blocked_without_following_location(persisted_scope, monkeypatch):
    response = (
        b"HTTP/1.1 302 Found\r\nLocation: https://attacker.example/steal\r\n"
        b"Content-Type: text/html\r\nContent-Length: 0\r\n\r\n"
    )
    fake_dns(monkeypatch)
    sockets = install_fake_socket(monkeypatch, response)

    result = probe.scoped_http_probe("https://target.example.com/api", scope_context=scope_context())

    assert result["success"] is False
    assert result["outcome"] == "redirect_blocked"
    assert result["status"] == 302
    assert result["byte_count"] == 0
    assert "attacker.example" not in json.dumps(result)
    assert len(sockets) == 1
    assert bytes(sockets[0].sent).startswith(b"GET ")


def test_interim_http_response_is_not_reported_as_a_success(persisted_scope, monkeypatch):
    fake_dns(monkeypatch)
    sockets = install_fake_socket(monkeypatch, b"HTTP/1.1 100 Continue\r\n\r\n")

    result = probe.scoped_http_probe("https://target.example.com/api", scope_context=scope_context())

    assert result["success"] is False
    assert result["error_code"] == "interim_response_not_supported"
    assert bytes(sockets[0].sent).startswith(b"GET ")


def test_body_and_header_limits_and_slow_read_fail_closed(persisted_scope, monkeypatch):
    body = b"x" * (probe.MAX_RESPONSE_BODY_BYTES + 16)
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: " + b"a" * 20000 + b"\r\nContent-Length: "
        + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
    )
    fake_dns(monkeypatch)
    install_fake_socket(monkeypatch, response)
    monkeypatch.setattr(probe, "MAX_RESPONSE_HEADER_BYTES", 128)

    result = probe.scoped_http_probe("https://target.example.com/api", scope_context=scope_context())
    assert result["success"] is False
    assert result["error_code"] == "response_headers_too_large"

    monkeypatch.setattr(probe, "MAX_RESPONSE_HEADER_BYTES", 16 * 1024)
    timeout_socket = install_fake_socket(
        monkeypatch,
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n",
        timeout_after_response=True,
    )
    result = probe.scoped_http_probe("https://target.example.com/api", scope_context=scope_context())
    assert result["success"] is False
    assert result["error_code"] == "read_timeout"
    assert timeout_socket[0].closed


def test_oversized_response_is_truncated_and_hash_is_only_of_capped_bytes(persisted_scope, monkeypatch):
    body = b"z" * (probe.MAX_RESPONSE_BODY_BYTES + 1)
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
    )
    fake_dns(monkeypatch)
    install_fake_socket(monkeypatch, response)

    result = probe.scoped_http_probe("https://target.example.com/api", scope_context=scope_context())

    assert result["success"] is True
    assert result["truncated"] is True
    assert result["byte_count"] == probe.MAX_RESPONSE_BODY_BYTES
    assert result["sha256"] == hashlib.sha256(body[:probe.MAX_RESPONSE_BODY_BYTES]).hexdigest()


def test_output_metadata_limit_falls_back_to_a_small_safe_result(monkeypatch):
    monkeypatch.setattr(probe, "MAX_OUTPUT_CHARS", 200)
    result = probe._bounded_result(
        success=True,
        outcome="response_received",
        status=200,
        content_type="x" * 128,
        body=b"x" * probe.MAX_RESPONSE_BODY_BYTES,
    )
    encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
    assert len(encoded) <= 200
    assert result["outcome"] == "output_limit"
    assert "sha256" not in result


def test_registry_requires_owner_authorization_proof_and_snapshot_binding(persisted_scope, monkeypatch):
    context = owner_context(persisted_scope)
    scoped = scope_context()
    url = "https://target.example.com/api"
    decision = authorize_tool(["scoped_http_probe", url], context=context)
    assert decision.allowed
    call_id = "probe-call-no-proof"

    with pytest.raises(PermissionError, match="PROOF_REQUIRED"):
        execute(
            "scoped_http_probe", url,
            authorization_decision=decision.decision,
            scope_context=scoped,
            request_id=context.request_id,
            tool_call_id=call_id,
        )

    proof = OwnerDirectBoundary.derive(
        tool="scoped_http_probe", argument=url, decision=decision.decision,
        request_id=context.request_id, tool_call_id="probe-call-no-owner",
        scope_context=scoped,
    )
    with pytest.raises(PermissionError, match="Owner AuthorizationDecision required"):
        execute(
            "scoped_http_probe", url,
            execution_proof=proof,
            request_id=context.request_id,
            tool_call_id="probe-call-no-owner",
            scope_context=scoped,
        )


def test_registry_charges_one_scope_rate_event_and_handler_revalidation_is_non_consuming(persisted_scope, monkeypatch):
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    fake_dns(monkeypatch)
    install_fake_socket(monkeypatch, response)
    context = owner_context(persisted_scope)
    scoped = scope_context()
    url = "https://target.example.com/api"
    decision = authorize_tool(["scoped_http_probe", url], context=context)
    assert decision.allowed

    result = OwnerDirectBoundary.execute(
        tool="scoped_http_probe", argument=url, decision=decision.decision,
        request_id=context.request_id, tool_call_id="probe-call-rate",
        scope_context=scoped, execute=execute,
    )

    assert result["success"] is True
    from security.scope_resolver import resolve
    from security.scope_store import count_rate_events
    assert resolve("probe-snapshot", "probe-target", "https://target.example.com/api/a", consume_rate=False).allowed
    assert count_rate_events("probe-program:probe-target", time.time() - 60) == 1


def test_probe_output_cannot_mint_signed_criterion_evidence():
    from agent.mission_runtime import MissionRuntime

    class Store:
        def __init__(self):
            self.calls = []

        def issue_criterion_evidence(self, *args):
            self.calls.append(args)
            return {"system_evidence": {"provenance_token": "should-not-exist"}}

    store = Store()
    runtime = object.__new__(MissionRuntime)
    runtime.store = store
    class MissionStub:
        completion_criteria = [{"criterion_id": "mission-goal"}]
        action_history = [{"action_id": "http-action", "observation": {"source": "scoped_http_probe", "success": True, "status": 200}}]

    runtime._record_verified_criterion_evidence(MissionStub(), "http-action")
    assert store.calls == []
