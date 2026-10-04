from __future__ import annotations

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

import bridge
from security.public_session import PublicSessionManager


OWNER_TOKEN = "a" * 43


@pytest.fixture
def manager():
    return PublicSessionManager(ttl_seconds=60)


def _owner_record(_token: str):
    return {
        "session_id": "0" * 64,
        "owner_id": 7,
        "username": "release-owner",
        "auth_method": "username_password",
        "expires_at": "2099-01-01T00:00:00+00:00",
    }


@pytest.fixture
def public_server(monkeypatch):
    monkeypatch.setattr(bridge, "PUBLIC_WEB_ENABLED", True)
    monkeypatch.setattr(bridge, "PUBLIC_WEB_ORIGIN", "")
    monkeypatch.setattr(bridge, "PUBLIC_SESSIONS", PublicSessionManager(ttl_seconds=60))
    monkeypatch.setattr(bridge.owner_password, "resolve_session", _owner_record)
    monkeypatch.setattr(
        bridge,
        "owner_password_login",
        lambda username, password: {
            "session_id": OWNER_TOKEN,
            "owner_id": 7,
            "username": username or "release-owner",
            "expires_at": "2099-01-01T00:00:00+00:00",
        },
    )
    monkeypatch.setattr(bridge, "owner_password_logout", lambda token: True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(server, method, path, *, body=None, headers=None):
    connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    encoded = None if body is None else json.dumps(body).encode("utf-8")
    request_headers = dict(headers or {})
    if encoded is not None:
        request_headers.setdefault("Content-Type", "application/json")
    connection.request(method, path, body=encoded, headers=request_headers)
    response = connection.getresponse()
    result = response.status, json.loads(response.read() or b"{}"), response.headers
    connection.close()
    return result


def _public_session(server):
    status, payload, headers = _request(server, "POST", "/api/public/session")
    assert status == 201
    session_cookie = headers.get("Set-Cookie")
    assert session_cookie
    cookie = session_cookie.split(";", 1)[0]
    return cookie, payload["session"]["csrf_token"], session_cookie


def _owner_session(server):
    public_cookie, csrf, public_set_cookie = _public_session(server)
    assert "HttpOnly" in public_set_cookie
    assert "Secure" in public_set_cookie
    assert "Path=/api/public" in public_set_cookie
    status, payload, headers = _request(
        server,
        "POST",
        "/api/public/auth/login",
        body={"username": "release-owner", "password": "not-captured"},
        headers={"Cookie": public_cookie, "X-CSRF-Token": csrf},
    )
    assert status == 200
    assert payload["authenticated"] is True
    owner_set_cookie = headers.get("Set-Cookie")
    assert owner_set_cookie and "HttpOnly" in owner_set_cookie and "Secure" in owner_set_cookie
    assert "Path=/api/public" in owner_set_cookie
    assert OWNER_TOKEN not in json.dumps(payload)
    cookie = f"{public_cookie}; {owner_set_cookie.split(';', 1)[0]}"
    return cookie, csrf


def test_public_session_does_not_grant_owner_authority(manager):
    session = manager.create()
    assert session.public().keys() == {"csrf_token", "created_at", "expires_at"}
    assert "owner" not in session.public()
    assert manager.validate(session.session_id, session.csrf_token) == session


def test_public_session_rejects_missing_or_invalid_csrf(manager):
    session = manager.create()
    with pytest.raises(PermissionError, match="csrf"):
        manager.validate(session.session_id, "wrong")
    with pytest.raises(PermissionError, match="session"):
        manager.validate("missing", session.csrf_token)


def test_public_session_can_be_revoked(manager):
    session = manager.create()
    manager.revoke(session.session_id)
    with pytest.raises(PermissionError, match="session"):
        manager.validate(session.session_id, session.csrf_token)


def test_frontend_contains_no_browser_secret_prompt_or_storage():
    source = Path("web/app.js").read_text(encoding="utf-8")
    forbidden = (
        "BRIDGE_TOKEN",
        "OWNER_TOKEN",
        "cs_bridge_token",
        "cs_owner_token",
        "sessionStorage",
        "localStorage",
        "prompt(",
        "X-CyberSentinel-Token",
        "X-CyberSentinel-Owner-Token",
    )
    for value in forbidden:
        assert value not in source
    assert 'credentials: "include"' in source
    assert "X-CSRF-Token" in source
    assert "evidence_reference" in source
    assert "OWNER_CONFIRM_APPLIED" in source


def test_http_public_boundary_sets_cookie_and_requires_owner_and_csrf(public_server):
    public_cookie, csrf, public_set_cookie = _public_session(public_server)
    assert "HttpOnly" in public_set_cookie
    assert "Secure" in public_set_cookie
    assert "Path=/api/public" in public_set_cookie

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/chat",
        body={"text": "Owner"},
        headers={"Cookie": public_cookie, "X-CSRF-Token": csrf},
    )
    assert status == 403
    assert payload["error"] == "owner_authorization_required"

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/chat",
        body={"text": "hello"},
        headers={"Cookie": public_cookie},
    )
    assert status == 401
    assert payload["error"]


def test_owner_cookie_is_http_only_and_auth_session_is_server_managed(public_server):
    cookie, csrf = _owner_session(public_server)
    status, payload, _headers = _request(
        public_server,
        "GET",
        "/api/public/auth/session",
        headers={"Cookie": cookie},
    )
    assert status == 200
    assert payload["authenticated"] is True
    assert payload["username"] == "release-owner"
    assert "session_id" not in payload
    assert OWNER_TOKEN not in json.dumps(payload)
    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/auth/logout",
        body={},
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 200
    assert payload["authenticated"] is False


def test_mission_list_is_owner_scoped_and_summary_is_minimized(public_server, monkeypatch):
    cookie, _csrf = _owner_session(public_server)

    class FakeService:
        def list_missions(self, *, owner_session_token, limit):
            assert owner_session_token == OWNER_TOKEN
            assert limit == 5
            return [{
                "mission_id": "mission-123",
                "objective": "Inspect the repository",
                "status": "QUEUED",
                "request_id": "request-1",
                "owner_identity_ref": "owner:7",
                "authorization_snapshot": {"private": "not-for-list"},
            }]

    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda self: FakeService())
    status, payload, _headers = _request(
        public_server,
        "GET",
        "/api/public/missions?limit=5",
        headers={"Cookie": cookie},
    )
    assert status == 200
    assert payload["missions"][0]["mission_id"] == "mission-123"
    assert "owner_identity_ref" not in payload["missions"][0]
    assert "authorization_snapshot" not in payload["missions"][0]


def test_public_mission_create_uses_server_scope_and_queues_owner_mission(public_server, monkeypatch):
    cookie, csrf = _owner_session(public_server)
    captured = {}

    class FakeCore:
        def __init__(self, router, *, db_path):
            captured["db_path"] = db_path

        def run_owner_mission(self, objective, **kwargs):
            captured["objective"] = objective
            captured.update(kwargs)
            return SimpleNamespace(mission_id="mission-abc")

    class FakeService:
        def start_mission(self, mission_id, *, owner_session_token):
            captured["started"] = (mission_id, owner_session_token)
            return {"mission_id": mission_id}

        def status(self, mission_id, *, owner_session_token):
            return {
                "mission_id": mission_id,
                "objective": captured["objective"],
                "status": "QUEUED",
                "queue": {"state": "QUEUED"},
                "authorization_snapshot": {"never": "returned"},
            }

    monkeypatch.setattr(bridge, "AgentCore", FakeCore)
    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda self: FakeService())
    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/missions",
        body={"objective": "Review the service", "scope_context": {"workspace_root": "/", "allowed_networks": ["*"]}},
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 201
    assert payload["mission_id"] == "mission-abc"
    assert captured["started"] == ("mission-abc", OWNER_TOKEN)
    assert captured["run"] is False
    assert captured["scope_context"]["workspace_root"] == str(bridge.ROOT.resolve())
    assert captured["scope_context"]["allowed_networks"] == []
    assert "authorization_snapshot" not in payload["mission"]


def test_public_mission_read_rejects_legacy_unbound_mission(public_server, monkeypatch):
    cookie, _csrf = _owner_session(public_server)

    class FakeService:
        def _authorized_mission(self, mission_id, owner_session_token, *, allow_unbound_read):
            assert allow_unbound_read is False
            raise PermissionError("mission access denied")

    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda self: FakeService())
    status, payload, _headers = _request(
        public_server,
        "GET",
        "/api/public/missions/legacy-1/status",
        headers={"Cookie": cookie},
    )
    assert status == 403
    assert payload["error"] == "mission access denied"


def test_public_effect_reconciliation_requires_exact_effect_and_reference(public_server, monkeypatch):
    cookie, csrf = _owner_session(public_server)
    captured = {}

    class FakeService:
        def reconcile_effect(self, mission_id, effect_id, **kwargs):
            captured["call"] = (mission_id, effect_id, kwargs)
            return {"status": "OWNER_CONFIRMED_APPLIED", "dispatch_authorized": False}

    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda self: FakeService())
    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/missions/mission-1/effects/effect-1/reconcile",
        body={"outcome": "OWNER_CONFIRM_APPLIED", "evidence_reference": "external-record:123"},
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 200
    assert captured["call"][0:2] == ("mission-1", "effect-1")
    assert captured["call"][2]["evidence_reference"] == "external-record:123"
    assert payload["reconciliation"]["dispatch_authorized"] is False

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/missions/mission-1/reconcile",
        body={"executed": True},
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 400
    assert payload["error"] == "effect_id_and_evidence_reference_required"


def test_public_provider_summary_requires_owner_session(public_server):
    public_cookie, _csrf, _set_cookie = _public_session(public_server)
    status, payload, _headers = _request(
        public_server,
        "GET",
        "/api/public/providers",
        headers={"Cookie": public_cookie},
    )
    assert status == 403
    assert payload["error"] == "owner_authorization_required"


def test_public_provider_summary_is_sanitized_and_bounded(public_server, monkeypatch):
    cookie, _csrf = _owner_session(public_server)
    provider = SimpleNamespace(
        name="local",
        model="private-model-id",
        base_url="https://provider.invalid/private-path?secret=value",
        api_key="provider-api-key-secret",
        last_error="exception with sensitive details",
        failure_count=3,
        capabilities=SimpleNamespace(chat=True, stream=False, vision=True),
    )
    unexpected = SimpleNamespace(
        name="untrusted-provider-name-with-secret",
        model="secret-model",
        base_url="https://another.invalid/",
        failure_count=10**100,
        capabilities=None,
    )
    monkeypatch.setattr(
        bridge,
        "RUNTIME",
        SimpleNamespace(router=SimpleNamespace(providers=[provider, unexpected])),
    )

    status, payload, _headers = _request(
        public_server,
        "GET",
        "/api/public/providers",
        headers={"Cookie": cookie},
    )
    assert status == 200
    assert payload["providers"][0]["name"] == "local"
    assert payload["providers"][0]["configured"] is True
    assert payload["providers"][0]["failure_count"] == 3
    assert payload["providers"][0]["capabilities"]["chat"] is True
    assert payload["providers"][0]["capabilities"]["stream"] is False
    assert payload["providers"][1]["name"] == "configured_provider"
    assert payload["providers"][1]["failure_count"] == 1_000_000
    serialized = json.dumps(payload)
    for secret in (
        provider.model,
        provider.base_url,
        provider.api_key,
        provider.last_error,
        unexpected.name,
        unexpected.model,
        unexpected.base_url,
    ):
        assert secret not in serialized
    for forbidden_key in ("model", "base_url", "api_key", "last_error"):
        assert f'"{forbidden_key}"' not in serialized


@pytest.mark.parametrize(
    ("remote", "expected"),
    (
        (
            "https://user:password@host.example/repo?access_token=abc&api_key=def&branch=main",
            "https://[REDACTED]@host.example/repo?access_token=[REDACTED]&api_key=[REDACTED]&branch=main",
        ),
        ("ssh://user:password@host.example/repo", "ssh://[REDACTED]@host.example/repo"),
    ),
)
def test_git_remote_redaction_covers_userinfo_and_secret_query_parameters(remote, expected):
    assert bridge._redact_git_remote(remote) == expected
