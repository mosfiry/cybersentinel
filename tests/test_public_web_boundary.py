from __future__ import annotations

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from http.cookies import SimpleCookie
from datetime import datetime, timedelta, timezone
import json
import sqlite3
from pathlib import Path
import threading

import pytest

import bridge
import core.db as core_db
from security import owner_password
from security.public_session import PublicSessionManager
import security.scope_store as scope_store

TEST_PASSWORD = "browser-owner-test-password-2026"


@pytest.fixture
def manager():
    return PublicSessionManager(ttl_seconds=60)


@pytest.fixture
def web_server(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, "PUBLIC_WEB_ENABLED", True)
    monkeypatch.setattr(bridge, "PUBLIC_WEB_ORIGIN", "")
    monkeypatch.setattr(bridge, "DEFAULT_PUBLIC_SESSIONS", PublicSessionManager(ttl_seconds=60))
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "browser-owner-auth.db")
    core_db.connect().close()
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", tmp_path / "scope-snapshots.sqlite3")
    scope_store.init_scope_store()
    owner_password.create_owner_account(owner_password.OWNER_USERNAME, TEST_PASSWORD)

    calls = []

    def fake_chat(payload, *, owner_session_token):
        calls.append((payload, owner_session_token))
        return {
            "conversation_id": payload.get("conversation_id") or "conversation-1",
            "answer": "Observed response",
            "activity": [],
        }

    monkeypatch.setattr(bridge, "chat", fake_chat)
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(server, method, path, payload=None, *, cookies="", csrf="", origin=None, owner_session_header="", raw_body=None):
    connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    headers = {"Content-Type": "application/json"} if payload is not None or raw_body is not None else {}
    if cookies:
        headers["Cookie"] = cookies
    if csrf:
        headers["X-CSRF-Token"] = csrf
    if origin is not None:
        headers["Origin"] = origin
    if owner_session_header:
        headers["X-CyberSentinel-Owner-Session"] = owner_session_header
    body = raw_body if raw_body is not None else json.dumps(payload) if payload is not None else None
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    result = response.read()
    status = response.status
    response_headers = dict(response.getheaders())
    connection.close()
    return status, response_headers, json.loads(result) if result else {}


def cookie_value(header, name):
    parsed = SimpleCookie()
    parsed.load(header)
    return parsed[name].value if name in parsed else ""


def create_public_session(server):
    status, headers, payload = request(server, "POST", "/api/public/session")
    assert status == 201
    return headers["Set-Cookie"].split(";", 1)[0], payload["session"]["csrf_token"]


def login(server, public_cookie, csrf, *, password=TEST_PASSWORD, owner_cookie=""):
    cookies = public_cookie
    if owner_cookie:
        cookies += f"; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}"
    return request(
        server,
        "POST",
        "/api/public/auth/login",
        {"username": owner_password.OWNER_USERNAME, "password": password},
        cookies=cookies,
        csrf=csrf,
    )


def manual_scope_payload(*, expires_at=None):
    return {
        "program_id": "manual-program-1",
        "platform": "owner-submitted",
        "scope_version": "2026-09-30-v1",
        "in_scope_assets": [
            {"host": "api.example.test", "schemes": ["https"], "ports": [443], "paths": ["/api"]},
        ],
        "out_of_scope_assets": [
            {"host": "admin.example.test", "paths": ["/private"]},
        ],
        "targets": [
            {
                "target_id": "api-prod",
                "host": "api.example.test",
                "asset_type": "web",
                "environment": "production",
                "allowed_ports": [443],
                "allowed_paths": ["/api"],
                "excluded_paths": ["/api/private"],
            },
        ],
        "allowed_methods": ["GET", "HEAD"],
        "prohibited_methods": ["POST", "PUT", "PATCH", "DELETE"],
        "rate_limits": {"requests_per_minute": 50},
        "expires_at": expires_at or (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }


def persisted_scope_count():
    with sqlite3.connect(str(scope_store.SCOPE_DB_PATH)) as connection:
        return int(connection.execute("SELECT COUNT(*) FROM scope_snapshots").fetchone()[0])


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


def test_frontend_exposes_login_but_never_bridge_secrets_or_owner_session_storage():
    script = Path("web/app.js").read_text(encoding="utf-8")
    page = Path("web/index.html").read_text(encoding="utf-8")
    forbidden = (
        "BRIDGE_TOKEN",
        "OWNER_TOKEN",
        "cs_bridge_token",
        "cs_owner_token",
        "prompt(",
        "X-CyberSentinel-Token",
        "X-CyberSentinel-Owner-Token",
    )
    for value in forbidden:
        assert value not in script
    assert 'type="password"' in page
    assert 'autocomplete="current-password"' in page
    assert "/api/public/auth/login" in script
    assert "/api/public/auth/session" in script
    assert "/api/public/auth/logout" in script
    assert "credentials: \"include\"" in script
    assert "X-CSRF-Token" in script
    assert "localStorage.setItem(CONVERSATION_STORAGE_KEY" in script
    assert "localStorage.getItem(CONVERSATION_STORAGE_KEY" in script
    assert "restoreConversation" in script
    assert "sessionStorage" not in script
    assert 'item.status || "completed"' not in script
    assert 'data.answer || "اكتمل التحليل."' not in script
    assert '"ONLINE"' not in script
    assert 'data-view="findings"' in page
    assert "system_evidence" in script
    assert 'placeholder="صف هدفك أو سؤالك أو خطوتك التالية…"' in page
    for fixed_action in ('data-p=', 'data-action="intel"', 'data-action="local"', 'id="intelBtn"', 'id="localBtn"'):
        assert fixed_action not in page
    assert "function direct(command, output)" not in script


def test_http_anonymous_public_boundary_remains_fail_closed(web_server):
    server, calls = web_server
    public_cookie, csrf = create_public_session(server)

    status, _, payload = request(
        server,
        "POST",
        "/api/public/chat",
        {"text": "Owner"},
        cookies=public_cookie,
        csrf=csrf,
    )
    assert status == 403
    assert payload["error"] == "owner_authorization_required"
    assert calls == []

    status, _, payload = request(
        server,
        "POST",
        "/api/public/chat",
        {"text": "hello"},
        cookies=public_cookie,
    )
    assert status == 401
    assert payload["error"] == "invalid csrf token"


def test_http_owner_login_session_and_chat_use_canonical_auth(web_server):
    server, calls = web_server
    public_cookie, csrf = create_public_session(server)

    status, headers, payload = login(server, public_cookie, csrf)
    assert status == 200
    assert payload["authenticated"] is True
    assert payload["username"] == owner_password.OWNER_USERNAME
    assert "session_id" not in json.dumps(payload)
    assert "password" not in json.dumps(payload)
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    assert owner_cookie
    assert "HttpOnly" in headers["Set-Cookie"]
    assert "Secure" in headers["Set-Cookie"]
    assert "SameSite=Lax" in headers["Set-Cookie"]
    assert "Path=/api/public" in headers["Set-Cookie"]

    owner_session = owner_password.resolve_session(owner_cookie)
    assert owner_session is not None
    combined_cookies = f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}"
    status, _, auth = request(
        server,
        "GET",
        "/api/public/auth/session",
        cookies=combined_cookies,
    )
    assert status == 200
    assert auth["authenticated"] is True
    assert auth["username"] == owner_password.OWNER_USERNAME
    assert "session_id" not in auth

    status, _, response = request(
        server,
        "POST",
        "/api/public/chat",
        {"text": "Check the system", "conversation_id": "browser-conversation"},
        cookies=combined_cookies,
        csrf=csrf,
    )
    assert status == 200
    assert response["answer"] == "Observed response"
    assert len(calls) == 1
    assert calls[0][0]["text"] == "Check the system"
    assert calls[0][1] == owner_session["session_id"]


def test_public_transcript_restore_is_durable_and_owner_scoped(web_server, monkeypatch):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)
    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    owner_session = owner_password.resolve_session(owner_cookie)
    assert owner_session is not None
    cookies = f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}"

    core_db.ensure_conversation("restore-conversation", str(owner_session["owner_id"]))
    core_db.add_conversation_message("restore-conversation", "user", "saved question", {"mission_id": "mission-1"}, owner_id=str(owner_session["owner_id"]))
    core_db.add_conversation_message("restore-conversation", "assistant", "saved answer", {"mission_id": "mission-1"}, owner_id=str(owner_session["owner_id"]))
    import api.chat as chat_api
    from types import SimpleNamespace

    foreign_task = SimpleNamespace(execution_state={"owner_identity": "different-owner", "events": []}, to_dict=lambda: {"task_id": "foreign-task"})
    owned_task = SimpleNamespace(execution_state={"owner_identity": str(owner_session["owner_id"]), "events": []}, to_dict=lambda: {"task_id": "owned-task"})
    monkeypatch.setattr(chat_api.TaskManager, "get_tasks_by_conversation", staticmethod(lambda _conversation_id: [foreign_task, owned_task]))
    status, _, payload = request(server, "GET", "/api/public/conversations/restore-conversation", cookies=cookies)
    assert status == 200
    conversation = payload["conversation"]
    assert conversation["conversation_id"] == "restore-conversation"
    assert [message["content"] for message in conversation["messages"]] == ["saved question", "saved answer"]
    assert [task["task_id"] for task in conversation["tasks"]] == ["owned-task"]
    assert "owner_id" not in conversation
    assert "owner_session_id" not in json.dumps(conversation)

    core_db.ensure_conversation("foreign-conversation", "different-owner")
    core_db.add_conversation_message("foreign-conversation", "assistant", "private", owner_id="different-owner")
    status, _, payload = request(server, "GET", "/api/public/conversations/foreign-conversation", cookies=cookies)
    assert status == 404
    assert payload["error"] == "unknown_conversation"

    status, _, payload = request(server, "GET", "/api/public/conversations/restore-conversation", cookies=public_cookie)
    assert status == 403
    assert payload["error"] == "owner_authorization_required"


def test_browser_login_returns_generic_failure_for_wrong_password(web_server):
    server, calls = web_server
    public_cookie, csrf = create_public_session(server)

    status, headers, payload = login(server, public_cookie, csrf, password="wrong-password")
    assert status == 403
    assert payload == {"ok": False, "error": "invalid_credentials"}
    assert "Set-Cookie" not in headers
    assert calls == []


def test_browser_login_rotates_and_revokes_the_previous_cookie_session(web_server):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)
    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    previous_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    previous_session = owner_password.resolve_session(previous_cookie)
    assert previous_session is not None

    status, headers, _ = login(server, public_cookie, csrf, owner_cookie=previous_cookie)
    assert status == 200
    current_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    assert current_cookie and current_cookie != previous_cookie
    assert owner_password.resolve_session(previous_cookie) is None
    assert owner_password.resolve_session(current_cookie) is not None


def test_browser_login_requires_csrf_and_rejects_foreign_origin(web_server):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)

    status, _, payload = request(
        server,
        "POST",
        "/api/public/auth/login",
        {"username": owner_password.OWNER_USERNAME, "password": TEST_PASSWORD},
        cookies=public_cookie,
    )
    assert status == 401
    assert payload["error"] == "invalid csrf token"

    status, _, payload = request(
        server,
        "POST",
        "/api/public/auth/login",
        {"username": owner_password.OWNER_USERNAME, "password": TEST_PASSWORD},
        cookies=public_cookie,
        csrf=csrf,
        origin="https://attacker.example",
    )
    assert status == 403
    assert payload["error"] == "origin_not_allowed"


def test_browser_logout_revokes_owner_session_and_expires_cookie(web_server):
    server, calls = web_server
    public_cookie, csrf = create_public_session(server)
    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    combined_cookies = f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}"
    assert owner_password.resolve_session(owner_cookie) is not None

    status, headers, payload = request(
        server,
        "POST",
        "/api/public/auth/logout",
        {},
        cookies=combined_cookies,
        csrf=csrf,
    )
    assert status == 200
    assert payload["authenticated"] is False
    assert cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE) == ""
    assert "Max-Age=0" in headers["Set-Cookie"]
    assert owner_password.resolve_session(owner_cookie) is None

    status, _, auth = request(
        server,
        "GET",
        "/api/public/auth/session",
        cookies=public_cookie,
    )
    assert status == 200
    assert auth["authenticated"] is False

    status, _, denied = request(
        server,
        "POST",
        "/api/public/chat",
        {"text": "No longer authorized"},
        cookies=public_cookie,
        csrf=csrf,
    )
    assert status == 403
    assert denied["error"] == "owner_authorization_required"
    assert calls == []


def test_browser_same_origin_is_accepted_when_no_origin_is_configured(web_server):
    server, _ = web_server
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    status, _, _ = request(server, "GET", "/api/public/health", origin=origin)
    assert status == 200


def test_bridge_serves_the_login_page_and_browser_assets(web_server):
    server, _ = web_server
    expected = {
        "/": b'<form id="loginForm">',
        "/app.js": b"/api/public/auth/login",
        "/style.css": b".auth-card",
    }
    for path, marker in expected.items():
        connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read()
        connection.close()
        assert response.status == 200
        assert marker in body


def test_public_model_catalog_requires_owner_and_returns_only_catalog_payload(web_server, monkeypatch):
    server, chat_calls = web_server
    called_with = []
    monkeypatch.setattr(
        bridge,
        "model_catalog",
        lambda owner_session_token: called_with.append(owner_session_token) or {"models": [{"id": "auto", "mode": "auto"}]},
    )

    status, _, denied = request(server, "GET", "/api/public/model-catalog")
    assert status == 401
    assert denied["error"] == "public session required"

    public_cookie, csrf = create_public_session(server)
    status, _, denied = request(server, "GET", "/api/public/model-catalog", cookies=public_cookie)
    assert status == 403
    assert denied["error"] == "owner_authorization_required"

    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    owner_session = owner_password.resolve_session(owner_cookie)
    assert owner_session is not None
    cookies = f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}"
    status, _, payload = request(server, "GET", "/api/public/model-catalog", cookies=cookies)

    assert status == 200
    assert payload == {"ok": True, "models": [{"id": "auto", "mode": "auto"}]}
    assert called_with == [owner_session["session_id"]]
    assert chat_calls == []


def test_manual_program_authorization_requires_owner_cookie_and_csrf_before_persistence(web_server):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)
    payload = manual_scope_payload()

    status, _, denied = request(
        server,
        "POST",
        "/api/public/program-authorizations",
        payload,
        owner_session_header="forged-owner-session",
    )
    assert status == 401
    assert denied["ok"] is False
    assert persisted_scope_count() == 0

    status, _, denied = request(
        server,
        "POST",
        "/api/public/program-authorizations",
        payload,
        cookies=public_cookie,
        csrf=csrf,
    )
    assert status == 403
    assert denied["error"] == "owner_authorization_required"
    assert persisted_scope_count() == 0

    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    cookies = f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}"
    status, _, denied = request(
        server,
        "POST",
        "/api/public/program-authorizations",
        payload,
        cookies=cookies,
        owner_session_header="forged-owner-session",
    )
    assert status == 401
    assert denied["error"] == "invalid csrf token"
    assert persisted_scope_count() == 0


def test_manual_program_authorization_round_trips_exact_scope_with_cookie_session_binding(web_server):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)
    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    owner_session = owner_password.resolve_session(owner_cookie)
    assert owner_session is not None
    payload = manual_scope_payload()

    status, _, response = request(
        server,
        "POST",
        "/api/public/program-authorizations",
        payload,
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )

    assert status == 201
    assert response["ok"] is True
    summary = response["snapshot"]
    assert set(summary) == {
        "snapshot_id",
        "program_id",
        "platform",
        "scope_version",
        "in_scope_asset_count",
        "out_of_scope_asset_count",
        "target_count",
        "allowed_methods",
        "prohibited_methods",
        "rate_limits",
        "created_at",
        "expires_at",
    }
    assert summary["program_id"] == payload["program_id"]
    assert summary["allowed_methods"] == payload["allowed_methods"]
    assert summary["prohibited_methods"] == payload["prohibited_methods"]
    assert summary["rate_limits"] == payload["rate_limits"]
    assert summary["expires_at"] == payload["expires_at"]
    assert summary["target_count"] == 1
    assert persisted_scope_count() == 1

    persisted = scope_store.get_snapshot(summary["snapshot_id"])
    assert persisted is not None
    authorization = persisted.authorization
    assert authorization.program_id == payload["program_id"]
    assert authorization.platform == payload["platform"]
    assert authorization.scope_version == payload["scope_version"]
    assert authorization.in_scope_assets == tuple(payload["in_scope_assets"])
    assert authorization.out_of_scope_assets == tuple(payload["out_of_scope_assets"])
    assert authorization.allowed_methods == tuple(payload["allowed_methods"])
    assert authorization.prohibited_methods == tuple(payload["prohibited_methods"])
    assert authorization.rate_limits == payload["rate_limits"]
    assert authorization.owner_session_id == owner_session["session_id"]
    expected_target = {**payload["targets"][0], "program_id": payload["program_id"]}
    assert persisted.targets[0].to_dict() == expected_target
    assert persisted.expires_at == payload["expires_at"]
    serialized = json.dumps(response)
    for private_value in ("session_id", "owner_session_id", "csrf_token", owner_cookie, csrf, owner_session["session_id"]):
        assert private_value not in serialized


@pytest.mark.parametrize(
    "invalid_case",
    [
        "unknown_top_level_field",
        "missing_required_methods",
        "unknown_asset_field",
        "invalid_port",
        "target_outside_allowlist",
        "method_overlap",
        "rate_limit_out_of_bounds",
        "boolean_rate_limit",
        "expired_snapshot",
        "expiration_too_far",
    ],
)
def test_manual_program_authorization_rejects_malformed_and_out_of_bounds_payloads(web_server, invalid_case):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)
    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    payload = manual_scope_payload()
    if invalid_case == "unknown_top_level_field":
        payload["owner_session_id"] = "caller-controlled"
    elif invalid_case == "missing_required_methods":
        payload.pop("allowed_methods")
    elif invalid_case == "unknown_asset_field":
        payload["in_scope_assets"][0]["workspace_root"] = "/tmp"
    elif invalid_case == "invalid_port":
        payload["in_scope_assets"][0]["ports"] = [65536]
    elif invalid_case == "target_outside_allowlist":
        payload["targets"][0]["host"] = "other.example.test"
    elif invalid_case == "method_overlap":
        payload["prohibited_methods"].append("GET")
    elif invalid_case == "rate_limit_out_of_bounds":
        payload["rate_limits"]["requests_per_minute"] = 1001
    elif invalid_case == "boolean_rate_limit":
        payload["rate_limits"]["requests_per_minute"] = True
    elif invalid_case == "expired_snapshot":
        payload["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    elif invalid_case == "expiration_too_far":
        payload["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=366)).isoformat()

    status, _, response = request(
        server,
        "POST",
        "/api/public/program-authorizations",
        payload,
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )

    assert status == 400
    assert response["ok"] is False
    assert persisted_scope_count() == 0


def test_manual_program_authorization_rejects_duplicate_json_fields(web_server):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)
    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    payload = manual_scope_payload()
    raw_body = json.dumps(payload).encode("utf-8")[:-1] + b',"allowed_methods":["TRACE"]}'

    status, _, response = request(
        server,
        "POST",
        "/api/public/program-authorizations",
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
        raw_body=raw_body,
    )

    assert status == 400
    assert response["error"] == "duplicate_json_field"
    assert persisted_scope_count() == 0
