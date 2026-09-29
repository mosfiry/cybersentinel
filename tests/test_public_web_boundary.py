from __future__ import annotations

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from http.cookies import SimpleCookie
import json
from pathlib import Path
import threading

import pytest

import bridge
import core.db as core_db
from security import owner_password
from security.public_session import PublicSessionManager

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


def request(server, method, path, payload=None, *, cookies="", csrf="", origin=None):
    connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    if cookies:
        headers["Cookie"] = cookies
    if csrf:
        headers["X-CSRF-Token"] = csrf
    if origin is not None:
        headers["Origin"] = origin
    body = json.dumps(payload) if payload is not None else None
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
        "sessionStorage",
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
    assert "localStorage" not in script
    assert 'item.status || "completed"' not in script
    assert 'data.answer || "اكتمل التحليل."' not in script
    assert '"ONLINE"' not in script
    assert 'data-view="findings"' in page
    assert "system_evidence" in script
    assert 'placeholder="اكتب سؤالك الأمني بلغة طبيعية...' in page
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
