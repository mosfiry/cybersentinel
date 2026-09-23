from __future__ import annotations

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import threading

import pytest

import bridge
from security.public_session import PublicSessionManager


@pytest.fixture
def manager():
    return PublicSessionManager(ttl_seconds=60)


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
        "prompt(",
        "X-CyberSentinel-Token",
        "X-CyberSentinel-Owner-Token",
    )
    for value in forbidden:
        assert value not in source
    assert "credentials:\"include\"" in source
    assert "X-CSRF-Token" in source


def test_http_public_boundary_sets_cookie_and_fails_closed(monkeypatch):
    monkeypatch.setattr(bridge, "PUBLIC_WEB_ENABLED", True)
    monkeypatch.setattr(bridge, "PUBLIC_WEB_ORIGIN", "")
    monkeypatch.setattr(bridge, "DEFAULT_PUBLIC_SESSIONS", PublicSessionManager(ttl_seconds=60))
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        connection.request("POST", "/api/public/session")
        response = connection.getresponse()
        payload = json.loads(response.read())
        assert response.status == 201
        assert payload["session"]["csrf_token"]
        cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        csrf = payload["session"]["csrf_token"]

        connection.request("POST", "/api/public/chat", body=json.dumps({"text": "Owner"}), headers={
            "Content-Type": "application/json",
            "Cookie": cookie,
            "X-CSRF-Token": csrf,
        })
        response = connection.getresponse()
        payload = json.loads(response.read())
        assert response.status == 403
        assert payload["error"] == "owner_authorization_required"

        connection.request("POST", "/api/public/chat", body=json.dumps({"text": "hello"}), headers={
            "Content-Type": "application/json",
            "Cookie": cookie,
        })
        response = connection.getresponse()
        assert response.status == 401
        response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
