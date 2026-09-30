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


def persisted_scope_snapshot_ids():
    with sqlite3.connect(str(scope_store.SCOPE_DB_PATH)) as connection:
        return {row[0] for row in connection.execute("SELECT snapshot_id FROM scope_snapshots")}


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
        "target_ids",
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
    assert summary["target_ids"] == ["api-prod"]
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
    for submitted_scope_detail in ("api.example.test", "admin.example.test", "/api/private"):
        assert submitted_scope_detail not in serialized
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


def save_manual_scope_snapshot(server, public_cookie, owner_cookie, csrf, *, payload=None):
    status, _, response = request(
        server,
        "POST",
        "/api/public/program-authorizations",
        payload or manual_scope_payload(),
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )
    assert status == 201
    return response["snapshot"]


def test_public_scope_snapshot_list_returns_only_safe_current_session_summaries(web_server):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)
    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    owner_session = owner_password.resolve_session(owner_cookie)
    assert owner_session is not None
    created_summary = save_manual_scope_snapshot(server, public_cookie, owner_cookie, csrf)

    status, _, response = request(
        server,
        "GET",
        "/api/public/program-authorizations",
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
    )

    assert status == 200
    assert response == {"ok": True, "snapshots": [created_summary]}
    assert set(response["snapshots"][0]) == set(created_summary)
    assert response["snapshots"][0]["target_ids"] == ["api-prod"]
    serialized = json.dumps(response)
    for private_value in (
        "targets",
        "api.example.test",
        "admin.example.test",
        "evidence_hash",
        "session_id",
        "owner_session_id",
        owner_cookie,
        csrf,
        owner_session["session_id"],
    ):
        assert private_value not in serialized


def test_public_scope_snapshot_list_hides_prior_rotated_owner_session_records(web_server):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)
    status, first_headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    first_owner_cookie = cookie_value(first_headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    first_session = owner_password.resolve_session(first_owner_cookie)
    assert first_session is not None
    created_summary = save_manual_scope_snapshot(server, public_cookie, first_owner_cookie, csrf)

    status, rotated_headers, _ = login(
        server,
        public_cookie,
        csrf,
        owner_cookie=first_owner_cookie,
    )
    assert status == 200
    rotated_owner_cookie = cookie_value(rotated_headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    assert rotated_owner_cookie != first_owner_cookie
    assert owner_password.resolve_session(first_owner_cookie) is None

    status, _, response = request(
        server,
        "GET",
        f"/api/public/program-authorizations?owner_session_id={first_session['session_id']}&snapshot_id={created_summary['snapshot_id']}",
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={rotated_owner_cookie}",
    )

    assert status == 200
    assert response == {"ok": True, "snapshots": []}
    assert first_session["session_id"] not in json.dumps(response)
    assert created_summary["snapshot_id"] not in json.dumps(response)


def test_public_scope_snapshot_list_preserves_public_owner_origin_and_safe_get_csrf_guards(web_server, monkeypatch):
    server, _ = web_server
    status, _, response = request(server, "GET", "/api/public/program-authorizations")
    assert status == 401
    assert response["error"] == "public session required"

    public_cookie, csrf = create_public_session(server)
    status, _, response = request(
        server,
        "GET",
        "/api/public/program-authorizations",
        cookies=public_cookie,
    )
    assert status == 403
    assert response["error"] == "owner_authorization_required"

    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    cookies = f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}"

    status, _, response = request(
        server,
        "GET",
        "/api/public/program-authorizations",
        cookies=cookies,
    )
    assert status == 200
    assert response == {"ok": True, "snapshots": []}

    status, _, response = request(
        server,
        "GET",
        "/api/public/program-authorizations",
        cookies=cookies,
        origin="https://attacker.example",
    )
    assert status == 403
    assert response["error"] == "origin_not_allowed"

    monkeypatch.setattr(bridge, "PUBLIC_WEB_ENABLED", False)
    status, _, response = request(
        server,
        "GET",
        "/api/public/program-authorizations",
        cookies=cookies,
    )
    assert status == 404
    assert response["error"] == "public_boundary_disabled"


def test_public_scope_snapshot_delete_requires_owner_session_and_csrf(web_server):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)
    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    summary = save_manual_scope_snapshot(server, public_cookie, owner_cookie, csrf)
    path = f"/api/public/program-authorizations/{summary['snapshot_id']}"
    cookies = f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}"

    status, _, response = request(server, "DELETE", path, cookies=cookies)
    assert status == 401
    assert response["error"] == "invalid csrf token"
    assert persisted_scope_snapshot_ids() == {summary["snapshot_id"]}

    status, _, response = request(server, "DELETE", path, cookies=public_cookie, csrf=csrf)
    assert status == 403
    assert response["error"] == "owner_authorization_required"
    assert persisted_scope_snapshot_ids() == {summary["snapshot_id"]}

    status, _, response = request(
        server,
        "DELETE",
        path,
        cookies=f"{bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )
    assert status == 401
    assert response["error"] == "public session required"
    assert persisted_scope_snapshot_ids() == {summary["snapshot_id"]}


def test_public_scope_snapshot_delete_removes_only_the_selected_current_session_row(web_server):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)
    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    cookies = f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}"
    target = save_manual_scope_snapshot(server, public_cookie, owner_cookie, csrf)
    sibling_payload = manual_scope_payload()
    sibling_payload["program_id"] = "keep-this-snapshot"
    sibling = save_manual_scope_snapshot(server, public_cookie, owner_cookie, csrf, payload=sibling_payload)

    status, _, response = request(
        server,
        "DELETE",
        f"/api/public/program-authorizations/{target['snapshot_id']}",
        cookies=cookies,
        csrf=csrf,
    )
    assert status == 200
    assert response == {"ok": True}
    assert persisted_scope_snapshot_ids() == {sibling["snapshot_id"]}

    status, _, response = request(server, "GET", "/api/public/program-authorizations", cookies=cookies)
    assert status == 200
    assert [item["snapshot_id"] for item in response["snapshots"]] == [sibling["snapshot_id"]]

    status, _, response = request(
        server,
        "DELETE",
        f"/api/public/program-authorizations/{target['snapshot_id']}",
        cookies=cookies,
        csrf=csrf,
    )
    assert status == 404
    assert response["error"] == "snapshot_not_found"
    assert persisted_scope_snapshot_ids() == {sibling["snapshot_id"]}


def test_public_scope_snapshot_delete_hides_other_sessions_and_ignores_caller_session_ids(web_server):
    server, _ = web_server
    first_public_cookie, first_csrf = create_public_session(server)
    status, first_headers, _ = login(server, first_public_cookie, first_csrf)
    assert status == 200
    first_owner_cookie = cookie_value(first_headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    first_session = owner_password.resolve_session(first_owner_cookie)
    assert first_session is not None
    first_cookies = f"{first_public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={first_owner_cookie}"
    first_snapshot = save_manual_scope_snapshot(server, first_public_cookie, first_owner_cookie, first_csrf)
    first_sibling_payload = manual_scope_payload()
    first_sibling_payload["program_id"] = "first-session-sibling"
    first_sibling = save_manual_scope_snapshot(server, first_public_cookie, first_owner_cookie, first_csrf, payload=first_sibling_payload)

    second_public_cookie, second_csrf = create_public_session(server)
    status, second_headers, _ = login(server, second_public_cookie, second_csrf)
    assert status == 200
    second_owner_cookie = cookie_value(second_headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    second_session = owner_password.resolve_session(second_owner_cookie)
    assert second_session is not None
    assert second_session["session_id"] != first_session["session_id"]
    second_cookies = f"{second_public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={second_owner_cookie}"
    second_snapshot = save_manual_scope_snapshot(server, second_public_cookie, second_owner_cookie, second_csrf)

    status, _, response = request(
        server,
        "DELETE",
        f"/api/public/program-authorizations/{first_snapshot['snapshot_id']}?owner_session_id={first_session['session_id']}",
        {"owner_session_id": first_session["session_id"]},
        cookies=second_cookies,
        csrf=second_csrf,
        owner_session_header=first_session["session_id"],
    )
    assert status == 404
    assert response["error"] == "snapshot_not_found"
    assert persisted_scope_snapshot_ids() == {
        first_snapshot["snapshot_id"],
        first_sibling["snapshot_id"],
        second_snapshot["snapshot_id"],
    }

    status, _, response = request(server, "GET", "/api/public/program-authorizations", cookies=first_cookies)
    assert status == 200
    assert {item["snapshot_id"] for item in response["snapshots"]} == {
        first_snapshot["snapshot_id"],
        first_sibling["snapshot_id"],
    }
    status, _, response = request(server, "GET", "/api/public/program-authorizations", cookies=second_cookies)
    assert status == 200
    assert [item["snapshot_id"] for item in response["snapshots"]] == [second_snapshot["snapshot_id"]]


def test_public_scope_snapshot_list_clamps_count_and_rejects_nonpositive_limit(web_server):
    server, _ = web_server
    public_cookie, csrf = create_public_session(server)
    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    owner_session = owner_password.resolve_session(owner_cookie)
    assert owner_session is not None

    from api.program_authorizations import build_manual_scope_snapshot

    for index in range(53):
        payload = manual_scope_payload()
        payload["program_id"] = f"bounded-program-{index}"
        snapshot = build_manual_scope_snapshot(payload)
        scope_store.save_snapshot(snapshot, owner_session_token=owner_session["session_id"])

    cookies = f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}"
    status, _, response = request(
        server,
        "GET",
        "/api/public/program-authorizations?limit=999",
        cookies=cookies,
    )
    assert status == 200
    assert len(response["snapshots"]) == 50
    assert all("owner_session_id" not in snapshot for snapshot in response["snapshots"])

    status, _, response = request(
        server,
        "GET",
        "/api/public/program-authorizations?limit=0",
        cookies=cookies,
    )
    assert status == 400
    assert response["error"] == "invalid_limit"



def _install_fake_public_mission_creator(monkeypatch, captured):
    from types import SimpleNamespace

    class FakeMission:
        mission_id = "mission-scope-reference-test"

        def to_public_dict(self):
            return {"mission_id": self.mission_id, "status": "READY"}

    class FakeCore:
        def __init__(self, *_args, **_kwargs):
            pass

        def run_owner_mission(self, instruction, **kwargs):
            captured.append((instruction, kwargs))
            return FakeMission()

    class FakeQueue:
        def __init__(self, *_args, **_kwargs):
            pass

        def enqueue(self, mission_id):
            assert mission_id == FakeMission.mission_id
            return SimpleNamespace(state="QUEUED", attempts=1, available_at="2026-09-30T00:00:00+00:00")

    monkeypatch.setattr(bridge, "AgentCore", FakeCore)
    monkeypatch.setattr(bridge, "MissionQueue", FakeQueue)


def _authenticated_public_owner_cookies(server):
    public_cookie, csrf = create_public_session(server)
    status, headers, _ = login(server, public_cookie, csrf)
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    assert owner_cookie
    return public_cookie, csrf, owner_cookie


def test_public_mission_scope_binding_forwards_only_persisted_references(web_server, monkeypatch):
    server, _ = web_server
    captured = []
    _install_fake_public_mission_creator(monkeypatch, captured)
    public_cookie, csrf, owner_cookie = _authenticated_public_owner_cookies(server)

    status, _, response = request(
        server,
        "POST",
        "/api/public/missions",
        {
            "objective": "Inspect the saved target safely",
            "scope_snapshot_id": "snapshot-selected",
            "target_id": "api-prod",
            "scope_context": {"program_id": "forged-program", "host": "attacker.example", "allowed_networks": ["0.0.0.0/0"]},
            "program_id": "forged-program",
            "host": "attacker.example",
        },
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )

    assert status == 201
    assert response["ok"] is True
    assert len(captured) == 1
    instruction, kwargs = captured[0]
    assert instruction == "Inspect the saved target safely"
    assert kwargs["owner_session_token"] == owner_password.resolve_session(owner_cookie)["session_id"]
    assert kwargs["scope_context"] == {
        "workspace_root": str(bridge.ROOT),
        "scope_snapshot_id": "snapshot-selected",
        "target_id": "api-prod",
    }
    assert "host" not in kwargs["scope_context"]
    assert "program_id" not in kwargs["scope_context"]
    assert "allowed_networks" not in kwargs["scope_context"]


def test_public_mission_without_scope_preserves_repository_workspace_path(web_server, monkeypatch):
    server, _ = web_server
    captured = []
    _install_fake_public_mission_creator(monkeypatch, captured)
    public_cookie, csrf, owner_cookie = _authenticated_public_owner_cookies(server)

    status, _, response = request(
        server,
        "POST",
        "/api/public/missions",
        {"objective": "Review the current repository"},
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )

    assert status == 201
    assert response["ok"] is True
    assert len(captured) == 1
    assert captured[0][1]["scope_context"] == {
        "workspace_root": str(bridge.ROOT),
        "target_id": "cybersentinel-repository",
    }
    assert "scope_snapshot_id" not in captured[0][1]["scope_context"]


def test_public_mission_rejects_incomplete_scope_reference_before_creation(web_server, monkeypatch):
    server, _ = web_server
    captured = []
    _install_fake_public_mission_creator(monkeypatch, captured)
    public_cookie, csrf, owner_cookie = _authenticated_public_owner_cookies(server)

    status, _, response = request(
        server,
        "POST",
        "/api/public/missions",
        {"objective": "Do not start without a complete binding", "scope_snapshot_id": "snapshot-selected"},
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )

    assert status == 400
    assert response == {"ok": False, "error": "invalid_scope_binding"}
    assert captured == []
