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
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.observation_intelligence import ObservationInterpreter
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState
from agent.planning import Plan, PlanStep
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


def _prepare_owner_reconciliation(
    tmp_path, monkeypatch, owner_id, *, incomplete=False, plan=None, completion_criteria=None
):
    memory_path = tmp_path / "mission-memory.sqlite3"
    monkeypatch.setenv("CYBERSENTINEL_MEMORY_DB_PATH", str(memory_path))
    import agent.memory as mission_memory

    monkeypatch.setattr(bridge, "DB_PATH", tmp_path / "bridge.sqlite3")
    monkeypatch.setattr(mission_memory, "MEMORY_DB_PATH", memory_path)
    mission_memory._init_memory_db()
    missions_path = tmp_path / "missions.sqlite3"
    store = MissionStore(missions_path)
    runtime = MissionRuntime(store, executor=lambda *_: {"success": True})
    plan = plan or Plan.initial("synthetic bridge recovery").replan(
        steps=(PlanStep("observe", "observe synthetic state", action="status"),),
        reason="local bridge regression",
    )
    mission = runtime.create(
        "synthetic bridge recovery",
        "synthetic bridge recovery",
        plan,
        completion_criteria=completion_criteria or [],
        request_id="synthetic-bridge-reconciliation",
        owner_identity_ref=str(owner_id),
    )
    if incomplete:
        mission.checkpoint = {"status": "in_flight_parallel", "ambiguous_tool_call_ids": []}
    else:
        step = mission.plan.steps[0]
        action_id = f"{mission.mission_id}:{mission.plan.version}:{step.step_id}:0"
        mission.checkpoint = {
            "status": "in_flight",
            "action_id": action_id,
            "step_id": step.step_id,
            "plan_fingerprint": mission.plan.fingerprint,
        }
    mission.transition(MissionStatus.RECOVERY_REQUIRED, "synthetic ambiguous action")
    store.save(mission)

    queue = MissionQueue(tmp_path / "mission_queue.sqlite3")
    queue.enqueue(mission.mission_id)
    claimed = queue.claim_next(worker_id="synthetic-before-reconcile")
    assert claimed is not None
    waiting = queue.release(
        mission.mission_id,
        WorkerMissionState.WAITING_FOR_TOOL,
        worker_id="synthetic-before-reconcile",
        error="ambiguous action requires reconciliation",
    )
    assert waiting.state is WorkerMissionState.WAITING_FOR_TOOL
    return mission, missions_path, queue


def test_public_owner_reconciliation_persists_receipt_before_queue_requeue(web_server, tmp_path, monkeypatch):
    server, _ = web_server
    public_cookie, csrf, owner_cookie = _authenticated_public_owner_cookies(server)
    owner = owner_password.resolve_session(owner_cookie)
    assert owner is not None
    mission, missions_path, queue = _prepare_owner_reconciliation(
        tmp_path, monkeypatch, owner["owner_id"]
    )
    assert queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert queue.claim_next(worker_id="synthetic-before-owner-reconcile") is None

    durable_store = MissionStore(missions_path)
    enqueue_order = []
    queue_claims = []
    original_enqueue = MissionQueue.enqueue
    original_claim_next = MissionQueue.claim_next

    def verify_receipt_before_enqueue(self, mission_id, *args, **kwargs):
        if mission_id == mission.mission_id:
            persisted = durable_store.load(mission_id)
            assert persisted.status is MissionStatus.READY
            assert persisted.checkpoint["status"] == "completed"
            assert persisted.checkpoint["reconciled"] is True
            receipt = next(
                item for item in persisted.observations
                if item.get("action_id") == mission.checkpoint["action_id"]
            )
            assert receipt["source"] == "external_reconciliation"
            action = next(
                item for item in persisted.action_history
                if item.get("action_id") == mission.checkpoint["action_id"]
            )
            assert action["status"] == "completed"
            assert self.get(mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
            enqueue_order.append("durable-receipt-before-enqueue")
        return original_enqueue(self, mission_id, *args, **kwargs)

    def track_claim(self, *args, **kwargs):
        queue_claims.append(args or kwargs)
        return original_claim_next(self, *args, **kwargs)

    monkeypatch.setattr(MissionQueue, "enqueue", verify_receipt_before_enqueue)
    monkeypatch.setattr(MissionQueue, "claim_next", track_claim)
    status, _, response = request(
        server,
        "POST",
        f"/api/public/missions/{mission.mission_id}/reconcile",
        {"executed": True},
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )

    assert status == 200, response
    assert response["ok"] is True
    assert response["result"]["queue"]["state"] == WorkerMissionState.QUEUED.value
    assert enqueue_order == ["durable-receipt-before-enqueue"]
    assert queue_claims == []

    replay_status, _, replay = request(
        server,
        "POST",
        f"/api/public/missions/{mission.mission_id}/reconcile",
        {"executed": True},
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )
    assert replay_status == 400
    assert replay == {"ok": False, "error": "mission has no in-flight action requiring reconciliation"}
    assert enqueue_order == ["durable-receipt-before-enqueue"]
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED
    replayed = durable_store.load(mission.mission_id)
    assert len(replayed.observations) == 1
    assert len(replayed.action_history) == 1
    assert queue_claims == []


def test_public_owner_reconciliation_requeues_for_worker_execution_once(web_server, tmp_path, monkeypatch):
    server, _ = web_server
    public_cookie, csrf, owner_cookie = _authenticated_public_owner_cookies(server)
    owner = owner_password.resolve_session(owner_cookie)
    assert owner is not None
    plan = Plan.initial("apply one local synthetic action and verify the local core").replan(
        steps=(
            PlanStep("apply", "apply one synthetic local action", action="local_fake_action"),
            PlanStep("verify", "read local core status", action="status", prerequisites=("apply",)),
        ),
        reason="local bridge-to-worker regression",
    )
    mission, missions_path, queue = _prepare_owner_reconciliation(
        tmp_path,
        monkeypatch,
        owner["owner_id"],
        plan=plan,
        completion_criteria=[
            {"criterion_id": "local-core-online", "description": "local core is online", "check": "system_online"}
        ],
    )
    assert queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert queue.claim_next(worker_id="synthetic-before-owner-reconcile") is None

    claim_events = []
    original_claim_next = MissionQueue.claim_next

    def track_claim(self, *args, **kwargs):
        item = original_claim_next(self, *args, **kwargs)
        if self.db_path == queue.db_path and item is not None:
            claim_events.append((item.state, item.attempts, item.lease_owner))
        return item

    monkeypatch.setattr(MissionQueue, "claim_next", track_claim)
    status, _, response = request(
        server,
        "POST",
        f"/api/public/missions/{mission.mission_id}/reconcile",
        {"executed": False},
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )

    assert status == 200, response
    assert response["result"]["queue"]["state"] == WorkerMissionState.QUEUED.value
    assert claim_events == []
    reconciled = MissionStore(missions_path).load(mission.mission_id)
    assert reconciled.status is MissionStatus.READY
    assert reconciled.checkpoint["status"] == "reconciled_not_executed"
    assert reconciled.action_history == []
    assert reconciled.evidence == []
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED

    side_effect_attempts = {}
    applied_action_ids = set()
    side_effect_ledger = []
    executor_calls = []

    def local_executor(_mission, step, action_id):
        executor_calls.append((step.step_id, action_id))
        if step.step_id == "apply":
            side_effect_attempts[action_id] = side_effect_attempts.get(action_id, 0) + 1
            if action_id not in applied_action_ids:
                applied_action_ids.add(action_id)
                side_effect_ledger.append(action_id)
            return {"success": True, "source": "local_fake_executor", "idempotency_key": action_id}
        assert step.step_id == "verify"
        # The payload is only an observation trigger; the criterion validator independently
        # reads core.engine.status and signs evidence rather than trusting this fake response.
        return {"success": True, "source": "status", "summary": "synthetic local status observation"}

    interpreter = ObservationInterpreter(
        proposer=lambda _context: {"summary": "synthetic local interpretation", "facts": []}
    )
    runtime = MissionRuntime(
        MissionStore(missions_path),
        executor=local_executor,
        interpreter=interpreter,
    )
    worker = MissionWorker(queue, runtime_factory=lambda: runtime, worker_id="local-reconcile-worker")
    first_run = worker.run_once(now=(datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat())

    assert first_run is not None
    assert first_run.state is WorkerMissionState.COMPLETED
    assert first_run.attempts == 2
    assert claim_events == [(WorkerMissionState.EXECUTING, 2, "local-reconcile-worker")]
    expected_action_id = f"{mission.mission_id}:{mission.plan.version}:apply:0"
    assert side_effect_attempts == {expected_action_id: 1}
    assert applied_action_ids == {expected_action_id}
    assert side_effect_ledger == [expected_action_id]
    assert executor_calls == [
        ("apply", expected_action_id),
        ("verify", f"{mission.mission_id}:{mission.plan.version}:verify:1"),
    ]

    persisted = MissionStore(missions_path).load(mission.mission_id)
    assert persisted.status is MissionStatus.GOAL_COMPLETED
    assert persisted.completion_proof_is_valid()
    assert persisted.verification_state == {"verified": True, "missing_criteria": [], "evidence_count": 1}
    assert len(persisted._verified_system_evidence()) == 1
    assert len(persisted.evidence) == 1
    assert persisted.evidence[0]["criterion_id"] == "local-core-online"
    assert persisted.evidence[0]["source"] == "system_online"
    effect_record = next(item for item in persisted.action_history if item["action_id"] == expected_action_id)
    assert effect_record["observation"]["idempotency_key"] == expected_action_id
    assert queue.get(mission.mission_id).state is WorkerMissionState.COMPLETED

    # Simulate duplicate queue delivery after completion: terminal mission state is authoritative.
    duplicate_delivery = queue.enqueue(
        mission.mission_id,
        available_at=(datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat(),
    )
    assert duplicate_delivery.state is WorkerMissionState.QUEUED
    second_run = worker.run_once(now=(datetime.now(timezone.utc) + timedelta(seconds=3)).isoformat())
    assert second_run is not None
    assert second_run.state is WorkerMissionState.COMPLETED
    assert second_run.attempts == 3
    assert claim_events == [
        (WorkerMissionState.EXECUTING, 2, "local-reconcile-worker"),
        (WorkerMissionState.EXECUTING, 3, "local-reconcile-worker"),
    ]
    assert side_effect_attempts == {expected_action_id: 1}
    assert side_effect_ledger == [expected_action_id]
    assert len(executor_calls) == 2

    replay_status, _, replay = request(
        server,
        "POST",
        f"/api/public/missions/{mission.mission_id}/reconcile",
        {"executed": False},
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )
    assert replay_status == 400
    assert replay == {"ok": False, "error": "mission has no in-flight action requiring reconciliation"}
    after_replay = MissionStore(missions_path).load(mission.mission_id)
    assert after_replay.status is MissionStatus.GOAL_COMPLETED
    assert after_replay.completion_proof_is_valid()
    assert len(after_replay._verified_system_evidence()) == 1
    assert len(after_replay.action_history) == 2
    assert len(after_replay.evidence) == 1
    assert queue.get(mission.mission_id).state is WorkerMissionState.COMPLETED
    assert side_effect_attempts == {expected_action_id: 1}
    assert side_effect_ledger == [expected_action_id]
    assert len(executor_calls) == 2


def test_public_owner_reconciliation_recovers_crashed_worker_side_effect_once(web_server, tmp_path, monkeypatch):
    class SimulatedWorkerProcessCrash(BaseException):
        pass

    server, _ = web_server
    public_cookie, csrf, owner_cookie = _authenticated_public_owner_cookies(server)
    owner = owner_password.resolve_session(owner_cookie)
    assert owner is not None

    memory_path = tmp_path / "crash-mission-memory.sqlite3"
    monkeypatch.setenv("CYBERSENTINEL_MEMORY_DB_PATH", str(memory_path))
    import agent.memory as mission_memory

    monkeypatch.setattr(bridge, "DB_PATH", tmp_path / "bridge.sqlite3")
    monkeypatch.setattr(mission_memory, "MEMORY_DB_PATH", memory_path)
    mission_memory._init_memory_db()

    missions_path = tmp_path / "missions.sqlite3"
    queue_path = tmp_path / "mission_queue.sqlite3"
    store = MissionStore(missions_path)
    plan = Plan.initial("apply one local synthetic action and verify the local core").replan(
        steps=(
            PlanStep("apply", "apply one synthetic local action", action="unwatch"),
            PlanStep("verify", "read local core status", action="status", prerequisites=("apply",)),
        ),
        reason="local crash-reconciliation regression",
    )
    runtime = MissionRuntime(store, executor=lambda *_args: {})
    mission = runtime.create(
        "apply one local synthetic action and verify the local core",
        "apply one local synthetic action and verify the local core",
        plan,
        completion_criteria=[
            {"criterion_id": "local-core-online", "description": "local core is online", "check": "system_online"}
        ],
        request_id="synthetic-bridge-worker-crash-reconciliation",
        owner_identity_ref=str(owner["owner_id"]),
    )
    queue = MissionQueue(queue_path)
    start_status, _, start_response = request(
        server,
        "POST",
        f"/api/public/missions/{mission.mission_id}/start",
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )
    assert start_status == 200, start_response
    assert start_response["result"]["queue"]["state"] == WorkerMissionState.QUEUED.value
    assert MissionStore(missions_path).load(mission.mission_id).authorization_snapshot

    effect_attempts = {}
    effect_ledger = []
    expected_action_id = f"{mission.mission_id}:{mission.plan.version}:apply:0"

    def apply_fake_effect(action_id):
        effect_attempts[action_id] = effect_attempts.get(action_id, 0) + 1
        effect_ledger.append(action_id)

    def crash_after_fake_effect(current, step, action_id):
        assert step.step_id == "apply"
        assert queue.get(current.mission_id).state is WorkerMissionState.EXECUTING
        assert queue.get(current.mission_id).lease_owner == "worker-before-crash"
        persisted = MissionStore(missions_path).load(current.mission_id)
        assert persisted.checkpoint["status"] == "in_flight"
        assert not any(item.get("action_id") == action_id for item in persisted.action_history)
        apply_fake_effect(action_id)
        raise SimulatedWorkerProcessCrash("simulated process termination after side effect")

    crashing_runtime = MissionRuntime(MissionStore(missions_path), executor=crash_after_fake_effect)
    crashing_worker = MissionWorker(queue, runtime_factory=lambda: crashing_runtime, worker_id="worker-before-crash")
    crash_time = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
    with pytest.raises(SimulatedWorkerProcessCrash):
        crashing_worker.run_once(now=crash_time)

    after_crash = MissionStore(missions_path).load(mission.mission_id)
    assert effect_attempts == {expected_action_id: 1}
    assert effect_ledger == [expected_action_id]
    assert after_crash.checkpoint["status"] == "in_flight"
    assert after_crash.action_history == []
    assert after_crash.observations == []
    claimed = queue.get(mission.mission_id)
    assert claimed.state is WorkerMissionState.EXECUTING
    assert claimed.lease_owner == "worker-before-crash"

    # Reopen both durable stores as a fresh process would. Queue recovery makes
    # the lease claimable, but the runtime must first quarantine the ambiguous action.
    restarted_queue = MissionQueue(queue_path)
    recovered = restarted_queue.recover_after_restart()
    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.QUEUED
    assert recovered[0].lease_owner is None
    restarted_executor_calls = []

    def restarted_executor(_current, step, action_id):
        restarted_executor_calls.append((step.step_id, action_id))
        if step.step_id == "apply":
            apply_fake_effect(action_id)
        return {"success": True, "source": "local_fake_executor", "idempotency_key": action_id}

    restarted_runtime = MissionRuntime(MissionStore(missions_path), executor=restarted_executor)
    restarted_worker = MissionWorker(
        restarted_queue,
        runtime_factory=lambda: restarted_runtime,
        worker_id="worker-after-restart-before-owner",
    )
    waiting = restarted_worker.run_once(now=crash_time)
    assert waiting is not None
    assert waiting.state is WorkerMissionState.WAITING_FOR_TOOL
    assert waiting.lease_owner is None
    ambiguous = MissionStore(missions_path).load(mission.mission_id)
    assert ambiguous.status is MissionStatus.RECOVERY_REQUIRED
    assert ambiguous.checkpoint["status"] == "in_flight"
    assert ambiguous.action_history == []
    assert ambiguous.observations == []
    assert restarted_executor_calls == []
    assert effect_attempts == {expected_action_id: 1}
    assert effect_ledger == [expected_action_id]

    status, _, response = request(
        server,
        "POST",
        f"/api/public/missions/{mission.mission_id}/reconcile",
        {"executed": True},
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )
    assert status == 200, response
    assert response["ok"] is True
    assert response["result"]["queue"]["state"] == WorkerMissionState.QUEUED.value

    reconciled = MissionStore(missions_path).load(mission.mission_id)
    assert reconciled.status is MissionStatus.READY
    assert reconciled.checkpoint["status"] == "completed"
    assert reconciled.checkpoint["reconciled"] is True
    receipt = next(item for item in reconciled.observations if item.get("action_id") == expected_action_id)
    assert receipt["type"] == "reconciled_observation"
    assert receipt["source"] == "external_reconciliation"
    assert receipt["success"] is True
    action = next(item for item in reconciled.action_history if item.get("action_id") == expected_action_id)
    assert action["status"] == "completed"
    assert action["observation"] == receipt
    assert reconciled.evidence == []

    # Reopen the post-reconciliation queue/runtime and deliver work again.
    post_reconcile_queue = MissionQueue(queue_path)
    assert post_reconcile_queue.recover_after_restart() == []
    post_reconcile_executor_calls = []

    def post_reconcile_executor(_current, step, action_id):
        post_reconcile_executor_calls.append((step.step_id, action_id))
        if step.step_id == "apply":
            apply_fake_effect(action_id)
        if step.step_id == "verify":
            return {"success": True, "source": "status", "summary": "synthetic local status observation"}
        return {"success": True, "source": "local_fake_executor"}

    post_reconcile_runtime = MissionRuntime(
        MissionStore(missions_path),
        executor=post_reconcile_executor,
        interpreter=ObservationInterpreter(
            proposer=lambda _context: {"summary": "synthetic local interpretation", "facts": []}
        ),
    )
    post_reconcile_worker = MissionWorker(
        post_reconcile_queue,
        runtime_factory=lambda: post_reconcile_runtime,
        worker_id="worker-after-owner-reconciliation",
    )
    completed = post_reconcile_worker.run_once(
        now=(datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    )
    assert completed is not None
    assert completed.state is WorkerMissionState.COMPLETED
    assert post_reconcile_executor_calls == [
        ("verify", f"{mission.mission_id}:{mission.plan.version}:verify:1")
    ]

    final = MissionStore(missions_path).load(mission.mission_id)
    assert final.status is MissionStatus.GOAL_COMPLETED
    assert final.completion_proof_is_valid()
    assert final.verification_state == {"verified": True, "missing_criteria": [], "evidence_count": 1}
    assert len(final._verified_system_evidence()) == 1
    assert len(final.evidence) == 1
    final_receipt = next(item for item in final.observations if item.get("action_id") == expected_action_id)
    final_action = next(item for item in final.action_history if item.get("action_id") == expected_action_id)
    assert final_receipt["source"] == "external_reconciliation"
    assert final_action["status"] == "completed"
    assert effect_attempts == {expected_action_id: 1}
    assert effect_ledger == [expected_action_id]

    # A duplicate delivery to another reopened queue/worker remains harmless.
    duplicate_queue = MissionQueue(queue_path)
    duplicate_queue.enqueue(
        mission.mission_id,
        available_at=(datetime.now(timezone.utc) + timedelta(seconds=3)).isoformat(),
    )
    duplicate_executor_calls = []
    duplicate_runtime = MissionRuntime(
        MissionStore(missions_path),
        executor=lambda *_args: duplicate_executor_calls.append("unexpected execution") or {"success": True},
    )
    duplicate_worker = MissionWorker(duplicate_queue, runtime_factory=lambda: duplicate_runtime, worker_id="worker-redelivery")
    duplicate_delivery = duplicate_worker.run_once(
        now=(datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat()
    )
    assert duplicate_delivery is not None
    assert duplicate_delivery.state is WorkerMissionState.COMPLETED
    assert duplicate_executor_calls == []
    assert effect_attempts == {expected_action_id: 1}
    assert effect_ledger == [expected_action_id]


def test_public_owner_reconciliation_rejects_incomplete_receipt_without_requeue(web_server, tmp_path, monkeypatch):
    server, _ = web_server
    public_cookie, csrf, owner_cookie = _authenticated_public_owner_cookies(server)
    owner = owner_password.resolve_session(owner_cookie)
    assert owner is not None
    mission, missions_path, queue = _prepare_owner_reconciliation(
        tmp_path, monkeypatch, owner["owner_id"], incomplete=True
    )
    assert queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert queue.claim_next(worker_id="synthetic-before-owner-reconcile") is None
    enqueue_calls = []
    queue_claims = []
    original_enqueue = MissionQueue.enqueue
    original_claim_next = MissionQueue.claim_next

    def track_enqueue(self, mission_id, *args, **kwargs):
        if mission_id == mission.mission_id:
            enqueue_calls.append(mission_id)
        return original_enqueue(self, mission_id, *args, **kwargs)

    def track_claim(self, *args, **kwargs):
        queue_claims.append(args or kwargs)
        return original_claim_next(self, *args, **kwargs)

    monkeypatch.setattr(MissionQueue, "enqueue", track_enqueue)
    monkeypatch.setattr(MissionQueue, "claim_next", track_claim)
    status, _, response = request(
        server,
        "POST",
        f"/api/public/missions/{mission.mission_id}/reconcile",
        {"executed": True},
        cookies=f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}",
        csrf=csrf,
    )

    assert status == 400
    assert response == {"ok": False, "error": "parallel checkpoint has no ambiguous tool calls"}
    assert enqueue_calls == []
    assert queue_claims == []
    persisted = MissionStore(missions_path).load(mission.mission_id)
    assert persisted.status is MissionStatus.RECOVERY_REQUIRED
    assert persisted.checkpoint["status"] == "in_flight_parallel"
    assert persisted.observations == []
    assert persisted.action_history == []
    assert queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert original_claim_next(queue, worker_id="synthetic-after-rejected-reconcile") is None
