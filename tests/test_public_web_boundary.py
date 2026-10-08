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


def test_mission_observability_requires_owner_session_and_csrf(public_server, monkeypatch):
    calls = []

    class FakeObservability:
        def get(self, mission_id, *, owner_session_token, **kwargs):
            calls.append((mission_id, owner_session_token, kwargs))
            if mission_id in {"foreign", "missing"}:
                raise KeyError("unknown_mission")
            return {"mission_id": mission_id, "graph": {"tasks": []}}

    monkeypatch.setattr(
        bridge.Handler,
        "_mission_observability_service",
        lambda self: FakeObservability(),
    )
    cookie, csrf = _owner_session(public_server)

    status, denied, _ = _request(
        public_server,
        "GET",
        "/api/public/missions/mission-safe/observability",
        headers={"Cookie": cookie},
    )
    assert status == 401
    assert denied["ok"] is False

    status, result, _ = _request(
        public_server,
        "GET",
        "/api/public/missions/mission-safe/observability?timeline_limit=5",
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 200
    assert result["observability"]["mission_id"] == "mission-safe"
    assert calls[-1][1] == OWNER_TOKEN
    assert "owner_session_token" not in json.dumps(result)

    denied_results = []
    for mission_id in ("foreign", "missing"):
        denied_status, denied_body, _ = _request(
            public_server,
            "GET",
            f"/api/public/missions/{mission_id}/observability",
            headers={"Cookie": cookie, "X-CSRF-Token": csrf},
        )
        denied_results.append((denied_status, denied_body))
    assert denied_results == [
        (404, {"ok": False, "error": "unknown_mission"}),
        (404, {"ok": False, "error": "unknown_mission"}),
    ]

    oversized_status, oversized, _ = _request(
        public_server,
        "GET",
        "/api/public/missions/mission-safe/observability?timeline_limit=51",
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert oversized_status == 400
    assert oversized["error"] == "invalid_observability_query"


def test_mission_evaluation_summary_requires_owner_csrf_and_exact_mission_scope(public_server, monkeypatch):
    calls = []

    class FakeEvaluationSummary:
        def get(self, mission_id, *, owner_session_token):
            calls.append((mission_id, owner_session_token))
            if mission_id in {"foreign", "missing"}:
                raise KeyError("unknown_mission")
            return {
                "status": "no_run",
                "run_count": 0,
                "verdict": "not_persisted",
                "metrics": [],
            }

    monkeypatch.setattr(
        bridge.Handler,
        "_mission_evaluation_service",
        lambda self: FakeEvaluationSummary(),
    )
    cookie, csrf = _owner_session(public_server)

    status, denied, _ = _request(
        public_server,
        "GET",
        "/api/public/missions/mission-safe/evaluation",
        headers={"Cookie": cookie},
    )
    assert status == 401
    assert denied["ok"] is False

    status, result, _ = _request(
        public_server,
        "GET",
        "/api/public/missions/mission-safe/evaluation",
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 200
    assert result["evaluation"]["status"] == "no_run"
    assert calls[-1] == ("mission-safe", OWNER_TOKEN)
    assert OWNER_TOKEN not in json.dumps(result)

    denied_results = []
    for mission_id in ("foreign", "missing"):
        denied_status, denied_body, _ = _request(
            public_server,
            "GET",
            f"/api/public/missions/{mission_id}/evaluation",
            headers={"Cookie": cookie, "X-CSRF-Token": csrf},
        )
        denied_results.append((denied_status, denied_body))
    assert denied_results == [
        (404, {"ok": False, "error": "unknown_mission"}),
        (404, {"ok": False, "error": "unknown_mission"}),
    ]

    query_status, query_error, _ = _request(
        public_server,
        "GET",
        "/api/public/missions/mission-safe/evaluation?limit=101",
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert query_status == 400
    assert query_error == {"ok": False, "error": "invalid_evaluation_query"}


def test_owner_evaluation_dashboard_requires_owner_csrf_and_rejects_client_identity(public_server, monkeypatch):
    calls = []

    class FakeEvaluationDashboard:
        def get_owner_dashboard(self, *, owner_session_token, limit):
            calls.append((owner_session_token, limit))
            if limit > 10:
                raise ValueError("invalid_evaluation_dashboard_request")
            return {
                "status": "no_run",
                "mission_count": 0,
                "mission_count_capped": False,
                "evaluated_mission_count": 0,
                "metrics": [],
                "verdict": "not_computed",
            }

    monkeypatch.setattr(
        bridge.Handler,
        "_mission_evaluation_service",
        lambda self: FakeEvaluationDashboard(),
    )
    public_cookie, public_csrf, _ = _public_session(public_server)
    public_status, public_error, _ = _request(
        public_server,
        "GET",
        "/api/public/evaluation-dashboard",
        headers={"Cookie": public_cookie, "X-CSRF-Token": public_csrf},
    )
    assert public_status == 403
    assert public_error == {"ok": False, "error": "owner_authorization_required"}

    owner_cookie, csrf = _owner_session(public_server)
    missing_csrf_status, missing_csrf, _ = _request(
        public_server,
        "GET",
        "/api/public/evaluation-dashboard",
        headers={"Cookie": owner_cookie},
    )
    assert missing_csrf_status == 401
    assert missing_csrf["ok"] is False

    status, result, _ = _request(
        public_server,
        "GET",
        "/api/public/evaluation-dashboard?limit=5",
        headers={"Cookie": owner_cookie, "X-CSRF-Token": csrf},
    )
    assert status == 200
    assert result["dashboard"]["status"] == "no_run"
    assert calls[-1] == (OWNER_TOKEN, 5)
    assert OWNER_TOKEN not in json.dumps(result)

    for query in ("limit=11", "owner=owner%3A8", "limit=" + "1" * 300):
        denied_status, denied_body, _ = _request(
            public_server,
            "GET",
            "/api/public/evaluation-dashboard?" + query,
            headers={"Cookie": owner_cookie, "X-CSRF-Token": csrf},
        )
        assert denied_status == 400
        assert denied_body == {"ok": False, "error": "invalid_evaluation_dashboard_request"}


def test_public_schedule_api_is_owner_csrf_protected_and_only_accepts_one_shot_payloads(public_server, monkeypatch):
    calls = []

    class FakeMissionService:
        def schedule_mission(self, mission_id, *, owner_session_token, run_at):
            if mission_id != "mission-safe":
                raise KeyError("unknown_mission")
            calls.append((mission_id, owner_session_token, run_at))
            return {
                "schedule_id": "schedule-safe",
                "mission_id": mission_id,
                "next_run_at": run_at,
                "interval_seconds": None,
                "retry_limit": 0,
                "state": "SCHEDULED",
            }

    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda self: FakeMissionService())
    public_cookie, public_csrf, _ = _public_session(public_server)
    public_status, public_body, _ = _request(
        public_server,
        "POST",
        "/api/public/missions/mission-safe/schedule",
        body={"run_at": "2030-01-01T00:00:00Z"},
        headers={"Cookie": public_cookie, "X-CSRF-Token": public_csrf},
    )
    assert public_status == 403
    assert public_body == {"ok": False, "error": "owner_authorization_required"}

    owner_cookie, csrf = _owner_session(public_server)
    no_csrf_status, _, _ = _request(
        public_server,
        "POST",
        "/api/public/missions/mission-safe/schedule",
        body={"run_at": "2030-01-01T00:00:00Z"},
        headers={"Cookie": owner_cookie},
    )
    assert no_csrf_status == 401

    status, response, _ = _request(
        public_server,
        "POST",
        "/api/public/missions/mission-safe/schedule",
        body={"run_at": "2030-01-01T00:00:00Z"},
        headers={"Cookie": owner_cookie, "X-CSRF-Token": csrf},
    )
    assert status == 201
    assert response["schedule"]["retry_limit"] == 0
    assert calls == [("mission-safe", OWNER_TOKEN, "2030-01-01T00:00:00Z")]
    assert OWNER_TOKEN not in json.dumps(response)

    for mission_id in ("foreign", "missing"):
        denied_status, denied_body, _ = _request(
            public_server,
            "POST",
            f"/api/public/missions/{mission_id}/schedule",
            body={"run_at": "2030-01-01T00:00:00Z"},
            headers={"Cookie": owner_cookie, "X-CSRF-Token": csrf},
        )
        assert denied_status == 404
        assert denied_body == {"ok": False, "error": "unknown_mission"}

    invalid_payloads = (
        {"run_at": "2030-01-01T00:00:00Z", "interval_seconds": 60},
        {"run_at": "2030-01-01T00:00:00Z", "cron": "* * * * *"},
        {"run_at": "2030-01-01T00:00:00Z", "retry_limit": 1},
        {"run_at": 2030},
        ["2030-01-01T00:00:00Z"],
    )
    for payload in invalid_payloads:
        denied_status, denied_body, _ = _request(
            public_server,
            "POST",
            "/api/public/missions/mission-safe/schedule",
            body=payload,
            headers={"Cookie": owner_cookie, "X-CSRF-Token": csrf},
        )
        assert denied_status == 400
        assert denied_body == {"ok": False, "error": "invalid_schedule_request"}
    assert len(calls) == 1, "invalid and foreign requests never reach the scheduling service"

    monkeypatch.setattr(bridge, "BRIDGE_TOKEN", "bridge-test-token")
    legacy_headers = {
        "X-CyberSentinel-Token": "bridge-test-token",
        "X-CyberSentinel-Owner-Session": OWNER_TOKEN,
    }
    legacy_status, legacy_response, _ = _request(
        public_server,
        "POST",
        "/api/missions/mission-safe/schedule",
        body={"run_at": "2030-01-02T00:00:00Z"},
        headers=legacy_headers,
    )
    assert legacy_status == 201
    assert legacy_response["schedule"]["retry_limit"] == 0
    assert calls[-1] == ("mission-safe", OWNER_TOKEN, "2030-01-02T00:00:00Z")
    for payload in invalid_payloads:
        denied_status, denied_body, _ = _request(
            public_server,
            "POST",
            "/api/missions/mission-safe/schedule",
            body=payload,
            headers=legacy_headers,
        )
        assert denied_status == 400
        assert denied_body == {"ok": False, "error": "invalid_schedule_request"}
    assert len(calls) == 2, "unsupported legacy action payloads never reach scheduling"


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
    assert 'id="skillsLink"' in Path("web/index.html").read_text(encoding="utf-8")
    assert 'id="missionSkill"' in Path("web/index.html").read_text(encoding="utf-8")
    skills_ui = source[source.index("async function skillsPanel()"):source.index("async function settingsPanel()")]
    assert ".innerHTML" not in skills_ui
    assert "textContent" in skills_ui


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


def test_public_mission_create_uses_server_project_scope_and_queues_owner_mission(public_server, monkeypatch, tmp_path):
    cookie, csrf = _owner_session(public_server)
    captured = {}
    project_id = "a" * 32
    project_root = tmp_path / "owner-project"
    project_root.mkdir()

    class FakeProject:
        def __init__(self):
            self.project_id = project_id
            self.root_path = project_root

    class FakeProjects:
        def get(self, owner_id, selected_id, *, include_archived):
            assert owner_id == 7
            assert selected_id == project_id
            assert include_archived is False
            return FakeProject()

        def ensure_default(self, _owner_id):
            pytest.fail("a client-selected project must not fall back to General")

        def assign_mission(self, owner_id, mission_id, selected_id):
            captured["project_assignment"] = (owner_id, mission_id, selected_id)

    class FakeCore:
        def __init__(self, router, *, db_path, skill_registry):
            captured["db_path"] = db_path
            captured["skill_registry"] = skill_registry

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
    monkeypatch.setattr(bridge, "_project_store", lambda: FakeProjects())
    registry_sentinel = object()
    monkeypatch.setattr(bridge, "_skill_registry", lambda: registry_sentinel)
    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/missions",
        body={
            "objective": "Review the service",
            "project_id": project_id,
            "skill_id": "approved-guide",
            "scope_context": {"workspace_root": "/", "allowed_networks": ["*"]},
        },
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 201
    assert payload["mission_id"] == "mission-abc"
    assert captured["started"] == ("mission-abc", OWNER_TOKEN)
    assert captured["run"] is False
    assert captured["scope_context"]["workspace_root"] == str(project_root.resolve())
    assert captured["scope_context"]["target_id"] == f"local-project:{project_id}"
    assert captured["scope_context"]["allowed_tools"] == [
        "latest_intel", "local_security_check", "local_system_info", "status"
    ]
    assert captured["scope_context"]["allowed_networks"] == []
    assert captured["skill_registry"] is registry_sentinel
    assert captured["skill_id"] == "approved-guide"
    assert captured["project_assignment"] == (7, "mission-abc", project_id)
    assert "authorization_snapshot" not in payload["mission"]


def test_public_project_tool_scope_is_local_and_owner_intent_bounded():
    base = {"latest_intel", "local_security_check", "local_system_info", "status"}
    assert set(bridge._public_project_owner_tool_scope("Review this local project")) == base
    assert set(bridge._public_project_owner_tool_scope("Run the project test suite once")) == base | {"run_project_tests"}
    assert set(bridge._public_project_owner_tool_scope("Do not run the project tests")) == base
    assert set(bridge._public_project_owner_tool_scope("Do not use pytest")) == base
    assert set(bridge._public_project_owner_tool_scope("Can I run the project test suite?")) == base
    assert set(bridge._public_project_owner_tool_scope("Can you run tests?")) == base
    assert set(bridge._public_project_owner_tool_scope("Could you explain how to run pytest?")) == base
    assert set(bridge._public_project_owner_tool_scope("What does pytest do?")) == base
    assert set(bridge._public_project_owner_tool_scope("Please execute pytest -q")) == base | {"run_project_tests"}
    assert set(bridge._public_project_owner_tool_scope("Run tests but do not use pytest")) == base
    assert set(bridge._public_project_owner_tool_scope("Add a watch on this indicator")) == base | {"watch"}
    assert set(bridge._public_project_owner_tool_scope("Can you add a watch on this indicator?")) == base
    assert set(bridge._public_project_owner_tool_scope("What does watch do?")) == base
    assert set(bridge._public_project_owner_tool_scope("Do not watch this indicator")) == base
    assert set(bridge._public_project_owner_tool_scope("Unwatch this indicator")) == base | {"unwatch"}
    assert set(bridge._public_project_owner_tool_scope("What does unwatch do?")) == base
    assert set(bridge._public_project_owner_tool_scope("Do not unwatch this indicator")) == base
    assert set(bridge._public_project_owner_tool_scope("Could you stop watching this indicator?")) == base
    assert set(bridge._public_project_owner_tool_scope("Stop watching this indicator")) == base | {"unwatch"}
    assert set(bridge._public_project_owner_tool_scope("لا تشغّل الاختبارات")) == base
    assert set(bridge._public_project_owner_tool_scope("شغّل الاختبارات")) == base | {"run_project_tests"}
    for objective in ("Review this local project", "Run the project test suite once"):
        allowed = set(bridge._public_project_owner_tool_scope(objective))
        assert not allowed.intersection({
            "browser", "browser.fill", "search", "web_research", "refresh_intel",
            "mcp.discover", "mcp.invoke", "red_team_assess", "scoped_http_probe",
            "watch", "unwatch",
        })


def test_public_skill_routes_require_owner_and_csrf_and_forward_narrow_requests(public_server, monkeypatch):
    public_cookie, csrf, _ = _public_session(public_server)
    status, payload, _headers = _request(
        public_server,
        "GET",
        "/api/public/skills",
        headers={"Cookie": public_cookie, "X-CSRF-Token": csrf},
    )
    assert status == 403
    assert payload["error"] == "owner_authorization_required"

    cookie, owner_csrf = _owner_session(public_server)
    captured = []
    sample = {
        "skill_id": "owner-guide",
        "name": "Owner guide",
        "version": 1,
        "status": "candidate",
        "active": False,
        "content_hash": "a" * 64,
        "execution_mode": "untrusted_guidance_only",
    }

    class FakeSkills:
        def list_revisions(self, owner_session_token):
            assert owner_session_token == OWNER_TOKEN
            return [sample]

        def detail(self, owner_session_token, skill_id, version):
            assert owner_session_token == OWNER_TOKEN
            if skill_id != "owner-guide" or version != 1:
                raise KeyError("unknown_skill_revision")
            return sample

        def submit_candidate(self, owner_session_token, mission_id, definition):
            assert owner_session_token == OWNER_TOKEN
            captured.append(("candidate", mission_id, definition))
            return sample

        def approve(self, owner_session_token, skill_id, version, content_hash):
            captured.append(("approve", owner_session_token, skill_id, version, content_hash))
            return {**sample, "status": "approved", "active": True}

        def revoke(self, owner_session_token, skill_id, version, content_hash):
            captured.append(("revoke", owner_session_token, skill_id, version, content_hash))
            return {**sample, "status": "revoked", "active": False}

    monkeypatch.setattr(bridge.Handler, "_skill_service", lambda self: FakeSkills())
    status, payload, _headers = _request(
        public_server,
        "GET",
        "/api/public/skills",
        headers={"Cookie": cookie},
    )
    assert status == 401

    status, payload, _headers = _request(
        public_server,
        "GET",
        "/api/public/skills",
        headers={"Cookie": cookie, "X-CSRF-Token": "incorrect-token"},
    )
    assert status == 401

    status, payload, _headers = _request(
        public_server,
        "GET",
        "/api/public/skills",
        headers={"Cookie": cookie, "X-CSRF-Token": owner_csrf},
    )
    assert status == 200
    assert payload["skills"][0]["skill_id"] == "owner-guide"

    status, payload, _headers = _request(
        public_server,
        "GET",
        "/api/public/skills/owner-guide/1",
        headers={"Cookie": cookie, "X-CSRF-Token": owner_csrf},
    )
    assert status == 200
    assert payload["skill"]["content_hash"] == "a" * 64

    status, _payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/skills/candidates",
        body={"mission_id": "mission-owned", "definition": {"skill_id": "owner-guide"}},
        headers={"Cookie": cookie},
    )
    assert status == 401

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/skills/candidates",
        body={
            "mission_id": "mission-owned",
            "definition": {"skill_id": "owner-guide"},
            "evidence": {"verified": True},
        },
        headers={"Cookie": cookie, "X-CSRF-Token": owner_csrf},
    )
    assert status == 400
    assert payload["error"] == "invalid_skill_candidate_request"
    assert captured == []

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/skills/candidates",
        body={"mission_id": "mission-owned", "definition": {"skill_id": "owner-guide"}},
        headers={"Cookie": cookie, "X-CSRF-Token": owner_csrf},
    )
    assert status == 201
    assert captured[0] == ("candidate", "mission-owned", {"skill_id": "owner-guide"})

    for action, expected in (("approve", "approved"), ("revoke", "revoked")):
        status, payload, _headers = _request(
            public_server,
            "POST",
            f"/api/public/skills/owner-guide/1/{action}",
            body={"content_hash": "a" * 64},
            headers={"Cookie": cookie, "X-CSRF-Token": owner_csrf},
        )
        assert status == 200
        assert payload["skill"]["status"] == expected
    assert [item[0] for item in captured] == ["candidate", "approve", "revoke"]

    status, payload, _headers = _request(
        public_server,
        "GET",
        "/api/public/skills/foreign-owner-skill/1",
        headers={"Cookie": cookie, "X-CSRF-Token": owner_csrf},
    )
    assert status == 404
    assert payload["error"] == "unknown_skill_revision"


def test_public_skill_mission_analysis_requires_owner_csrf_and_fixed_payload(public_server, monkeypatch):
    cookie, csrf = _owner_session(public_server)
    captured = []
    safe_analysis = {
        "analysis_version": 1,
        "outcome_class": "verified_success",
        "candidate_seed_eligible": True,
        "reason_code": "ready_for_owner_authored_candidate",
        "analysis_digest": "b" * 64,
    }

    class FakeSkills:
        def analyze_mission(self, owner_session_token, mission_id):
            assert owner_session_token == OWNER_TOKEN
            captured.append(mission_id)
            if mission_id == "foreign-mission":
                raise PermissionError("mission access denied")
            return safe_analysis

    monkeypatch.setattr(bridge.Handler, "_skill_service", lambda self: FakeSkills())

    status, _payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/skills/mission-analysis",
        body={"mission_id": "owned-mission"},
        headers={"Cookie": cookie},
    )
    assert status == 401

    status, _payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/skills/mission-analysis",
        body={"mission_id": "owned-mission"},
        headers={"Cookie": cookie, "X-CSRF-Token": "incorrect-token"},
    )
    assert status == 401

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/skills/mission-analysis",
        body={"mission_id": "owned-mission", "objective": "forged"},
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 400
    assert payload["error"] == "invalid_mission_analysis_request"
    assert captured == []

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/skills/mission-analysis",
        body={"mission_id": "owned-mission"},
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 200
    assert payload == {"ok": True, "analysis": safe_analysis}
    assert captured == ["owned-mission"]

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/skills/mission-analysis",
        body={"mission_id": "foreign-mission"},
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 404
    assert payload["error"] == "unknown_mission"
    assert captured == ["owned-mission", "foreign-mission"]


def test_public_skill_mission_analysis_requires_owner_not_only_public_session(public_server, monkeypatch):
    public_cookie, public_csrf, _ = _public_session(public_server)
    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/skills/mission-analysis",
        body={"mission_id": "mission-owned"},
        headers={"Cookie": public_cookie, "X-CSRF-Token": public_csrf},
    )
    assert status == 403
    assert payload["error"] == "owner_authorization_required"


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


@pytest.mark.parametrize(
    ("action", "suffix", "capability"),
    (
        ("files", "/files?path=.", "workspace_read"),
        ("file", "/file?path=secret.txt", "workspace_read"),
        ("git", "/git?operation=diff", "git_read"),
    ),
)
def test_public_workspace_views_fail_closed_without_secure_descriptor_support(
    public_server, monkeypatch, action, suffix, capability
):
    cookie, _csrf = _owner_session(public_server)
    workspace = SimpleNamespace(
        supports_secure_public_workspace_access=action == "git",
        supports_secure_public_git_access=False,
        close=lambda: None,
    )

    def workspace_for_mission(_handler, mission_id, _owner, requested_capability):
        assert mission_id == "mission-1"
        assert requested_capability == capability
        return SimpleNamespace(mission_id=mission_id), object(), workspace

    monkeypatch.setattr(bridge.Handler, "_workspace_for_mission", workspace_for_mission)
    status, payload, _headers = _request(
        public_server,
        "GET",
        f"/api/public/workspace/mission-1{suffix}",
        headers={"Cookie": cookie},
    )
    assert status == 501
    assert payload == {"ok": False, "error": "secure_workspace_access_unavailable"}


def test_ui_explains_secure_workspace_views_unavailable():
    source = Path("web/app.js").read_text(encoding="utf-8")
    assert "secure_workspace_access_unavailable:" in source
    assert "عرض مساحة العمل غير متاح على هذا النظام" in source


def test_desktop_owner_first_run_is_capability_gated_and_one_time(public_server, monkeypatch):
    monkeypatch.setattr(bridge, "DESKTOP_MODE", True)
    monkeypatch.setattr(bridge, "DESKTOP_SETUP_TOKEN", "one-time-desktop-capability")
    account_exists = {"value": False}
    created = []
    defaults = []

    class FakeProjects:
        def ensure_default(self, owner_id):
            defaults.append(owner_id)

    def create_owner(username, password):
        created.append((username, password))
        account_exists["value"] = True
        return 7

    monkeypatch.setattr(bridge.owner_password, "owner_account_exists", lambda: account_exists["value"])
    monkeypatch.setattr(bridge.owner_password, "create_owner_account", create_owner)
    monkeypatch.setattr(bridge, "_project_store", lambda: FakeProjects())
    origin = f"http://{public_server.server_address[0]}:{public_server.server_address[1]}"

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/desktop/bootstrap-owner",
        body={"password": "a-long-owner-password"},
        headers={"Origin": origin},
    )
    assert status == 403
    assert payload["error"] == "desktop_setup_authorization_required"

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/desktop/bootstrap-owner",
        body={"password": "a-long-owner-password"},
        headers={
            "Origin": "http://attacker.invalid",
            "X-CyberSentinel-Setup-Key": "one-time-desktop-capability",
        },
    )
    assert status == 403
    assert payload["error"] == "origin_not_allowed"

    valid_headers = {
        "Origin": origin,
        "X-CyberSentinel-Setup-Key": "one-time-desktop-capability",
    }
    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/desktop/bootstrap-owner",
        body={"password": "short"},
        headers=valid_headers,
    )
    assert status == 400
    assert payload["error"] == "password_must_be_12_to_256_characters"
    assert created == []

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/desktop/bootstrap-owner",
        body={"password": "a-long-owner-password"},
        headers=valid_headers,
    )
    assert status == 201
    assert payload == {"ok": True, "owner_created": True}
    assert created == [(bridge.owner_password.OWNER_USERNAME, "a-long-owner-password")]
    assert defaults == [7]
    assert "a-long-owner-password" not in json.dumps(payload)

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/desktop/bootstrap-owner",
        body={"password": "a-second-long-password"},
        headers=valid_headers,
    )
    assert status == 409
    assert payload["error"] == "owner_account_already_exists"
    assert len(created) == 1


def test_project_import_requires_main_process_capability_owner_and_csrf(public_server, monkeypatch, tmp_path):
    monkeypatch.setattr(bridge, "DESKTOP_MODE", True)
    monkeypatch.setattr(bridge, "DESKTOP_SETUP_TOKEN", "native-folder-capability")
    cookie, csrf = _owner_session(public_server)
    selected_root = tmp_path / "chosen-folder"
    selected_root.mkdir()
    captured = {}

    class FakeProject:
        def public(self, *, mission_count=None):
            return {"project_id": "project-1", "name": "Imported", "mission_count": mission_count}

    class FakeProjects:
        def create(self, owner_id, name, description, *, selected_root):
            captured.update(owner_id=owner_id, name=name, description=description, selected_root=selected_root)
            return FakeProject()

    monkeypatch.setattr(bridge, "_project_store", lambda: FakeProjects())
    origin = f"http://{public_server.server_address[0]}:{public_server.server_address[1]}"
    body = {"name": "Imported", "description": "from native picker", "selected_root": str(selected_root)}
    headers = {"Cookie": cookie, "Origin": origin, "X-CSRF-Token": csrf}

    status, payload, _headers = _request(
        public_server, "POST", "/api/public/projects/import", body=body, headers=headers
    )
    assert status == 403
    assert payload["error"] == "native_folder_selection_required"

    capability_headers = {
        **headers,
        "X-CyberSentinel-Desktop-Capability": "native-folder-capability",
    }
    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/projects/import",
        body=body,
        headers={**capability_headers, "X-CSRF-Token": "invalid"},
    )
    assert status == 401
    assert payload["error"] == "invalid csrf token"

    status, payload, _headers = _request(
        public_server,
        "POST",
        "/api/public/projects/import",
        body=body,
        headers=capability_headers,
    )
    assert status == 201
    assert payload["project"]["project_id"] == "project-1"
    assert captured == {
        "owner_id": 7,
        "name": "Imported",
        "description": "from native picker",
        "selected_root": str(selected_root),
    }


class _FakeMCPStore:
    def __init__(self):
        self.calls = []
        self.server_id = "mcp_" + "a" * 32
        self.server = {
            "server_id": self.server_id,
            "endpoint": "https://mcp.example.test/mcp",
            "trust_level": "UNTRUSTED",
            "identity_sha256": "",
            "protocol_version": "",
            "updated_at": "2026-10-05T00:00:00+00:00",
        }
        self.tool = {
            "name": "lookup_record",
            "schema": {"input": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}, "output": None},
            "schema_sha256": "a" * 64,
            "approved": False,
        }

    def register_server(self, **kwargs):
        self.calls.append(("register", kwargs))
        return {**self.server, "endpoint": kwargs["endpoint"]}

    def list_servers(self, **kwargs):
        self.calls.append(("list", kwargs))
        return [{**self.server, "tools": [dict(self.tool)]}]

    def get_server(self, **kwargs):
        self.calls.append(("get_server", kwargs))
        return dict(self.server)

    def get_tool(self, **kwargs):
        self.calls.append(("get_tool", kwargs))
        return dict(self.tool)

    def set_trust(self, **kwargs):
        self.calls.append(("trust", kwargs))
        if not isinstance(kwargs["trust_level"], str) or kwargs["trust_level"] not in {"TRUSTED", "KNOWN", "UNTRUSTED", "BLOCKED"}:
            raise ValueError("invalid_mcp_trust_level")
        self.server["trust_level"] = kwargs["trust_level"]
        return dict(self.server)

    def approve_tool(self, **kwargs):
        self.calls.append(("approve", kwargs))
        self.tool["approved"] = True
        return dict(self.tool)


def _fake_mcp_context(self, mission_id, owner):
    if mission_id in {"foreign", "missing"}:
        raise KeyError("unknown_mission")
    return None, f"owner:{int(owner['owner_id'])}", None, {
        "scope_snapshot_id": "scope-safe",
        "target_id": "target-safe",
        "program_id": "program-safe",
    }


def test_public_mcp_management_requires_owner_csrf_and_exact_mission(public_server, monkeypatch):
    import security.scope_resolver as scope_resolver

    store = _FakeMCPStore()
    calls = []
    monkeypatch.setattr(bridge.Handler, "_mcp_mission_context", _fake_mcp_context)
    monkeypatch.setattr(bridge.Handler, "_mcp_server_store", lambda self: store)
    monkeypatch.setattr(bridge.Handler, "_assert_mcp_endpoint_scope", staticmethod(lambda endpoint, _scope: endpoint))
    cookie, csrf = _owner_session(public_server)

    status, _, _ = _request(public_server, "GET", "/api/public/missions/mission-safe/mcp", headers={"Cookie": cookie})
    assert status == 401
    status, _, _ = _request(
        public_server, "POST", "/api/public/missions/mission-safe/mcp",
        body={"endpoint": "https://mcp.example.test/mcp"}, headers={"Cookie": cookie},
    )
    assert status == 401

    status, registered, _ = _request(
        public_server, "POST", "/api/public/missions/mission-safe/mcp",
        body={"endpoint": "https://mcp.example.test/mcp"}, headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 201
    assert registered["server"]["trust_level"] == "UNTRUSTED"
    assert store.calls[-1][1]["owner_identity_ref"] == "owner:7"
    assert store.calls[-1][1]["mission_id"] == "mission-safe"

    status, inventory, _ = _request(
        public_server, "GET", "/api/public/missions/mission-safe/mcp",
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 200
    assert inventory["servers"][0]["tools"][0]["schema_sha256"] == "a" * 64
    assert "schema" not in inventory["servers"][0]["tools"][0]
    assert "owner_identity_ref" not in json.dumps(inventory)

    status, details, _ = _request(
        public_server, "GET",
        f"/api/public/missions/mission-safe/mcp?server_id={store.server_id}&tool_name=lookup_record",
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 200
    assert details["tool"]["name"] == "lookup_record"
    assert details["tool"]["schema_sha256"] == "a" * 64

    status, trusted, _ = _request(
        public_server, "POST", f"/api/public/missions/mission-safe/mcp/{store.server_id}/trust",
        body={"trust_level": "TRUSTED"}, headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 200
    assert trusted["server"]["trust_level"] == "TRUSTED"
    status, approved, _ = _request(
        public_server, "POST", f"/api/public/missions/mission-safe/mcp/{store.server_id}/approve",
        body={"tool_name": "lookup_record", "schema_sha256": "a" * 64},
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 200
    assert approved["tool"]["approved"] is True
    assert all(call[1].get("owner_identity_ref", "owner:7") == "owner:7" for call in store.calls)

    status, malformed_trust, _ = _request(
        public_server, "POST", f"/api/public/missions/mission-safe/mcp/{store.server_id}/trust",
        body={"trust_level": []}, headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 400
    assert malformed_trust["error"] == "invalid_mcp_trust_level"

    status, denied, _ = _request(
        public_server, "GET", "/api/public/missions/foreign/mcp",
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 404
    assert denied == {"ok": False, "error": "unknown_mission_or_mcp_record"}

    status, rejected, _ = _request(
        public_server, "POST", "/api/public/missions/mission-safe/mcp",
        body={"endpoint": "https://mcp.example.test/mcp", "owner_identity_ref": "owner:999"},
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 400
    assert rejected["error"] == "invalid_mcp_registration"


def test_public_mcp_inventory_is_size_bounded(public_server, monkeypatch):
    class LargeStore(_FakeMCPStore):
        def list_servers(self, **kwargs):
            return [{
                **self.server,
                "server_id": "mcp_" + f"{index:032x}",
                "tools": [{"name": "t" * 128, "schema_sha256": "b" * 64, "approved": False} for _ in range(32)],
            } for index in range(32)]

    monkeypatch.setattr(bridge.Handler, "_mcp_mission_context", _fake_mcp_context)
    monkeypatch.setattr(bridge.Handler, "_mcp_server_store", lambda self: LargeStore())
    cookie, csrf = _owner_session(public_server)
    status, payload, _ = _request(
        public_server, "GET", "/api/public/missions/mission-safe/mcp",
        headers={"Cookie": cookie, "X-CSRF-Token": csrf},
    )
    assert status == 413
    assert payload == {"ok": False, "error": "mcp_inventory_too_large"}


def test_mcp_mission_context_checks_canonical_owner_integrity_and_capabilities(monkeypatch):
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from security.mission_authorization import MissionAuthorizationSnapshot

    created = datetime.now(timezone.utc)
    snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="owner:7", mission_id="mission-safe", target_identity="target-safe",
        scope=["network"], allowed_actions=["mcp.discover", "mcp.invoke"], forbidden_actions=[],
        allowed_tools=["mcp.discover", "mcp.invoke"], time_window={"timezone": "UTC"}, max_duration=3600,
        rate_limits={"mcp.discover": 10, "mcp.invoke": 10},
        network_boundary={"allowed": ["https://mcp.example.test"]}, data_boundary={"allowed": ["target-safe"]},
        credential_boundary={"allowed": []}, workspace_boundary={}, policy_version="test-policy",
        owner_approval="explicit-test-owner-approval", created_at=created.isoformat(),
        expires_at=(created + timedelta(hours=1)).isoformat(),
    )
    scope = {"scope_snapshot_id": "scope-safe", "target_id": "target-safe", "program_id": "program-safe"}
    mission = SimpleNamespace(
        mission_id="mission-safe", owner_identity_ref="owner:7", authorization_snapshot=snapshot.to_dict(),
        scope_snapshot=scope, provenance={"authorization_snapshot_version": 1}, verify_integrity=lambda: True,
    )

    class Service:
        def load_authorized_mission(self, mission_id, owner_session_token):
            assert owner_session_token == OWNER_TOKEN
            if mission_id != "mission-safe":
                raise KeyError("unknown_mission")
            return mission, "owner:7"

    dummy = SimpleNamespace(_mission_service=lambda: Service())
    loaded, owner_ref, loaded_snapshot, loaded_scope = bridge.Handler._mcp_mission_context(
        dummy, "mission-safe", {"session_token": OWNER_TOKEN}
    )
    assert loaded is mission
    assert owner_ref == "owner:7"
    assert loaded_snapshot.mission_id == "mission-safe"
    assert loaded_scope == scope

    mission.verify_integrity = lambda: False
    with pytest.raises(ValueError, match="mission_integrity_invalid"):
        bridge.Handler._mcp_mission_context(dummy, "mission-safe", {"session_token": OWNER_TOKEN})

    mission.verify_integrity = lambda: True
    insufficient = MissionAuthorizationSnapshot.create(
        owner_identity="owner:7", mission_id="mission-safe", target_identity="target-safe",
        scope=["network"], allowed_actions=["mcp.discover"], forbidden_actions=[], allowed_tools=["mcp.discover"],
        time_window={"timezone": "UTC"}, max_duration=3600, rate_limits={"mcp.discover": 1},
        network_boundary={"allowed": ["https://mcp.example.test"]}, data_boundary={"allowed": ["target-safe"]},
        credential_boundary={"allowed": []}, workspace_boundary={}, policy_version="test-policy",
        owner_approval="explicit-test-owner-approval", created_at=created.isoformat(),
        expires_at=(created + timedelta(hours=1)).isoformat(),
    )
    mission.authorization_snapshot = insufficient.to_dict()
    with pytest.raises(PermissionError, match="mcp_mission_capability_missing"):
        bridge.Handler._mcp_mission_context(dummy, "mission-safe", {"session_token": OWNER_TOKEN})
