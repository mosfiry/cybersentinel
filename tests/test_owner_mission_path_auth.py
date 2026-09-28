"""Adversarial battery: bridge Owner-controlled mission routes authenticate
ONLY through the server-side username+password session.

Every rejection must happen BEFORE any MissionService/chat handler is reached
(handler_calls == 0). Client-supplied claims (OWNER_TOKEN values, magic "Owner"
strings, role/boolean forgeries, the transport BRIDGE_TOKEN) never authenticate.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread
import json

import pytest

import bridge
import core.db as core_db
from owner_session_testutils import allow_owner_sessions

PLAN = {"version": 1, "objective": "battery mission", "steps": [{"step_id": "s1", "objective": "status", "action": "status"}]}

OWNER_ROUTES = [
    ("GET", "/api/missions/m1", None),
    ("GET", "/api/missions/m1/status", None),
    ("GET", "/api/missions/m1/timeline", None),
    ("GET", "/api/missions/m1/evidence", None),
    ("GET", "/api/missions/m1/artifacts", None),
    ("GET", "/api/missions/m1/logs", None),
    ("POST", "/api/missions/m1/start", None),
    ("POST", "/api/missions/m1/pause", None),
    ("POST", "/api/missions/m1/resume", None),
    ("POST", "/api/missions/m1/cancel", None),
    ("POST", "/api/missions/m1/schedule", {"run_at": "2099-01-01T00:00:00+00:00"}),
    ("POST", "/api/missions", {"objective": "battery mission", "plan": PLAN}),
    ("POST", "/api/missions", {"text": "chat fallback"}),
]

FORGED_CREDENTIALS = [
    "unknown-session",
    "OWNER_TOKEN",
    "Owner",
    "owner",
    "true",
    json.dumps({"role": "owner", "owner_authenticated": True, "is_owner": True}),
    "bridge-test",
]


class OwnerActionRecorder:
    """Counts every Owner-controlled action reachable through the bridge."""

    def __init__(self):
        self.calls = 0

    def status(self, mission_id):
        self.calls += 1
        return {"mission_id": mission_id, "status": "RUNNING"}

    def timeline(self, mission_id):
        self.calls += 1
        return []

    def evidence(self, mission_id):
        self.calls += 1
        return []

    def artifacts(self, mission_id):
        self.calls += 1
        return []

    def logs(self, mission_id):
        self.calls += 1
        return []

    def create_mission(self, *args, **kwargs):
        self.calls += 1
        return {"mission_id": "m-counted", "status": "CREATED"}

    def start_mission(self, mission_id):
        self.calls += 1
        return {"mission_id": mission_id, "status": "RUNNING"}

    def pause_mission(self, mission_id):
        self.calls += 1
        return {"mission_id": mission_id, "status": "PAUSED"}

    def resume_mission(self, mission_id):
        self.calls += 1
        return {"mission_id": mission_id, "status": "RUNNING"}

    def cancel_mission(self, mission_id):
        self.calls += 1
        return {"mission_id": mission_id, "status": "CANCELLED"}

    def schedule_mission(self, mission_id, **kwargs):
        self.calls += 1
        return {"schedule_id": "s-counted"}

    def __call__(self, payload, *, owner_session_token):
        self.calls += 1
        return {"answer": "ok", "mission": None, "mission_id": None, "status": "completed"}


@pytest.fixture
def mission_bridge(tmp_path, monkeypatch):
    recorder = OwnerActionRecorder()
    monkeypatch.setattr(bridge, "BRIDGE_TOKEN", "bridge-test")
    monkeypatch.setattr(bridge, "DB_PATH", tmp_path / "mission-auth.sqlite3")
    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda self: recorder)
    monkeypatch.setattr(bridge, "chat", recorder)
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(method, path, payload=None, *, session="live-session", bridge_token="bridge-test", with_session=True):
        headers = {"X-CyberSentinel-Token": bridge_token}
        if with_session:
            headers["X-CyberSentinel-Owner-Session"] = session
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = json.loads(response.read() or b"{}")
        connection.close()
        return response.status, data

    try:
        yield request, recorder
    finally:
        server.shutdown()
        server.server_close()


def test_missing_owner_session_rejects_every_owner_route_before_any_handler(mission_bridge, monkeypatch):
    allow_owner_sessions(monkeypatch, "live-session")
    request, recorder = mission_bridge
    for method, path, payload in OWNER_ROUTES:
        code, body = request(method, path, payload, with_session=False)
        assert code == 403, (method, path, code, body)
    assert recorder.calls == 0


def test_forged_and_legacy_credentials_reject_every_owner_route(mission_bridge, monkeypatch):
    allow_owner_sessions(monkeypatch, "live-session")
    request, recorder = mission_bridge
    for value in FORGED_CREDENTIALS:
        for method, path, payload in OWNER_ROUTES:
            code, _ = request(method, path, payload, session=value)
            assert code == 403, (value, method, path, code)
    assert recorder.calls == 0


def test_revoked_session_rejects_every_owner_route(mission_bridge, monkeypatch):
    allow_owner_sessions(monkeypatch, "live-session")
    request, recorder = mission_bridge
    code, _ = request("GET", "/api/missions/m1")
    assert code == 200
    assert recorder.calls == 1
    allow_owner_sessions(monkeypatch)
    for method, path, payload in OWNER_ROUTES:
        code, _ = request(method, path, payload)
        assert code == 403, (method, path, code)
    assert recorder.calls == 1


def test_wrong_bridge_token_is_401_and_reaches_no_handler(mission_bridge, monkeypatch):
    allow_owner_sessions(monkeypatch, "live-session")
    request, recorder = mission_bridge
    for method, path, payload in OWNER_ROUTES:
        code, _ = request(method, path, payload, bridge_token="wrong")
        assert code == 401, (method, path, code)
    assert recorder.calls == 0


def test_valid_session_reaches_handlers_on_every_owner_route(mission_bridge, monkeypatch):
    allow_owner_sessions(monkeypatch, "live-session")
    request, recorder = mission_bridge
    expected = {
        ("POST", "/api/missions/m1/schedule"): 201,
        ("POST", "/api/missions"): 201,
    }
    for method, path, payload in OWNER_ROUTES:
        code, body = request(method, path, payload)
        assert code == expected.get((method, path), 200), (method, path, code, body)
        assert body.get("ok") is True
    assert recorder.calls == len(OWNER_ROUTES)


def test_real_password_session_lifecycle_gates_mission_routes(tmp_path, monkeypatch):
    """End-to-end over the real password DB: login, revoke, and expire."""
    from security import owner_password

    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "owner-auth.sqlite3")
    core_db.connect().close()
    monkeypatch.setattr(bridge, "BRIDGE_TOKEN", "bridge-test")
    monkeypatch.setattr(bridge, "DB_PATH", tmp_path / "bridge.sqlite3")
    recorder = OwnerActionRecorder()
    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda self: recorder)
    monkeypatch.setattr(bridge, "chat", recorder)
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(path, session, bridge_token="bridge-test"):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", path, headers={"X-CyberSentinel-Token": bridge_token, "X-CyberSentinel-Owner-Session": session})
        response = connection.getresponse()
        data = json.loads(response.read() or b"{}")
        connection.close()
        return response.status, data

    try:
        owner_password.create_owner_account("mosfiry", "battery-isolated-test-pass-42")
        with pytest.raises(PermissionError):
            owner_password.login("mosfiry", "wrong-password")
        session = owner_password.login("mosfiry", "battery-isolated-test-pass-42")
        code, body = request("/api/missions/m1", session["session_id"])
        assert code == 200 and body["ok"] is True
        assert recorder.calls == 1

        owner_password.revoke_session(session["session_id"])
        code, _ = request("/api/missions/m1", session["session_id"])
        assert code == 403
        assert recorder.calls == 1

        second = owner_password.login("mosfiry", "battery-isolated-test-pass-42")
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        with core_db.connect() as con:
            con.execute("UPDATE owner_sessions SET expires_at = ? WHERE session_id = ?", (expired, second["session_id"]))
            con.commit()
        code, _ = request("/api/missions/m1", second["session_id"])
        assert code == 403
        assert recorder.calls == 1
    finally:
        server.shutdown()
        server.server_close()
