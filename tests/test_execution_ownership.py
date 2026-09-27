"""HTTP-level authorization and request-ownership tests for the execution endpoints.

BRIDGE_TOKEN is transport authentication only. GET /api/execution/{request_id}
and POST /api/cancel additionally require a valid Owner session that OWNS the
request. Every other case must fail closed without leaking lifecycle data.
"""
from __future__ import annotations

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import threading

import pytest

import bridge
import core.db as core_db
from core.lifecycle import begin, get, transition
from security import owner_password as op

TEST_PASSWORD = "execution-ownership-battery-password-01"
BRIDGE_TOKEN = "test-bridge-token"


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "test-exec-ownership.db")
    monkeypatch.setattr(bridge, "BRIDGE_TOKEN", BRIDGE_TOKEN)
    op.create_owner_account(op.OWNER_USERNAME, TEST_PASSWORD)
    session_a = op.login(op.OWNER_USERNAME, TEST_PASSWORD)
    session_b = op.login(op.OWNER_USERNAME, TEST_PASSWORD)
    begin("req-owned-a", "test", owner_session_id=session_a["session_id"])
    begin("req-owned-b", "test", owner_session_id=session_b["session_id"])
    transition("req-owned-a", "planned")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield {
            "server": httpd,
            "session_a": session_a["session_id"],
            "session_b": session_b["session_id"],
        }
    finally:
        httpd.shutdown()


def request(server, method, path, *, bridge_token=BRIDGE_TOKEN, owner_session=None, body=None):
    headers = {"Content-Type": "application/json"}
    if bridge_token is not None:
        headers["X-CyberSentinel-Token"] = bridge_token
    if owner_session is not None:
        headers["X-CyberSentinel-Owner-Session"] = owner_session
    connection = HTTPConnection("127.0.0.1", server["server"].server_address[1], timeout=5)
    connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
    response = connection.getresponse()
    payload = json.loads(response.read() or b"{}")
    connection.close()
    return response.status, payload


def test_get_execution_without_bridge_token_is_unauthorized(server):
    status, _ = request(server, "GET", "/api/execution/req-owned-a", bridge_token=None, owner_session=server["session_a"])
    assert status == 401


def test_get_execution_with_bridge_token_only_is_forbidden(server):
    status, _ = request(server, "GET", "/api/execution/req-owned-a", owner_session=None)
    assert status == 403


def test_get_execution_with_invalid_owner_session_is_forbidden(server):
    status, _ = request(server, "GET", "/api/execution/req-owned-a", owner_session="forged-session-id")
    assert status == 403


def test_get_execution_with_foreign_owner_session_is_forbidden(server):
    status, payload = request(server, "GET", "/api/execution/req-owned-a", owner_session=server["session_b"])
    assert status == 403
    assert "lifecycle" not in payload


def test_get_execution_with_owning_owner_session_succeeds(server):
    status, payload = request(server, "GET", "/api/execution/req-owned-a", owner_session=server["session_a"])
    assert status == 200
    assert payload["ok"] is True
    assert payload["request_id"] == "req-owned-a"


def test_get_execution_unknown_request_is_not_found(server):
    status, _ = request(server, "GET", "/api/execution/req-missing", owner_session=server["session_a"])
    assert status == 404


def test_cancel_without_bridge_token_is_unauthorized(server):
    status, _ = request(server, "POST", "/api/cancel", bridge_token=None, owner_session=server["session_a"], body={"request_id": "req-owned-a"})
    assert status == 401


def test_cancel_with_bridge_token_only_is_forbidden(server):
    status, _ = request(server, "POST", "/api/cancel", body={"request_id": "req-owned-a"})
    assert status == 403


def test_cancel_of_foreign_request_is_forbidden(server):
    status, _ = request(server, "POST", "/api/cancel", owner_session=server["session_b"], body={"request_id": "req-owned-a"})
    assert status == 403
    assert get("req-owned-a").cancel_requested is False


def test_cancel_by_owning_owner_session_succeeds(server):
    status, payload = request(server, "POST", "/api/cancel", owner_session=server["session_a"], body={"request_id": "req-owned-a"})
    assert status == 200
    assert payload["ok"] is True
    assert payload["cancel_requested"] is True


def test_cancel_unknown_request_is_not_found(server):
    status, _ = request(server, "POST", "/api/cancel", owner_session=server["session_a"], body={"request_id": "req-missing"})
    assert status == 404


def test_unbound_request_fails_closed(server):
    begin("req-legacy-unbound", "test")
    status, payload = request(server, "GET", "/api/execution/req-legacy-unbound", owner_session=server["session_a"])
    assert status == 403
    assert "lifecycle" not in payload
