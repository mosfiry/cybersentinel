"""Adversarial battery for owner-auth hardening (session 10, unit X-J).

Covers the accepted risks closed in session 10:
- X-J.1 login throttling: fail-closed lockout after repeated failures for
  the canonical username; expiry; counter reset on success; canonical-only
  keying (unknown usernames never create throttle rows, so the table
  cannot be flooded); the reset_password current-password check shares the
  same lockout (it is the same kind of KDF oracle).
- X-J.2 bootstrap atomicity: the UNIQUE constraint closes the
  check-then-insert race; IntegrityError converts to the generic
  already-exists PermissionError and no duplicate row is ever created.
- X-J.3 authenticated logout: bridge logout requires proof of possession
  of the live session token; body-supplied or forged session ids never
  revoke anything.

Uses an ISOLATED test password created only inside this test execution;
the real Owner password never appears here.
"""
from __future__ import annotations

import getpass
import json
import sqlite3
from datetime import timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread

import pytest

import bridge
import core.db as core_db
from security import owner_password as op
from security.owner_password_bootstrap import main as bootstrap_main

TEST_PASSWORD = "correct-horse-battery-staple-42"


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "test-owner-auth.db")
    yield tmp_path / "test-owner-auth.db"


def _bootstrap(monkeypatch, username="mosfiry", password=TEST_PASSWORD, confirm=None):
    inputs = iter([username])
    prompts = iter([password, confirm if confirm is not None else password])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
    monkeypatch.setattr(getpass, "getpass", lambda *_: next(prompts))
    return bootstrap_main([])


def _fail_login(count=op.LOGIN_FAILURE_THRESHOLD, password="not-the-password"):
    for _ in range(count):
        with pytest.raises(PermissionError):
            op.login("mosfiry", password)


# ---------------------------------------------------------------------------
# X-J.1: login throttling
# ---------------------------------------------------------------------------

def test_lockout_rejects_correct_credentials_fail_closed(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    _fail_login()
    # Fail closed: even CORRECT credentials are rejected during lockout.
    with pytest.raises(PermissionError):
        op.login("mosfiry", TEST_PASSWORD)
    with sqlite3.connect(tmp_db) as con:
        assert con.execute("SELECT COUNT(*) FROM owner_sessions").fetchone()[0] == 0


def test_lockout_expires_and_login_succeeds(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    _fail_login()
    real_now = op._now()
    monkeypatch.setattr(op, "_now", lambda: real_now + timedelta(seconds=op.LOGIN_LOCKOUT_SECONDS + 1))
    session = op.login("mosfiry", TEST_PASSWORD)
    assert op.resolve_session(session["session_id"]) is not None


def test_successful_login_resets_failure_counter(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    _fail_login(count=op.LOGIN_FAILURE_THRESHOLD - 1)
    assert op.login("mosfiry", TEST_PASSWORD)["session_id"]
    _fail_login(count=op.LOGIN_FAILURE_THRESHOLD - 1)
    # Still below threshold after the reset: correct login succeeds.
    assert op.login("mosfiry", TEST_PASSWORD)["session_id"]


def test_lockout_cannot_be_extended_by_attempts_during_lockout(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    _fail_login()
    # Attempts during lockout must not record new failures.
    for _ in range(5):
        with pytest.raises(PermissionError):
            op.login("mosfiry", "still-not-the-password")
    real_now = op._now()
    monkeypatch.setattr(op, "_now", lambda: real_now + timedelta(seconds=op.LOGIN_LOCKOUT_SECONDS + 1))
    # Window elapsed: correct login succeeds (failures were not pushed forward).
    assert op.login("mosfiry", TEST_PASSWORD)["session_id"]


def test_unknown_username_failures_never_flood_throttle_table(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    for i in range(20):
        with pytest.raises(PermissionError):
            op.login("attacker-%d" % i, "not-the-password")
    with sqlite3.connect(tmp_db) as con:
        assert con.execute("SELECT COUNT(*) FROM owner_login_throttle").fetchone()[0] == 0
    # The canonical account is unaffected by failures on other usernames.
    assert op.login("mosfiry", TEST_PASSWORD)["session_id"]


def test_forged_claims_during_lockout_mint_nothing(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    _fail_login()
    for forged in ("OWNER_TOKEN", "Owner", "true", json.dumps({"role": "owner", "is_owner": True})):
        with pytest.raises(PermissionError):
            op.login("mosfiry", forged)
    with sqlite3.connect(tmp_db) as con:
        assert con.execute("SELECT COUNT(*) FROM owner_sessions").fetchone()[0] == 0


def test_reset_password_shares_the_lockout(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    for _ in range(op.LOGIN_FAILURE_THRESHOLD):
        with pytest.raises(PermissionError):
            op.reset_password("mosfiry", "wrong-current-password", "rotated-password-value")
    # The reset KDF oracle is locked too: even the CORRECT current password fails.
    with pytest.raises(PermissionError):
        op.reset_password("mosfiry", TEST_PASSWORD, "rotated-password-value")
    # And login with correct credentials is locked as well.
    with pytest.raises(PermissionError):
        op.login("mosfiry", TEST_PASSWORD)
    with sqlite3.connect(tmp_db) as con:
        assert con.execute("SELECT COUNT(*) FROM owner_sessions").fetchone()[0] == 0


# ---------------------------------------------------------------------------
# X-J.2: bootstrap atomicity
# ---------------------------------------------------------------------------

class _NoRows:
    def fetchone(self):
        return None

    def fetchall(self):
        return []


class _StaleSelectConnection:
    """Simulates the check-then-insert race: SELECTs see no row (stale view)
    while the UNIQUE constraint on username still holds at INSERT time."""

    def __init__(self, con):
        self._con = con

    def execute(self, sql, *args, **kwargs):
        if sql.lstrip().upper().startswith("SELECT") and "owner_accounts" in sql:
            return _NoRows()
        return self._con.execute(sql, *args, **kwargs)

    def commit(self):
        self._con.commit()

    def rollback(self):
        self._con.rollback()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_bootstrap_race_closed_by_unique_constraint(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    real_connect = core_db.connect
    with monkeypatch.context() as m:
        m.setattr(core_db, "connect", lambda: _StaleSelectConnection(real_connect()))
        with pytest.raises(PermissionError) as excinfo:
            op.create_owner_account("mosfiry", "racing-password-attempt")
    assert "exists" in str(excinfo.value)
    with sqlite3.connect(tmp_db) as con:
        assert con.execute("SELECT COUNT(*) FROM owner_accounts").fetchone()[0] == 1
    # The racing attempt never replaced the real verifier.
    assert op.login("mosfiry", TEST_PASSWORD)["session_id"]


# ---------------------------------------------------------------------------
# X-J.3: authenticated logout (proof of possession)
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_bridge(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, "BRIDGE_TOKEN", "bridge-test")
    db_path = tmp_path / "bridge-auth.sqlite3"
    monkeypatch.setattr(bridge, "DB_PATH", db_path)
    monkeypatch.setattr(core_db, "DB_PATH", db_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(method, path, payload=None, *, session=None, bridge_token="bridge-test"):
        headers = {"X-CyberSentinel-Token": bridge_token}
        if session is not None:
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

    yield request
    server.shutdown()
    server.server_close()


def test_logout_requires_session_possession(auth_bridge, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    session = op.login("mosfiry", TEST_PASSWORD)
    token = session["session_id"]
    # 1. No session header: a body-supplied session_id is ignored entirely.
    status, _ = auth_bridge("POST", "/api/auth/logout", {"session_id": token}, session=None)
    assert status == 403
    assert op.resolve_session(token) is not None
    # 2. Forged header: never revokes the real session.
    status, _ = auth_bridge("POST", "/api/auth/logout", {"session_id": token}, session="forged-session")
    assert status == 403
    assert op.resolve_session(token) is not None
    # 3. Proof of possession: the live session revokes itself.
    status, _ = auth_bridge("POST", "/api/auth/logout", None, session=token)
    assert status == 200
    assert op.resolve_session(token) is None
    # 4. Replay: the revoked token no longer authenticates anything.
    status, _ = auth_bridge("POST", "/api/auth/logout", None, session=token)
    assert status == 403


def test_logout_never_revokes_other_sessions(auth_bridge, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    first = op.login("mosfiry", TEST_PASSWORD)
    second = op.login("mosfiry", TEST_PASSWORD)
    # Presenting the first token while naming the second in the body:
    # only the presented (first) session may be revoked.
    status, _ = auth_bridge("POST", "/api/auth/logout", {"session_id": second["session_id"]}, session=first["session_id"])
    assert status == 200
    assert op.resolve_session(first["session_id"]) is None
    assert op.resolve_session(second["session_id"]) is not None
