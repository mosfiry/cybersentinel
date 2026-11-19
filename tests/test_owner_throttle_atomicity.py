"""Adversarial battery for the atomic login throttle (session 11, unit X-K.2).

The failure slot is consumed atomically BEFORE any KDF work inside one
BEGIN IMMEDIATE transaction, so a concurrent burst can never overshoot
LOGIN_FAILURE_THRESHOLD recorded failures, and once the threshold is
reached no concurrent attempt (even with CORRECT credentials) can slip
through or extend the window. Unknown usernames never create rows, and
no rejection path ever mints a session.
"""
from __future__ import annotations

import getpass
import sqlite3
from threading import Barrier, Thread

import pytest

import core.db as core_db
from security import owner_password as op

TEST_PASSWORD = "atomic-throttle-battery-password-77"


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "atomic-throttle.db")
    yield tmp_path / "atomic-throttle.db"


def _bootstrap(monkeypatch, password=TEST_PASSWORD):
    from security.owner_password_bootstrap import main as bootstrap_main

    inputs = iter(["mosfiry"])
    prompts = iter([password, password])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
    monkeypatch.setattr(getpass, "getpass", lambda *_: next(prompts))
    assert bootstrap_main([]) == 0


def _throttle_row(db_path):
    with sqlite3.connect(db_path) as con:
        return con.execute(
            "SELECT failures, last_failure_at FROM owner_login_throttle WHERE username = 'mosfiry'"
        ).fetchone()


def _run_threads(count, worker):
    barrier = Barrier(count)
    errors: list[BaseException] = []

    def wrapped(i):
        try:
            barrier.wait(timeout=10)
            worker(i)
        except BaseException as exc:  # pragma: no cover - diagnostic only
            errors.append(exc)

    threads = [Thread(target=wrapped, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert errors == []


def test_threshold_never_overshot_under_concurrent_burst(tmp_db, monkeypatch):
    _bootstrap(monkeypatch)
    burst = op.LOGIN_FAILURE_THRESHOLD + 4

    def worker(_i):
        with pytest.raises(PermissionError):
            op.login("mosfiry", "wrong-concurrent-password")

    _run_threads(burst, worker)
    # Atomic reserve: the stored failure count can never exceed the threshold.
    row = _throttle_row(tmp_db)
    assert row is not None
    assert int(row[0]) <= op.LOGIN_FAILURE_THRESHOLD
    # Fail closed: correct credentials are rejected during the lockout.
    with pytest.raises(PermissionError):
        op.login("mosfiry", TEST_PASSWORD)
    with sqlite3.connect(tmp_db) as con:
        assert con.execute("SELECT COUNT(*) FROM owner_sessions").fetchone()[0] == 0


def test_locked_concurrent_correct_credentials_mint_no_session(tmp_db, monkeypatch):
    _bootstrap(monkeypatch)
    for _ in range(op.LOGIN_FAILURE_THRESHOLD):
        with pytest.raises(PermissionError):
            op.login("mosfiry", "not-the-password")
    before = _throttle_row(tmp_db)

    def worker(_i):
        try:
            op.login("mosfiry", TEST_PASSWORD)
            raise AssertionError("session minted during lockout")
        except PermissionError:
            pass

    _run_threads(6, worker)
    after = _throttle_row(tmp_db)
    # Attempts during lockout never move the counter or extend the window.
    assert list(after) == list(before)
    with sqlite3.connect(tmp_db) as con:
        assert con.execute("SELECT COUNT(*) FROM owner_sessions").fetchone()[0] == 0


def test_concurrent_unknown_usernames_never_create_rows(tmp_db, monkeypatch):
    _bootstrap(monkeypatch)

    def worker(i):
        with pytest.raises(PermissionError):
            op.login("attacker-%d" % i, "whatever")

    _run_threads(8, worker)
    with sqlite3.connect(tmp_db) as con:
        assert con.execute("SELECT COUNT(*) FROM owner_login_throttle").fetchone()[0] == 0
    # The canonical account is unaffected by the burst on other usernames.
    assert op.login("mosfiry", TEST_PASSWORD)["session_id"]


def test_reset_password_slots_are_counted_atomically(tmp_db, monkeypatch):
    _bootstrap(monkeypatch)
    for _ in range(op.LOGIN_FAILURE_THRESHOLD):
        with pytest.raises(PermissionError):
            op.reset_password("mosfiry", "wrong-current-password", "rotated-password-value")
    row = _throttle_row(tmp_db)
    assert int(row[0]) == op.LOGIN_FAILURE_THRESHOLD
    # The reset KDF oracle is locked too: even the CORRECT current password fails.
    with pytest.raises(PermissionError):
        op.reset_password("mosfiry", TEST_PASSWORD, "rotated-password-value")
    row = _throttle_row(tmp_db)
    assert int(row[0]) == op.LOGIN_FAILURE_THRESHOLD
    with sqlite3.connect(tmp_db) as con:
        assert con.execute("SELECT COUNT(*) FROM owner_sessions").fetchone()[0] == 0
