from __future__ import annotations

"""Adversarial tests for the canonical username+password Owner authentication.

These tests use a dedicated TEST-ONLY password. The real Owner password never
appears here, in fixtures, or in any committed artifact.
"""

import sqlite3

import pytest

from core import db as core_db
from security import owner_password as owner_auth
from security.owner_password_bootstrap import main as bootstrap_main

TEST_PASSWORD = "correct-horse-battery-staple-TEST-ONLY-4f9a"
WRONG_PASSWORD = "definitely-not-the-owner-password-TEST"
OTHER_PASSWORD = "another-TEST-password-2c71"


@pytest.fixture()
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "test-intel.db")
    with core_db.connect() as con:
        yield con


@pytest.fixture()
def owner_account(isolated_db):
    owner_auth.create_owner_account(owner_auth.OWNER_USERNAME, TEST_PASSWORD)


def _all_text_values(con):
    tables = [
        r[0]
        for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    ]
    for table in tables:
        for row in con.execute(f"SELECT * FROM {table}").fetchall():
            for value in row:
                yield value


def _assert_no_plaintext(con, secret: str):
    for value in _all_text_values(con):
        assert secret not in str(value)


class TestBootstrap:
    def test_bootstrap_stores_verifier_only(self, isolated_db):
        owner_auth.create_owner_account(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        account = owner_auth.get_owner_account(owner_auth.OWNER_USERNAME)
        assert account is not None
        assert account["password_hash"].startswith("scrypt$")
        assert account["kdf_algorithm"] == "scrypt"
        assert account["status"] == "active"
        _assert_no_plaintext(isolated_db, TEST_PASSWORD)

    def test_bootstrap_is_idempotent_and_never_overwrites(self, isolated_db):
        owner_auth.create_owner_account(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        with pytest.raises(owner_auth.OwnerAuthenticationError):
            owner_auth.create_owner_account(
                owner_auth.OWNER_USERNAME, OTHER_PASSWORD
            )
        # Original credential still valid.
        session = owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        assert session["authentication_method"] == "username_password"

    def test_bootstrap_rejects_non_canonical_username(self, isolated_db):
        with pytest.raises(owner_auth.OwnerAuthenticationError):
            owner_auth.create_owner_account("attacker", TEST_PASSWORD)

    def test_bootstrap_cli_interactive_flow(self, isolated_db, monkeypatch, capsys):
        monkeypatch.setattr("builtins.input", lambda _prompt: "mosfiry")
        answers = iter([TEST_PASSWORD, TEST_PASSWORD])
        monkeypatch.setattr("getpass.getpass", lambda _prompt: next(answers))
        assert bootstrap_main([]) == 0
        assert owner_auth.owner_account_exists()
        captured = capsys.readouterr()
        assert TEST_PASSWORD not in captured.out
        assert TEST_PASSWORD not in captured.err
        _assert_no_plaintext(isolated_db, TEST_PASSWORD)

    def test_bootstrap_cli_mismatch_aborts_without_account(self, isolated_db, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _prompt: "mosfiry")
        answers = iter([TEST_PASSWORD, "mismatch-TEST"])
        monkeypatch.setattr("getpass.getpass", lambda _prompt: next(answers))
        assert bootstrap_main([]) == 1
        assert not owner_auth.owner_account_exists()


class TestLogin:
    def test_login_success_creates_secure_session(self, owner_account):
        session = owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        assert session["owner_id"] >= 1
        assert session["username"] == "mosfiry"
        assert session["authentication_method"] == "username_password"
        assert len(session["session_id"]) >= 32
        # Session id never derives from identity material.
        assert "mosfiry" not in session["session_id"]
        assert TEST_PASSWORD not in session["session_id"]

    def test_two_logins_get_independent_random_ids(self, owner_account):
        first = owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        second = owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        assert first["session_id"] != second["session_id"]

    def test_wrong_password_fails(self, owner_account):
        with pytest.raises(owner_auth.OwnerAuthenticationError):
            owner_auth.login(owner_auth.OWNER_USERNAME, WRONG_PASSWORD)

    def test_unknown_username_fails_with_generic_error(self, owner_account):
        with pytest.raises(owner_auth.OwnerAuthenticationError) as known:
            owner_auth.login(owner_auth.OWNER_USERNAME, WRONG_PASSWORD)
        with pytest.raises(owner_auth.OwnerAuthenticationError) as unknown:
            owner_auth.login("nobody-TEST", "whatever-TEST")
        assert str(known.value) == str(unknown.value)

    def test_disabled_account_cannot_login(self, owner_account, isolated_db):
        with core_db.connect() as con:
            con.execute("UPDATE owner_accounts SET status='disabled'")
        with pytest.raises(owner_auth.OwnerAuthenticationError):
            owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)


class TestSessions:
    def test_valid_session_resolves_owner(self, owner_account):
        session = owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        resolved = owner_auth.resolve_session(session["session_id"])
        assert resolved is not None
        assert resolved["username"] == "mosfiry"
        assert resolved["owner_id"] == session["owner_id"]

    def test_expired_session_rejected(self, owner_account):
        session = owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        with core_db.connect() as con:
            con.execute(
                "UPDATE owner_sessions SET expires_at='2000-01-01T00:00:00+00:00'"
                " WHERE session_id=?",
                (session["session_id"],),
            )
        assert owner_auth.resolve_session(session["session_id"]) is None

    def test_revoked_session_rejected(self, owner_account):
        session = owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        assert owner_auth.revoke_session(session["session_id"]) is True
        assert owner_auth.resolve_session(session["session_id"]) is None

    def test_forged_session_rejected(self, owner_account):
        assert owner_auth.resolve_session("forged-session-TEST") is None
        assert owner_auth.resolve_session("") is None
        assert owner_auth.resolve_session(None) is None  # type: ignore[arg-type]

    def test_tampered_authentication_method_rejected(self, owner_account):
        session = owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        with core_db.connect() as con:
            con.execute(
                "UPDATE owner_sessions SET authentication_method='owner_token'"
                " WHERE session_id=?",
                (session["session_id"],),
            )
        assert owner_auth.resolve_session(session["session_id"]) is None

    def test_sessions_never_persist_password_material(self, owner_account, isolated_db):
        owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        _assert_no_plaintext(isolated_db, TEST_PASSWORD)


class TestClientForgery:
    def test_boolean_forgery_never_authenticates(self, owner_account):
        claims = {
            "owner_authenticated": True,
            "is_owner": True,
            "owner": True,
        }
        assert owner_auth.authenticated_owner(None, claims) is None

    def test_role_forgery_never_authenticates(self, owner_account):
        claims = {"role": "owner"}
        assert owner_auth.authenticated_owner(None, claims) is None

    def test_method_and_id_forgery_never_authenticates(self, owner_account):
        claims = {"authentication_method": "owner_token", "owner_id": 1}
        assert owner_auth.authenticated_owner(None, claims) is None

    def test_magic_owner_string_never_authenticates(self, owner_account):
        assert owner_auth.resolve_session("Owner") is None
        assert owner_auth.authenticated_owner("Owner", {"role": "owner"}) is None

    def test_owner_token_value_never_authenticates(self, owner_account):
        assert owner_auth.resolve_session("CSO-TOKEN-LIKE-VALUE") is None
        assert owner_auth.authenticated_owner("CSO-TOKEN-LIKE-VALUE", None) is None

    def test_valid_session_wins_and_claims_are_ignored(self, owner_account):
        session = owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        claims = {"role": "attacker", "owner_id": 999}
        resolved = owner_auth.authenticated_owner(session["session_id"], claims)
        assert resolved is not None
        assert resolved["owner_id"] == session["owner_id"]
        assert "role" not in claims


class TestPasswordReset:
    def test_reset_requires_current_password(self, owner_account):
        with pytest.raises(owner_auth.OwnerAuthenticationError):
            owner_auth.reset_password(
                owner_auth.OWNER_USERNAME, WRONG_PASSWORD, OTHER_PASSWORD
            )
        # Old credential still valid: reset was not a bypass.
        assert owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)

    def test_reset_rotates_and_revokes_sessions(self, owner_account):
        session = owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        owner_auth.reset_password(
            owner_auth.OWNER_USERNAME, TEST_PASSWORD, OTHER_PASSWORD
        )
        assert owner_auth.resolve_session(session["session_id"]) is None
        with pytest.raises(owner_auth.OwnerAuthenticationError):
            owner_auth.login(owner_auth.OWNER_USERNAME, TEST_PASSWORD)
        assert owner_auth.login(owner_auth.OWNER_USERNAME, OTHER_PASSWORD)

    def test_unknown_account_reset_fails_closed(self, isolated_db):
        with pytest.raises(owner_auth.OwnerAuthenticationError):
            owner_auth.reset_password("nobody-TEST", "x-TEST", "y-TEST")


class TestKDF:
    def test_hashes_are_salted_and_unique(self):
        first = owner_auth.hash_password(TEST_PASSWORD)
        second = owner_auth.hash_password(TEST_PASSWORD)
        assert first["password_hash"] != second["password_hash"]

    def test_verify_roundtrip(self):
        record = owner_auth.hash_password(TEST_PASSWORD)
        assert owner_auth.verify_password(record["password_hash"], TEST_PASSWORD)
        assert not owner_auth.verify_password(record["password_hash"], WRONG_PASSWORD)

    def test_verify_rejects_malformed_hashes(self):
        for bad in ["", "plain", "bcrypt$1$2$3$4$5", "scrypt$1$1$1$zz$zz"]:
            assert not owner_auth.verify_password(bad, TEST_PASSWORD)

    def test_empty_password_refused(self):
        with pytest.raises(ValueError):
            owner_auth.hash_password("")
