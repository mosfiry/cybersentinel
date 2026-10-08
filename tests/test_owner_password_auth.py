"""Adversarial battery for canonical Owner username+password authentication.

Uses an ISOLATED test password created only inside this test execution.
The real Owner password must never appear here.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import core.db as core_db
from security import owner_password as op
from security.owner_password_bootstrap import main as bootstrap_main
from security.session_reference import session_reference

TEST_PASSWORD = "correct-horse-battery-staple-42"


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "test-owner-auth.db")
    yield tmp_path / "test-owner-auth.db"


def _bootstrap(monkeypatch, username="mosfiry", password=TEST_PASSWORD, confirm=None):
    inputs = iter([username])
    prompts = iter([password, confirm if confirm is not None else password])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda *_: next(prompts))
    return bootstrap_main([])


def test_bootstrap_creates_verifier_only(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    assert op.owner_account_exists()
    with sqlite3.connect(tmp_db) as con:
        rows = con.execute("SELECT username, password_hash, kdf_algorithm, kdf_params_json, status FROM owner_accounts").fetchall()
    assert len(rows) == 1
    username, password_hash, kdf_algorithm, kdf_params_json, status = rows[0]
    assert username == "mosfiry"
    assert status == "active"
    assert kdf_algorithm == "scrypt"
    assert TEST_PASSWORD not in password_hash
    assert TEST_PASSWORD not in kdf_params_json
    assert len(password_hash) == 64  # raw scrypt digest hex


def test_bootstrap_idempotent_no_overwrite(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    with sqlite3.connect(tmp_db) as con:
        before = con.execute("SELECT password_hash FROM owner_accounts").fetchone()[0]
    assert _bootstrap(monkeypatch) == 0
    with sqlite3.connect(tmp_db) as con:
        after = con.execute("SELECT password_hash FROM owner_accounts").fetchone()[0]
        count = con.execute("SELECT COUNT(*) FROM owner_accounts").fetchone()[0]
    assert before == after
    assert count == 1


def test_bootstrap_rejects_wrong_username(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch, username="not-the-owner") == 2
    assert not op.owner_account_exists()


def test_bootstrap_rejects_mismatched_confirm(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch, confirm="different") == 2
    assert not op.owner_account_exists()


def test_plaintext_password_absent_from_database(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    raw = tmp_db.read_bytes()
    assert TEST_PASSWORD.encode("utf-8") not in raw
    assert TEST_PASSWORD not in raw.decode("utf-8", errors="replace")


def test_plaintext_password_absent_from_logs(tmp_db, monkeypatch, caplog):
    assert _bootstrap(monkeypatch) == 0
    with pytest.raises(PermissionError):
        op.login("mosfiry", "wrong-password-attempt")
    assert caplog.text == "" or TEST_PASSWORD not in caplog.text


def test_login_success(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    session = op.login("mosfiry", TEST_PASSWORD)
    assert session["auth_method"] == "username_password"
    assert session["session_id"]
    assert "password" not in session
    assert "password_hash" not in session


def test_first_run_bootstrap_to_login_uses_canonical_username(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0

    app = Path("web/app.js").read_text(encoding="utf-8")
    bridge = Path("bridge.py").read_text(encoding="utf-8")
    html = Path("web/index.html").read_text(encoding="utf-8")
    assert '"owner_username": owner_password.OWNER_USERNAME' in bridge
    assert 'const canonicalUsername = String(state.desktopSetup?.owner_username || "").trim();' in app
    assert "setupUsername.textContent = canonicalUsername" in app
    assert "loginUsername.value = canonicalUsername" in app
    assert 'id="setupOwnerUsername"' in html
    assert "username: canonicalUsername" in app
    assert 'username: "owner"' not in app

    with pytest.raises(PermissionError):
        op.login("owner", TEST_PASSWORD)
    session = op.login(op.OWNER_USERNAME, TEST_PASSWORD)
    assert session["auth_method"] == "username_password"
    assert session["username"] == op.OWNER_USERNAME
    assert session["session_id"]


def test_owner_session_bearer_token_is_not_persisted(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    session = op.login("mosfiry", TEST_PASSWORD)
    reference = session_reference(session["session_id"])
    with sqlite3.connect(tmp_db) as con:
        stored = con.execute("SELECT session_id FROM owner_sessions").fetchone()[0]
    assert stored == reference
    assert session["session_id"] not in tmp_db.read_bytes().decode("utf-8", errors="ignore")
    resolved = op.resolve_session(session["session_id"])
    assert resolved is not None and resolved["session_id"] == reference


def test_legacy_session_token_migrates_to_digest_and_remains_usable(tmp_db, monkeypatch):
    owner_id = op.create_owner_account("mosfiry", TEST_PASSWORD)
    raw_token = "legacy-owner-session-token"
    expires = "2999-01-01T00:00:00+00:00"
    with sqlite3.connect(tmp_db) as con:
        con.execute(
            "INSERT INTO owner_sessions(session_id,owner_id,created_at,authenticated_at,expires_at,status,auth_method) "
            "VALUES(?,?,?,?,?,'active','username_password')",
            (raw_token, owner_id, expires, expires, expires),
        )
        con.execute(
            "INSERT INTO conversations(conversation_id,owner_session_id) VALUES(?,?)",
            ("legacy-conversation", raw_token),
        )
        con.execute(
            "INSERT INTO events(kind,severity,title,body,source,trusted,metadata_json) VALUES(?,?,?,?,?,?,?)",
            ("auth", "info", "test", "test", "test", 1, '{"session_id":"legacy-owner-session-token"}'),
        )
        con.commit()
    with core_db.connect() as con:
        stored = con.execute("SELECT session_id FROM owner_sessions").fetchone()[0]
        conversation = con.execute(
            "SELECT owner_session_id FROM conversations WHERE conversation_id='legacy-conversation'"
        ).fetchone()[0]
    assert stored == session_reference(raw_token)
    assert conversation == stored
    assert op.resolve_session(raw_token)["session_id"] == stored
    assert raw_token.encode() not in tmp_db.read_bytes()


def test_login_wrong_password(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    with pytest.raises(PermissionError):
        op.login("mosfiry", "not-the-password")


def test_login_unknown_username(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    with pytest.raises(PermissionError):
        op.login("someone-else", TEST_PASSWORD)


def test_login_disabled_account_rejected(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    with sqlite3.connect(tmp_db) as con:
        con.execute("UPDATE owner_accounts SET status = 'disabled'")
        con.commit()
    with pytest.raises(PermissionError):
        op.login("mosfiry", TEST_PASSWORD)


def test_login_non_string_inputs_rejected(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    with pytest.raises(PermissionError):
        op.login(None, TEST_PASSWORD)
    with pytest.raises(PermissionError):
        op.login("mosfiry", {"password": TEST_PASSWORD})


def test_session_forgery_rejected(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    assert op.resolve_session("forged-session-id") is None
    assert op.authenticated_owner("forged-session-id") is None


def test_owner_magic_string_rejected(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    assert op.resolve_session("Owner") is None
    assert op.authenticated_owner("owner_authenticated=true") is None


def test_client_claims_never_authenticate(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    for bogus in (True, 1, {"role": "owner"}, ["is_owner", "true"], "OWNER_TOKEN"):
        assert op.authenticated_owner(bogus) is None


def test_expired_session_rejected(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    session = op.login("mosfiry", TEST_PASSWORD)
    with sqlite3.connect(tmp_db) as con:
        con.execute("UPDATE owner_sessions SET expires_at = '2000-01-01T00:00:00+00:00' WHERE session_id = ?", (session_reference(session["session_id"]),))
        con.commit()
    assert op.resolve_session(session["session_id"]) is None


def test_revoked_session_rejected(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    session = op.login("mosfiry", TEST_PASSWORD)
    assert op.logout(session["session_id"]) is True
    assert op.resolve_session(session["session_id"]) is None
    # logout is idempotent
    assert op.logout(session["session_id"]) is False


def test_session_ids_are_random_and_unique(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    first = op.login("mosfiry", TEST_PASSWORD)
    second = op.login("mosfiry", TEST_PASSWORD)
    assert first["session_id"] != second["session_id"]


def test_corrupt_expiry_rejected(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    session = op.login("mosfiry", TEST_PASSWORD)
    with sqlite3.connect(tmp_db) as con:
        con.execute("UPDATE owner_sessions SET expires_at = 'not-a-timestamp' WHERE session_id = ?", (session_reference(session["session_id"]),))
        con.commit()
    assert op.resolve_session(session["session_id"]) is None


def test_hashes_use_unique_salts():
    first = op.hash_password("same-password")
    second = op.hash_password("same-password")
    assert first["password_hash"] != second["password_hash"]
    assert first["kdf_params_json"] != second["kdf_params_json"]


def test_verify_rejects_wrong_kdf_algorithm():
    verifier = op.hash_password(TEST_PASSWORD)
    assert op._verify(TEST_PASSWORD, verifier["password_hash"], "md5", verifier["kdf_params_json"]) is False


def test_verify_rejects_malformed_params():
    verifier = op.hash_password(TEST_PASSWORD)
    assert op._verify(TEST_PASSWORD, verifier["password_hash"], "scrypt", "not-json") is False
    assert op._verify(TEST_PASSWORD, verifier["password_hash"], "scrypt", "{}") is False


def test_reset_requires_current_password(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    with pytest.raises(PermissionError):
        op.reset_password("mosfiry", "wrong-current", "brand-new-password")
    # original password still works
    assert op.login("mosfiry", TEST_PASSWORD)["auth_method"] == "username_password"


def test_reset_revokes_all_sessions(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    first = op.login("mosfiry", TEST_PASSWORD)
    second = op.login("mosfiry", TEST_PASSWORD)
    op.reset_password("mosfiry", TEST_PASSWORD, "brand-new-password")
    assert op.resolve_session(first["session_id"]) is None
    assert op.resolve_session(second["session_id"]) is None
    with pytest.raises(PermissionError):
        op.login("mosfiry", TEST_PASSWORD)
    assert op.login("mosfiry", "brand-new-password")["auth_method"] == "username_password"


def test_create_account_rejects_duplicate(tmp_db, monkeypatch):
    assert _bootstrap(monkeypatch) == 0
    with pytest.raises(PermissionError):
        op.create_owner_account("mosfiry", "another-password")


def test_create_account_rejects_wrong_username(tmp_db, monkeypatch):
    with pytest.raises(PermissionError):
        op.create_owner_account("intruder", "some-password")
    assert not op.owner_account_exists()
