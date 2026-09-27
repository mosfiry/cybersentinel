from __future__ import annotations

import pytest

import core.db as core_db
import security.owner_password as owner_password

TEST_PASSWORD = "live-owner-test-password-2026"


@pytest.fixture
def owner_account(tmp_path, monkeypatch):
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "owner-auth.db")
    core_db.connect().close()
    owner_password.create_owner_account(owner_password.OWNER_USERNAME, TEST_PASSWORD)


def test_wrong_password_is_rejected(owner_account):
    with pytest.raises(PermissionError):
        owner_password.login(owner_password.OWNER_USERNAME, "wrong-password")


def test_login_issues_resolvable_session(owner_account):
    session = owner_password.login(owner_password.OWNER_USERNAME, TEST_PASSWORD)
    assert session["auth_method"] == "username_password"
    resolved = owner_password.resolve_session(session["session_id"])
    assert resolved is not None and resolved["username"] == owner_password.OWNER_USERNAME


def test_logout_revokes_session(owner_account):
    session = owner_password.login(owner_password.OWNER_USERNAME, TEST_PASSWORD)
    owner_password.logout(session["session_id"])
    assert owner_password.resolve_session(session["session_id"]) is None
