import importlib
import json
import secrets

import pytest

import security.owner_credentials as credentials
from security.owner_session import OwnerSessionManager


def configured(monkeypatch, tmp_path):
    monkeypatch.setattr(credentials, "CREDENTIALS_PATH", tmp_path / "owner.json")
    importlib.reload(credentials)
    credentials.CREDENTIALS_PATH = tmp_path / "owner.json"
    return credentials


def test_bootstrap_login_new_device_and_wrong_credentials(monkeypatch, tmp_path):
    store = configured(monkeypatch, tmp_path)
    secret = secrets.token_urlsafe(24)
    store.bootstrap_owner(username="mosfiry", password=secret)
    owner = store.authenticate("mosfiry", secret)
    assert owner.username == "mosfiry"
    manager = OwnerSessionManager(ttl_seconds=10)
    session = manager.create(username="mosfiry", password=secret)
    context = manager.consume(session.session_id, session.challenge, session.challenge, request_id="login-1")
    assert context["owner_identity"] == "mosfiry"
    with pytest.raises(store.OwnerCredentialError):
        store.authenticate("mosfiry", secrets.token_urlsafe(24))
    with pytest.raises(store.OwnerCredentialError):
        store.authenticate("unknown-user", secret)
    with pytest.raises(PermissionError):
        manager.create(username="", password=secret)


def test_password_change_invalidates_old_session_and_accepts_new_password(monkeypatch, tmp_path):
    store = configured(monkeypatch, tmp_path)
    old_secret = secrets.token_urlsafe(24)
    new_secret = secrets.token_urlsafe(24)
    store.bootstrap_owner(username="mosfiry", password=old_secret)
    manager = OwnerSessionManager(ttl_seconds=10)
    session = manager.create(username="mosfiry", password=old_secret)
    proof = manager.consume(session.session_id, session.challenge, session.challenge, request_id="rotate-1")["session_proof"]
    changed = store.change_password(session_manager=manager, session_id=session.session_id, request_id="rotate-1", session_proof=proof, current_password=old_secret, new_password=new_secret)
    assert changed.credential_version == 2
    assert manager.is_active(session.session_id) is False
    with pytest.raises(store.OwnerCredentialError):
        store.authenticate("mosfiry", old_secret)
    assert store.authenticate("mosfiry", new_secret).credential_version == 2


def test_username_change_is_authenticated_and_does_not_expose_plaintext(monkeypatch, tmp_path):
    store = configured(monkeypatch, tmp_path)
    secret = secrets.token_urlsafe(24)
    store.bootstrap_owner(username="mosfiry", password=secret)
    manager = OwnerSessionManager(ttl_seconds=10)
    session = manager.create(username="mosfiry", password=secret)
    context = manager.consume(session.session_id, session.challenge, session.challenge, request_id="rename-1")
    renamed = store.change_username(session_manager=manager, session_id=session.session_id, request_id="rename-1", session_proof=context["session_proof"], password=secret, new_username="owner-renamed")
    assert renamed.username == "owner-renamed"
    serialized = json.dumps({"context": context, "session": session.public(), "renamed": renamed.public(), "file": json.loads((tmp_path / "owner.json").read_text())})
    assert secret not in serialized
    assert "password_hash" in serialized
    assert "password" not in json.dumps(context).lower()
