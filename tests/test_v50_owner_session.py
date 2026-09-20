import importlib
from datetime import datetime, timedelta, timezone

import pytest

import security.owner_policy as owner_policy
from security.owner_session import OwnerSessionManager


def configured_manager(monkeypatch):
    monkeypatch.setenv("OWNER_TOKEN", "owner-secret")
    importlib.reload(owner_policy)
    return OwnerSessionManager(ttl_seconds=10)


def test_owner_session_creation_and_context(monkeypatch):
    manager = configured_manager(monkeypatch)
    session = manager.create("owner-secret")
    context = manager.consume(session.session_id, session.challenge, f"{session.challenge} حلل الحالة")
    assert context["owner_authenticated"] is True
    assert context["owner_session_id"] == session.session_id
    assert context["authentication_method"] == "owner_session_challenge"


def test_owner_challenge_is_single_use_and_rejects_invalid(monkeypatch):
    manager = configured_manager(monkeypatch)
    session = manager.create("owner-secret")
    with pytest.raises(PermissionError, match="invalid owner challenge"):
        manager.consume(session.session_id, "CSO-invalid", "CSO-invalid test")
    manager.consume(session.session_id, session.challenge, session.challenge)
    with pytest.raises(PermissionError, match="already used"):
        manager.consume(session.session_id, session.challenge, session.challenge)


def test_owner_challenge_is_bound_to_session_and_expires(monkeypatch):
    manager = configured_manager(monkeypatch)
    first = manager.create("owner-secret")
    second = manager.create("owner-secret")
    with pytest.raises(PermissionError, match="invalid owner challenge"):
        manager.consume(second.session_id, first.challenge, first.challenge)
    first.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    with pytest.raises(PermissionError, match="expired"):
        manager.consume(first.session_id, first.challenge, first.challenge)


def test_non_owner_cannot_create_session(monkeypatch):
    manager = configured_manager(monkeypatch)
    with pytest.raises(PermissionError):
        manager.create("wrong-token")
