from __future__ import annotations

from pathlib import Path

import api.chat as chat_mod
import core.engine as engine_mod
import security.owner_password as owner_password


def test_legacy_challenge_names_are_absent_from_live_path_modules():
    chat_source = Path(chat_mod.__file__).read_text(encoding="utf-8")
    engine_source = Path(engine_mod.__file__).read_text(encoding="utf-8")
    for source in (chat_source, engine_source):
        assert "owner_challenge" not in source
        assert "owner_session_challenge" not in source
        assert "verify_owner" not in source


def test_resolve_session_rejects_empty_and_unknown_tokens():
    assert owner_password.resolve_session("") is None
    assert owner_password.resolve_session("unknown-session-token") is None


def test_owner_password_auth_method_is_username_password():
    assert owner_password.AUTH_METHOD == "username_password"
