import security.owner_password as owner_password
from security.session_reference import session_reference


def allow_owner_sessions(monkeypatch, *valid_tokens):
    valid = set(valid_tokens)
    valid_references = {session_reference(token) for token in valid_tokens}

    def _resolve(token):
        if token in valid or session_reference(token) in valid_references:
            return {
                "session_id": session_reference(token),
                "owner_id": 1,
                "username": "mosfiry",
                "auth_method": "username_password",
                "expires_at": "2999-01-01T00:00:00+00:00",
            }
        return None

    monkeypatch.setattr(owner_password, "resolve_session", _resolve)
    monkeypatch.setattr(owner_password, "_resolve_session_reference", _resolve)
