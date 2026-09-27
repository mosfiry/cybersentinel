import security.owner_password as owner_password


def allow_owner_sessions(monkeypatch, *valid_tokens):
    valid = set(valid_tokens)

    def _resolve(token):
        if token in valid:
            return {
                "session_id": token,
                "owner_id": 1,
                "username": "mosfiry",
                "auth_method": "username_password",
                "expires_at": "2999-01-01T00:00:00+00:00",
            }
        return None

    monkeypatch.setattr(owner_password, "resolve_session", _resolve)
