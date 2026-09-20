import importlib


def test_bridge_token_cannot_authenticate_owner(monkeypatch):
    monkeypatch.setenv("OWNER_TOKEN", "owner-secret")
    import security.owner_policy as owner_policy
    importlib.reload(owner_policy)
    assert owner_policy.verify_owner("Owner status", "bridge-secret")[0] is False
    assert owner_policy.verify_owner("Owner status", "owner-secret")[0] is True


def test_missing_owner_token_is_denied(monkeypatch):
    monkeypatch.setenv("OWNER_TOKEN", "owner-secret")
    import security.owner_policy as owner_policy
    importlib.reload(owner_policy)
    assert owner_policy.verify_owner("status", None)[0] is False
