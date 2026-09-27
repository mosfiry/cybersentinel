from __future__ import annotations

import json

import pytest

from security.owner_policy import OwnerPolicy, load_policy


def test_canonical_policy_uses_password_requirement_key() -> None:
    policy = load_policy()
    assert policy.require_owner_password is True


def test_owner_policy_dataclass_has_no_legacy_token_field() -> None:
    assert "require_owner_token" not in OwnerPolicy.__dataclass_fields__


def test_legacy_require_owner_token_key_fails_closed() -> None:
    """No compatibility mode: a policy file carrying the legacy OWNER_TOKEN-era
    key must be rejected instead of silently ignored or remapped."""
    raw = {
        "version": "2.0",
        "require_owner_token": True,
        "owner_phrase": "Owner",
        "evidence_required": True,
        "sandbox_by_default": True,
        "external_targets_require_scope": True,
        "destructive_requires_approval": True,
        "immutable": False,
    }
    with pytest.raises(TypeError):
        OwnerPolicy(**raw)


def test_policy_file_has_no_owner_token_terminology() -> None:
    from security.owner_policy import POLICY_PATH

    text = POLICY_PATH.read_text(encoding="utf-8")
    assert "owner_token" not in json.loads(text)
    assert "owner_token" not in text.lower()


def test_owner_authentication_is_username_password_only() -> None:
    from security.owner_policy import OwnerInstructionSource

    assert {item.value for item in OwnerInstructionSource} == {"username_password"}
