from __future__ import annotations

from enum import IntEnum
from typing import Any


class AuthorityTier(IntEnum):
    SYSTEM_PLATFORM = 700
    OWNER_POLICY = 600
    OWNER_INSTRUCTION = 500
    DETERMINISTIC_ENFORCEMENT = 400
    AUTHORIZATION_SCOPE = 300
    TOOL_RUNTIME = 200
    MODEL_OUTPUT = 100
    EXTERNAL_DATA = 0


FIXED_AUTHORITY_TIERS = tuple(item.name for item in AuthorityTier)


def assert_authority_invariant() -> None:
    assert AuthorityTier.SYSTEM_PLATFORM > AuthorityTier.OWNER_POLICY
    assert AuthorityTier.OWNER_POLICY > AuthorityTier.OWNER_INSTRUCTION
    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.DETERMINISTIC_ENFORCEMENT
    assert AuthorityTier.DETERMINISTIC_ENFORCEMENT > AuthorityTier.AUTHORIZATION_SCOPE
    assert AuthorityTier.AUTHORIZATION_SCOPE > AuthorityTier.TOOL_RUNTIME
    assert AuthorityTier.TOOL_RUNTIME > AuthorityTier.MODEL_OUTPUT
    assert AuthorityTier.MODEL_OUTPUT > AuthorityTier.EXTERNAL_DATA


def validate_tier_name(name: str) -> AuthorityTier:
    try:
        return AuthorityTier[name]
    except KeyError as exc:
        raise ValueError("authority tiers are closed; unknown tier") from exc


def authority_snapshot() -> dict[str, Any]:
    assert_authority_invariant()
    return {
        "tiers": {tier.name: int(tier) for tier in AuthorityTier},
        "owner_above": ["MODEL_OUTPUT", "EXTERNAL_DATA", "TOOL_RUNTIME", "AUTHORIZATION_SCOPE"],
        "system_boundary_immutable": True,
        "closed_world": True,
    }


assert_authority_invariant()
