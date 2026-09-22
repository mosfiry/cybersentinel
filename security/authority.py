from __future__ import annotations

from enum import IntEnum
from typing import Any


class AuthorityTier(IntEnum):
    # Owner Instruction is the highest application authority. Platform safety
    # boundaries remain immutable, but are not an alternate application goal.
    OWNER_INSTRUCTION = 800
    SYSTEM_PLATFORM = 700
    OWNER_POLICY = 600
    DETERMINISTIC_ENFORCEMENT = 500
    AUTHORIZATION_SCOPE = 400
    TOOL_RUNTIME = 300
    MODEL_OUTPUT = 200
    EXTERNAL_DATA = 100


FIXED_AUTHORITY_TIERS = tuple(item.name for item in AuthorityTier)


def assert_authority_invariant() -> None:
    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.SYSTEM_PLATFORM
    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.OWNER_POLICY
    assert AuthorityTier.OWNER_POLICY > AuthorityTier.DETERMINISTIC_ENFORCEMENT
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
        "application_policy_order": ["OWNER_INSTRUCTION", "SYSTEM_PLATFORM", "OWNER_POLICY", "DETERMINISTIC_ENFORCEMENT", "AUTHORIZATION_SCOPE", "TOOL_RUNTIME", "MODEL_OUTPUT", "EXTERNAL_DATA"],
        "owner_above": ["MODEL_OUTPUT", "EXTERNAL_DATA", "TOOL_RUNTIME", "AUTHORIZATION_SCOPE", "DETERMINISTIC_ENFORCEMENT"],
        "system_boundary_immutable": True,
        "closed_world": True,
    }


assert_authority_invariant()
