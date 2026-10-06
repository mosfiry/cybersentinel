from __future__ import annotations

from enum import IntEnum
from typing import Any


class AuthorityTier(IntEnum):
    # Immutable system/platform constraints are the outer authority boundary.
    SYSTEM_PLATFORM = 900
    # Owner Instruction is the highest application-configurable authority.
    OWNER_INSTRUCTION = 800
    OWNER_POLICY = 600
    DETERMINISTIC_ENFORCEMENT = 500
    AUTHORIZATION_SCOPE = 400
    TOOL_RUNTIME = 300
    MODEL_OUTPUT = 200
    EXTERNAL_DATA = 100


FIXED_AUTHORITY_TIERS = tuple(item.name for item in AuthorityTier)


def assert_authority_invariant() -> None:
    assert AuthorityTier.SYSTEM_PLATFORM > AuthorityTier.OWNER_INSTRUCTION
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
        "authority_order": list(FIXED_AUTHORITY_TIERS),
        "application_policy_order": [
            "OWNER_INSTRUCTION",
            "OWNER_POLICY",
            "DETERMINISTIC_ENFORCEMENT",
            "AUTHORIZATION_SCOPE",
            "TOOL_RUNTIME",
            "MODEL_OUTPUT",
            "EXTERNAL_DATA",
        ],
        "system_above": [
            "OWNER_INSTRUCTION",
            "OWNER_POLICY",
            "DETERMINISTIC_ENFORCEMENT",
            "AUTHORIZATION_SCOPE",
            "TOOL_RUNTIME",
            "MODEL_OUTPUT",
            "EXTERNAL_DATA",
        ],
        "owner_above": [
            "OWNER_POLICY",
            "DETERMINISTIC_ENFORCEMENT",
            "AUTHORIZATION_SCOPE",
            "TOOL_RUNTIME",
            "MODEL_OUTPUT",
            "EXTERNAL_DATA",
        ],
        "system_boundary_immutable": True,
        "closed_world": True,
    }


assert_authority_invariant()
