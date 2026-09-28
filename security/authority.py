from __future__ import annotations

from enum import IntEnum
from typing import Any


class AuthorityTier(IntEnum):
    # Authority Constitution (docs/AUTHORITY_CONSTITUTION.md), Article 6:
    # SYSTEM_PLATFORM is not internal legislation. There is no SYSTEM_PLATFORM
    # authority tier and it must never be reintroduced as a competing
    # application-policy source. OWNER_INSTRUCTION is the single internal
    # legislative source; OWNER_POLICY, DETERMINISTIC_ENFORCEMENT,
    # AUTHORIZATION_SCOPE, TOOL_RUNTIME, MODEL_OUTPUT, and EXTERNAL_DATA are
    # derived execution layers below it. Platform/runtime limits remain
    # immutable implementation and execution constraints (see
    # authority_snapshot()["system_boundary_immutable"]), never legislation.
    # The 700 numbering gap is intentional: it records the removed
    # SYSTEM_PLATFORM drift and keeps the derived-tier numbering stable.
    OWNER_INSTRUCTION = 800
    OWNER_POLICY = 600
    DETERMINISTIC_ENFORCEMENT = 500
    AUTHORIZATION_SCOPE = 400
    TOOL_RUNTIME = 300
    MODEL_OUTPUT = 200
    EXTERNAL_DATA = 100


FIXED_AUTHORITY_TIERS = tuple(item.name for item in AuthorityTier)


def assert_authority_invariant() -> None:
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
        # Application policy order contains no SYSTEM_PLATFORM entry:
        # the platform layer is an execution boundary, not an application
        # policy source (Constitution, Article 6).
        "application_policy_order": ["OWNER_INSTRUCTION", "OWNER_POLICY", "DETERMINISTIC_ENFORCEMENT", "AUTHORIZATION_SCOPE", "TOOL_RUNTIME", "MODEL_OUTPUT", "EXTERNAL_DATA"],
        "owner_above": ["MODEL_OUTPUT", "EXTERNAL_DATA", "TOOL_RUNTIME", "AUTHORIZATION_SCOPE", "DETERMINISTIC_ENFORCEMENT"],
        # Immutable platform boundary is retained as an implementation
        # constraint flag, not as a legislative tier.
        "system_boundary_immutable": True,
        "closed_world": True,
    }


assert_authority_invariant()
