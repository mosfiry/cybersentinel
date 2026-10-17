from __future__ import annotations

from enum import IntEnum
from typing import Any


class AuthorityTier(IntEnum):
    """Descriptive precedence ranks for policy/instruction sources only.

    These values never grant execution permission. Runtime security gates are
    enforced separately and remain mandatory regardless of instruction rank.
    """

    OWNER_INSTRUCTION = 900
    SYSTEM_PLATFORM = 800
    OWNER_POLICY = 600
    DETERMINISTIC_ENFORCEMENT = 500
    AUTHORIZATION_SCOPE = 400
    TOOL_RUNTIME = 300
    MODEL_OUTPUT = 200
    EXTERNAL_DATA = 100


FIXED_AUTHORITY_TIERS = tuple(item.name for item in AuthorityTier)

# These are execution gates, not competing instruction sources. Every relevant
# operation must satisfy them even when OWNER_INSTRUCTION requests otherwise.
NON_OVERRIDABLE_EXECUTION_GATES = (
    "OWNER_AUTHENTICATION",
    "EXPLICIT_OWNER_SELECTED_SCOPE",
    "TOOL_AUTHORIZATION",
    "PROCESS_SANDBOX",
    "OWNER_CANCELLATION",
    "EVIDENCE_INTEGRITY",
)


def assert_authority_invariant() -> None:
    assert AuthorityTier.OWNER_INSTRUCTION == 900
    assert AuthorityTier.SYSTEM_PLATFORM == 800
    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.SYSTEM_PLATFORM
    assert AuthorityTier.SYSTEM_PLATFORM > AuthorityTier.OWNER_POLICY
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
    order = list(FIXED_AUTHORITY_TIERS)
    return {
        "tiers": {tier.name: int(tier) for tier in AuthorityTier},
        "authority_order": order,
        "application_policy_order": order,
        "precedence_semantics": "instruction_source_precedence_only_not_execution_permission",
        "owner_instruction_is_highest": True,
        "owner_instruction_grants_execution_permission": False,
        "execution_gates_unconditionally_required": True,
        "non_overridable_execution_gates": list(NON_OVERRIDABLE_EXECUTION_GATES),
        "system_boundary_immutable": True,
        "closed_world": True,
    }


assert_authority_invariant()
