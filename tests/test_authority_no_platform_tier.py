from __future__ import annotations

"""Adversarial battery: SYSTEM_PLATFORM is not an internal authority tier.

Constitution: docs/AUTHORITY_CONSTITUTION.md, Article 6. SYSTEM_PLATFORM is
not internal legislation; it must never reappear as a competing
application-policy source. Platform/runtime limits remain implementation
and execution constraints (system_boundary_immutable), never legislation.
"""

import pytest

from security.authority import (
    AuthorityTier,
    FIXED_AUTHORITY_TIERS,
    application_policy_order_guard,
)


def test_no_platform_tier_exists():
    assert "SYSTEM_PLATFORM" not in {tier.name for tier in AuthorityTier}
    assert "SYSTEM_PLATFORM" not in FIXED_AUTHORITY_TIERS


def test_platform_tier_name_is_rejected_as_unknown():
    with pytest.raises(ValueError):
        validate_tier_name("SYSTEM_PLATFORM")


def test_application_policy_order_has_no_platform_entry():
    snapshot = authority_snapshot()
    assert "SYSTEM_PLATFORM" not in snapshot["tiers"]
    assert "SYSTEM_PLATFORM" not in snapshot["application_policy_order"]
    assert snapshot["application_policy_order"][0] == "OWNER_INSTRUCTION"


def test_system_boundary_remains_immutable_execution_constraint():
    snapshot = authority_snapshot()
    assert snapshot["system_boundary_immutable"] is True
    assert snapshot["closed_world"] is True


def test_owner_instruction_remains_highest_internal_tier():
    assert max(int(tier) for tier in AuthorityTier) == int(AuthorityTier.OWNER_INSTRUCTION)
    assert int(AuthorityTier.OWNER_INSTRUCTION) > int(AuthorityTier.OWNER_POLICY)


def test_numbering_gap_records_removed_drift():
    values = sorted(int(tier) for tier in AuthorityTier)
    assert 700 not in values
    assert values == [100, 200, 300, 400, 500, 600, 800]

