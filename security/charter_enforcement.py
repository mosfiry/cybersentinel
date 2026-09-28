from __future__ import annotations

"""Production wiring of the OWNER_INSTRUCTION charter (DRIFT-4 closure).

The charter module (security.owner_charter) existed on main but was never
part of the production call graph. This module registers the
constitutional invariants (docs/AUTHORITY_CONSTITUTION.md, read-only
reference) as OWNER_INSTRUCTION charter rules, registers the shipped
enforcement mechanisms as DERIVED_SYSTEM_RULE rules, and enforces — at
production startup — that every REQUIRED charter behavior is implemented
and that no system rule contradicts the charter. Any contradiction is
classified OWNER_INSTRUCTION_CONFLICT (implementation drift): the system
rule is corrected, the charter stays supreme.
"""

from security.owner_charter import (
    CharterDomain,
    CharterRule,
    LegislationError,
    OwnerInstructionConflict,
    RuleProvenance,
    Stance,
    assert_charter_compliance,
    assert_required_behaviors_present,
    resolve_against_charter,
    try_legislate,
)


# Constitutional invariants issued by the Owner. Provenance is
# OWNER_INSTRUCTION by issuance (docs/AUTHORITY_CONSTITUTION.md is the
# read-only constitutional text); these rules never compete with
# anything — they are the single internal legislative source.
CHARTER_RULES: frozenset[CharterRule] = frozenset({
    CharterRule(CharterDomain.EXECUTION, "goal_completion_requires_deterministic_verification", Stance.REQUIRED, provenance=RuleProvenance.OWNER_INSTRUCTION),
    CharterRule(CharterDomain.AUTHORIZATION, "mission_execution_requires_owner_derived_authorization", Stance.REQUIRED, provenance=RuleProvenance.OWNER_INSTRUCTION),
    CharterRule(CharterDomain.AUTHORIZATION, "tool_runtime_self_minted_authorization", Stance.FORBIDDEN, provenance=RuleProvenance.OWNER_INSTRUCTION),
    CharterRule(CharterDomain.POLICY, "system_platform_as_internal_legislation", Stance.FORBIDDEN, provenance=RuleProvenance.OWNER_INSTRUCTION),
    CharterRule(CharterDomain.POLICY, "owner_instruction_is_single_legislative_source", Stance.REQUIRED, provenance=RuleProvenance.OWNER_INSTRUCTION),
})


# The shipped enforcement mechanisms. Each is DERIVED_SYSTEM_RULE: an
# execution mechanism of the charter, never a competing authority.
SYSTEM_RULES: tuple[CharterRule, ...] = (
    CharterRule(CharterDomain.EXECUTION, "goal_completion_requires_deterministic_verification", Stance.REQUIRED, specification="agent.mission.Mission.transition GOAL_COMPLETED guard", provenance=RuleProvenance.DERIVED_SYSTEM_RULE),
    CharterRule(CharterDomain.AUTHORIZATION, "mission_execution_requires_owner_derived_authorization", Stance.REQUIRED, specification="security.mission_authorization + agent.mission_runtime._mission_authorization", provenance=RuleProvenance.DERIVED_SYSTEM_RULE),
    CharterRule(CharterDomain.AUTHORIZATION, "tool_runtime_self_minted_authorization", Stance.FORBIDDEN, specification="tools.registry.execute fail-closed mint rejection", provenance=RuleProvenance.DERIVED_SYSTEM_RULE),
    CharterRule(CharterDomain.POLICY, "system_platform_as_internal_legislation", Stance.FORBIDDEN, specification="security.authority tiers without SYSTEM_PLATFORM", provenance=RuleProvenance.DERIVED_SYSTEM_RULE),
    CharterRule(CharterDomain.POLICY, "owner_instruction_is_single_legislative_source", Stance.REQUIRED, specification="security.owner_policy OwnerInstruction with authentication evidence", provenance=RuleProvenance.DERIVED_SYSTEM_RULE),
)


def enforce_charter() -> None:
    """Fail-closed production charter gate.

    Called from the production mission runtime import path. Raises
    OwnerInstructionConflict (classification OWNER_INSTRUCTION_CONFLICT,
    remediation IMPLEMENTATION_DRIFT_CORRECTION) when a shipped system
    rule contradicts the charter or a REQUIRED charter behavior is not
    implemented. Never silently permits.
    """
    assert_required_behaviors_present(CHARTER_RULES, list(SYSTEM_RULES))
    for rule in SYSTEM_RULES:
        assert_charter_compliance(CHARTER_RULES, rule)


def enforce_charter_with_extra_system_rules(extra_system_rules: list[CharterRule]) -> None:
    """Fail-closed gate including candidate system rules (drift detection)."""
    combined = list(SYSTEM_RULES) + list(extra_system_rules)
    assert_required_behaviors_present(CHARTER_RULES, combined)
    for rule in combined:
        assert_charter_compliance(CHARTER_RULES, rule)


def charter_stance(domain: CharterDomain, behavior: str) -> CharterRule | None:
    """Resolve a behavior against the charter. The charter always wins."""
    return resolve_against_charter(CHARTER_RULES, domain, behavior)


__all__ = ["CHARTER_RULES", "SYSTEM_RULES", "charter_stance", "enforce_charter", "LegislationError", "OwnerInstructionConflict", "try_legislate"]
