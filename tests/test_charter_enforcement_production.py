from __future__ import annotations

"""Production charter enforcement battery (DRIFT-4).

The charter must be enforced in the production call graph, not only as a
library. agent.mission_runtime imports the gate; these tests prove the
gate holds and detects drift.
"""

import pytest

import security.charter_enforcement as ce
from security.owner_charter import (
    CharterDomain,
    CharterRule,
    LegislationError,
    OwnerInstructionConflict,
    RuleProvenance,
    Stance,
)


def test_production_charter_gate_passes_on_shipped_rules():
    ce.enforce_charter()  # must not raise


def test_charter_is_registered_in_production_import_path():
    import agent.mission_runtime  # noqa: F401  (production import executes the gate)
    assert agent.mission_runtime._CHARTER_ENFORCED is True


def test_conflicting_system_rule_is_authority_conflict():
    drift = CharterRule(CharterDomain.AUTHORIZATION, "tool_runtime_self_minted_authorization", Stance.ALLOWED, provenance=RuleProvenance.DERIVED_SYSTEM_RULE)
    with pytest.raises(OwnerInstructionConflict) as exc_info:
        ce.enforce_charter_with_extra_system_rules([drift])
    record = exc_info.value.audit_record()
    assert record["classification"] == "OWNER_INSTRUCTION_CONFLICT"
    assert record["remediation"] == "IMPLEMENTATION_DRIFT_CORRECTION"
    assert record["legislative_reference"] == "OWNER_INSTRUCTION"


def test_missing_required_behavior_is_drift():
    from security.owner_charter import assert_required_behaviors_present
    reduced_system = [r for r in ce.SYSTEM_RULES if not (r.domain is CharterDomain.EXECUTION and r.behavior == "goal_completion_requires_deterministic_verification")]
    with pytest.raises(OwnerInstructionConflict):
        assert_required_behaviors_present(ce.CHARTER_RULES, reduced_system)


def test_model_output_cannot_legislate():
    forged = CharterRule(CharterDomain.POLICY, "model_makes_law", Stance.REQUIRED, provenance=RuleProvenance.MODEL_OUTPUT)
    with pytest.raises(LegislationError):
        ce.try_legislate(forged, identity=None)


def test_owner_instruction_legislation_requires_authenticated_owner():
    rule = CharterRule(CharterDomain.POLICY, "owner_extends_charter", Stance.REQUIRED, provenance=RuleProvenance.OWNER_INSTRUCTION)
    with pytest.raises(LegislationError):
        ce.try_legislate(rule, identity=None)
    with pytest.raises(LegislationError):
        ce.try_legislate(rule, identity={"auth_method": "bridge_token"})
    accepted = ce.try_legislate(rule, identity={"auth_method": "username_password"})
    assert accepted.provenance is RuleProvenance.OWNER_INSTRUCTION


def test_charter_stance_resolution_always_favors_owner():
    stance = ce.charter_stance(CharterDomain.POLICY, "system_platform_as_internal_legislation")
    assert stance is not None and stance.stance is Stance.FORBIDDEN
