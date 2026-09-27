"""Adversarial battery for the OWNER_INSTRUCTION charter (supreme legislation).

The Owner's mandated scenarios: a contradicting POLICY / SCOPE /
AUTHORIZATION / ETHICS / SECURITY rule must be detected as
OWNER_INSTRUCTION_CONFLICT (implementation drift), and MODEL_OUTPUT
must never become a legislative source.
"""
from __future__ import annotations

import pytest

from security.owner_charter import (
    AUTHORITATIVE_AUTH_METHOD,
    CHARTER_PRECEDENCE,
    CharterDomain,
    CharterRule,
    LegislationError,
    OwnerInstructionConflict,
    RuleProvenance,
    Stance,
    assert_charter_compliance,
    assert_required_behaviors_present,
    derive,
    is_authoritative_source,
    resolve_against_charter,
    try_legislate,
)

OWNER_IDENTITY = {"owner_id": 1, "username": "mosfiry", "auth_method": AUTHORITATIVE_AUTH_METHOD}


def owner_rule(domain, behavior, stance, spec=None):
    return CharterRule(
        domain=domain,
        behavior=behavior,
        stance=stance,
        specification=spec,
        provenance=RuleProvenance.OWNER_INSTRUCTION,
    )


def system_rule(domain, behavior, stance, spec=None):
    return CharterRule(
        domain=domain,
        behavior=behavior,
        stance=stance,
        specification=spec,
        provenance=RuleProvenance.DERIVED_SYSTEM_RULE,
    )


def test_charter_precedence_has_owner_instruction_supreme():
    assert CHARTER_PRECEDENCE[0] == RuleProvenance.OWNER_INSTRUCTION
    for other in CHARTER_PRECEDENCE[1:]:
        assert other is not RuleProvenance.OWNER_INSTRUCTION


# --- Mandated test 1: POLICY contradiction is detected as drift ---

def test_policy_conflict_detected_as_implementation_drift():
    charter = frozenset({owner_rule(CharterDomain.POLICY, "data_handling", Stance.FORBIDDEN)})
    with pytest.raises(OwnerInstructionConflict) as excinfo:
        assert_charter_compliance(charter, system_rule(CharterDomain.POLICY, "data_handling", Stance.ALLOWED))
    assert excinfo.value.classification == "OWNER_INSTRUCTION_CONFLICT"
    assert excinfo.value.remediation == "IMPLEMENTATION_DRIFT_CORRECTION"
    record = excinfo.value.audit_record()
    assert record["legislative_reference"] == "OWNER_INSTRUCTION"
    assert record["domain"] == "policy"


# --- Mandated test 2: SCOPE contradiction is detected ---

def test_scope_conflict_detected():
    charter = frozenset({owner_rule(CharterDomain.SCOPE, "target_lab_only", Stance.REQUIRED, "lab")})
    with pytest.raises(OwnerInstructionConflict):
        assert_charter_compliance(
            charter, system_rule(CharterDomain.SCOPE, "target_lab_only", Stance.REQUIRED, "external")
        )
    # and the loosening variant: owner requires, system merely allows
    with pytest.raises(OwnerInstructionConflict):
        assert_charter_compliance(
            charter, system_rule(CharterDomain.SCOPE, "target_lab_only", Stance.ALLOWED)
        )


# --- Mandated test 3: AUTHORIZATION contradiction is detected ---

def test_authorization_conflict_detected():
    charter = frozenset({owner_rule(CharterDomain.AUTHORIZATION, "delegation_to_model", Stance.FORBIDDEN)})
    with pytest.raises(OwnerInstructionConflict):
        assert_charter_compliance(
            charter, system_rule(CharterDomain.AUTHORIZATION, "delegation_to_model", Stance.ALLOWED)
        )


# --- Mandated test 4: ETHICS contradiction is detected ---

def test_ethics_conflict_detected():
    charter = frozenset({owner_rule(CharterDomain.ETHICS, "external_target_engagement", Stance.FORBIDDEN)})
    with pytest.raises(OwnerInstructionConflict):
        assert_charter_compliance(
            charter,
            system_rule(CharterDomain.ETHICS, "external_target_engagement", Stance.REQUIRED),
        )


# --- Mandated test 5: SECURITY contradiction is detected ---

def test_security_conflict_detected():
    charter = frozenset({owner_rule(CharterDomain.SECURITY, "proof_required", Stance.REQUIRED, "hmac")})
    with pytest.raises(OwnerInstructionConflict):
        assert_charter_compliance(
            charter, system_rule(CharterDomain.SECURITY, "proof_required", Stance.REQUIRED, "none")
        )
    with pytest.raises(OwnerInstructionConflict):
        assert_charter_compliance(
            charter, system_rule(CharterDomain.SECURITY, "proof_required", Stance.ALLOWED)
        )


# --- Mandated test 6: MODEL OUTPUT can never legislate ---

@pytest.mark.parametrize(
    "provenance",
    [
        RuleProvenance.MODEL_OUTPUT,
        RuleProvenance.EXTERNAL_DATA,
        RuleProvenance.TOOL_OUTPUT,
        RuleProvenance.KNOWLEDGE_BASE,
        RuleProvenance.DERIVED_SYSTEM_RULE,
    ],
)
def test_non_owner_sources_cannot_legislate(provenance):
    rule = CharterRule(
        domain=CharterDomain.POLICY,
        behavior="anything",
        stance=Stance.REQUIRED,
        provenance=provenance,
    )
    with pytest.raises(LegislationError):
        try_legislate(rule, identity=OWNER_IDENTITY)


def test_model_output_attempting_charter_amendment_is_rejected_and_inert():
    # a model tries to create a "competing" charter rule
    model_rule = CharterRule(
        domain=CharterDomain.POLICY,
        behavior="data_handling",
        stance=Stance.ALLOWED,
        provenance=RuleProvenance.MODEL_OUTPUT,
    )
    with pytest.raises(LegislationError) as excinfo:
        try_legislate(model_rule)
    assert "cannot_legislate" in str(excinfo.value)
    # the charter is untouched: owner forbids data_handling and that stands
    charter = frozenset({owner_rule(CharterDomain.POLICY, "data_handling", Stance.FORBIDDEN)})
    assert resolve_against_charter(charter, CharterDomain.POLICY, "data_handling").stance == Stance.FORBIDDEN


def test_owner_instruction_legislation_requires_authenticated_owner_identity():
    rule = owner_rule(CharterDomain.POLICY, "new_rule", Stance.REQUIRED)
    with pytest.raises(LegislationError):
        try_legislate(rule, identity=None)
    with pytest.raises(LegislationError):
        try_legislate(rule, identity={"auth_method": "owner_token"})  # transport/legacy claim
    with pytest.raises(LegislationError):
        try_legislate(rule, identity={"auth_method": "owner_session_challenge"})
    legislated = try_legislate(rule, identity=OWNER_IDENTITY)
    assert legislated.provenance == RuleProvenance.OWNER_INSTRUCTION


def test_client_claims_are_never_authoritative():
    for bogus in (
        None,
        "Owner",
        True,
        {"owner_authenticated": True},
        {"role": "owner"},
        {"is_owner": True},
        {"auth_method": "OWNER_TOKEN"},
    ):
        assert is_authoritative_source(bogus) is False


# --- Charter resolution: the charter always wins, no arbitration ---

def test_resolve_against_charter_returns_owner_rule():
    charter = frozenset({owner_rule(CharterDomain.SCOPE, "network_egress", Stance.FORBIDDEN)})
    resolved = resolve_against_charter(charter, CharterDomain.SCOPE, "network_egress")
    assert resolved is not None
    assert resolved.stance == Stance.FORBIDDEN
    assert resolved.provenance == RuleProvenance.OWNER_INSTRUCTION


def test_required_behavior_absent_from_system_is_drift():
    charter = frozenset({owner_rule(CharterDomain.SECURITY, "audit_logging", Stance.REQUIRED)})
    with pytest.raises(OwnerInstructionConflict):
        assert_required_behaviors_present(charter, [])
    with pytest.raises(OwnerInstructionConflict):
        assert_required_behaviors_present(
            charter, [system_rule(CharterDomain.SECURITY, "audit_logging", Stance.ALLOWED)]
        )
    # compliant: system implements the requirement
    assert_required_behaviors_present(
        charter, [system_rule(CharterDomain.SECURITY, "audit_logging", Stance.REQUIRED)]
    )


def test_compliant_system_rule_passes():
    charter = frozenset(
        {
            owner_rule(CharterDomain.POLICY, "tool_use", Stance.ALLOWED),
            owner_rule(CharterDomain.SCOPE, "lab_only", Stance.REQUIRED),
        }
    )
    assert_charter_compliance(charter, system_rule(CharterDomain.POLICY, "tool_use", Stance.ALLOWED))
    assert_charter_compliance(charter, system_rule(CharterDomain.SCOPE, "lab_only", Stance.REQUIRED))
    # tightening is allowed, loosening is not
    assert_charter_compliance(charter, system_rule(CharterDomain.POLICY, "tool_use", Stance.FORBIDDEN))


def test_different_domain_or_behavior_never_conflicts():
    charter = frozenset({owner_rule(CharterDomain.POLICY, "data_handling", Stance.FORBIDDEN)})
    assert_charter_compliance(charter, system_rule(CharterDomain.ETHICS, "data_handling", Stance.ALLOWED))
    assert_charter_compliance(charter, system_rule(CharterDomain.POLICY, "other_behavior", Stance.REQUIRED))


def test_derived_layers_declare_non_competing_provenance():
    for domain in CharterDomain:
        derived_layer = derive(domain)
        assert derived_layer["legislative_source"] == "OWNER_INSTRUCTION"
        assert derived_layer["may_override_charter"] is False
        assert "OWNER_INSTRUCTION_CONFLICT" in derived_layer["conflict_policy"]


def test_charter_rule_construction_fail_closed():
    with pytest.raises(ValueError):
        CharterRule(domain="not-a-domain", behavior="x", stance=Stance.REQUIRED)
    with pytest.raises(ValueError):
        CharterRule(domain=CharterDomain.POLICY, behavior="  ", stance=Stance.REQUIRED)


def test_conflict_audit_record_is_complete_and_deterministic():
    charter = frozenset({owner_rule(CharterDomain.AUTHORIZATION, "tool_delegation", Stance.FORBIDDEN)})
    try:
        assert_charter_compliance(
            charter, system_rule(CharterDomain.AUTHORIZATION, "tool_delegation", Stance.REQUIRED)
        )
        raise AssertionError("expected OwnerInstructionConflict")
    except OwnerInstructionConflict as exc:
        record = exc.audit_record()
        assert record == {
            "classification": "OWNER_INSTRUCTION_CONFLICT",
            "remediation": "IMPLEMENTATION_DRIFT_CORRECTION",
            "domain": "authorization",
            "behavior": "tool_delegation",
            "owner_stance": "forbidden",
            "owner_specification": None,
            "rule_stance": "required",
            "rule_specification": None,
            "rule_provenance": "derived_system_rule",
            "legislative_reference": "OWNER_INSTRUCTION",
        }
