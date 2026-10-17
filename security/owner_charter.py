"""Reference model for Owner policy precedence; not a live authorization path.

OWNER_INSTRUCTION is the highest-ranked normative instruction source
(AuthorityTier 900; SYSTEM_PLATFORM is 800). This source ordering resolves
policy/instruction precedence only. It never grants execution permission and
cannot bypass the unconditional authentication, explicit-scope, tool-authorization,
sandbox, cancellation, or evidence-integrity gates enforced elsewhere.

This module is not imported by the production request/authorization path. Its
helpers model policy intent only; they do not issue tool permissions, modify a
ScopeSnapshot, launch a process, or certify evidence. Keep that boundary explicit
if this reference model is extended or connected in the future.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class CharterDomain(str, Enum):
    """Domains for normative Owner policy intent, not execution capabilities."""

    POLICY = "policy"
    ETHICS = "ethics"
    SECURITY = "security"
    SCOPE = "scope"
    AUTHORIZATION = "authorization"
    DELEGATION = "delegation"
    EXECUTION = "execution"


class Stance(str, Enum):
    REQUIRED = "required"
    FORBIDDEN = "forbidden"
    ALLOWED = "allowed"


class RuleProvenance(str, Enum):
    OWNER_INSTRUCTION = "owner_instruction"
    DERIVED_SYSTEM_RULE = "derived_system_rule"
    RUNTIME_GATE = "non_overridable_runtime_gate"
    MODEL_OUTPUT = "model_output"
    EXTERNAL_DATA = "external_data"
    TOOL_OUTPUT = "tool_output"
    KNOWLEDGE_BASE = "knowledge_base"


#: Normative instruction precedence. Execution gates are separate and are never
#: compared as subordinate policy rules.
CHARTER_PRECEDENCE: tuple[RuleProvenance, ...] = (
    RuleProvenance.OWNER_INSTRUCTION,
    RuleProvenance.DERIVED_SYSTEM_RULE,
)

#: Provenances that can NEVER become a legislative source.
FORBIDDEN_LEGISLATIVE_SOURCES: frozenset[RuleProvenance] = frozenset(
    {
        RuleProvenance.MODEL_OUTPUT,
        RuleProvenance.EXTERNAL_DATA,
        RuleProvenance.TOOL_OUTPUT,
        RuleProvenance.KNOWLEDGE_BASE,
        RuleProvenance.DERIVED_SYSTEM_RULE,
        RuleProvenance.RUNTIME_GATE,
    }
)

#: Only the authenticated human Owner issues charter rules.
AUTHORITATIVE_AUTH_METHOD = "username_password"


class CharterError(Exception):
    """Base class for charter violations (fail-closed)."""


class OwnerInstructionConflict(CharterError):
    """A system rule contradicts the Owner charter.

    This is an implementation drift to be DETECTED and CORRECTED —
    never a legitimate alternative reading. The charter remains the
    sole legislative reference.
    """

    classification = "OWNER_INSTRUCTION_CONFLICT"
    remediation = "IMPLEMENTATION_DRIFT_CORRECTION"

    def __init__(
        self,
        domain: CharterDomain,
        behavior: str,
        owner_stance: Stance | None,
        owner_specification: Any,
        rule,
    ) -> None:
        self.domain = domain
        self.behavior = behavior
        self.owner_stance = owner_stance
        self.owner_specification = owner_specification
        self.rule = rule
        super().__init__(
            f"OWNER_INSTRUCTION_CONFLICT in {domain.value}:{behavior} — "
            f"charter={owner_stance.value if owner_stance else 'unspecified'}"
            f"{('/' + str(owner_specification)) if owner_specification is not None else ''}, "
            f"rule={rule.stance.value}"
            f"{('/' + str(rule.specification)) if rule.specification is not None else ''}. "
            "The system rule is implementation drift and must be corrected; "
            "the Owner charter stays supreme."
        )

    def audit_record(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "remediation": self.remediation,
            "domain": self.domain.value,
            "behavior": self.behavior,
            "owner_stance": self.owner_stance.value if self.owner_stance else None,
            "owner_specification": self.owner_specification,
            "rule_stance": self.rule.stance.value,
            "rule_specification": self.rule.specification,
            "rule_provenance": self.rule.provenance.value,
            "legislative_reference": "OWNER_INSTRUCTION",
        }


class LegislationError(CharterError):
    """A non-owner source attempted to legislate the charter."""

    classification = "ILLEGITIMATE_LEGISLATION"


class NonOverridableExecutionGateError(CharterError):
    """A runtime gate was incorrectly submitted to policy-precedence logic."""

    classification = "NON_OVERRIDABLE_EXECUTION_GATE"


@dataclass(frozen=True)
class CharterRule:
    """A normative statement about one behavior in one charter domain."""

    domain: CharterDomain
    behavior: str
    stance: Stance
    specification: Any = None
    provenance: RuleProvenance = RuleProvenance.DERIVED_SYSTEM_RULE
    derived_from: str = "OWNER_INSTRUCTION"

    def __post_init__(self) -> None:
        if not isinstance(self.behavior, str) or not self.behavior.strip():
            raise ValueError("charter rule requires a behavior")
        if not isinstance(self.domain, CharterDomain):
            raise ValueError("charter rule requires a CharterDomain")


def is_authoritative_source(identity: Any, *, request_id: str | None = None) -> bool:
    """Accept only issued, request-bound Owner authentication evidence.

    A client-controlled mapping containing ``auth_method`` is not proof. This
    reference model does not authenticate sessions itself; its caller must pass
    typed evidence issued by ``security.owner_policy``.
    """
    if not request_id:
        return False
    try:
        from security.owner_policy import OwnerAuthenticationEvidence

        if not isinstance(identity, OwnerAuthenticationEvidence):
            return False
        return identity.is_valid(str(request_id), identity.session_id) or identity.is_valid_for_active_session(
            str(request_id), identity.session_id
        )
    except Exception:
        return False


def try_legislate(
    rule: CharterRule,
    identity: Any = None,
    *,
    request_id: str | None = None,
) -> CharterRule:
    """Attempt to register a charter rule. Fail-closed by design.

    - OWNER_INSTRUCTION provenance requires issued OwnerAuthenticationEvidence
      valid for this request ID.
    - Any other provenance can NEVER legislate: the attempt is rejected
      as ILLEGITIMATE_LEGISLATION and never becomes a rule source.
    """
    if rule.provenance == RuleProvenance.OWNER_INSTRUCTION:
        if not is_authoritative_source(identity, request_id=request_id):
            raise LegislationError(
                "owner_instruction_requires_request_bound_owner_evidence"
            )
        return rule
    raise LegislationError(
        f"{rule.provenance.value}_cannot_legislate: only the authenticated "
        "Owner (OWNER_INSTRUCTION) may create charter rules"
    )


def _stances_conflict(owner_stance: Stance, rule_stance: Stance) -> bool:
    if owner_stance == Stance.REQUIRED:
        return rule_stance != Stance.REQUIRED
    if owner_stance == Stance.FORBIDDEN:
        return rule_stance != Stance.FORBIDDEN
    # Owner explicitly ALLOWS: forbidding it is drift (the charter allows it).
    return rule_stance == Stance.FORBIDDEN


def assert_charter_compliance(
    charter_rules: frozenset[CharterRule] | set[CharterRule],
    system_rule: CharterRule,
) -> None:
    """Compare normative policy rules only; never adjudicate execution gates.

    Raises OwnerInstructionConflict on contradiction. A contradiction is
    NEVER resolved by choosing the system rule — it is classified as
    OWNER_INSTRUCTION_CONFLICT / policy implementation drift to be reviewed.
    Runtime gates are not policy rules: submitting one here raises a separate
    error and cannot label a security denial as drift to be removed.
    """
    if system_rule.provenance == RuleProvenance.RUNTIME_GATE:
        raise NonOverridableExecutionGateError(
            "runtime gates are unconditional and outside Owner policy precedence"
        )
    if system_rule.provenance != RuleProvenance.DERIVED_SYSTEM_RULE:
        raise ValueError("only derived normative policy rules are comparable")
    for charter_rule in charter_rules:
        if charter_rule.domain != system_rule.domain:
            continue
        if charter_rule.behavior != system_rule.behavior:
            continue
        if charter_rule.provenance != RuleProvenance.OWNER_INSTRUCTION:
            continue
        if _stances_conflict(charter_rule.stance, system_rule.stance):
            raise OwnerInstructionConflict(
                system_rule.domain,
                system_rule.behavior,
                charter_rule.stance,
                charter_rule.specification,
                system_rule,
            )
        if (
            charter_rule.specification is not None
            and system_rule.specification is not None
            and charter_rule.specification != system_rule.specification
        ):
            raise OwnerInstructionConflict(
                system_rule.domain,
                system_rule.behavior,
                charter_rule.stance,
                charter_rule.specification,
                system_rule,
            )


def assert_required_behaviors_present(
    charter_rules: frozenset[CharterRule] | set[CharterRule],
    system_rules: list[CharterRule],
) -> None:
    """Every behavior the Owner REQUIRES must exist among system rules.

    Absence of a required behavior is implementation drift (fail-closed),
    not silent permission.
    """
    system_index = {(r.domain, r.behavior): r for r in system_rules}
    for charter_rule in charter_rules:
        if charter_rule.provenance != RuleProvenance.OWNER_INSTRUCTION:
            continue
        if charter_rule.stance != Stance.REQUIRED:
            continue
        present = system_index.get((charter_rule.domain, charter_rule.behavior))
        if present is None or present.stance != Stance.REQUIRED:
            raise OwnerInstructionConflict(
                charter_rule.domain,
                charter_rule.behavior,
                charter_rule.stance,
                charter_rule.specification,
                present
                or CharterRule(
                    domain=charter_rule.domain,
                    behavior=charter_rule.behavior,
                    stance=Stance.ALLOWED if present is None else present.stance,
                    specification=None,
                    provenance=RuleProvenance.DERIVED_SYSTEM_RULE,
                ),
            )


def derive(domain: CharterDomain) -> dict[str, Any]:
    """Describe a derived layer. Derived layers are EXECUTION of the charter.

    The returned provenance declares, structurally, that this layer is a
    derivation of OWNER_INSTRUCTION and never a competing authority.
    """
    return {
        "domain": domain.value,
        "legislative_source": "OWNER_INSTRUCTION",
        "provenance": RuleProvenance.DERIVED_SYSTEM_RULE.value,
        "may_override_charter": False,
        "conflict_policy": "OWNER_INSTRUCTION_CONFLICT -> IMPLEMENTATION_DRIFT_CORRECTION",
    }


def resolve_against_charter(
    charter_rules: frozenset[CharterRule] | set[CharterRule],
    domain: CharterDomain,
    behavior: str,
) -> CharterRule | None:
    """Resolve normative policy intent; this result is not execution permission.

    There is no policy-source arbitration: if the Owner legislated the behavior,
    that is the normative policy result. Authorization, selected scope, sandbox,
    cancellation, and evidence gates are evaluated independently by runtime code.
    """
    for charter_rule in charter_rules:
        if (
            charter_rule.provenance == RuleProvenance.OWNER_INSTRUCTION
            and charter_rule.domain == domain
            and charter_rule.behavior == behavior
        ):
            return charter_rule
    return None


__all__ = [
    "AUTHORITATIVE_AUTH_METHOD",
    "CHARTER_PRECEDENCE",
    "CharterDomain",
    "CharterError",
    "CharterRule",
    "FORBIDDEN_LEGISLATIVE_SOURCES",
    "LegislationError",
    "NonOverridableExecutionGateError",
    "OwnerInstructionConflict",
    "RuleProvenance",
    "Stance",
    "assert_charter_compliance",
    "assert_required_behaviors_present",
    "derive",
    "is_authoritative_source",
    "resolve_against_charter",
    "try_legislate",
]
