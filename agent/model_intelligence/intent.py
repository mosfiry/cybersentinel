from __future__ import annotations

"""Deterministic intent proposal validator (R1: INV-INTENT-1, INV-INTENT-2).

MODEL_OUTPUT is an untrusted proposal. Before any proposal may become a
typed MissionIntent it must pass this deterministic validator. A rejected
proposal never reaches the typed contract: the caller must fall back to the
deterministic interpretation and record the rejection.

Authority model:

- The validator never grants, narrows, or interprets authority. It only
  REJECTS authority-shaped content proposed by the model.
- Allowed intent types are a fixed allowlist; anything else is rejected.
- authorization_requirements and scope_references are authority-bearing
  fields: authority-shaped or wildcard values are rejected (fail closed).
  Over-rejection is intentional and safe: the fallback interpretation is
  deterministic and never carries model-proposed authority.
"""

from typing import Any

ALLOWED_INTENT_TYPES = frozenset({
    "GENERAL_CONVERSATION",
    "MISSION_REQUEST",
    "STATUS_REQUEST",
    "TOOL_REQUEST",
})

_AUTHORITY_TOKENS: tuple[str, ...] = (
    "grant",
    "self_grant",
    "owner",
    "authority",
    "authorize",
    "authorise",
    "authorization",
    "authorisation",
    "permission",
    "escalate",
    "escalation",
    "policy",
    "bypass",
    "admin",
    "mint",
    "credential",
    "expand scope",
    "scope expansion",
)

_WILDCARD_SCOPES = frozenset({"all", "all scopes", "everything", "unrestricted", "any"})


def validate_intent_proposal(data: Any) -> tuple[bool, str]:
    """Deterministically validate an untrusted intent proposal dict.

    Returns (ok, reason). Pure function: no I/O, no clock, no randomness;
    identical inputs always produce identical results (replay-safe).
    """
    if not isinstance(data, dict) or not data:
        return False, "empty or non-dict proposal"
    intent_type = str(data.get("intent_type") or "GENERAL_CONVERSATION")
    if intent_type not in ALLOWED_INTENT_TYPES:
        return False, f"unknown intent_type: {intent_type}"
    requirements = data.get("authorization_requirements", ()) or ()
    if not isinstance(requirements, (list, tuple)):
        return False, "authorization_requirements must be a list"
    for requirement in requirements:
        folded = str(requirement).casefold()
        if any(token in folded for token in _AUTHORITY_TOKENS):
            return False, f"authority-shaped authorization requirement rejected: {requirement}"
    references = data.get("scope_references", ()) or ()
    if not isinstance(references, (list, tuple)):
        return False, "scope_references must be a list"
    for reference in references:
        folded = str(reference).strip().casefold()
        if "*" in folded or folded in _WILDCARD_SCOPES:
            return False, f"wildcard scope reference rejected: {reference}"
    return True, "valid"


__all__ = ["ALLOWED_INTENT_TYPES", "validate_intent_proposal"]
