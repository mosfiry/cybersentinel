from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
from security.owner_policy import OwnerAuthenticationEvidence, OwnerPolicySnapshot

MAX_TOOLS_PER_PLAN = 8


@dataclass(frozen=True)
class AuthorizationResult:
    allowed: bool
    reason: str
    name: str | None = None
    argument: str | None = None
    risk_class: str | None = None


def authorize_tool(item: Any, *, owner_authenticated: bool | None = None, owner_evidence: OwnerAuthenticationEvidence | None = None, request_id: str | None = None, current_policy: str = "") -> AuthorizationResult:
    if owner_evidence is None and owner_authenticated is True:
        return AuthorizationResult(False, "typed Owner authentication evidence required")
    evidence_valid = owner_evidence is not None and (request_id is None or owner_evidence.is_valid(request_id))
    if owner_evidence is not None and not evidence_valid:
        return AuthorizationResult(False, "invalid or stale Owner authentication evidence")
    structural_only = owner_evidence is None and owner_authenticated is None
    effective_authenticated = evidence_valid or (owner_evidence is None and owner_authenticated is True) or structural_only
    if owner_authenticated is False or (not effective_authenticated and not structural_only):
        return AuthorizationResult(False, "owner authentication required")
    if not isinstance(item, (str, list, tuple)):
        return AuthorizationResult(False, "tool entry must be a string or [name, argument]")
    if isinstance(item, str):
        name, argument = item, None
    else:
        if len(item) != 2:
            return AuthorizationResult(False, "tool arguments must contain exactly name and argument")
        name, argument = item
    if not isinstance(name, str) or name not in KNOWN_TOOLS:
        return AuthorizationResult(False, "unknown tool")
    spec = get_tool(name)
    if spec is None or (spec.owner_only and not effective_authenticated) or (spec.owner_only and structural_only):
        return AuthorizationResult(False, "tool requires authenticated Owner")
    valid, reason = spec.validate(argument)
    if not valid:
        return AuthorizationResult(False, reason)
    if isinstance(argument, str):
        argument = argument.strip()
    return AuthorizationResult(True, "authorized", name, argument, spec.risk_class)


def authorize_plan(plan: Any, *, owner_authenticated: bool | None = None, owner_evidence: OwnerAuthenticationEvidence | None = None, request_id: str | None = None, policy_snapshot: OwnerPolicySnapshot | None = None, current_policy: str = "") -> tuple[list[tuple[str, str | None]], list[str]]:
    if not isinstance(plan, list):
        return [], ["plan must be a JSON array"]
    if len(plan) > MAX_TOOLS_PER_PLAN:
        return [], ["plan exceeds maximum tool count"]
    accepted: list[tuple[str, str | None]] = []
    errors: list[str] = []
    for item in plan:
        result = authorize_tool(item, owner_authenticated=owner_authenticated, owner_evidence=owner_evidence, request_id=request_id, current_policy=current_policy)
        if result.allowed:
            accepted.append((result.name, result.argument))
        else:
            errors.append(result.reason)
    return accepted, errors


def public_plan(authorized: list[tuple[str, str | None]]) -> list[str | list[str]]:
    return [name if arg is None else [name, arg] for name, arg in authorized]
