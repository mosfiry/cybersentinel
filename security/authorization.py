from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tools.registry import KNOWN_TOOLS, MAX_ARG_LENGTH, get_tool
from security.owner_policy import OwnerAuthenticationEvidence, OwnerPolicySnapshot
from security.authorization_context import AuthorizationContext, AuthorizationDecision

MAX_TOOLS_PER_PLAN = 8


@dataclass(frozen=True)
class AuthorizationResult:
    allowed: bool
    reason: str
    name: str | None = None
    argument: str | None = None
    risk_class: str | None = None
    decision: AuthorizationDecision | None = None


@dataclass(frozen=True)
class AuthorizationPlanResult:
    accepted: tuple[tuple[str, str | None], ...]
    errors: tuple[str, ...]
    decisions: tuple[AuthorizationDecision, ...] = ()

    def __iter__(self):
        # Compatibility: existing callers may still unpack (accepted, errors).
        yield list(self.accepted)
        yield list(self.errors)


def _result(context: AuthorizationContext | None, *, allowed: bool, reason: str, name: str | None = None, argument: str | None = None, risk_class: str | None = None) -> AuthorizationResult:
    decision = AuthorizationDecision.issue(context, allowed=allowed, reason=reason, tool=name or "", risk_class=risk_class, argument=argument) if context is not None else None
    return AuthorizationResult(allowed, reason, name, argument, risk_class, decision)


def authorize_tool(item: Any, *, context: AuthorizationContext | None = None, owner_authenticated: bool | None = None, owner_evidence: OwnerAuthenticationEvidence | None = None, request_id: str | None = None, current_policy: str = "") -> AuthorizationResult:
    """Authorize a tool. Sensitive execution must use an immutable AuthorizationContext.

    Legacy evidence arguments remain as a compatibility adapter for the core boundary;
    boolean authentication is never accepted as a source of authority.
    """
    if context is not None and any(value is not None for value in (owner_authenticated, owner_evidence, request_id)):
        return _result(context, allowed=False, reason="mixed authorization inputs are forbidden")
    if context is None and owner_evidence is None and owner_authenticated is True:
        return AuthorizationResult(False, "typed Owner authentication evidence required")
    evidence_valid = owner_evidence is not None and (request_id is None or owner_evidence.is_valid(request_id))
    if owner_evidence is not None and not evidence_valid:
        return AuthorizationResult(False, "invalid or stale Owner authentication evidence")
    structural_only = context is None and owner_evidence is None and owner_authenticated is None
    effective_authenticated = context is not None or evidence_valid or structural_only
    if owner_authenticated is False or (not effective_authenticated and not structural_only):
        return AuthorizationResult(False, "owner authentication required")
    if not isinstance(item, (str, list, tuple)):
        return _result(context, allowed=False, reason="tool entry must be a string or [name, argument]")
    if isinstance(item, str):
        name, argument = item, None
    else:
        if len(item) != 2:
            return _result(context, allowed=False, reason="tool arguments must contain exactly name and argument")
        name, argument = item
    if not isinstance(name, str) or name not in KNOWN_TOOLS:
        return _result(context, allowed=False, reason="unknown tool", name=name if isinstance(name, str) else None)
    spec = get_tool(name)
    if spec is None:
        return _result(context, allowed=False, reason="unknown tool", name=name)
    if spec.owner_only and not effective_authenticated:
        return _result(context, allowed=False, reason="tool requires authenticated Owner", name=name, risk_class=spec.risk_class)
    if spec.owner_only and structural_only:
        return _result(context, allowed=False, reason="sensitive tool requires AuthorizationContext", name=name, risk_class=spec.risk_class)
    if spec.scope_required and (context is None or context.scope_snapshot is None):
        return _result(context, allowed=False, reason="scope-bound tool requires AuthorizationContext with ScopeSnapshot", name=name, risk_class=spec.risk_class)
    valid, reason = spec.validate(argument)
    if not valid:
        return _result(context, allowed=False, reason=reason, name=name, risk_class=spec.risk_class)
    if isinstance(argument, str):
        argument = argument.strip()
    return _result(context, allowed=True, reason="authorized", name=name, argument=argument, risk_class=spec.risk_class)


def authorize_plan(plan: Any, *, context: AuthorizationContext | None = None, owner_authenticated: bool | None = None, owner_evidence: OwnerAuthenticationEvidence | None = None, request_id: str | None = None, policy_snapshot: OwnerPolicySnapshot | None = None, current_policy: str = "") -> AuthorizationPlanResult:
    if not isinstance(plan, list):
        return AuthorizationPlanResult((), ("plan must be a JSON array",))
    if len(plan) > MAX_TOOLS_PER_PLAN:
        return AuthorizationPlanResult((), ("plan exceeds maximum tool count",))
    accepted: list[tuple[str, str | None]] = []
    errors: list[str] = []
    decisions: list[AuthorizationDecision] = []
    for item in plan:
        result = authorize_tool(item, context=context, owner_authenticated=owner_authenticated, owner_evidence=owner_evidence, request_id=request_id, current_policy=current_policy)
        if result.decision is not None:
            decisions.append(result.decision)
        if result.allowed:
            accepted.append((result.name, result.argument))
        else:
            errors.append(result.reason)
    return AuthorizationPlanResult(tuple(accepted), tuple(errors), tuple(decisions))


def public_plan(authorized: list[tuple[str, str | None]]) -> list[str | list[str]]:
    return [name if arg is None else [name, arg] for name, arg in authorized]
