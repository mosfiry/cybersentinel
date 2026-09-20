from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MAX_ARG_LENGTH = 256
MAX_TOOLS_PER_PLAN = 8


@dataclass(frozen=True)
class AuthorizationResult:
    allowed: bool
    reason: str
    name: str | None = None
    argument: str | None = None


# The model may propose only these defensive tools. Execution remains in engine code.
KNOWN_TOOLS = frozenset({
    "status",
    "latest_intel",
    "refresh_intel",
    "local_security_check",
    "local_system_info",
    "search",
    "watch",
    "unwatch",
})

_ARGUMENT_TOOLS = frozenset({"search", "watch", "unwatch"})


def authorize_tool(item: Any, *, owner_authenticated: bool = True, current_policy: str = "") -> AuthorizationResult:
    if not owner_authenticated:
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
    if name in _ARGUMENT_TOOLS:
        if not isinstance(argument, str) or not argument.strip():
            return AuthorizationResult(False, f"{name} requires a non-empty string argument")
        argument = argument.strip()
        if len(argument) > MAX_ARG_LENGTH:
            return AuthorizationResult(False, "tool argument exceeds maximum length")
    elif argument is not None:
        return AuthorizationResult(False, f"{name} does not accept an argument")
    return AuthorizationResult(True, "authorized", name, argument)


def authorize_plan(plan: Any, *, owner_authenticated: bool = True, current_policy: str = "") -> tuple[list[tuple[str, str | None]], list[str]]:
    if not isinstance(plan, list):
        return [], ["plan must be a JSON array"]
    if len(plan) > MAX_TOOLS_PER_PLAN:
        return [], ["plan exceeds maximum tool count"]
    accepted: list[tuple[str, str | None]] = []
    errors: list[str] = []
    for item in plan:
        result = authorize_tool(item, owner_authenticated=owner_authenticated, current_policy=current_policy)
        if result.allowed:
            accepted.append((result.name, result.argument))
        else:
            errors.append(result.reason)
    return accepted, errors


def public_plan(authorized: list[tuple[str, str | None]]) -> list[str | list[str]]:
    return [name if arg is None else [name, arg] for name, arg in authorized]
