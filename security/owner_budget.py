"""Owner-authorized tool budget (INV-SCOPE-2 / B-1 closure).

Deterministic contract:

    EFFECTIVE_TOOLS = OWNER_AUTHORIZED_BUDGET intersect MODEL_REQUESTED_TOOLS

The budget is authority the Owner has ALREADY granted (the Owner Policy
declaration, optionally narrowed by an Owner scope declaration). It is never
derived from model output: the model may request tools, it may never grant
them. Every widening attempt (wildcards, unknown tools, declarations beyond
the policy budget) fails closed. This object carries provenance of its grant;
it is a reflection of existing authority, never a mint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from tools.registry import KNOWN_TOOLS


class OwnerBudgetError(PermissionError):
    """Raised when an Owner budget is absent, malformed, or attempts widening."""


def _normalized(names: Iterable[str], *, context: str) -> tuple[str, ...]:
    ordered: list[str] = []
    seen: set[str] = set()
    for item in names:
        name = str(item).strip()
        if not name:
            raise OwnerBudgetError("empty tool name in " + context)
        if "*" in name or "?" in name:
            raise OwnerBudgetError("wildcards are forbidden in " + context)
        if name not in KNOWN_TOOLS:
            raise OwnerBudgetError("unknown tool in " + context + ": " + name)
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return tuple(ordered)


@dataclass(frozen=True)
class OwnerAuthorizedToolBudget:
    """Immutable, already-granted Owner tool authority with provenance."""

    tools: frozenset[str]
    source: str = "owner_policy"
    policy_version: str = ""
    owner_approval: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "tools", frozenset(self.tools))
        unknown = self.tools - KNOWN_TOOLS
        if unknown:
            raise OwnerBudgetError("owner budget contains unknown tools: " + ", ".join(sorted(unknown)))

    def intersect(self, requested_tools: Iterable[str]) -> tuple[str, ...]:
        """EFFECTIVE_TOOLS = budget intersection model request.

        The intersection is order preserving and deduplicated. Unknown,
        renamed, or ungranted tools never enter the effective scope; the
        model request can only narrow the budget.
        """
        effective: list[str] = []
        seen: set[str] = set()
        for item in requested_tools:
            name = str(item).strip()
            if name in self.tools and name not in seen:
                seen.add(name)
                effective.append(name)
        return tuple(effective)

    def narrowed_by(self, declaration: Iterable[str]) -> "OwnerAuthorizedToolBudget":
        """Narrow the granted budget; widening is rejected deterministically."""
        granted = _normalized(declaration, context="owner tool budget declaration")
        widening = [name for name in granted if name not in self.tools]
        if widening:
            raise OwnerBudgetError("owner declaration widens the Owner Policy budget: " + ", ".join(widening))
        return OwnerAuthorizedToolBudget(frozenset(granted), source=self.source + "+owner_declaration", policy_version=self.policy_version, owner_approval=self.owner_approval)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": sorted(self.tools),
            "source": self.source,
            "policy_version": self.policy_version,
            "owner_approval": self.owner_approval,
        }

    @classmethod
    def from_owner_policy(cls, *, policy_version: str = "", owner_approval: str = "") -> "OwnerAuthorizedToolBudget":
        from security.owner_policy import load_policy
        budget = load_policy().owner_tool_budget
        if not budget:
            raise OwnerBudgetError("Owner Policy does not declare an owner tool budget; no tool authority may be granted")
        granted = _normalized(budget, context="Owner Policy tool budget")
        return cls(frozenset(granted), source="owner_policy", policy_version=str(policy_version), owner_approval=str(owner_approval))

    @classmethod
    def from_owner_declaration(cls, scope_context: dict[str, Any] | None, *, policy_version: str = "", owner_approval: str = "") -> "OwnerAuthorizedToolBudget":
        """Policy budget, optionally narrowed by the Owner's declaration.

        The declaration can only narrow the Owner Policy budget; it can
        never widen it, and the model plan is never an input to this object.
        """
        budget = cls.from_owner_policy(policy_version=policy_version, owner_approval=owner_approval)
        declaration = (scope_context or {}).get("owner_allowed_tools")
        if declaration is None:
            return budget
        if not isinstance(declaration, (list, tuple)):
            raise OwnerBudgetError("owner_allowed_tools declaration must be a list of granted tool names")
        return budget.narrowed_by(declaration)


__all__ = ["OwnerAuthorizedToolBudget", "OwnerBudgetError"]
