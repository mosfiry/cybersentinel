from __future__ import annotations

"""B3-C2: typed execution-intent structure only.

ExecutionPlan is the boundary after ActionIntent and before any future
execution-plan/authorization integration. It is descriptive data, never
authority: this module does not import authorization, proof, policy, budget,
or tool-execution machinery.

The current ActionIntent contract exposes a semantic mission fingerprint but
not a runtime mission_id or run_id. C2 therefore binds the plan to the common
parent_mission_fingerprint and records runtime identity fields as deferred,
not invented.
"""

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from security.intent_ladder import ActionIntent


ALLOWED_ACTION_PROVENANCE = frozenset({"MODEL_PROPOSAL", "DETERMINISTIC_DERIVED"})


MAX_EXECUTION_PLAN_ACTIONS = 64


class ExecutionPlanError(ValueError):
    """Raised when a typed execution-intent structure is invalid."""


def _canonical_fingerprint(value: Any) -> str:
    """Use the repository's established canonical JSON/SHA-256 contract."""
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _authority_key(name: Any) -> bool:
    folded = str(name).casefold()
    return any(token in folded for token in (
        "authorization", "authorisation", "owner", "credential", "execution_proof",
        "proof", "capability", "permission", "grant", "budget", "approval",
        "allowed_tools", "scope_expansion", "token", "secret", "password",
    ))


def _validate_provenance(value: Any) -> str:
    if not isinstance(value, str) or value not in ALLOWED_ACTION_PROVENANCE:
        raise ExecutionPlanError("invalid descriptive provenance")
    return value


def _action_payload(action: ActionIntent) -> dict[str, Any]:
    if not _is_action_intent(action):
        raise ExecutionPlanError("execution plan requires typed ActionIntent objects")
    payload = action.to_dict()
    if any(_authority_key(key) for key in payload):
        raise ExecutionPlanError("authority-shaped ActionIntent field rejected")
    if action.arguments_fingerprint != _canonical_fingerprint(action.arguments):
        raise ExecutionPlanError("non-canonical ActionIntent arguments")
    if action.fingerprint != _canonical_fingerprint(payload):
        raise ExecutionPlanError("ActionIntent fingerprint mismatch")
    return payload


def _is_action_intent(value: Any) -> bool:
    """Recognize the existing typed ActionIntent without importing its module."""
    return (
        value.__class__.__name__ == "ActionIntent"
        and value.__class__.__module__ == "security.intent_ladder"
        and callable(getattr(value, "to_dict", None))
        and isinstance(getattr(value, "arguments", None), dict)
    )


def _validate_actions(actions: tuple[ActionIntent, ...], mission_fingerprint: str) -> tuple[str, ...]:
    if not actions:
        raise ExecutionPlanError("execution plan requires at least one ActionIntent")
    if len(actions) > MAX_EXECUTION_PLAN_ACTIONS:
        raise ExecutionPlanError("execution plan exceeds its bounded action limit")
    if not str(mission_fingerprint).strip():
        raise ExecutionPlanError("execution plan requires a parent mission fingerprint")

    action_ids: set[str] = set()
    known_ids: set[str] = set()
    fingerprints: list[str] = []
    for index, action in enumerate(actions):
        payload = _action_payload(action)
        action_id = str(action.action_id).strip()
        if not action_id or "*" in action_id or "?" in action_id:
            raise ExecutionPlanError("invalid action identity at index " + str(index))
        if action_id in action_ids:
            raise ExecutionPlanError("duplicate action identity: " + action_id)
        if action.parent_mission_fingerprint != mission_fingerprint:
            raise ExecutionPlanError("cross-mission ActionIntent binding rejected")
        dependencies = tuple(str(item).strip() for item in action.dependencies)
        if action_id in dependencies:
            raise ExecutionPlanError("self-dependency rejected: " + action_id)
        for dependency in dependencies:
            if dependency not in known_ids:
                raise ExecutionPlanError("dependency must reference an earlier action: " + dependency)
        action_ids.add(action_id)
        known_ids.add(action_id)
        fingerprints.append(_canonical_fingerprint(payload))
    return tuple(fingerprints)


def validate_execution_plan(plan: Any) -> tuple[bool, str]:
    """Purely validate an ExecutionPlan; return deterministic (ok, reason)."""
    if not isinstance(plan, ExecutionPlan):
        return False, "execution plan must be a typed ExecutionPlan"
    try:
        provenance = _validate_provenance(plan.provenance)
        if provenance != plan.provenance:
            return False, "invalid descriptive provenance"
        current = _validate_actions(tuple(plan.actions), plan.mission_fingerprint)
        if current != plan._action_fingerprints:
            return False, "ActionIntent changed after ExecutionPlan construction"
        expected = _plan_fingerprint(plan.mission_fingerprint, plan.actions, provenance)
        if plan.plan_fingerprint != expected:
            return False, "execution plan fingerprint mismatch"
    except (ExecutionPlanError, TypeError, ValueError, AttributeError) as exc:
        return False, str(exc)
    return True, "valid"


def _plan_fingerprint(mission_fingerprint: str, actions: tuple[ActionIntent, ...], provenance: str) -> str:
    return _canonical_fingerprint({
        "mission_fingerprint": mission_fingerprint,
        "actions": [action.to_dict() for action in actions],
        "provenance": provenance,
    })


@dataclass(frozen=True)
class ExecutionPlan:
    """Immutable, deterministic, authority-free ordered ActionIntent plan."""

    mission_fingerprint: str
    actions: tuple[ActionIntent, ...]
    provenance: str = "DETERMINISTIC_DERIVED"
    plan_fingerprint: str = ""
    _action_fingerprints: tuple[str, ...] = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "actions", tuple(self.actions))
        provenance = _validate_provenance(self.provenance)
        action_fingerprints = _validate_actions(self.actions, self.mission_fingerprint)
        computed = _plan_fingerprint(self.mission_fingerprint, self.actions, provenance)
        if self.plan_fingerprint and self.plan_fingerprint != computed:
            raise ExecutionPlanError("caller-supplied plan fingerprint is invalid")
        object.__setattr__(self, "plan_fingerprint", computed)
        object.__setattr__(self, "_action_fingerprints", action_fingerprints)

    @classmethod
    def derive(cls, actions: Any, *, provenance: str = "DETERMINISTIC_DERIVED") -> "ExecutionPlan":
        """Derive a plan from ordered ActionIntents without inventing bindings."""
        if not isinstance(actions, (list, tuple)) or not actions:
            raise ExecutionPlanError("execution plan derivation requires non-empty ActionIntent objects")
        typed = tuple(actions)
        if not all(_is_action_intent(item) for item in typed):
            raise ExecutionPlanError("execution plan derivation requires typed ActionIntent objects")
        mission_fingerprint = typed[0].parent_mission_fingerprint
        return cls(mission_fingerprint, typed, provenance=provenance)

    @property
    def fingerprint(self) -> str:
        return self.plan_fingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_fingerprint": self.mission_fingerprint,
            "actions": [action.to_dict() for action in self.actions],
            "provenance": self.provenance,
            "plan_fingerprint": self.plan_fingerprint,
        }


__all__ = ["ExecutionPlan", "ExecutionPlanError", "MAX_EXECUTION_PLAN_ACTIONS", "validate_execution_plan"]
