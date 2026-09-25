from __future__ import annotations

"""B3-A of the four-layer intent ladder: MissionIntent -> TaskIntent.

INV-LADDER-1 (typed boundary): a TaskIntent is a typed, frozen, immutable
semantic decomposition of a typed MissionIntent. It carries task identity,
the parent MissionIntent fingerprint, a bounded objective, bounded
dependencies, and proposal-only resources/evidence requirements. It never
carries authorization, owner approval, owner policy, credentials,
capability grants, scope expansion, or execution proofs. A TaskIntent is
data, never authority: no field of a TaskIntent is consulted by any
authorization, budget, snapshot, or proof machinery.

INV-LADDER-2 (deterministic derivation): the final TaskIntent objects are
always produced by this module's deterministic derivation. MODEL_OUTPUT may
only PROPOSE a decomposition (an untrusted list of proposal dicts). The
proposal passes the deterministic validator below, and only the derivation
in this module constructs typed TaskIntent objects. Rejected proposals fail
closed. Derivation is a pure function: identical inputs always produce
identical task identities and fingerprints (replay-safe; no clock, no
randomness, no external data).

INV-LADDER-3 (no authority widening): a TaskIntent can never widen the
Owner budget, mint an AuthorizationDecision, alter a
MissionAuthorizationSnapshot, or derive an ExecutionAuthorizationProof.
Provenance on a TaskIntent (MODEL_PROPOSAL vs DETERMINISTIC_DERIVED) is
descriptive only; it never grants or removes authority.
"""

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from agent.model_intelligence.conversation import MissionIntent

__all__ = [
    "ALLOWED_TASK_TYPES",
    "MAX_TASK_INTENTS",
    "TaskIntent",
    "TaskIntentError",
    "derive_task_intents",
    "validate_task_intent_proposal",
]


class TaskIntentError(PermissionError):
    """Raised when a task decomposition proposal is invalid or fails closed."""


ALLOWED_TASK_TYPES = frozenset({"single_task", "objective_decomposition", "verification_task"})
MAX_TASK_INTENTS = 32
ALLOWED_TASK_PROPOSAL_FIELDS = frozenset({
    "task_id",
    "objective",
    "task_type",
    "constraints",
    "dependencies",
    "proposed_resources",
    "proposed_evidence",
})
ALLOWED_TASK_PROVENANCE = frozenset({"MODEL_PROPOSAL", "DETERMINISTIC_DERIVED"})

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
    "proof",
    "attestation",
    "capability",
    "expand scope",
    "scope expansion",
)
_WILDCARD_SCOPES = frozenset({"all", "all scopes", "everything", "unrestricted", "any"})


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))


def _bounded_text_list(value: Any, *, context: str) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if not isinstance(value, (list, tuple)):
        raise TaskIntentError(context + " must be a list")
    items: list[str] = []
    for item in value:
        text = str(item).strip()
        if not text:
            raise TaskIntentError("empty entry in " + context)
        folded = text.casefold()
        if any(token in folded for token in _AUTHORITY_TOKENS):
            raise TaskIntentError("authority-shaped " + context + " entry rejected: " + text)
        if "*" in folded or "?" in folded or folded in _WILDCARD_SCOPES:
            raise TaskIntentError("wildcard " + context + " entry rejected: " + text)
        items.append(text)
    return tuple(items)


def validate_task_intent_proposal(proposal: Any) -> tuple[bool, str]:
    """Deterministically validate an UNTRUSTED model decomposition proposal.

    Pure function: no I/O, no clock, no randomness. Returns (ok, reason).
    Authority-shaped fields, unknown fields, unknown task types, wildcards,
    duplicate identities, and unbounded decompositions are rejected fail
    closed.
    """
    if not isinstance(proposal, (list, tuple)) or not proposal:
        return False, "task decomposition proposal must be a non-empty list"
    if len(proposal) > MAX_TASK_INTENTS:
        return False, "task decomposition exceeds the bounded limit of " + str(MAX_TASK_INTENTS) + " tasks"
    seen_ids: set[str] = set()
    for index, item in enumerate(proposal):
        if not isinstance(item, dict):
            return False, "task proposal entry " + str(index) + " must be a dict"
        unknown = set(item) - ALLOWED_TASK_PROPOSAL_FIELDS
        if unknown:
            return False, "unknown task proposal fields rejected: " + ", ".join(sorted(str(name) for name in unknown))
        objective = str(item.get("objective") or "").strip()
        if not objective:
            return False, "task proposal entry " + str(index) + " has an empty objective"
        task_type = str(item.get("task_type") or "single_task")
        if task_type not in ALLOWED_TASK_TYPES:
            return False, "unknown task_type: " + task_type
        task_id = str(item.get("task_id") or "task-" + str(index + 1)).strip()
        if not task_id or "*" in task_id or "?" in task_id:
            return False, "task proposal entry " + str(index) + " has an invalid task_id: " + task_id
        if task_id in seen_ids:
            return False, "duplicate task_id in decomposition proposal: " + task_id
        seen_ids.add(task_id)
        dependencies = item.get("dependencies", ()) or ()
        if not isinstance(dependencies, (list, tuple)):
            return False, "dependencies must be a list"
        for dependency in dependencies:
            if str(dependency).strip() == task_id:
                return False, "task " + task_id + " cannot depend on itself"
        try:
            _bounded_text_list(item.get("constraints", ()) or (), context="task constraints")
            _bounded_text_list(item.get("proposed_resources", ()) or (), context="proposed resources")
            _bounded_text_list(item.get("proposed_evidence", ()) or (), context="proposed evidence")
        except TaskIntentError as exc:
            return False, str(exc)
    return True, "valid"


@dataclass(frozen=True)
class TaskIntent:
    """Typed, frozen, immutable semantic decomposition of one MissionIntent.

    This is proposal/derived data only. It is not, and can never become, an
    authorization, a capability grant, or an execution permission.
    """

    task_id: str
    parent_mission_fingerprint: str
    objective: str
    task_type: str
    constraints: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    proposed_resources: tuple[str, ...] = ()
    proposed_evidence: tuple[str, ...] = ()
    provenance: str = "DETERMINISTIC_DERIVED"

    def __post_init__(self) -> None:
        for name in ("constraints", "dependencies", "proposed_resources", "proposed_evidence"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        if not str(self.task_id).strip():
            raise TaskIntentError("task intent requires a task identity")
        if not str(self.objective).strip():
            raise TaskIntentError("task intent requires a bounded objective")
        if self.task_type not in ALLOWED_TASK_TYPES:
            raise TaskIntentError("unknown task_type: " + str(self.task_type))
        if self.provenance not in ALLOWED_TASK_PROVENANCE:
            raise TaskIntentError("unknown task provenance: " + str(self.provenance))
        if not str(self.parent_mission_fingerprint).strip():
            raise TaskIntentError("task intent requires its parent MissionIntent fingerprint")
        if self.task_id in self.dependencies:
            raise TaskIntentError("task intent cannot depend on itself")

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "parent_mission_fingerprint": self.parent_mission_fingerprint,
            "objective": self.objective,
            "task_type": self.task_type,
            "constraints": list(self.constraints),
            "dependencies": list(self.dependencies),
            "proposed_resources": list(self.proposed_resources),
            "proposed_evidence": list(self.proposed_evidence),
            "provenance": self.provenance,
        }

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict()).encode("utf-8")).hexdigest()


def _mission_fingerprint(mission_intent: MissionIntent) -> str:
    existing = str(getattr(mission_intent, "semantic_fingerprint", "") or "")
    if existing:
        return existing
    return hashlib.sha256(_canonical(mission_intent.to_dict()).encode("utf-8")).hexdigest()


def derive_task_intents(mission_intent: Any, proposal: Any = None) -> tuple[TaskIntent, ...]:
    """Deterministically derive the typed TaskIntent layer for one mission.

    - mission_intent must be a typed MissionIntent; MODEL_OUTPUT never
      constructs TaskIntent objects directly.
    - proposal (when supplied) is an UNTRUSTED model decomposition: it must
      pass validate_task_intent_proposal, and every dependency must bind to
      an earlier task in the same decomposition; failures raise
      TaskIntentError (fail closed).
    - without a proposal the derivation is deterministic from the mission
      objective alone (provenance DETERMINISTIC_DERIVED).

    This function never touches the Owner budget, the Owner policy, any
    MissionAuthorizationSnapshot, any AuthorizationDecision, or any
    ExecutionAuthorizationProof.
    """
    if not isinstance(mission_intent, MissionIntent):
        raise TaskIntentError("task derivation requires a typed MissionIntent")
    parent = _mission_fingerprint(mission_intent)
    if proposal is None:
        return (
            TaskIntent(
                task_id="task-1",
                parent_mission_fingerprint=parent,
                objective=str(mission_intent.objective).strip(),
                task_type="single_task",
                constraints=tuple(mission_intent.constraints),
                proposed_evidence=tuple(mission_intent.verification_criteria),
                provenance="DETERMINISTIC_DERIVED",
            ),
        )
    ok, reason = validate_task_intent_proposal(proposal)
    if not ok:
        raise TaskIntentError(reason)
    tasks: list[TaskIntent] = []
    known_ids: set[str] = set()
    for index, item in enumerate(proposal):
        task_id = str(item.get("task_id") or "task-" + str(index + 1)).strip()
        dependencies = tuple(str(dependency).strip() for dependency in (item.get("dependencies", ()) or ()))
        unbound = [dependency for dependency in dependencies if dependency not in known_ids]
        if unbound:
            raise TaskIntentError(
                "task dependency binding failure: task " + task_id + " depends on unknown/later tasks: " + ", ".join(unbound)
            )
        tasks.append(
            TaskIntent(
                task_id=task_id,
                parent_mission_fingerprint=parent,
                objective=str(item.get("objective") or "").strip(),
                task_type=str(item.get("task_type") or "single_task"),
                constraints=_bounded_text_list(item.get("constraints", ()) or (), context="task constraints"),
                dependencies=dependencies,
                proposed_resources=_bounded_text_list(item.get("proposed_resources", ()) or (), context="proposed resources"),
                proposed_evidence=_bounded_text_list(item.get("proposed_evidence", ()) or (), context="proposed evidence"),
                provenance="MODEL_PROPOSAL",
            )
        )
        known_ids.add(task_id)
    return tuple(tasks)
