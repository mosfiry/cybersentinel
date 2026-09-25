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
    "ACTION_LADDER_MAX_ACTIONS",
    "ALLOWED_ACTION_PROVENANCE",
    "ALLOWED_TASK_TYPES",
    "ActionIntent",
    "ActionIntentError",
    "MAX_TASK_INTENTS",
    "TaskIntent",
    "TaskIntentError",
    "derive_action_intents",
    "derive_task_intents",
    "validate_action_intent_proposal",
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



# ---------------------------------------------------------------------------
# B3-B: TaskIntent -> ActionIntent (INV-LADDER-4..8)
# ---------------------------------------------------------------------------

"""B3-B of the four-layer intent ladder: TaskIntent -> ActionIntent.

An ActionIntent is a typed, frozen, immutable SEMANTIC ACTION PROPOSAL bound
to one known TaskIntent. It carries the requested tool name, canonically
normalized arguments, and the deterministic argument fingerprint. It never
carries or creates authorization: no AuthorizationDecision, no
MissionAuthorizationSnapshot, no ExecutionAuthorizationProof, no owner
policy, no credentials, no capability grants, no scope expansion. Nothing
in this section is consulted by any authorization, budget, snapshot, proof,
or registry machinery, and no path exists from an ActionIntent to
authorize_tool(), MissionAuthorizationSnapshot, ExecutionAuthorizationProof,
or registry.execute(). The STOP boundary after ActionIntent is enforced by
construction: this module never imports or calls any of them (except the
shared canonical fingerprint helper, which is pure hashing, not authority).

The Owner budget intersection (OWNER_AUTHORIZED_BUDGET intersect
MODEL_REQUEST) is NOT moved into this layer: it belongs to the later
ExecutionPlan boundary (B3-C). ActionIntent validation only rejects
authority-shaped content and unknown tools fail-closed; it never grants or
narrows any budget.
"""

from security.execution_proof import canonical_execution_fingerprint

ACTION_LADDER_MAX_ACTIONS = 64
ALLOWED_ACTION_PROPOSAL_FIELDS = frozenset({
    "action_id",
    "task_id",
    "tool_name",
    "arguments",
    "dependencies",
    "description",
})
ALLOWED_ACTION_PROVENANCE = frozenset({"MODEL_PROPOSAL", "DETERMINISTIC_DERIVED"})

_ACTION_ARGUMENT_FORBIDDEN_KEY_TOKENS: tuple[str, ...] = (
    "authorization",
    "authorisation",
    "owner_approval",
    "owner_policy",
    "owner_evidence",
    "credential",
    "execution_proof",
    "proof",
    "attestation",
    "capability",
    "grant",
    "permission",
    "allowed_tools",
    "owner_budget",
    "scope_expansion",
    "token",
    "secret",
    "password",
    "api_key",
)


class ActionIntentError(PermissionError):
    """Raised when an action proposal is invalid or fails closed."""


def _validate_action_arguments(arguments: Any) -> dict[str, Any]:
    """Deterministically normalize and validate untrusted action arguments.

    Reuses the existing canonical fingerprint mechanism (sort_keys JSON) so
    identical logical arguments always produce the identical canonical
    representation and fingerprint, independent of dictionary ordering,
    nesting, Unicode, or value types. Non-dict, non-serializable, or
    authority-shaped arguments fail closed. No clock, randomness, network,
    or model judgment is involved.
    """
    if arguments is None:
        return {}
    if not isinstance(arguments, dict):
        raise ActionIntentError("action arguments must be a dict")
    normalized: dict[str, Any] = {}
    for key, value in arguments.items():
        name = str(key)
        folded = name.casefold()
        if any(token in folded for token in _ACTION_ARGUMENT_FORBIDDEN_KEY_TOKENS):
            raise ActionIntentError("authority-shaped action argument key rejected: " + name)
        normalized[name] = value
    try:
        canonical_execution_fingerprint(normalized)
    except (TypeError, ValueError) as exc:
        raise ActionIntentError("action arguments are not canonically serializable: " + str(exc))
    return normalized


def validate_action_intent_proposal(proposal: Any, task_ids: Any) -> tuple[bool, str]:
    """Deterministically validate an UNTRUSTED action proposal list.

    Pure function: no I/O, no clock, no randomness. Every action must bind
    to a known task_id from the typed TaskIntent layer; identities must be
    unique; dependencies must reference earlier actions in the same
    proposal (forward references, self-dependencies, and therefore cycles
    are rejected); tool names must be known registry tools without
    wildcards; unknown fields and authority-shaped content fail closed.
    """
    if not isinstance(proposal, (list, tuple)) or not proposal:
        return False, "action proposal must be a non-empty list"
    if len(proposal) > ACTION_LADDER_MAX_ACTIONS:
        return False, "action proposal exceeds the bounded limit of " + str(ACTION_LADDER_MAX_ACTIONS) + " actions"
    if not isinstance(task_ids, (set, frozenset, list, tuple)) or not task_ids:
        return False, "action proposal requires known task identities"
    known_tasks = set(task_ids)
    from tools.registry import KNOWN_TOOLS
    seen_actions: set[str] = set()
    for index, item in enumerate(proposal):
        if not isinstance(item, dict):
            return False, "action proposal entry " + str(index) + " must be a dict"
        unknown = set(item) - ALLOWED_ACTION_PROPOSAL_FIELDS
        if unknown:
            return False, "unknown action proposal fields rejected: " + ", ".join(sorted(str(name) for name in unknown))
        action_id = str(item.get("action_id") or "action-" + str(index + 1)).strip()
        if not action_id or "*" in action_id or "?" in action_id:
            return False, "invalid action_id: " + action_id
        if action_id in seen_actions:
            return False, "duplicate action_id in proposal: " + action_id
        seen_actions.add(action_id)
        task_id = str(item.get("task_id") or "").strip()
        if task_id not in known_tasks:
            return False, "action " + action_id + " does not bind to a known TaskIntent: " + task_id
        tool_name = str(item.get("tool_name") or "").strip()
        if not tool_name or "*" in tool_name or "?" in tool_name:
            return False, "invalid tool_name in action " + action_id
        if tool_name not in KNOWN_TOOLS:
            return False, "unknown tool in action " + action_id + ": " + tool_name
        dependencies = item.get("dependencies", ()) or ()
        if not isinstance(dependencies, (list, tuple)):
            return False, "action dependencies must be a list"
        if action_id in {str(dependency).strip() for dependency in dependencies}:
            return False, "action " + action_id + " cannot depend on itself"
        try:
            _validate_action_arguments(item.get("arguments"))
        except ActionIntentError as exc:
            return False, str(exc)
    known_actions: set[str] = set()
    for item in proposal:
        action_id = str(item.get("action_id") or "").strip()
        dependencies = item.get("dependencies", ()) or ()
        for dependency in dependencies:
            name = str(dependency).strip()
            if name == action_id:
                return False, "action " + action_id + " cannot depend on itself"
            if name not in known_actions:
                return False, "action dependency binding failure: " + action_id + " depends on unknown or later action: " + name
        known_actions.add(action_id)
    return True, "valid"


@dataclass(frozen=True)
class ActionIntent:
    """Typed, frozen, immutable semantic action proposal bound to one TaskIntent.

    This is proposal data only. It is not, and can never become, an
    authorization, a capability grant, or an execution permission.
    """

    action_id: str
    task_id: str
    parent_task_fingerprint: str
    parent_mission_fingerprint: str
    tool_name: str
    arguments: dict[str, Any]
    arguments_fingerprint: str = ""
    dependencies: tuple[str, ...] = ()
    description: str = ""
    provenance: str = "MODEL_PROPOSAL"

    def __post_init__(self) -> None:
        object.__setattr__(self, "arguments", dict(self.arguments))
        object.__setattr__(self, "dependencies", tuple(self.dependencies))
        if not str(self.action_id).strip():
            raise ActionIntentError("action intent requires an action identity")
        if not str(self.task_id).strip():
            raise ActionIntentError("action intent requires its parent TaskIntent identity")
        if not str(self.tool_name).strip():
            raise ActionIntentError("action intent requires a tool name")
        if "*" in self.tool_name or "?" in self.tool_name:
            raise ActionIntentError("wildcard tool names are forbidden: " + self.tool_name)
        if self.provenance not in ALLOWED_ACTION_PROVENANCE:
            raise ActionIntentError("unknown action provenance: " + str(self.provenance))
        if not str(self.parent_task_fingerprint).strip() or not str(self.parent_mission_fingerprint).strip():
            raise ActionIntentError("action intent requires its parent task and mission fingerprints")
        if self.action_id in self.dependencies:
            raise ActionIntentError("action intent cannot depend on itself")
        object.__setattr__(self, "arguments_fingerprint", canonical_execution_fingerprint(self.arguments))

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "task_id": self.task_id,
            "parent_task_fingerprint": self.parent_task_fingerprint,
            "parent_mission_fingerprint": self.parent_mission_fingerprint,
            "tool_name": self.tool_name,
            "arguments": dict(self.arguments),
            "arguments_fingerprint": self.arguments_fingerprint,
            "dependencies": list(self.dependencies),
            "description": self.description,
            "provenance": self.provenance,
        }

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict()).encode("utf-8")).hexdigest()


def derive_action_intents(task_intents: Any, proposal: Any) -> tuple[ActionIntent, ...]:
    """Deterministically derive the typed ActionIntent layer for known tasks.

    - task_intents must be typed TaskIntent objects produced by
      derive_task_intents; MODEL_OUTPUT never constructs ActionIntent
      objects directly.
    - proposal is an UNTRUSTED model action proposal: it must pass
      validate_action_intent_proposal against the known task identities;
      failures raise ActionIntentError (fail closed). A missing proposal is
      rejected: no deterministic fallback may invent executable tool
      semantics without a model proposal.
    - every derived ActionIntent is bound to its parent TaskIntent
      (task identity, task fingerprint, mission fingerprint); the model
      cannot alter this binding after derivation.

    This function never touches the Owner budget, the Owner policy, any
    MissionAuthorizationSnapshot, any AuthorizationDecision, any
    ExecutionAuthorizationProof, or the tool registry execute path.
    """
    if not isinstance(task_intents, (list, tuple)) or not task_intents:
        raise ActionIntentError("action derivation requires typed TaskIntent objects")
    for task in task_intents:
        if not isinstance(task, TaskIntent):
            raise ActionIntentError("action derivation requires typed TaskIntent objects")
    tasks_by_id = {task.task_id: task for task in task_intents}
    if len(tasks_by_id) != len(task_intents):
        raise ActionIntentError("duplicate task identities in the parent layer")
    if proposal is None:
        raise ActionIntentError("action derivation requires a model action proposal; no deterministic fallback may invent executable tool semantics")
    ok, reason = validate_action_intent_proposal(proposal, set(tasks_by_id))
    if not ok:
        raise ActionIntentError(reason)
    actions: list[ActionIntent] = []
    for index, item in enumerate(proposal):
        task = tasks_by_id[str(item["task_id"]).strip()]
        actions.append(
            ActionIntent(
                action_id=str(item.get("action_id") or "action-" + str(index + 1)).strip(),
                task_id=task.task_id,
                parent_task_fingerprint=task.fingerprint,
                parent_mission_fingerprint=task.parent_mission_fingerprint,
                tool_name=str(item["tool_name"]).strip(),
                arguments=_validate_action_arguments(item.get("arguments")),
                dependencies=tuple(str(dependency).strip() for dependency in (item.get("dependencies", ()) or ())),
                description=str(item.get("description") or ""),
                provenance="MODEL_PROPOSAL",
            )
        )
    return tuple(actions)
