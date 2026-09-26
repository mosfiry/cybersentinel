from __future__ import annotations

"""B3-C4B: canonical ExecutionPlan runtime integration.

This module is the single runtime adapter between untrusted MODEL_OUTPUT
(ToolCallProposal objects / legacy PlanStep objects) and the typed
ExecutionPlan layer established by B3-C2/C3. It closes the B3-C4A finding
that model-derived proposals could reach authorize_tool() -> proof ->
registry.execute() without ever becoming part of a derived ExecutionPlan.

Canonical Mission model execution path after B3-C4B:

    OWNER_INSTRUCTION
        -> MissionIntent
        -> TaskIntent
        -> validated ActionIntent
        -> OwnerAuthorizedToolBudget (intersection)
        -> ExecutionPlan            (derive_execution_plan only)
        -> MissionAuthorizationSnapshot agreement
        -> AuthorizationDecision
        -> MissionExecutionBoundary
        -> ExecutionAuthorizationProof
        -> validate_against_mission()
        -> tools.registry.execute()
        -> ToolSpec.handler

Authority rules (INV-C4-1..15):

- ExecutionPlan is a deterministic effective-action representation. It is
  never an AuthorizationDecision, never a MissionAuthorizationSnapshot, never
  an ExecutionAuthorizationProof, and never a permission. No field of a plan
  grants anything.
- The only tool-authority source is the OwnerAuthorizedToolBudget. On the
  Mission model path the runtime budget is reconstructed from the
  Owner-minted MissionAuthorizationSnapshot allowlist (policy -> budget ->
  snapshot -> budget view); the model can only NARROW it.
- MODEL-supplied identity fields (tool_call_id, action_id, arguments,
  mission/run/turn identity) are preserved as descriptive identity only.
  Authority-shaped values (owner_budget, effective_actions, authorization,
  approval, snapshot, proof, scope expansion, ...) are rejected by the
  existing ActionIntent validation; nothing here re-implements it.
- The runtime obtains ExecutionPlan objects only through
  derive_execution_plan(owner_budget, action_intents) (B3-C3 trusted
  derivation). No effective_actions parameter, no caller-supplied plan.
- Empty intersection at the pure layer still raises ExecutionPlanError
  (B3-C3, unchanged). The runtime maps derivation failure to a deterministic
  fail-closed outcome; it never falls back to model tools, policy tools,
  registered tools, or the legacy Plan.
- Legacy Plan/PlanStep remain a descriptive compatibility representation.
  They reach executable authority only through this adapter -> validated
  ActionIntent -> derive_execution_plan; they never execute independently.

This module imports nothing from agent.mission_runtime or agent.agent_core, so
the security layer keeps its existing dependency direction.
"""

from typing import Any, Iterable

from security.execution_plan import (
    ExecutionPlan,
    ExecutionPlanError,
    derive_execution_plan,
    validate_execution_plan,
)
from security.execution_proof import RejectionCode, canonical_execution_fingerprint
from security.intent_ladder import (
    ActionIntent,
    ActionIntentError,
    TaskIntent,
    TaskIntentError,
    derive_action_intents,
    derive_task_intents,
    validate_action_intent_proposal,
)
from security.owner_budget import OwnerAuthorizedToolBudget, OwnerBudgetError

__all__ = [
    "ExecutionPlanRuntimeError",
    "adapt_model_proposals",
    "bind_execution_plan",
    "canonical_plan_identity",
    "derive_mission_execution_plan",
    "gate_action_against_plan",
    "legacy_plan_effective_tools",
    "legacy_step_execution_plan",
    "mission_binding_fingerprint",
    "owner_budget_from_snapshot",
    "proposal_action_identity",
    "registered_owner_budget_from_snapshot",
    "reconstruct_execution_plan",
    "runtime_task_intents",
    "validate_stored_execution_plan",
]


class ExecutionPlanRuntimeError(PermissionError):
    """Raised when the runtime plan path fails closed (never a widening)."""


def mission_binding_fingerprint(mission: Any) -> str:
    """Deterministic canonical binding of one ExecutionPlan to its Mission.

    Pure: derived only from durable mission identity fields. A plan derived
    for another mission can never match this binding (INV-C4-12).
    """
    return canonical_execution_fingerprint({
        "mission_id": str(getattr(mission, "mission_id", "") or ""),
        "request_id": str(getattr(mission, "request_id", "") or ""),
        "objective": str(getattr(mission, "objective", "") or ""),
    })


def runtime_task_intents(mission: Any) -> tuple[TaskIntent, ...]:
    """Deterministic TaskIntent layer for one mission (no model proposal).

    Reuses the canonical B3-A derivation: the model never constructs
    TaskIntent objects, and this deterministic path carries
    provenance=DETERMINISTIC_DERIVED with the mission binding fingerprint.
    """
    from agent.model_intelligence.conversation import MissionIntent

    intent = MissionIntent(
        objective=str(getattr(mission, "objective", "") or ""),
        semantic_fingerprint=mission_binding_fingerprint(mission),
        source="deterministic_fallback",
    )
    return derive_task_intents(intent)


def proposal_action_identity(proposal: Any) -> str:
    """Deterministic canonical action identity for one model proposal.

    Preserves legitimate model-supplied identity (action_id / step_id /
    tool_call_id) but qualifies it with the unique tool_call_id so two
    proposals of one turn can never collide on the same model-supplied
    action_id (the plan requires unique action identities). The identity is
    a pure function of the proposal fields, so the derivation adapter and
    the execution gate always compute the same value. MODEL-supplied values
    remain descriptive identity only; none is ever interpreted as Owner
    authority (INV-C4-2).
    """
    action_id = str(getattr(proposal, "action_id", "") or "").strip()
    tool_call_id = str(getattr(proposal, "tool_call_id", "") or "").strip()
    if action_id and tool_call_id:
        return action_id + ":" + tool_call_id
    return tool_call_id or action_id


def adapt_model_proposals(mission: Any, proposals: Iterable[Any]) -> tuple[ActionIntent, ...]:
    """B3-C4B adapter: untrusted model proposals -> validated ActionIntents.

    Exactly one adapter boundary (section 4 of the C4B contract). It reuses
    derive_action_intents / validate_action_intent_proposal; it does not
    duplicate validation. Authority-shaped arguments and unknown fields are
    rejected fail-closed by that existing validator. A model value is never
    interpreted as Owner authority.
    """
    tasks = runtime_task_intents(mission)
    task_ids = frozenset(task.task_id for task in tasks)
    items: list[dict[str, Any]] = []
    for proposal in proposals:
        arguments = getattr(proposal, "arguments", None)
        if not isinstance(arguments, dict):
            arguments = {}
        items.append({
            "action_id": proposal_action_identity(proposal),
            "task_id": tasks[0].task_id,
            "tool_name": str(getattr(proposal, "name", "") or "").strip(),
            "arguments": dict(arguments),
            "dependencies": (),
            "description": "",
        })
    return derive_action_intents(tasks, items)


def owner_budget_from_snapshot(mission: Any) -> OwnerAuthorizedToolBudget:
    """Reconstruct the Mission tool-authority view from the Owner snapshot.

    The snapshot is Owner-minted evidence of the already-granted budget
    (policy -> owner_tool_budget -> snapshot allowlist). Rebuilding a typed
    OwnerAuthorizedToolBudget from it does not mint or widen authority: the
    model request is intersected afterwards and can only narrow. Unknown or
    malformed allowlists fail closed (OwnerBudgetError / snapshot errors).
    """
    from security.mission_authorization import MissionAuthorizationSnapshot

    snapshot = MissionAuthorizationSnapshot.from_dict(dict(getattr(mission, "authorization_snapshot", None) or {}))
    return OwnerAuthorizedToolBudget(
        frozenset(snapshot.allowed_tools),
        source="mission_snapshot",
        policy_version=str(snapshot.policy_version),
        owner_approval=str(snapshot.owner_approval),
    )


def registered_owner_budget_from_snapshot(mission: Any) -> OwnerAuthorizedToolBudget:
    """B3-C5: registered-only reconstruction of the snapshot tool budget.

    Compatibility-era snapshots may name tools that predate the registry
    (for example legacy "write" fixtures). The OwnerAuthorizedToolBudget
    constructor fails closed on unknown tools, so reconstructing the budget
    directly from such a snapshot would block the whole mission path before
    any deterministic narrowing can happen. This variant intersects the
    snapshot allowlist with the registry KNOWN_TOOLS first:

    - pure narrowing: registered = snapshot allowlist & KNOWN_TOOLS, so the
      reconstructed budget is a subset of the Owner-minted view and can
      never mint or widen authority;
    - fail closed preserved: malformed snapshots still raise the same
      snapshot validation errors, and an empty registered set still yields
      an empty budget (empty intersection -> empty effective scope, never
      a fallback grant).
    """
    from security.mission_authorization import MissionAuthorizationSnapshot
    from security.owner_budget import KNOWN_TOOLS

    snapshot = MissionAuthorizationSnapshot.from_dict(dict(getattr(mission, "authorization_snapshot", None) or {}))
    allowed = frozenset(str(item) for item in snapshot.allowed_tools)
    registered = allowed & KNOWN_TOOLS
    return OwnerAuthorizedToolBudget(
        registered,
        source="mission_snapshot+registered",
        policy_version=str(snapshot.policy_version),
        owner_approval=str(snapshot.owner_approval),
    )


def derive_mission_execution_plan(mission: Any, proposals: Iterable[Any]) -> ExecutionPlan:
    """Derive the canonical per-turn ExecutionPlan for a Mission model turn.

    Trusted derivation only (INV-C4-4): OwnerAuthorizedToolBudget (from the
    Owner-minted snapshot) intersected with validated model ActionIntents,
    through the B3-C3 derive_execution_plan boundary. No effective_actions
    input exists. Cross-mission bindings fail closed (INV-C4-12). Empty
    intersection raises ExecutionPlanError (INV-C4-11, pure layer unchanged).
    """
    budget = owner_budget_from_snapshot(mission)
    intents = adapt_model_proposals(mission, proposals)
    plan = derive_execution_plan(budget, intents)
    if plan.mission_fingerprint != mission_binding_fingerprint(mission):
        raise ExecutionPlanError("cross-mission ExecutionPlan binding rejected")
    return plan


def gate_action_against_plan(plan: ExecutionPlan, *, action_id: str, tool_name: str, arguments: Any) -> tuple[bool, str, str]:
    """B3-C4B execution gate (section 9): action-in-plan proof before execution.

    B3-C4B-H1 strict action identity: a proposal may execute only if it
    maps to a concrete action of the CURRENT ExecutionPlan by exact planned
    action identity, with identical tool and canonical arguments. There is
    NO tool+arguments fallback: equality of tool and arguments never mints
    an execution, and a fresh action identity fails closed with
    PLAN_MISMATCH even when it repeats an already-planned action
    (INV-C4-H1-2, INV-C4-H1-3). A model cannot introduce a new action
    between planning and execution by emitting another ToolCall: identity,
    tool, or argument mismatches fail closed with PLAN_MISMATCH and no tool
    handler runs (INV-C4-3). A forged/tampered plan is rejected by full plan
    re-validation (INV-C4-2).

    Execution cardinality equals derived ExecutionPlan cardinality
    (INV-C4-H1-4): the C3 plan represents effective actions as
    first-seen-unique per tool (by_tool), so one planned action carries
    exactly one executable identity per turn and duplicate proposals of the
    same planned action are rejected. The plan representation itself has no
    repeated-action multiplicity, so the gate must not discover any
    implicitly. Legitimate repetition of a side effect is a new model turn,
    which derives a new plan with fresh identities (INV-C4-H1-5).
    """
    ok, reason = validate_execution_plan(plan)
    if not ok:
        return False, RejectionCode.PLAN_MISMATCH.value, "execution plan integrity failure: " + reason
    wanted = str(action_id or "").strip()
    candidate = arguments if isinstance(arguments, dict) else {}
    candidate_fingerprint = canonical_execution_fingerprint(candidate)
    match = next((action for action in plan.actions if action.action_id == wanted), None)
    if match is None:
        return False, RejectionCode.PLAN_MISMATCH.value, "action is not part of the current ExecutionPlan: " + wanted
    if match.tool_name != str(tool_name or "").strip():
        return False, RejectionCode.PLAN_MISMATCH.value, "action tool differs from the current ExecutionPlan: " + str(tool_name)
    if match.arguments_fingerprint != candidate_fingerprint:
        return False, RejectionCode.PLAN_MISMATCH.value, "action arguments differ from the current ExecutionPlan: " + wanted
    return True, "", "authorized"


def bind_execution_plan(mission: Any, plan: ExecutionPlan) -> dict[str, Any]:
    """Bind the derived plan to the mission as the canonical plan identity.

    The current plan is stored in mission.progress["execution_plan"] and an
    immutable copy is appended to the history, so replans never mutate a
    previous plan (P1 stays P1; P2 is a new plan, section 12). The stored
    plan_fingerprint is the canonical plan identity used by
    ExecutionAuthorizationProof.validate_against_mission (section 8).
    """
    entry = plan.to_dict()
    history = mission.progress.setdefault("execution_plans", [])
    history.append(dict(entry))
    mission.progress["execution_plan"] = entry
    return entry


def canonical_plan_identity(mission: Any) -> str:
    """One canonical plan identity for the Mission model execution path.

    When a derived ExecutionPlan is bound (model path), its fingerprint is
    the canonical identity. Otherwise the legacy Plan fingerprint remains
    canonical (slice / owner-direct compatibility). The two are never
    silently mixed: a proof bound to one identity cannot validate against the
    other (INV-C4-7, INV-C4-8, INV-C4-9).
    """
    stored = (getattr(mission, "progress", None) or {}).get("execution_plan") or {}
    if isinstance(stored, dict):
        fingerprint = str(stored.get("plan_fingerprint", "") or "")
        if fingerprint:
            return fingerprint
    return mission.plan.fingerprint


def reconstruct_execution_plan(data: Any) -> ExecutionPlan:
    """Rebuild a typed ExecutionPlan from its persisted dict (tamper check).

    Reuses the frozen constructors; the recomputed fingerprint is compared by
    callers against the stored one, so any stored-plan mutation fails closed.
    """
    if not isinstance(data, dict):
        raise ExecutionPlanRuntimeError("stored execution plan must be a dict")
    actions: list[ActionIntent] = []
    for item in data.get("actions", ()):
        if not isinstance(item, dict):
            raise ExecutionPlanRuntimeError("stored execution plan action must be a dict")
        arguments = item.get("arguments")
        if not isinstance(arguments, dict):
            raise ExecutionPlanRuntimeError("stored execution plan arguments must be a dict")
        actions.append(ActionIntent(
            action_id=str(item.get("action_id", "")),
            task_id=str(item.get("task_id", "")),
            parent_task_fingerprint=str(item.get("parent_task_fingerprint", "")),
            parent_mission_fingerprint=str(item.get("parent_mission_fingerprint", "")),
            tool_name=str(item.get("tool_name", "")),
            arguments=dict(arguments),
            arguments_fingerprint=str(item.get("arguments_fingerprint", "")),
            dependencies=tuple(str(dep) for dep in (item.get("dependencies", ()) or ())),
            description=str(item.get("description", "")),
            provenance=str(item.get("provenance", "")),
        ))
    if not actions:
        raise ExecutionPlanRuntimeError("stored execution plan requires at least one action")
    plan = ExecutionPlan.derive(tuple(actions), provenance=str(data.get("provenance", "DETERMINISTIC_DERIVED")))
    if plan.mission_fingerprint != str(data.get("mission_fingerprint", "")):
        raise ExecutionPlanRuntimeError("stored execution plan mission binding mismatch")
    if plan.plan_fingerprint != str(data.get("plan_fingerprint", "")):
        raise ExecutionPlanRuntimeError("stored execution plan fingerprint mismatch")
    return plan


def validate_stored_execution_plan(mission: Any) -> tuple[bool, str]:
    """Entry-gate check: a bound plan must match its Owner snapshot allowlist.

    The stored canonical plan is fully reconstructed and fingerprint-
    verified (any tampering fails closed), and every planned tool must remain
    inside the Owner-minted snapshot allowlist. This makes the invariant
    explicit at mission entry: the plan authorized equals the plan derived
    from Owner Budget intersect validated ActionIntents (sections 7 and 8).
    A mission without a bound plan is unaffected (legacy compatibility).
    """
    stored = (getattr(mission, "progress", None) or {}).get("execution_plan")
    if not stored:
        return True, ""
    try:
        plan = reconstruct_execution_plan(stored)
    except (ExecutionPlanError, ExecutionPlanRuntimeError, ActionIntentError, TaskIntentError, KeyError, TypeError, ValueError, PermissionError) as exc:
        return False, "stored execution plan is invalid: " + str(exc)
    from security.mission_authorization import MissionAuthorizationError, MissionAuthorizationSnapshot

    try:
        snapshot = MissionAuthorizationSnapshot.from_dict(dict(getattr(mission, "authorization_snapshot", None) or {}))
    except (MissionAuthorizationError, KeyError, TypeError, ValueError, PermissionError) as exc:
        return False, "stored execution plan requires a valid authorization snapshot: " + str(exc)
    for action in plan.actions:
        if action.tool_name in snapshot.forbidden_actions or action.tool_name not in snapshot.allowed_tools or action.tool_name not in snapshot.allowed_actions:
            return False, "stored execution plan contains actions or tools outside authorization snapshot: " + action.tool_name
    return True, "authorized"


def legacy_plan_effective_tools(owner_budget: OwnerAuthorizedToolBudget, plan: Any, *, request_id: str = "") -> tuple[tuple[str, ...], ExecutionPlan | None]:
    """B3-C4B compatibility adapter for the legacy Plan/PlanStep (section 16).

    legacy Plan/PlanStep -> adapter -> validated ActionIntent ->
    derive_execution_plan(owner_budget, ...) -> effective tools. The result
    is identical to the previous owner_budget.intersect(step actions)
    semantics (order preserving, deduplicated, unknown tools dropped,
    empty intersection -> empty effective scope, never a fallback grant),
    but the effective scope now provably equals the tool names of a derived
    ExecutionPlan (section 7: the snapshot allowlist corresponds to the
    derived plan). Invalid individual steps are dropped (narrowing only);
    a derivation that still fails (e.g. empty intersection) yields an empty
    effective scope, which fails closed at the snapshot and proof layers.
    The returned plan is descriptive; it is not stored as mission plan
    identity because the legacy slice path keeps Plan.fingerprint.
    """
    from agent.model_intelligence.conversation import MissionIntent
    from tools.registry import KNOWN_TOOLS

    binding = canonical_execution_fingerprint({
        "request_id": str(request_id or ""),
        "objective": str(getattr(plan, "objective", "") or ""),
    })
    intent = MissionIntent(objective=str(getattr(plan, "objective", "") or ""), semantic_fingerprint=binding, source="deterministic_fallback")
    tasks = derive_task_intents(intent)
    items: list[dict[str, Any]] = []
    for step in getattr(plan, "steps", ()) or ():
        action = str(getattr(step, "action", "") or "").strip()
        if not action or action == "__planning_failure__":
            continue
        if action not in KNOWN_TOOLS:
            continue
        arguments = dict(getattr(step, "retry_policy", None) or {}).get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        item = {
            "action_id": str(getattr(step, "step_id", "") or "").strip(),
            "task_id": tasks[0].task_id,
            "tool_name": action,
            "arguments": dict(arguments),
            "dependencies": (),
            "description": "",
        }
        ok, _reason = validate_action_intent_proposal([item], frozenset(task.task_id for task in tasks))
        if ok:
            items.append(item)
    if not items:
        return (), None
    try:
        intents = derive_action_intents(tasks, items)
        derived = derive_execution_plan(owner_budget, intents)
    except (ExecutionPlanError, ActionIntentError, TaskIntentError, OwnerBudgetError, ValueError, PermissionError):
        return (), None
    return tuple(action.tool_name for action in derived.actions), derived


def legacy_step_execution_plan(owner_budget: OwnerAuthorizedToolBudget, plan: Any, step: Any, *, request_id: str = "") -> ExecutionPlan | None:
    """B3-C5: canonical per-step conversion of one legacy PlanStep.

    The C3 ExecutionPlan represents effective actions first-seen-unique per
    tool (INV-C4-H1-4), so converting a whole legacy plan collapses repeated
    same-tool steps into a single action and every later identical step
    would fail the strict identity gate forever. The slice path therefore
    converts the CURRENT legacy step only:

    - acceptance is identical to whole-plan conversion: a step may execute
      iff its tool is registered and inside the Owner budget (intersection
      at derivation, B3-H4); unknown, malformed, or out-of-budget steps
      return None and fail closed;
    - repeated same-tool steps each derive their own fresh canonical
      identity (INV-C4-H1-5: legitimate repetition is a new derivation,
      never implicit plan multiplicity);
    - derivation is still only derive_execution_plan(owner_budget,
      validated ActionIntent): no caller-supplied plan, no widening.
    """
    from agent.model_intelligence.conversation import MissionIntent
    from tools.registry import KNOWN_TOOLS

    action = str(getattr(step, "action", "") or "").strip()
    if not action or action == "__planning_failure__" or action not in KNOWN_TOOLS:
        return None
    binding = canonical_execution_fingerprint({
        "request_id": str(request_id or ""),
        "objective": str(getattr(plan, "objective", "") or ""),
    })
    intent = MissionIntent(objective=str(getattr(plan, "objective", "") or ""), semantic_fingerprint=binding, source="deterministic_fallback")
    tasks = derive_task_intents(intent)
    arguments = dict(getattr(step, "retry_policy", None) or {}).get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}
    item = {
        "action_id": str(getattr(step, "step_id", "") or "").strip(),
        "task_id": tasks[0].task_id,
        "tool_name": action,
        "arguments": dict(arguments),
        "dependencies": (),
        "description": "",
    }
    ok, _reason = validate_action_intent_proposal([item], frozenset(task.task_id for task in tasks))
    if not ok:
        return None
    try:
        intents = derive_action_intents(tasks, [item])
        return derive_execution_plan(owner_budget, intents)
    except (ExecutionPlanError, ActionIntentError, TaskIntentError, OwnerBudgetError, ValueError, PermissionError):
        return None
