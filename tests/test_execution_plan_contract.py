from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from agent.model_intelligence.conversation import NaturalLanguageUnderstanding
from security.execution_plan import ExecutionPlan, ExecutionPlanError, validate_execution_plan
from security.intent_ladder import ActionIntent, ActionIntentError, derive_action_intents, derive_task_intents


def _mission(text: str = "Inspect the local workspace"):
    return NaturalLanguageUnderstanding().understand(text)


def _actions(*, text: str = "Inspect the local workspace", proposal=None):
    tasks = derive_task_intents(
        _mission(text),
        [{"task_id": "task-1", "objective": "Inspect workspace", "task_type": "single_task"}],
    )
    proposal = proposal or [{"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "arguments": {}}]
    return derive_action_intents(tasks, proposal)


def test_c2_execution_plan_is_typed_frozen_and_has_only_descriptive_fields():
    plan = ExecutionPlan.derive(_actions())
    assert isinstance(plan, ExecutionPlan)
    assert dataclasses.is_dataclass(plan)
    assert plan.__dataclass_params__.frozen is True
    assert set(plan.to_dict()) == {"mission_fingerprint", "actions", "provenance", "plan_fingerprint"}
    assert not any(hasattr(plan, name) for name in ("authorization", "decision", "proof", "owner_budget", "allowed_tools"))


def test_c2_construction_is_deterministic_and_replay_safe():
    expected = ExecutionPlan.derive(_actions())
    for _ in range(100):
        current = ExecutionPlan.derive(_actions())
        assert current == expected
        assert current.fingerprint == expected.fingerprint


def test_c2_fingerprint_is_key_order_normalized():
    first = _actions(proposal=[{"action_id": "action-1", "task_id": "task-1", "tool_name": "search", "arguments": {"a": 1, "b": {"x": 1, "y": 2}}}])
    second = _actions(proposal=[{"action_id": "action-1", "task_id": "task-1", "tool_name": "search", "arguments": {"b": {"y": 2, "x": 1}, "a": 1}}])
    assert ExecutionPlan.derive(first).fingerprint == ExecutionPlan.derive(second).fingerprint


def test_c2_modified_action_changes_plan_fingerprint():
    first = ExecutionPlan.derive(_actions())
    changed = ExecutionPlan.derive(_actions(proposal=[{"action_id": "action-1", "task_id": "task-1", "tool_name": "search", "arguments": {"query": "changed"}}]))
    assert first.fingerprint != changed.fingerprint


def test_c2_plan_fingerprint_is_computed_and_tampering_rejected():
    actions = _actions()
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan(actions[0].parent_mission_fingerprint, actions, plan_fingerprint="f" * 64)
    plan = ExecutionPlan.derive(actions)
    object.__setattr__(plan, "plan_fingerprint", "f" * 64)
    assert validate_execution_plan(plan) == (False, "execution plan fingerprint mismatch")


def test_c2_mutation_after_construction_is_rejected():
    plan = ExecutionPlan.derive(_actions())
    with pytest.raises(dataclasses.FrozenInstanceError):
        plan.provenance = "MODEL_PROPOSAL"
    object.__setattr__(plan.actions[0], "arguments", {"query": "mutated"})
    ok, reason = validate_execution_plan(plan)
    assert not ok
    assert "canonical" in reason or "changed" in reason or "fingerprint" in reason


def test_c2_empty_plan_and_missing_action_fail_closed():
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan.derive([])
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan("mission-fingerprint", ())
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan.derive([object()])


def test_c2_duplicate_action_ids_rejected():
    action = _actions()[0]
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan.derive((action, action))


def test_c2_multiple_actions_may_bind_the_same_parent_task():
    actions = _actions()
    duplicate_task_action = ActionIntent(
        action_id="action-2",
        task_id=actions[0].task_id,
        parent_task_fingerprint=actions[0].parent_task_fingerprint,
        parent_mission_fingerprint=actions[0].parent_mission_fingerprint,
        tool_name="status",
        arguments={},
    )
    plan = ExecutionPlan.derive((actions[0], duplicate_task_action))
    assert [item.task_id for item in plan.actions] == ["task-1", "task-1"]


def test_c2_dependency_ordering_forward_and_self_dependency_rejected():
    actions = _actions(proposal=[
        {"action_id": "action-1", "task_id": "task-1", "tool_name": "status"},
        {"action_id": "action-2", "task_id": "task-1", "tool_name": "search", "dependencies": ["action-1"]},
    ])
    assert len(ExecutionPlan.derive(actions).actions) == 2
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks_for_dependency(), [{"action_id": "a", "task_id": "task-1", "tool_name": "status", "dependencies": ["b"]}, {"action_id": "b", "task_id": "task-1", "tool_name": "search"}])
    self_dependent = actions[0]
    object.__setattr__(self_dependent, "dependencies", (self_dependent.action_id,))
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan.derive((self_dependent,))


def _tasks_for_dependency():
    return derive_task_intents(_mission(), [{"task_id": "task-1", "objective": "Inspect", "task_type": "single_task"}])


def test_c2_cycle_and_unknown_dependency_fail_closed():
    actions = _actions()
    second = dataclasses.replace(actions[0], action_id="action-2", dependencies=("action-1",))
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan.derive((dataclasses.replace(actions[0], dependencies=("action-2",)), second))
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan.derive((dataclasses.replace(actions[0], dependencies=("missing",)),))


def test_c2_cross_mission_action_binding_rejected():
    first = _actions()[0]
    other = _actions(text="Inspect a different mission")[0]
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan.derive((first, other))


def test_c2_malformed_action_and_noncanonical_arguments_rejected():
    action = _actions()[0]
    object.__setattr__(action, "arguments", {"owner_budget": "x"})
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan.derive((action,))
    action = _actions()[0]
    object.__setattr__(action, "arguments_fingerprint", "f" * 64)
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan.derive((action,))


@pytest.mark.parametrize("provenance", ["", "OWNER_APPROVAL", "authorization", "unknown"])
def test_c2_provenance_is_descriptive_and_allowlisted(provenance):
    with pytest.raises(ExecutionPlanError):
        ExecutionPlan.derive(_actions(), provenance=provenance)


def test_c2_authority_proof_budget_and_authorization_fields_are_not_contract_fields():
    plan = ExecutionPlan.derive(_actions())
    payload = plan.to_dict()
    forbidden = {"authorization", "authorization_decision", "execution_proof", "proof", "owner_budget", "allowed_tools", "owner_approval", "credentials"}
    assert not (forbidden & set(payload))
    for action in plan.actions:
        assert not (forbidden & set(action.to_dict()))
    with pytest.raises(TypeError):
        ExecutionPlan.derive(_actions(), owner_budget=["status"])


def test_c2_no_authority_or_execution_imports():
    source = Path(__file__).resolve().parents[1] / "security" / "execution_plan.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    forbidden = {"security.authorization", "security.authorization_context", "security.mission_authorization", "security.execution_proof", "security.owner_budget", "tools.registry", "security.owner_policy"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not (imported & forbidden), imported


def test_c2_mission_binding_is_parent_fingerprint_only_and_runtime_bindings_deferred():
    plan = ExecutionPlan.derive(_actions())
    assert plan.mission_fingerprint == plan.actions[0].parent_mission_fingerprint
    assert "mission_id" not in plan.to_dict()
    assert "run_id" not in plan.to_dict()
    assert "snapshot_hash" not in plan.to_dict()
    assert "authorization_revision" not in plan.to_dict()
    assert "scope_hash" not in plan.to_dict()


__all__ = []
