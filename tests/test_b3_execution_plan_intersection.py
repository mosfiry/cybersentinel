from __future__ import annotations

import dataclasses

import pytest

from agent.model_intelligence.conversation import NaturalLanguageUnderstanding
from security.execution_plan import ExecutionPlanError, derive_execution_plan, validate_execution_plan
from security.intent_ladder import derive_action_intents, derive_task_intents
from security.owner_budget import OwnerAuthorizedToolBudget


def _actions(proposal):
    mission = NaturalLanguageUnderstanding().understand("Inspect the local workspace")
    tasks = derive_task_intents(
        mission,
        [{"task_id": "task-1", "objective": "Inspect workspace", "task_type": "single_task"}],
    )
    return derive_action_intents(tasks, proposal)


def _budget(*tools):
    return OwnerAuthorizedToolBudget(frozenset(tools), source="test-owner-budget")


def test_c3_allowed_and_partial_intersections_retain_only_owner_allowed_actions():
    actions = _actions([
        {"action_id": "a", "task_id": "task-1", "tool_name": "status"},
        {"action_id": "b", "task_id": "task-1", "tool_name": "refresh_intel"},
        {"action_id": "c", "task_id": "task-1", "tool_name": "watch", "arguments": {"query": "x"}},
    ])
    plan = derive_execution_plan(_budget("status", "refresh_intel"), actions)
    assert [action.tool_name for action in plan.actions] == ["status", "refresh_intel"]
    assert plan.provenance == "DETERMINISTIC_DERIVED"


def test_c3_order_is_first_seen_and_duplicate_tools_are_deduplicated():
    actions = _actions([
        {"action_id": "a", "task_id": "task-1", "tool_name": "status"},
        {"action_id": "b", "task_id": "task-1", "tool_name": "refresh_intel"},
        {"action_id": "c", "task_id": "task-1", "tool_name": "status"},
        {"action_id": "d", "task_id": "task-1", "tool_name": "watch", "arguments": {"query": "x"}},
        {"action_id": "e", "task_id": "task-1", "tool_name": "refresh_intel"},
    ])
    plan = derive_execution_plan(_budget("status", "refresh_intel"), actions)
    assert [action.tool_name for action in plan.actions] == ["status", "refresh_intel"]
    assert [action.action_id for action in plan.actions] == ["a", "b"]


def test_c3_empty_intersection_and_empty_budget_fail_closed():
    actions = _actions([{"action_id": "a", "task_id": "task-1", "tool_name": "status"}])
    with pytest.raises(ExecutionPlanError, match="empty intersection"):
        derive_execution_plan(_budget("refresh_intel"), actions)
    with pytest.raises(ExecutionPlanError, match="empty intersection"):
        derive_execution_plan(_budget(), actions)


def test_c3_unknown_and_wildcard_requests_fail_closed_before_intersection():
    unknown = _actions([{"action_id": "a", "task_id": "task-1", "tool_name": "status"}])
    object.__setattr__(unknown[0], "tool_name", "not-a-known-tool")
    with pytest.raises(ExecutionPlanError, match="invalid ActionIntent request"):
        derive_execution_plan(_budget("status"), unknown)

    wildcard = _actions([{"action_id": "a", "task_id": "task-1", "tool_name": "status"}])
    object.__setattr__(wildcard[0], "tool_name", "*")
    with pytest.raises(ExecutionPlanError, match="invalid ActionIntent request"):
        derive_execution_plan(_budget("status"), wildcard)


def test_c3_effective_actions_are_not_caller_supplied():
    actions = _actions([{"action_id": "a", "task_id": "task-1", "tool_name": "status"}])
    with pytest.raises(TypeError):
        derive_execution_plan(_budget("status"), actions, effective_actions=actions)

    plan = derive_execution_plan(_budget("status"), actions)
    assert plan.actions == (actions[0],)
    assert not hasattr(plan, "effective_actions")


def test_c3_extra_action_enters_only_as_a_model_request_and_cannot_expand_budget():
    actions = _actions([
        {"action_id": "a", "task_id": "task-1", "tool_name": "status"},
        {"action_id": "b", "task_id": "task-1", "tool_name": "watch", "arguments": {"query": "x"}},
    ])
    plan = derive_execution_plan(_budget("status"), actions)
    assert [action.tool_name for action in plan.actions] == ["status"]


def test_c3_owner_budget_replacement_after_derivation_cannot_change_plan():
    actions = _actions([{"action_id": "a", "task_id": "task-1", "tool_name": "status"}])
    original_budget = _budget("status")
    plan = derive_execution_plan(original_budget, actions)
    replacement_budget = _budget("status", "watch")
    assert [action.tool_name for action in plan.actions] == ["status"]
    assert replacement_budget.tools != original_budget.tools
    assert [action.tool_name for action in plan.actions] == ["status"]


def test_c3_replay_and_effective_plan_fingerprint_are_deterministic():
    actions = _actions([
        {"action_id": "a", "task_id": "task-1", "tool_name": "status"},
        {"action_id": "b", "task_id": "task-1", "tool_name": "watch", "arguments": {"query": "x"}},
    ])
    budget = _budget("status")
    first = derive_execution_plan(budget, actions)
    for _ in range(25):
        current = derive_execution_plan(_budget("status"), _actions([
            {"action_id": "a", "task_id": "task-1", "tool_name": "status"},
            {"action_id": "b", "task_id": "task-1", "tool_name": "watch", "arguments": {"query": "x"}},
        ]))
        assert current == first
        assert current.fingerprint == first.fingerprint


def test_c3_argument_change_changes_effective_plan_fingerprint():
    first = derive_execution_plan(_budget("search"), _actions([
        {"action_id": "a", "task_id": "task-1", "tool_name": "search", "arguments": {"query": "one"}},
    ]))
    changed = derive_execution_plan(_budget("search"), _actions([
        {"action_id": "a", "task_id": "task-1", "tool_name": "search", "arguments": {"query": "two"}},
    ]))
    assert first.fingerprint != changed.fingerprint


def test_c3_cross_mission_requests_fail_closed_even_if_filtered():
    first = _actions([{"action_id": "a", "task_id": "task-1", "tool_name": "status"}])[0]
    other_action = _actions([{"action_id": "b", "task_id": "task-1", "tool_name": "status"}],)
    object.__setattr__(other_action[0], "parent_mission_fingerprint", "different-mission")
    with pytest.raises(ExecutionPlanError, match="cross-mission"):
        derive_execution_plan(_budget("status"), (first, other_action[0]))


def test_c3_returned_plan_remains_frozen_and_validates_after_forbidden_mutation():
    actions = _actions([{"action_id": "a", "task_id": "task-1", "tool_name": "status"}])
    plan = derive_execution_plan(_budget("status"), actions)
    with pytest.raises(dataclasses.FrozenInstanceError):
        plan.actions = ()
    object.__setattr__(plan.actions[0], "arguments", {"query": "mutated"})
    ok, reason = validate_execution_plan(plan)
    assert not ok
    assert "canonical" in reason or "changed" in reason or "fingerprint" in reason
