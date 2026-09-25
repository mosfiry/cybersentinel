from __future__ import annotations

"""B3-C1 characterization only: current ActionIntent -> execution behavior.

These tests describe the current state after B3-C2. H1 is inverted because
the typed ExecutionPlan contract now exists; H2/H3 remain pre-C3 pins. These
tests do not prescribe or implement B3-C3/B3-C4.
"""

from dataclasses import fields
import importlib.util

import pytest

import security.intent_ladder as intent_ladder
from agent.agent_core import AgentCore
from agent.model_intelligence.conversation import NaturalLanguageUnderstanding
from agent.planning import Plan, PlanStep
from security.execution_proof import ExecutionAuthorizationProof, ExecutionProofError
from security.mission_authorization import MissionAuthorizationError, MissionAuthorizationSnapshot
from security.owner_budget import OwnerAuthorizedToolBudget


def _tasks():
    mission = NaturalLanguageUnderstanding().understand("Inspect the local workspace")
    return intent_ladder.derive_task_intents(
        mission,
        [{"task_id": "task-1", "objective": "Inspect workspace", "task_type": "single_task"}],
    )


def _action():
    return intent_ladder.derive_action_intents(
        _tasks(),
        [{"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "arguments": {}}],
    )[0]


def test_b3c2_h1_typed_execution_plan_contract_exists():
    """B3-C2 inverts H1 without connecting the contract to execution."""
    from agent.model_intelligence.conversation import NaturalLanguageUnderstanding
    from security.execution_plan import ExecutionPlan, validate_execution_plan
    from security.intent_ladder import derive_action_intents, derive_task_intents

    assert importlib.util.find_spec("security.execution_plan") is not None
    mission = NaturalLanguageUnderstanding().understand("Inspect the local workspace")
    tasks = derive_task_intents(mission, [{"task_id": "task-1", "objective": "Inspect workspace"}])
    action = derive_action_intents(tasks, [{"action_id": "action-1", "task_id": "task-1", "tool_name": "status"}])
    plan = ExecutionPlan.derive(action)
    assert validate_execution_plan(plan) == (True, "valid")


def test_b3c1_h2_legacy_plan_has_only_legacy_fingerprint_binding():
    """Plan/PlanStep do not carry the complete execution binding contract."""
    plan_fields = {item.name for item in fields(Plan)}
    step_fields = {item.name for item in fields(PlanStep)}
    full_binding = {"mission_id", "run_id", "snapshot_hash", "authorization_revision", "plan_hash"}
    assert not (plan_fields & full_binding)
    assert not (step_fields & full_binding)
    assert "fingerprint" not in plan_fields
    assert isinstance(Plan.initial("objective").fingerprint, str)


def test_b3c1_h3_agent_core_model_path_still_emits_legacy_plan_steps(monkeypatch):
    """The current production planner maps model tool calls directly to PlanStep."""
    core = AgentCore(router=object())
    monkeypatch.setattr(
        core,
        "_ask",
        lambda *args, **kwargs: {
            "tool_calls": [{"name": "status", "arguments": {}, "id": "call-1"}],
        },
    )
    plan = core._plan("Inspect the local workspace", request_id="req-b3c1", conversation_id="conv-b3c1")
    assert isinstance(plan, Plan)
    assert len(plan.steps) == 1
    assert isinstance(plan.steps[0], PlanStep)
    assert plan.steps[0].action == "status"
    assert not hasattr(plan, "mission_id")
    assert not hasattr(plan, "run_id")
    assert not hasattr(plan, "snapshot_hash")
    assert not hasattr(plan, "authorization_revision")


def test_b3c1_h4_owner_budget_intersection_is_outside_action_intent():
    """ActionIntent stores a model tool proposal, not effective Owner authority."""
    action = _action()
    assert action.tool_name == "status"
    assert not hasattr(action, "effective_tools")
    assert not hasattr(action, "owner_budget")
    assert not hasattr(action, "authorization_snapshot")
    assert not hasattr(action, "authorization_revision")
    budget = OwnerAuthorizedToolBudget(frozenset({"status"}))
    assert budget.intersect((action.tool_name, "watch")) == ("status",)


def test_b3c1_h5_current_proof_binds_legacy_plan_snapshot_and_lifecycle():
    """Current proof binds live mission data, but has no run_id/revision field."""
    proof_fields = {item.name for item in fields(ExecutionAuthorizationProof)}
    for required in (
        "mission_id",
        "request_id",
        "arguments_hash",
        "snapshot_hash",
        "snapshot_version",
        "plan_hash",
        "scope_hash",
        "lifecycle_revision",
    ):
        assert required in proof_fields
    assert "run_id" not in proof_fields
    assert "authorization_revision" not in proof_fields


def test_b3c1_h6_action_proposal_cannot_create_snapshot_or_proof():
    """Current model-derived ActionIntent remains data, not authority."""
    action = _action()
    with pytest.raises(ExecutionProofError):
        ExecutionAuthorizationProof.derive(
            mission_id="mission-b3c1",
            request_id="request-b3c1",
            tool=action.tool_name,
            argument=action.arguments,
            snapshot=action,
        )
    with pytest.raises((MissionAuthorizationError, TypeError, ValueError)):
        MissionAuthorizationSnapshot.from_dict(action.to_dict())


__all__ = []
