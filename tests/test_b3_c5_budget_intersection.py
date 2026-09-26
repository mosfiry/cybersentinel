from __future__ import annotations

"""B3-C5-C: Owner budget intersection excludes out-of-budget model actions at
derivation (B3-H4).

Model-derived actions outside the Owner budget are excluded deterministically
at derivation time (budget intersection inside derive_execution_plan), never
rejected late at execution. Any attempt to expand the effective action set
through the proposal fails closed (authority-shaped arguments, cross-mission
bindings, empty intersections).
"""

from dataclasses import dataclass, field
from typing import Any

import pytest

from security.execution_plan import ExecutionPlanError
from security.intent_ladder import ActionIntentError
from security.mission_authorization import MissionAuthorizationSnapshot
from security.execution_plan_runtime import derive_mission_execution_plan


@dataclass
class FakeProposal:
    action_id: str
    tool_call_id: str
    name: str
    arguments: dict = field(default_factory=dict)


@dataclass
class FakeMission:
    mission_id: str = "m-1"
    request_id: str = "req-1"
    objective: str = "investigate the objective"
    authorization_snapshot: dict[str, Any] = field(default_factory=dict)
    progress: dict[str, Any] = field(default_factory=dict)


def _mission(allowed_tools):
    snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="owner-identity",
        mission_id="m-1",
        target_identity="local-workspace",
        scope=("workspace",),
        allowed_actions=tuple(allowed_tools),
        forbidden_actions=(),
        allowed_tools=tuple(allowed_tools),
        time_window={"timezone": "UTC"},
        max_duration=600,
        rate_limits={tool: 1 for tool in allowed_tools},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("local-workspace",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": "/tmp"},
        policy_version="owner-policy",
        owner_approval="owner-approval-proof",
        expires_at="2099-01-01T00:00:00Z",
    )
    return FakeMission(authorization_snapshot=snapshot.to_dict())


def test_out_of_budget_actions_are_excluded_at_derivation_not_late():
    mission = _mission(("status",))
    proposals = [
        FakeProposal(action_id="a1", tool_call_id="c1", name="status", arguments={}),
        FakeProposal(action_id="a2", tool_call_id="c2", name="search", arguments={"query": "out-of-budget"}),
    ]
    plan = derive_mission_execution_plan(mission, proposals)
    # B3-H4: the out-of-budget action never enters the canonical plan; there
    # is no late rejection to bypass because the plan never contains it
    assert [action.tool_name for action in plan.actions] == ["status"]
    # effective actions are exactly the Owner budget intersection (never a widening)
    assert set(action.tool_name for action in plan.actions) <= {"status"}


def test_empty_intersection_fails_closed():
    mission = _mission(("status",))
    proposals = [FakeProposal(action_id="a1", tool_call_id="c1", name="search", arguments={"query": "x"})]
    with pytest.raises(ExecutionPlanError):
        derive_mission_execution_plan(mission, proposals)


def test_expansion_attempt_with_authority_shaped_argument_fails_closed():
    mission = _mission(("status",))
    proposals = [
        FakeProposal(
            action_id="a1",
            tool_call_id="c1",
            name="status",
            arguments={"authorization_granted": True},
        ),
    ]
    with pytest.raises((ActionIntentError, ExecutionPlanError, PermissionError)):
        derive_mission_execution_plan(mission, proposals)


def test_derived_plan_never_exceeds_owner_budget_for_widening_model_requests():
    mission = _mission(("status", "search"))
    proposals = [
        FakeProposal(action_id="a1", tool_call_id="c1", name="status", arguments={}),
        FakeProposal(action_id="a2", tool_call_id="c2", name="search", arguments={"query": "widen"}),
        FakeProposal(action_id="a3", tool_call_id="c3", name="watch", arguments={"query": "widen"}),
    ]
    plan = derive_mission_execution_plan(mission, proposals)
    tools = set(action.tool_name for action in plan.actions)
    assert tools == {"status", "search"}
    assert tools <= set(mission.authorization_snapshot["allowed_tools"])
