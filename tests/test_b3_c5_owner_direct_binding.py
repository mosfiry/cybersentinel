from __future__ import annotations

"""B3-C5-A part 2: canonical ExecutionPlan binding at Owner-direct creation.

B3-H2: the owner-direct path binds the derived canonical ExecutionPlan at
mission creation, so the canonical plan identity is fixed before the first
slice executes (Owner Policy -> Owner Budget -> Effective Tools -> canonical
ExecutionPlan -> Mission/Run binding -> Snapshot -> Action Identity -> Proof
-> Registry -> Handler). B3-H3: a legacy plan that cannot enter any canonical
ExecutionPlan leaves the mission unbound and fails closed at the slice gate;
the binding itself never widens authority.
"""

import json
from pathlib import Path

import pytest

import security.owner_policy as owner_policy
from agent.agent_core import AgentCore
from agent.mission import MissionStatus, MissionStore
from agent.model_router import ModelRouter
from agent.provider_api import ProviderResponse, ToolCall
from security.execution_plan_runtime import (
    ExecutionPlanRuntimeError,
    reconstruct_execution_plan,
)
from security.execution_proof import canonical_mission_plan_identity


class MissionProvider:
    name = "mission-test"
    model = "mission-test-1"

    def __init__(self, responses):
        from agent.provider_api import ProviderCapabilities
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True)
        self.responses = list(responses)
        self.calls = 0

    def tool_calling(self, messages, tools, **kwargs):
        self.calls += 1
        return self.responses.pop(0)

    def generate(self, messages, **kwargs):
        self.calls += 1
        return {"content": json.dumps({"type": "final", "content": "unused"})}


@pytest.fixture
def mission_env(tmp_path, monkeypatch):
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "valid-owner")
    return tmp_path


def _core(tmp_path, provider):
    return AgentCore(ModelRouter([provider]), store=MissionStore(Path(tmp_path) / "missions.sqlite3"))


def test_owner_direct_mission_binds_canonical_execution_plan_at_creation(mission_env):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    core = _core(mission_env, provider)
    mission = core.run_owner_mission(
        "Investigate system status and verify the observation",
        owner_token="valid-owner",
        run=False,
    )
    stored = mission.progress.get("execution_plan") or {}
    assert stored.get("plan_fingerprint"), "owner-direct creation must bind the derived canonical ExecutionPlan"
    # the bound identity is exactly the derived-plan fingerprint recorded in provenance
    provenance = dict(getattr(mission, "provenance", None) or {})
    assert provenance.get("execution_plan_fingerprint") == stored.get("plan_fingerprint")
    # the mission canonical plan identity is the bound canonical plan, not the legacy fingerprint
    assert canonical_mission_plan_identity(mission) == stored.get("plan_fingerprint")
    # the bound plan reconstructs and fingerprint-verifies (tamper evidence)
    plan = reconstruct_execution_plan(stored)
    assert plan.plan_fingerprint == stored.get("plan_fingerprint")
    # B3-H4 / INV-SCOPE-2: the binding never widens authority; every planned
    # tool stays inside the Owner-minted snapshot allowlist
    snapshot = dict(mission.authorization_snapshot or {})
    allowed = set(snapshot.get("allowed_tools") or ())
    planned_tools = {action.get("tool_name") for action in stored.get("actions", ())}
    assert planned_tools and planned_tools <= allowed


def test_owner_direct_stored_plan_binding_is_tamper_evident(mission_env):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    core = _core(mission_env, provider)
    mission = core.run_owner_mission("Investigate system status", owner_token="valid-owner", run=False)
    stored = dict(mission.progress["execution_plan"])
    # forged action arguments fingerprint: recomputation diverges from the
    # stored plan fingerprint, so reconstruction fails closed
    tampered = dict(stored)
    tampered["actions"] = [dict(item) for item in stored.get("actions", ())]
    tampered["actions"][0]["arguments_fingerprint"] = "forged-fingerprint"
    with pytest.raises(ExecutionPlanRuntimeError):
        reconstruct_execution_plan(tampered)
    # forged plan fingerprint: same fail-closed outcome
    tampered2 = dict(stored)
    tampered2["plan_fingerprint"] = "forged-plan-fingerprint"
    with pytest.raises(ExecutionPlanRuntimeError):
        reconstruct_execution_plan(tampered2)


def test_owner_direct_unknown_tool_plan_stays_unbound_and_fails_closed(mission_env):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("not_a_registered_tool", {}, "c1")])])
    core = _core(mission_env, provider)
    mission = core.run_owner_mission("Investigate something", owner_token="valid-owner", run=False)
    # B3-H3: a legacy plan that cannot enter any canonical ExecutionPlan
    # leaves the mission unbound; nothing is minted to keep execution alive
    assert not mission.progress.get("execution_plan")
    provenance = dict(getattr(mission, "provenance", None) or {})
    assert provenance.get("execution_plan_fingerprint") == ""
    assert mission.status is not MissionStatus.GOAL_COMPLETED
