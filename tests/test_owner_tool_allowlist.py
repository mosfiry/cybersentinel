from __future__ import annotations

import json
from pathlib import Path

import pytest

import security.owner_policy as owner_policy
from agent.agent_core import AgentCore
from agent.mission import MissionStatus, MissionStore
from agent.model_router import ModelRouter
from agent.provider_api import ProviderResponse, ToolCall
from tools.registry import REGISTRY


class MissionProvider:
    name = "mission-allowlist-test"
    model = "mission-allowlist-test-1"

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


def _core(env, provider):
    return AgentCore(ModelRouter([provider]), store=MissionStore(Path(env) / "missions.sqlite3"))


def _snapshot_tools(mission):
    snapshot = mission.authorization_snapshot or {}
    return set(snapshot.get("allowed_tools") or ())


def test_allowlist_001_owner_scope_context_is_authoritative(mission_env):
    """The owner-supplied allowlist, not the model plan, defines the snapshot."""
    assert "run_project_tests" in REGISTRY
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("run_project_tests", {}, "c1")])])
    core = _core(mission_env, provider)
    mission = core.run_owner_mission(
        "Investigate and run checks",
        owner_token="valid-owner",
        scope_context={"allowed_tools": ["status"]},
    )
    assert _snapshot_tools(mission) == {"status"}
    assert "run_project_tests" not in _snapshot_tools(mission)
    assert mission.provenance.get("tool_allowlist_source") == "owner_scope_context"
    assert mission.provenance.get("blocked_tool_proposals") == ["run_project_tests"]
    assert not mission.action_history
    assert not mission.observations
    assert all(step.action == "__planning_failure__" for step in mission.plan.steps)


def test_allowlist_002_allowed_tool_executes(mission_env):
    """A tool inside the owner allowlist executes normally."""
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    core = _core(mission_env, provider)
    mission = core.run_owner_mission(
        "Investigate system status and verify the observation",
        owner_token="valid-owner",
        scope_context={"allowed_tools": ["status"]},
    )
    assert mission.status is MissionStatus.GOAL_COMPLETED
    assert mission.provenance.get("blocked_tool_proposals") == []
    assert _snapshot_tools(mission) == {"status"}
    assert mission.action_history and mission.action_history[0]["status"] == "completed"


def test_allowlist_003_default_allowlist_is_registry_not_model(mission_env):
    """Without an owner list, the deterministic default is the system registry."""
    assert "status" in REGISTRY
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    core = _core(mission_env, provider)
    mission = core.run_owner_mission("Check status", owner_token="valid-owner")
    assert mission.provenance.get("tool_allowlist_source") == "system_tool_registry"
    assert mission.status is MissionStatus.GOAL_COMPLETED
    assert "status" in _snapshot_tools(mission)


def test_allowlist_004_model_cannot_widen_owner_allowlist(mission_env):
    """Extra tools proposed by the model never enter the snapshot or execute."""
    provider = MissionProvider([
        ProviderResponse(tool_calls=[ToolCall("status", {}, "c1"), ToolCall("run_project_tests", {}, "c2")]),
        ProviderResponse(tool_calls=[ToolCall("status", {}, "c3")]),
    ])
    core = _core(mission_env, provider)
    mission = core.run_owner_mission(
        "Investigate system status and verify the observation",
        owner_token="valid-owner",
        scope_context={"allowed_tools": ["status"]},
    )
    assert _snapshot_tools(mission) == {"status"}
    assert "run_project_tests" not in [step.action for step in mission.plan.steps]
    assert mission.provenance.get("blocked_tool_proposals") == ["run_project_tests"]
    assert not any("run_project_tests" in json.dumps(entry) for entry in mission.action_history)


def test_allowlist_005_unregistered_tool_proposal_is_blocked(mission_env):
    """An unregistered tool can never reach the snapshot, even by default."""
    unknown_tool = "definitely_not_a_registered_tool_xyz"
    assert unknown_tool not in REGISTRY
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall(unknown_tool, {}, "c1")])])
    core = _core(mission_env, provider)
    mission = core.run_owner_mission("Investigate things", owner_token="valid-owner")
    assert mission.provenance.get("blocked_tool_proposals") == [unknown_tool]
    assert unknown_tool not in _snapshot_tools(mission)
    assert not mission.action_history
    assert all(step.action == "__planning_failure__" for step in mission.plan.steps)
