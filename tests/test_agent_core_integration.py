from __future__ import annotations

import json
from pathlib import Path

import pytest

import api.chat as chat_mod
import security.owner_policy as owner_policy
from agent.agent_core import AgentCore
from agent.mission import MissionStatus, MissionStore
from agent.model_router import ModelRouter
from agent.provider_api import ProviderResponse, ToolCall


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


def test_agent_001_to_008_owner_goal_runs_real_mission_loop(mission_env):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"))
    mission = core.run_owner_mission("Investigate system status and verify the observation", owner_token="valid-owner")
    assert mission.status is MissionStatus.GOAL_COMPLETED
    assert mission.action_history[0]["status"] == "completed"
    assert mission.observations
    assert mission.evidence
    assert [item["event"] for item in mission.trajectory][:2] == ["MissionStarted", "PlanCreated"]
    assert any(item["event"] == "GoalVerified" for item in mission.trajectory)


def test_agent_011_replan_preserves_owner_objective(mission_env):
    provider = MissionProvider([
        ProviderResponse(tool_calls=[ToolCall("run_project_tests", {}, "c1")]),
        ProviderResponse(tool_calls=[ToolCall("status", {}, "c2")]),
    ])
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"))
    mission = core.run_owner_mission("Investigate and verify the result", owner_token="valid-owner")
    assert mission.objective == "Investigate and verify the result"
    assert mission.plan.objective == mission.objective


def test_agent_015_restart_resumes_persisted_mission(mission_env):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    store = MissionStore(Path(mission_env) / "missions.sqlite3")
    core = AgentCore(ModelRouter([provider]), store=store)
    mission = core.run_owner_mission("Check and verify status", owner_token="valid-owner")
    restarted = MissionStore(Path(mission_env) / "missions.sqlite3").load(mission.mission_id)
    assert restarted is not None
    assert restarted.status is MissionStatus.GOAL_COMPLETED
    assert restarted.trajectory


def test_agent_041_api_chat_mission_mode_uses_agent_core(mission_env, monkeypatch):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"))
    monkeypatch.setattr(chat_mod, "_agent_core", lambda: core)
    result = chat_mod.chat({"text": "ابحث وحلل النتيجة", "conversation_id": "mission-chat", "mode": "mission"}, owner_token="valid-owner")
    assert result["mission_id"]
    assert result["status"] == MissionStatus.GOAL_COMPLETED.value
    assert result["mission"]["owner_instruction"] == "ابحث وحلل النتيجة"


def test_agent_028_model_tool_proposal_cannot_authorize(mission_env):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {"authorization_granted": True}, "c1")])])
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"))
    mission = core.run_owner_mission("Check status", owner_token="valid-owner")
    # B3-C4B: a proposal carrying an authority-shaped argument
    # ("authorization_granted") is rejected fail-closed by ActionIntent
    # validation during canonical ExecutionPlan derivation (INV-C4-2), so
    # the mission is durably blocked instead of silently ignoring the
    # forged field. No Owner authority is ever granted by model output.
    assert mission.status in {MissionStatus.GOAL_COMPLETED, MissionStatus.FAILED_RETRY_EXHAUSTED, MissionStatus.AUTHORIZATION_BLOCKED}
    assert mission.authorization_context is not None
