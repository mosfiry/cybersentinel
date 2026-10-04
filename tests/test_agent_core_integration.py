from __future__ import annotations

import json
from pathlib import Path

import pytest

import api.chat as chat_mod
import security.owner_policy as owner_policy
from owner_session_testutils import allow_owner_sessions
from agent.agent_core import AgentCore
from agent.mission import MissionStatus, MissionStore
from agent.model_router import ModelRouter
from agent.planning import RecoveryPolicy
from agent.provider_api import ProviderRequestRejected, ProviderResponse, ProviderTimeout, ToolCall


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


class FailingPlanningProvider:
    name = "local_llama_cpp"
    model = "qwen3-4b-q4-k-m"

    def __init__(self, error):
        from agent.provider_api import ProviderCapabilities
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True)
        self.error = error
        self.calls = 0

    def tool_calling(self, messages, tools, **kwargs):
        self.calls += 1
        raise self.error

    def generate(self, messages, **kwargs):
        self.calls += 1
        raise self.error


@pytest.fixture
def mission_env(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "valid-owner")
    return tmp_path


def test_agent_001_to_008_owner_goal_runs_real_mission_loop(mission_env):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"))
    mission = core.run_owner_mission("Investigate system status and verify the observation", owner_session_token="valid-owner")
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
    mission = core.run_owner_mission("Investigate and verify the result", owner_session_token="valid-owner")
    assert mission.objective == "Investigate and verify the result"
    assert mission.plan.objective == mission.objective


def test_agent_015_restart_resumes_persisted_mission(mission_env):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    store = MissionStore(Path(mission_env) / "missions.sqlite3")
    core = AgentCore(ModelRouter([provider]), store=store)
    mission = core.run_owner_mission("Check and verify status", owner_session_token="valid-owner")
    restarted = MissionStore(Path(mission_env) / "missions.sqlite3").load(mission.mission_id)
    assert restarted is not None
    assert restarted.status is MissionStatus.GOAL_COMPLETED
    assert restarted.trajectory


def test_agent_041_api_chat_mission_mode_uses_agent_core(mission_env, monkeypatch):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"))
    monkeypatch.setattr(chat_mod, "_agent_core", lambda: core)
    result = chat_mod.chat({"text": "ابحث وحلل النتيجة", "conversation_id": "mission-chat", "mode": "mission"}, owner_session_token="valid-owner")
    assert result["mission_id"]
    assert result["status"] != MissionStatus.GOAL_COMPLETED.value
    assert result["mission"]["evidence"] == []
    assert result["mission"]["owner_instruction"] == "ابحث وحلل النتيجة"


def test_agent_028_model_tool_proposal_cannot_authorize(mission_env):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {"authorization_granted": True}, "c1")])])
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"))
    mission = core.run_owner_mission("Check status", owner_session_token="valid-owner")
    assert mission.status in {MissionStatus.GOAL_COMPLETED, MissionStatus.FAILED_RETRY_EXHAUSTED}
    assert mission.authorization_context is not None


def test_agent_core_persists_bounded_planning_timeout_retries_without_ready(mission_env):
    provider = FailingPlanningProvider(ProviderTimeout("provider timeout"))
    store = MissionStore(Path(mission_env) / "planning-timeout.sqlite3")
    core = AgentCore(ModelRouter([provider]), store=store)

    mission = core.run_owner_mission(
        "Check status",
        owner_session_token="valid-owner",
        request_id="planning-timeout-request",
    )

    assert provider.calls == RecoveryPolicy().max_retries + 1
    assert mission.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert mission.retry_count == RecoveryPolicy().max_retries + 1
    assert mission.observations == []
    assert mission.evidence == []
    assert mission.action_history == []
    assert all(item["kind"] == "TIMEOUT" for item in mission.failures)
    assert [item["provider_attempt"] for item in mission.failures] == [1, 2, 3, 4]
    assert [item["retry_policy"]["action"] for item in mission.failures] == ["RETRY", "RETRY", "RETRY", "FAIL"]
    assert len({item["run_id"] for item in mission.failures}) == 1
    assert len({item["turn_id"] for item in mission.failures}) == 4
    assert all(item["request_id"] == "planning-timeout-request" for item in mission.failures)
    assert not any(item["to"] == MissionStatus.READY.value for item in mission.transitions)
    assert mission.error == "model provider failure: TIMEOUT"
    persisted = MissionStore(Path(mission_env) / "planning-timeout.sqlite3").load(mission.mission_id)
    assert persisted is not None and persisted.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert persisted.failures == mission.failures


def test_agent_core_fails_closed_on_http400_without_retry_or_ready(mission_env):
    provider = FailingPlanningProvider(ProviderRequestRejected(
        "provider request rejected (HTTP 400)",
        provider="local_llama_cpp",
        model="qwen3-4b-q4-k-m",
        status_code=400,
    ))
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "planning-http400.sqlite3"))

    mission = core.run_owner_mission(
        "Check status",
        owner_session_token="valid-owner",
        request_id="planning-http400-request",
    )

    assert provider.calls == 1
    assert mission.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert mission.retry_count == 1
    failure = mission.failures[0]
    assert failure["kind"] == "REQUEST_REJECTED"
    assert failure["http_status"] == 400
    assert failure["reason"] == "provider request rejected (HTTP 400)"
    assert failure["attempts"] == [{
        "provider": "local_llama_cpp",
        "model": "qwen3-4b-q4-k-m",
        "kind": "REQUEST_REJECTED",
        "http_status": "400",
    }]
    assert not any(item["to"] == MissionStatus.READY.value for item in mission.transitions)
