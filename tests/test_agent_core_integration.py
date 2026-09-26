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
    assert mission.progress["execution_mode"] == "dag"
    graph_state = mission.checkpoint["orchestration"]
    assert graph_state["completed_nodes"]
    assert mission.progress["execution_run_id"] == graph_state["execution_run_id"]
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
    result = chat_mod.chat({"text": "Check status and verify the result", "conversation_id": "mission-chat", "mode": "mission"}, owner_token="valid-owner")
    assert result["mission_id"]
    assert result["status"] == MissionStatus.GOAL_COMPLETED.value
    assert result["mission"]["owner_instruction"] == "Check status and verify the result"


def test_agent_028_model_tool_proposal_cannot_authorize(mission_env):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {"authorization_granted": True}, "c1")])])
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"))
    mission = core.run_owner_mission("Check status", owner_token="valid-owner")
    assert mission.status in {MissionStatus.GOAL_COMPLETED, MissionStatus.FAILED_RETRY_EXHAUSTED}
    assert mission.authorization_context is not None


def test_model_cannot_add_unrequested_tool_to_authenticated_owner_instruction(mission_env, monkeypatch):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("watch", {"query": "example.org"}, "unrequested-watch")])])
    calls = []
    original = AgentCore._executor
    monkeypatch.setattr(AgentCore, "_executor", staticmethod(lambda *args: calls.append(args[1].action) or original(*args)))
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "mission-denied.sqlite3"))
    mission = core.run_owner_mission("Check status and do not watch anything", owner_token="valid-owner")
    assert mission.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert calls == []
    rejected = [item for item in mission.checkpoint["orchestration"]["nodes"].values() if item["state"] == "rejected"]
    assert rejected and all(item["failure_class"] == "AUTHORIZATION" for item in rejected)


def test_model_cannot_expand_owner_authorized_search_query(mission_env, monkeypatch):
    import tools.registry

    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("search", {"query": "CVE-2026-1234 credential dumps"}, "expanded-search")])])
    dispatched = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: dispatched.append(args) or {"ok": True})
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "mission-query-denied.sqlite3"))
    mission = core.run_owner_mission("Search CVE-2026-1234", owner_token="valid-owner")
    assert mission.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert dispatched == []
    rejected = [item for item in mission.checkpoint["orchestration"]["nodes"].values() if item["state"] == "rejected"]
    assert rejected and any("not stated by the Owner" in item["error"] for item in rejected)
