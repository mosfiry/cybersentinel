from __future__ import annotations

import json
from pathlib import Path

import pytest

import api.chat as chat_mod
import core.db as core_db
import security.owner_policy as owner_policy
from owner_session_testutils import allow_owner_sessions
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
    allow_owner_sessions(monkeypatch, "valid-owner")
    monkeypatch.setattr(core_db, "DB_PATH", Path(tmp_path) / "conversations.sqlite3")
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
    mission = core.run_owner_mission("Check system status and verify", owner_session_token="valid-owner")
    restarted = MissionStore(Path(mission_env) / "missions.sqlite3").load(mission.mission_id)
    assert restarted is not None
    assert restarted.status is MissionStatus.GOAL_COMPLETED
    assert restarted.trajectory


def test_agent_041_api_chat_mission_mode_uses_agent_core(mission_env, monkeypatch):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"))
    monkeypatch.setattr(chat_mod, "_agent_core", lambda: core)
    result = chat_mod.chat({"text": "تحقق من حالة النظام", "conversation_id": "mission-chat", "mode": "mission"}, owner_session_token="valid-owner")
    assert result["mission_id"]
    assert result["status"] == MissionStatus.GOAL_COMPLETED.value
    assert result["mission"]["owner_instruction"] == "تحقق من حالة النظام"


def test_agent_028_model_tool_proposal_cannot_authorize(mission_env):
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {"authorization_granted": True}, "c1")])])
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"))
    mission = core.run_owner_mission("Check status", owner_session_token="valid-owner")
    assert mission.status in {MissionStatus.GOAL_COMPLETED, MissionStatus.FAILED_RETRY_EXHAUSTED}
    assert mission.authorization_context is not None


class SchemaCapturingProvider(MissionProvider):
    def __init__(self, responses, *, native=False):
        from agent.provider_api import ProviderCapabilities

        super().__init__(responses)
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True, native_chat=native)
        self.schema_names = []

    def tool_calling(self, messages, tools, **kwargs):
        self.calls += 1
        self.schema_names.append([item["function"]["name"] for item in tools])
        return self.responses.pop(0)


def test_agent_core_sends_only_budgeted_available_tools_and_rejects_widening(mission_env, monkeypatch):
    from dataclasses import replace

    import tools.registry

    policy = owner_policy.load_policy()
    monkeypatch.setattr(owner_policy, "load_policy", lambda: replace(policy, owner_tool_budget=(*policy.owner_tool_budget, "scoped_http_probe")))
    executed = []
    monkeypatch.setattr(tools.registry, "execute", lambda name, *args, **kwargs: executed.append(name) or {"success": True})
    provider = SchemaCapturingProvider([
        ProviderResponse(tool_calls=[
            ToolCall("status", {}, "planned-status"),
            ToolCall("watch", {"query": "outside declaration"}, "planned-watch"),
            ToolCall("scoped_http_probe", {"query": "https://example.invalid"}, "planned-unavailable"),
        ]),
        ProviderResponse(tool_calls=[ToolCall("watch", {"query": "native widening"}, "native-widening")]),
    ], native=True)
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"), max_iterations=1)

    mission = core.run_owner_mission(
        "Check service status",
        owner_session_token="valid-owner",
        scope_context={"owner_allowed_tools": ["status", "search", "scoped_http_probe"]},
    )

    assert set(provider.schema_names[0]) == {"status", "search"}
    assert provider.schema_names[1] == ["status"]
    assert [step.action for step in mission.plan.steps] == ["status"]
    assert mission.provenance["model_requested_tools"] == ["status"]
    assert "watch" not in provider.schema_names[0]
    assert "scoped_http_probe" not in provider.schema_names[0]
    assert executed == []
    assert any(event["event"] == "ExecutionRejected" for event in mission.trajectory)
    assert "outside mission authorization snapshot allowlist" in mission.progress["model_loop"]["tool_results"][-1]["error"]


def test_restart_replanning_keeps_the_mission_bound_tool_set(mission_env):
    provider = SchemaCapturingProvider([
        ProviderResponse(tool_calls=[ToolCall("status", {}, "initial-status")]),
        ProviderResponse(tool_calls=[ToolCall("search", {"query": "widen during replan"}, "replanned-search")]),
    ])
    database = Path(mission_env) / "missions.sqlite3"
    initial_core = AgentCore(ModelRouter([provider]), store=MissionStore(database), max_iterations=1)
    mission = initial_core.run_owner_mission(
        "Check status and search only if needed",
        owner_session_token="valid-owner",
        scope_context={"owner_allowed_tools": ["status", "search"]},
        run=False,
    )
    restarted_core = AgentCore(ModelRouter([provider]), store=MissionStore(database), max_iterations=1)
    restarted_core._executor = lambda *_: {"success": False, "failure_class": "COMPILATION", "error": "test-triggered replan"}

    resumed = restarted_core.resume_mission(mission.mission_id, owner_session_token="valid-owner", max_slices=1)

    assert set(provider.schema_names[0]) == {"status", "search"}
    assert provider.schema_names[1] == ["status"]
    assert [step.action for step in resumed.plan.steps] == ["__planning_failure__"]
