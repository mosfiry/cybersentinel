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
from agent.model_router import ModelRouter, ModelSelectionError
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
        self.context_messages = []

    def tool_calling(self, messages, tools, **kwargs):
        self.calls += 1
        self.schema_names.append([item["function"]["name"] for item in tools])
        self.context_messages.append("\n".join(str(item.get("content", "")) for item in messages))
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
            ToolCall("scoped_http_probe", {"query": "https://example.invalid"}, "planned-scope-probe"),
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
    assert "watch: " not in provider.context_messages[0]
    assert "scoped_http_probe: " not in provider.context_messages[0]
    assert "status: " in provider.context_messages[0]
    assert "search: " in provider.context_messages[0]
    assert executed == []
    assert any(event["event"] == "ExecutionRejected" for event in mission.trajectory)
    rejection = mission.progress["model_loop"]["tool_results"][-1]["error"]
    # Mind schema filtering omits unauthorized actions from the plan; a later
    # attempted call is therefore rejected as an unknown plan step. Older
    # persisted plans may instead reach the authorization-snapshot rejection.
    assert rejection in {
        "tool call references an unknown plan step",
        "tool call is outside mission authorization snapshot allowlist",
    }


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


def test_explicit_model_profile_is_persisted_and_pinned_across_resume_and_replan(mission_env):
    fallback = SchemaCapturingProvider([], native=False)
    selected = SchemaCapturingProvider([
        ProviderResponse(tool_calls=[ToolCall("status", {}, "selected-initial")]),
        ProviderResponse(tool_calls=[ToolCall("status", {}, "selected-replan")]),
    ], native=False)
    router = ModelRouter(
        [fallback, selected],
        configured_profiles={"colab": fallback, "local": selected},
    )
    store = MissionStore(Path(mission_env) / "pinned-missions.sqlite3")
    initial_core = AgentCore(router, store=store, max_iterations=1)
    mission = initial_core.run_owner_mission(
        "Check system status and verify the result",
        owner_session_token="valid-owner",
        model_id="local",
        scope_context={"owner_allowed_tools": ["status"]},
        run=False,
    )

    persisted = MissionStore(Path(mission_env) / "pinned-missions.sqlite3").load(mission.mission_id)
    assert persisted is not None
    assert persisted.model_selection["profile_id"] == "local"
    assert persisted.model_selection["mode"] == "explicit"
    assert persisted.model_selection["profile_fingerprint"]
    assert selected.calls == 1
    assert fallback.calls == 0

    restarted_core = AgentCore(router, store=MissionStore(Path(mission_env) / "pinned-missions.sqlite3"), max_iterations=1)
    restarted_core._executor = lambda *_: {"success": False, "failure_class": "COMPILATION", "error": "test-triggered replan"}
    resumed = restarted_core.resume_mission(
        mission.mission_id,
        owner_session_token="valid-owner",
        max_slices=1,
    )

    assert resumed.model_selection["profile_id"] == "local"
    assert selected.calls >= 2
    assert fallback.calls == 0


def test_explicit_model_profile_resume_fails_closed_on_fingerprint_drift(mission_env):
    original = SchemaCapturingProvider([
        ProviderResponse(tool_calls=[ToolCall("status", {}, "selected-initial")]),
    ], native=False)
    original_router = ModelRouter([original], configured_profiles={"local": original})
    database = Path(mission_env) / "changed-profile-missions.sqlite3"
    mission = AgentCore(original_router, store=MissionStore(database), max_iterations=1).run_owner_mission(
        "Check system status and verify the result",
        owner_session_token="valid-owner",
        model_id="local",
        scope_context={"owner_allowed_tools": ["status"]},
        run=False,
    )

    replacement = SchemaCapturingProvider([], native=False)
    replacement.model = "different-configured-model"
    changed_router = ModelRouter([replacement], configured_profiles={"local": replacement})
    restarted = AgentCore(changed_router, store=MissionStore(database), max_iterations=1)
    with pytest.raises(ModelSelectionError) as changed:
        restarted.resume_mission(mission.mission_id, owner_session_token="valid-owner", run=False)

    assert changed.value.code == "selected_model_configuration_changed"
    assert replacement.calls == 0


def test_owner_switches_preference_and_profile_without_losing_durable_mission_state(mission_env):
    local = MissionProvider([ProviderResponse(text=json.dumps({"content": "untrusted plan"}))])
    remote = MissionProvider([ProviderResponse(text=json.dumps({"content": "unused"}))])
    local.name, local.model = "local-provider", "local-test-model"
    remote.name, remote.model = "remote-provider", "remote-test-model"
    router = ModelRouter([local, remote], configured_profiles={"local": local, "remote": remote})
    store = MissionStore(Path(mission_env) / "switch-missions.sqlite3")
    core = AgentCore(router, store=store, max_iterations=1)
    mission = core.run_owner_mission(
        "Check service status",
        owner_session_token="valid-owner",
        model_id="local",
        scope_context={"owner_allowed_tools": ["status"], "target_id": "test-service", "scope": ["test-service"]},
        run=False,
    )
    mission.hypotheses = [{"hypothesis_id": "hypothesis-preserved", "status": "UNVALIDATED"}]
    mission.interpretations = [{"reasoning_case": {"case_id": "case-preserved", "record_type": "REASONING_CASE"}}]
    mission.knowledge_context = [{"object_id": "knowledge-preserved", "content_hash": "knowledge-hash", "text": "untrusted fixture"}]
    mission.progress["memory_retrieval"] = [{"memory_id": "memory-preserved", "validation_state": "validated_by_system"}]
    mission.progress["custom_durable_state"] = {"checkpoint": "preserved"}
    store.save(mission)
    before = store.load(mission.mission_id)
    assert before is not None
    plan_fingerprint = before.plan.fingerprint
    evidence = list(before.evidence)
    scope_snapshot = dict(before.scope_snapshot)
    allowed_tools = tuple(before.authorization_snapshot["allowed_tools"])

    restarted = AgentCore(router, store=MissionStore(Path(mission_env) / "switch-missions.sqlite3"), max_iterations=1)
    preference_switched = restarted.resume_mission(
        mission.mission_id,
        owner_session_token="valid-owner",
        model_preference="deep",
        run=False,
    )
    assert preference_switched.model_selection["mode"] == "auto"
    assert preference_switched.model_selection["preference"] == "deep"
    assert preference_switched.plan.fingerprint == plan_fingerprint
    assert preference_switched.evidence == evidence
    assert preference_switched.scope_snapshot == scope_snapshot
    assert tuple(preference_switched.authorization_snapshot["allowed_tools"]) == allowed_tools
    assert preference_switched.hypotheses[0]["hypothesis_id"] == "hypothesis-preserved"
    assert preference_switched.reasoning_cases[-1]["case_id"] == "case-preserved"
    assert preference_switched.knowledge_context[0]["object_id"] == "knowledge-preserved"
    assert preference_switched.progress["memory_retrieval"][0]["memory_id"] == "memory-preserved"
    assert preference_switched.progress["custom_durable_state"] == {"checkpoint": "preserved"}

    provider_switched = restarted.resume_mission(
        mission.mission_id,
        owner_session_token="valid-owner",
        model_id="remote",
        run=False,
    )
    assert provider_switched.model_selection["profile_id"] == "remote"
    assert provider_switched.model_selection["preference"] == "deep"
    assert provider_switched.plan.fingerprint == plan_fingerprint
    assert provider_switched.evidence == evidence
    assert provider_switched.scope_snapshot == scope_snapshot
    assert tuple(provider_switched.authorization_snapshot["allowed_tools"]) == allowed_tools
    assert len(provider_switched.progress["model_selection_history"]) == 2
    assert [event["event"] for event in provider_switched.trajectory].count("ModelSelectionChanged") == 2
    assert local.calls == 1 and remote.calls == 0
