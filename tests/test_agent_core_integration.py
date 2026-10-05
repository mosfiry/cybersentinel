from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
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
from agent.intelligence_layer.skills import (
    SkillApprovalGrant,
    SkillCandidateEvidence,
    SkillDefinition,
    SkillRegistry,
    SkillStep,
    SkillTestCase,
)


class MissionProvider:
    name = "mission-test"
    model = "mission-test-1"

    def __init__(self, responses):
        from agent.provider_api import ProviderCapabilities
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True)
        self.responses = list(responses)
        self.calls = 0
        self.requests = []

    def tool_calling(self, messages, tools, **kwargs):
        self.calls += 1
        self.requests.append({"messages": messages, "tools": tools})
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


def approved_status_skill(tmp_path, *, owner_ref="owner:1", approve=True, expires_at=None):
    def approval(action, owner_ref, skill_id, version):
        return SkillApprovalGrant(owner_ref, owner_ref, action, f"approval:{action}:{skill_id}:{version}")

    registry = SkillRegistry(tmp_path / "skills.sqlite3", approval_authorizer=approval)
    definition = SkillDefinition(
        skill_id="bounded-status-guide",
        name="Bounded status guidance",
        description="Guide the Owner mission through one deterministic local status observation.",
        version=1,
        author_source="verified-mission-trajectory",
        capabilities=("local-status-review",),
        required_tools=("status",),
        allowed_scope=("workspace",),
        input_schema={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        output_schema={
            "type": "object",
            "properties": {"summary": {"type": "string", "maxLength": 120}},
            "required": ["summary"],
            "additionalProperties": False,
        },
        procedure=(SkillStep("status-step", "status", "status", expects_evidence=False),),
        preconditions=("Owner authorization is current",),
        postconditions=("A local status observation is captured",),
        examples=(),
        tests=(SkillTestCase("status-fixture", {}, ("status",), {"status-step": {"summary": "local status"}}),),
        provenance="verified test trajectory",
        output_bindings={"summary": "step.status-step.summary"},
        expires_at=expires_at,
    )
    evidence = SkillCandidateEvidence(
        owner_identity_ref=owner_ref,
        mission_id="verified-source-mission",
        trajectory_sha256="a" * 64,
        critic_id="test-critic",
        validator_id="test-validator",
        verification_evidence_sha256="b" * 64,
        evidence_refs=("evidence:source-status",),
        candidate_sha256=definition.content_hash,
    )
    registry.register_candidate(owner_ref, definition, evidence)
    if approve:
        registry.approve(owner_ref, definition.skill_id, definition.version)
    return registry, definition


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


def test_agent_core_explicit_approved_skill_is_untrusted_guidance_only(mission_env):
    registry, definition = approved_status_skill(mission_env)
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "skill-status-1")])])
    store = MissionStore(Path(mission_env) / "missions.sqlite3")
    core = AgentCore(ModelRouter([provider]), store=store, skill_registry=registry)
    captured_scopes = []
    canonical_executor = core._executor

    def capture_scoped_dispatch(mission, step, action_id, *, execution_fence=None, delegation_scope=None, **kwargs):
        captured_scopes.append(delegation_scope)
        return canonical_executor(mission, step, action_id, execution_fence=execution_fence, delegation_scope=delegation_scope, **kwargs)

    capture_scoped_dispatch.task_delegation_scope_enforced = True
    core._executor = capture_scoped_dispatch

    mission = core.run_owner_mission(
        "Check and verify local status",
        owner_session_token="valid-owner",
        skill_id=definition.skill_id,
    )

    assert mission.status is MissionStatus.GOAL_COMPLETED
    assert mission.verify_integrity()
    assert mission.skill_binding["owner_identity_ref"] == "owner:1"
    assert mission.skill_binding["skill_id"] == definition.skill_id
    assert mission.skill_binding["version"] == definition.version
    assert mission.skill_binding["content_hash"] == definition.content_hash
    assert mission.checkpoint["skill_reference"] == mission.skill_binding
    assert registry.run_events("owner:1", mission_id=mission.mission_id) == []
    assert len(captured_scopes) == 1
    assert captured_scopes[0].allowed_tools == ("status",)
    assert captured_scopes[0].allowed_actions == ("status",)
    assert captured_scopes[0].scope == ("workspace",)
    assert captured_scopes[0].target_identity == "local-workspace"
    assert captured_scopes[0].mission_id == mission.mission_id
    first_request = provider.requests[0]
    assert {item["function"]["name"] for item in first_request["tools"]} == {"status"}
    rendered_context = json.dumps(first_request["messages"], ensure_ascii=False)
    assert "UNTRUSTED_SKILL_GUIDANCE" in rendered_context
    assert "authority" in rendered_context and "none" in rendered_context
    assert "status-step" not in rendered_context
    assert "procedure" not in rendered_context


def test_native_mission_runtime_receives_only_untrusted_skill_guidance(mission_env):
    from agent.model_protocol import ModelTurn, ToolCallProposal
    from agent.mission_runtime import MissionRuntime

    registry, definition = approved_status_skill(mission_env)
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "native-skill-plan")])])
    store = MissionStore(Path(mission_env) / "native-missions.sqlite3")
    core = AgentCore(ModelRouter([provider]), store=store, skill_registry=registry)
    mission = core.run_owner_mission(
        "Check local status",
        owner_session_token="valid-owner",
        skill_id=definition.skill_id,
        run=False,
    )

    class NativeStatusModel:
        def __init__(self):
            self.messages = ()
            self.tools = ()

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version, timeout_seconds=None):
            self.messages = tuple(messages)
            self.tools = tuple(tools)
            return ModelTurn(turn_id, tool_calls=(ToolCallProposal.create(
                "status",
                {},
                mission_id=mission_id,
                run_id=run_id,
                turn_id=turn_id,
                plan_version=plan_version,
                step_id=mission.plan.steps[0].step_id,
                tool_call_id="native-skill-status",
            ),))

    native_model = NativeStatusModel()
    runtime = MissionRuntime(
        store,
        executor=core._executor,
        skill_context_provider=core._resolve_mission_skill_context,
        task_graph_policy=core.task_graph_policy,
    )
    dispatched_scopes = []

    def capture_native_dispatch(name, _argument, _decision, _mission, _fence, _execution_id, *, delegation_scope=None, **_kwargs):
        dispatched_scopes.append((name, delegation_scope))
        return {"success": True, "status": "ok"}

    runtime._execute_native_tool = capture_native_dispatch
    result = runtime.run_model_loop(
        mission.mission_id,
        native_model,
        tools=core._schemas(),
        run_id="native-skill-run",
        max_turns=1,
    )

    assert result.skill_binding == mission.skill_binding
    assert result.checkpoint["skill_reference"] == result.skill_binding
    assert {item["function"]["name"] for item in native_model.tools} == {"status"}
    rendered_context = json.dumps([item.to_dict() for item in native_model.messages], ensure_ascii=False)
    assert "UNTRUSTED_SKILL_GUIDANCE" in rendered_context
    assert "authority" in rendered_context and "none" in rendered_context
    assert "status-step" not in rendered_context
    assert "procedure" not in rendered_context
    assert len(dispatched_scopes) == 1
    assert dispatched_scopes[0][0] == "status"
    assert dispatched_scopes[0][1].allowed_tools == ("status",)
    assert dispatched_scopes[0][1].allowed_actions == ("status",)


@pytest.mark.parametrize("tamper", ["owner", "mission", "digest"])
def test_agent_core_skill_reference_tampering_blocks_before_dispatch(mission_env, tamper):
    registry, definition = approved_status_skill(mission_env)
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "skill-status-2")])])
    store = MissionStore(Path(mission_env) / "missions.sqlite3")
    core = AgentCore(ModelRouter([provider]), store=store, skill_registry=registry)
    mission = core.run_owner_mission(
        "Check local status",
        owner_session_token="valid-owner",
        skill_id=definition.skill_id,
        run=False,
    )
    mission.skill_binding = dict(mission.skill_binding)
    if tamper == "owner":
        mission.skill_binding["owner_identity_ref"] = "owner:999"
    elif tamper == "mission":
        mission.skill_binding["mission_id"] = "foreign-mission"
    else:
        mission.skill_binding["content_hash"] = "c" * 64
    store.save(mission)
    dispatched = []

    from agent.mission_runtime import MissionRuntime
    runtime = MissionRuntime(
        store,
        executor=lambda *args, **kwargs: dispatched.append(args) or {"success": True},
        skill_context_provider=core._resolve_mission_skill_context,
    )
    blocked = runtime.run_slice(mission.mission_id)

    assert blocked.status is MissionStatus.SAFETY_BLOCKED
    assert dispatched == []
    assert blocked.checkpoint.get("skill_reference") is None


def test_agent_core_revoked_skill_blocks_runtime_use(mission_env):
    registry, definition = approved_status_skill(mission_env)
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "skill-status-3")])])
    store = MissionStore(Path(mission_env) / "missions.sqlite3")
    core = AgentCore(ModelRouter([provider]), store=store, skill_registry=registry)
    mission = core.run_owner_mission(
        "Check local status",
        owner_session_token="valid-owner",
        skill_id=definition.skill_id,
        run=False,
    )
    registry.revoke("owner:1", definition.skill_id, definition.version)
    dispatched = []

    from agent.mission_runtime import MissionRuntime
    runtime = MissionRuntime(
        store,
        executor=lambda *args, **kwargs: dispatched.append(args) or {"success": True},
        skill_context_provider=core._resolve_mission_skill_context,
    )
    blocked = runtime.run_slice(mission.mission_id)

    assert blocked.status is MissionStatus.SAFETY_BLOCKED
    assert dispatched == []
    assert blocked.failures[-1]["reason_code"] == "mission_skill_context_invalid"


def test_agent_core_expired_skill_is_rejected_at_runtime_use(mission_env, monkeypatch):
    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    registry, definition = approved_status_skill(mission_env, expires_at=expiry)
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "skill-status-expiry")])])
    store = MissionStore(Path(mission_env) / "missions.sqlite3")
    core = AgentCore(ModelRouter([provider]), store=store, skill_registry=registry)
    mission = core.run_owner_mission(
        "Check local status",
        owner_session_token="valid-owner",
        skill_id=definition.skill_id,
        run=False,
    )

    import agent.intelligence_layer.skills as skills_module
    real_datetime = datetime

    class FutureDateTime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.now(tz) + timedelta(hours=2)

    monkeypatch.setattr(skills_module, "datetime", FutureDateTime)
    dispatched = []
    from agent.mission_runtime import MissionRuntime
    runtime = MissionRuntime(
        store,
        executor=lambda *args, **kwargs: dispatched.append(args) or {"success": True},
        skill_context_provider=core._resolve_mission_skill_context,
    )
    blocked = runtime.run_slice(mission.mission_id)

    assert blocked.status is MissionStatus.SAFETY_BLOCKED
    assert dispatched == []


def test_agent_core_rejects_unapproved_skill_before_planning(mission_env):
    from agent.intelligence_layer.skills import SkillAuthorizationError

    registry, definition = approved_status_skill(mission_env, approve=False)
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "unapproved")])])
    core = AgentCore(
        ModelRouter([provider]),
        store=MissionStore(Path(mission_env) / "missions.sqlite3"),
        skill_registry=registry,
    )

    with pytest.raises(SkillAuthorizationError):
        core.run_owner_mission(
            "Check local status",
            owner_session_token="valid-owner",
            skill_id=definition.skill_id,
        )
    assert provider.calls == 0


def test_agent_core_rejects_model_tool_outside_selected_skill_ceiling(mission_env):
    from agent.intelligence_layer.skills import SkillAuthorizationError

    registry, definition = approved_status_skill(mission_env)
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("run_project_tests", {"query": "."}, "outside-skill")])])
    store = MissionStore(Path(mission_env) / "missions.sqlite3")
    core = AgentCore(ModelRouter([provider]), store=store, skill_registry=registry)

    with pytest.raises(SkillAuthorizationError, match="tool ceiling"):
        core.run_owner_mission(
            "Check local status",
            owner_session_token="valid-owner",
            skill_id=definition.skill_id,
        )
    assert provider.requests[0]["tools"]
    assert {item["function"]["name"] for item in provider.requests[0]["tools"]} == {"status"}
    assert store.list_for_owner("owner:1") == []


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
