from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

import test_agent_core_integration as existing
from agent.agent_core import AgentCore
from agent.intelligence_layer.skills import (
    SkillCandidateEvidence,
    SkillRegistry,
)
from agent.mission import MissionStatus, MissionStore
from agent.model_router import ModelRouter
from owner_session_testutils import allow_owner_sessions


@pytest.fixture
def routing_env(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "valid-owner")
    return tmp_path


def _approve_revision(registry, definition, version: int):
    """Create a later approved revision using the real candidate/approval path."""
    revision = replace(definition, version=version, content_hash="")
    registry.register_candidate(
        "owner:1",
        revision,
        SkillCandidateEvidence(
            owner_identity_ref="owner:1",
            mission_id=f"verified-source-{version}",
            trajectory_sha256="c" * 64,
            critic_id="integration-test-critic",
            validator_id="integration-test-validator",
            verification_evidence_sha256="d" * 64,
            evidence_refs=(f"evidence:revision-{version}",),
            candidate_sha256=revision.content_hash,
        ),
    )
    registry.approve("owner:1", revision.skill_id, version)
    return revision


def _core(tmp_path, provider, registry=None, *, filename="missions.sqlite3"):
    return AgentCore(
        ModelRouter([provider]),
        store=MissionStore(Path(tmp_path) / filename),
        skill_registry=registry,
    )


def test_auto_skill_runs_approved_status_mission_and_persists_reference(routing_env):
    registry, base = existing.approved_status_skill(routing_env)
    # Version 2 makes sure the top-level routing schema version is not confused
    # with the selected Skill revision number.
    definition = _approve_revision(registry, base, 2)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "auto-status")])
    ])
    core = _core(routing_env, provider, registry)

    mission = core.run_owner_mission(
        "Check local status and verify the observation",
        owner_session_token="valid-owner",
        auto_skill=True,
    )

    assert mission.status is MissionStatus.GOAL_COMPLETED
    assert mission.skill_binding["owner_identity_ref"] == "owner:1"
    assert mission.skill_binding["skill_id"] == definition.skill_id
    assert mission.skill_binding["version"] == 2
    assert mission.skill_binding["content_hash"] == definition.content_hash
    assert mission.checkpoint["skill_reference"] == mission.skill_binding
    assert mission.evidence
    routing = mission.provenance["skill_routing"]
    assert routing["outcome"] == "selected"
    assert routing["version"] == 1  # Routing metadata schema version.
    assert routing["skill_version"] == 2
    assert routing["content_hash"] == definition.content_hash
    assert {tool["function"]["name"] for tool in provider.requests[0]["tools"]} == {"status"}
    persisted = core.store.load(mission.mission_id)
    assert persisted is not None and persisted.provenance["skill_routing"] == routing


def test_auto_skill_is_default_off_even_with_matching_approved_skill(routing_env):
    registry, _definition = existing.approved_status_skill(routing_env)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "ordinary-status")])
    ])
    core = _core(routing_env, provider, registry)

    mission = core.run_owner_mission(
        "Check local status", owner_session_token="valid-owner", run=False
    )

    assert mission.skill_binding is None
    assert "skill_routing" not in mission.provenance
    assert provider.calls == 1
    assert "status" in {tool["function"]["name"] for tool in provider.requests[0]["tools"]}


@pytest.mark.parametrize(
    ("objective", "add_tie", "expected"),
    [
        ("Explain the weather outlook", False, "no_match"),
        ("Check local status", True, "ambiguous"),
    ],
)
def test_abstention_keeps_normal_authorized_planning(routing_env, objective, add_tie, expected):
    registry, definition = existing.approved_status_skill(routing_env)
    if add_tie:
        second = replace(
            definition, skill_id="another-bounded-status-guide", content_hash=""
        )
        registry.register_candidate(
            "owner:1",
            second,
            SkillCandidateEvidence(
                owner_identity_ref="owner:1",
                mission_id="verified-source-tie",
                trajectory_sha256="e" * 64,
                critic_id="integration-test-critic",
                validator_id="integration-test-validator",
                verification_evidence_sha256="f" * 64,
                evidence_refs=("evidence:tie",),
                candidate_sha256=second.content_hash,
            ),
        )
        registry.approve("owner:1", second.skill_id, second.version)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "abstain-plan")])
    ])
    core = _core(routing_env, provider, registry)

    mission = core.run_owner_mission(
        objective, owner_session_token="valid-owner", auto_skill=True, run=False
    )

    assert mission.skill_binding is None
    assert mission.provenance["skill_routing"]["outcome"] == expected
    assert provider.calls == 1
    assert "status" in {tool["function"]["name"] for tool in provider.requests[0]["tools"]}


@pytest.mark.parametrize(
    ("auto_skill", "skill_id", "error"),
    [
        (True, "bounded-status-guide", "conflicting_skill_selection"),
        (1, None, "invalid_auto_skill_selection"),
        ("yes", None, "invalid_auto_skill_selection"),
    ],
)
def test_auto_skill_input_validation_happens_before_provider(routing_env, auto_skill, skill_id, error):
    registry, _definition = existing.approved_status_skill(routing_env)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "unused")])
    ])
    core = _core(routing_env, provider, registry)

    with pytest.raises(ValueError, match=error):
        core.run_owner_mission(
            "Check local status",
            owner_session_token="valid-owner",
            auto_skill=auto_skill,
            skill_id=skill_id,
        )

    assert provider.calls == 0
    assert core.store.list_for_owner("owner:1") == []


def test_invalid_owner_is_rejected_before_router_provider_or_tool(routing_env, monkeypatch):
    registry, _definition = existing.approved_status_skill(routing_env)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "unused")])
    ])
    core = _core(routing_env, provider, registry)
    routed = []
    import agent.intelligence_layer.skill_router as router_module

    monkeypatch.setattr(router_module, "route_skill", lambda *args, **kwargs: routed.append(args))
    with pytest.raises(PermissionError):
        core.run_owner_mission(
            "Check local status", owner_session_token="invalid-owner", auto_skill=True
        )

    assert routed == []
    assert provider.calls == 0
    assert core.store.list_for_owner("owner:1") == []


@pytest.mark.parametrize(
    ("scope", "allowed_tools", "expected_tools"),
    [
        ([], ["status"], {"status"}),
        (["workspace"], ["search"], {"search"}),
    ],
)
def test_router_eligibility_never_expands_requested_scope_or_tool_allowlist(
    routing_env, scope, allowed_tools, expected_tools
):
    registry, _definition = existing.approved_status_skill(routing_env)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "bounded-plan")])
    ])
    core = _core(routing_env, provider, registry)

    mission = core.run_owner_mission(
        "Check local status",
        owner_session_token="valid-owner",
        scope_context={"scope": scope, "allowed_tools": allowed_tools},
        auto_skill=True,
        run=False,
    )

    assert mission.skill_binding is None
    assert mission.provenance["skill_routing"]["outcome"] == "unavailable"
    # If the intent filter and Owner allowlist intersect to no tools, planning
    # abstains without calling the provider; otherwise it exposes only permitted tools.
    if provider.requests:
        visible_tools = {tool["function"]["name"] for tool in provider.requests[0]["tools"]}
        assert visible_tools.issubset(expected_tools)
        assert "status" not in visible_tools or "status" in expected_tools
    else:
        # The normal planner may use text generation when the authorized tool
        # intersection is empty, but no tool-call request can gain authority.
        assert provider.calls == 1


def test_auto_selected_skill_does_not_authorize_failed_model_tool(routing_env):
    registry, _definition = existing.approved_status_skill(routing_env)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[
            existing.ToolCall("run_project_tests", {"query": "."}, "outside-routed-skill")
        ])
    ])
    core = _core(routing_env, provider, registry)

    from agent.intelligence_layer.skills import SkillAuthorizationError

    with pytest.raises(SkillAuthorizationError, match="tool ceiling"):
        core.run_owner_mission(
            "Check local status", owner_session_token="valid-owner", auto_skill=True
        )

    assert {tool["function"]["name"] for tool in provider.requests[0]["tools"]} == {"status"}
    assert core.store.list_for_owner("owner:1") == []


def test_routed_skill_cannot_override_tool_excluded_by_owner_scope(routing_env):
    registry, _definition = existing.approved_status_skill(routing_env)
    # The planner attempts status although the Owner's allowed tool set excludes it.
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "scope-forbidden")])
    ])
    core = _core(routing_env, provider, registry)
    dispatched = []
    canonical_executor = core._executor

    def capture_dispatch(mission, step, action_id, **kwargs):
        dispatched.append(step.action)
        return canonical_executor(mission, step, action_id, **kwargs)

    capture_dispatch.task_delegation_scope_enforced = True
    core._executor = capture_dispatch

    mission = core.run_owner_mission(
        "Check local status",
        owner_session_token="valid-owner",
        scope_context={"scope": ["workspace"], "allowed_tools": ["search"]},
        auto_skill=True,
    )

    assert mission.skill_binding is None
    assert mission.provenance["skill_routing"]["outcome"] == "unavailable"
    if provider.requests:
        assert {tool["function"]["name"] for tool in provider.requests[0]["tools"]}.issubset({"search"})
    else:
        assert provider.calls == 1
    assert dispatched == []


def test_auto_skill_restart_preserves_validated_reference_and_revocation_blocks_dispatch(routing_env):
    registry, definition = existing.approved_status_skill(routing_env)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "restart-auto")])
    ])
    core = _core(routing_env, provider, registry, filename="restart-missions.sqlite3")
    mission = core.run_owner_mission(
        "Check local status", owner_session_token="valid-owner", auto_skill=True, run=False
    )
    original_reference = dict(mission.skill_binding)

    # Reopen both SQLite-backed stores just as a fresh process would.
    reopened_registry = SkillRegistry(
        Path(routing_env) / "skills.sqlite3",
        approval_authorizer=lambda action, owner_ref, skill_id, version: existing.SkillApprovalGrant(
            owner_ref, owner_ref, action, f"approval:{action}:{skill_id}:{version}"
        ),
    )
    reopened_store = MissionStore(Path(routing_env) / "restart-missions.sqlite3")
    restarted_core = AgentCore(ModelRouter([]), store=reopened_store, skill_registry=reopened_registry)
    restored = reopened_store.load(mission.mission_id)
    assert restored is not None and restored.verify_integrity()
    assert restored.skill_binding == original_reference
    assert restored.provenance["skill_routing"]["content_hash"] == definition.content_hash
    context = restarted_core._resolve_mission_skill_context(restored)
    assert context.reference == original_reference

    reopened_registry.revoke("owner:1", definition.skill_id, definition.version)
    dispatched = []
    from agent.mission_runtime import MissionRuntime

    runtime = MissionRuntime(
        reopened_store,
        executor=lambda *args, **kwargs: dispatched.append(args) or {"success": True},
        skill_context_provider=restarted_core._resolve_mission_skill_context,
    )
    blocked = runtime.run_slice(mission.mission_id)

    assert blocked.status is MissionStatus.SAFETY_BLOCKED
    assert blocked.failures[-1]["reason_code"] == "mission_skill_context_invalid"
    assert dispatched == []


def test_auto_route_bind_revision_toctou_mismatch_blocks_before_provider(routing_env, monkeypatch):
    registry, definition = existing.approved_status_skill(routing_env)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "should-not-run")])
    ])
    core = _core(routing_env, provider, registry)
    actual_bind = registry.bind_mission

    def rotate_active_revision(owner_ref, mission_id, skill_id):
        # This mutation lands after route_skill reads v1 and before canonical binding.
        _approve_revision(registry, definition, 2)
        return actual_bind(owner_ref, mission_id, skill_id)

    monkeypatch.setattr(registry, "bind_mission", rotate_active_revision)
    from agent.intelligence_layer.skills import SkillAuthorizationError

    with pytest.raises(SkillAuthorizationError, match="revision changed"):
        core.run_owner_mission(
            "Check local status", owner_session_token="valid-owner", auto_skill=True
        )

    assert provider.calls == 0
    assert core.store.list_for_owner("owner:1") == []


def test_reopened_core_resumes_routed_mission_to_verified_completion(routing_env):
    registry, definition = existing.approved_status_skill(routing_env)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "resume-plan")])
    ])
    core = _core(routing_env, provider, registry, filename="resume-completion.sqlite3")
    mission = core.run_owner_mission(
        "Check local status", owner_session_token="valid-owner", auto_skill=True, run=False,
    )
    reference = dict(mission.skill_binding)
    reopened_store = MissionStore(Path(routing_env) / "resume-completion.sqlite3")
    reopened_registry = SkillRegistry(Path(routing_env) / "skills.sqlite3")
    reopened_core = AgentCore(ModelRouter([]), store=reopened_store, skill_registry=reopened_registry)

    completed = reopened_core.resume_mission(mission.mission_id, owner_session_token="valid-owner")

    assert completed.status is MissionStatus.GOAL_COMPLETED, (completed.error, completed.failures)
    assert completed.skill_binding == reference
    assert completed.provenance["skill_routing"]["content_hash"] == definition.content_hash
    assert completed.evidence and completed.verify_integrity()
    assert completed.checkpoint["skill_reference"] == reference
    assert completed.action_history[0]["status"] == "completed"


def test_tool_failure_preserves_routed_reference_and_never_silently_reroutes(routing_env):
    from agent.mission_runtime import MissionRuntime
    from agent.planning import RecoveryPolicy

    registry, _ = existing.approved_status_skill(routing_env)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "failure-plan")])
    ])
    core = _core(routing_env, provider, registry, filename="tool-failure.sqlite3")
    mission = core.run_owner_mission(
        "Check local status", owner_session_token="valid-owner", auto_skill=True, run=False,
    )
    reference = dict(mission.skill_binding)
    dispatches = []

    def failing_tool(_mission, step, _action_id, **_kwargs):
        dispatches.append(step.action)
        return {"success": False, "error": "controlled tool failure"}

    failing_tool.task_delegation_scope_enforced = True
    runtime = MissionRuntime(
        core.store, executor=failing_tool, recovery_policy=RecoveryPolicy(max_retries=0),
        skill_context_provider=core._resolve_mission_skill_context,
    )
    failed = runtime.run_slice(mission.mission_id)
    assert failed.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert dispatches == ["status"]
    assert failed.failures
    assert failed.skill_binding == reference
    assert failed.provenance["skill_routing"] == mission.provenance["skill_routing"]
    assert failed.verify_integrity()
    assert core.store.load(mission.mission_id).skill_binding == reference


def test_skill_dispatch_scope_rejects_declared_authorization_version_mismatch(routing_env):
    from agent.intelligence_layer.models import DelegationDenied
    from agent.mission_runtime import MissionRuntime

    registry, _ = existing.approved_status_skill(routing_env)
    provider = existing.MissionProvider([
        existing.ProviderResponse(tool_calls=[existing.ToolCall("status", {}, "version-check")])
    ])
    core = _core(routing_env, provider, registry)
    mission = core.run_owner_mission(
        "Check local status", owner_session_token="valid-owner", auto_skill=True, run=False,
    )
    context = core._resolve_mission_skill_context(mission)
    mission.provenance["authorization_snapshot_version"] += 1
    with pytest.raises(DelegationDenied, match="version invalid"):
        MissionRuntime._skill_dispatch_scope(mission, context, "status")
