from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from agent.intelligence_layer.models import DelegationScope
from agent.intelligence_layer.skills import (
    SkillApprovalGrant,
    SkillAuthorizationError,
    SkillCandidateEvidence,
    SkillCritique,
    SkillDefinition,
    SkillError,
    SkillExecutionContext,
    SkillExecutor,
    SkillLearningPipeline,
    SkillRegistry,
    SkillStatus,
    SkillStep,
    SkillStepReceipt,
    SkillTestCase,
    validate_skill_definition,
)
from security.mission_authorization import MissionAuthorizationSnapshot
from tools.registry import REGISTRY
from agent.trajectory import EventType, TrajectoryEvent
from agent.verification import VerificationPlan, VerificationResult

OWNER = "owner-1"
MISSION = "mission-1"
TOOL = "search"


def make_snapshot(*, tools=(TOOL,), scope=("host:example.test",), actions=("search",)):
    created = datetime.now(timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity=OWNER,
        mission_id=MISSION,
        target_identity="example.test",
        scope=list(scope),
        allowed_actions=list(actions),
        forbidden_actions=[],
        allowed_tools=list(tools),
        time_window={},
        max_duration=3600,
        rate_limits={},
        network_boundary={"allowed": []},
        data_boundary={},
        credential_boundary={"allowed": []},
        workspace_boundary={},
        policy_version="test-v1",
        owner_approval="test owner approval",
        created_at=created.isoformat(),
        expires_at=(created + timedelta(hours=1)).isoformat(),
    )


def make_definition(version=1, *, allowed_scope=("host:example.test",), constant_arguments=None, content_hint="v1"):
    return SkillDefinition(
        skill_id="host-research",
        name="Bounded host research",
        description="Run the canonical search tool and return one typed finding.",
        version=version,
        author_source="deterministic-learning-pipeline",
        capabilities=("web-research",),
        required_tools=(TOOL,),
        allowed_scope=tuple(allowed_scope),
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": 240}},
            "required": ["query"],
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {"finding": {"type": "string", "maxLength": 500}},
            "required": ["finding"],
            "additionalProperties": False,
        },
        procedure=(SkillStep(
            step_id="search-step",
            tool_name=TOOL,
            action="search",
            argument_bindings={"query": "input.query"},
            constant_arguments=constant_arguments or {},
            expects_evidence=True,
            timeout_seconds=12,
        ),),
        preconditions=("authorized scope is active",),
        postconditions=("finding is returned with evidence",),
        examples=({"query": "known defensive topic"},),
        tests=(SkillTestCase(
            test_id="basic",
            inputs={"query": "known defensive topic"},
            expected_tool_sequence=(TOOL,),
            fixture_outputs={"search-step": {"finding": "fixture finding"}},
        ),),
        provenance=f"test trace {content_hint}",
        confidence=0.75,
        output_bindings={"finding": "step.search-step.finding"},
    )


def make_registry(tmp_path, *, authorizer=None):
    return SkillRegistry(
        tmp_path / "skills.sqlite3",
        tool_specs={TOOL: REGISTRY[TOOL]},
        approval_authorizer=authorizer,
    )


def owner_grant(action, owner_ref, skill_id, version):
    return SkillApprovalGrant(owner_ref, owner_ref, action, f"decision:{action}:{skill_id}:{version}")


def register_candidate(registry, definition, owner_ref=OWNER):
    evidence = SkillCandidateEvidence(
        owner_identity_ref=owner_ref,
        mission_id=MISSION,
        trajectory_sha256="a" * 64,
        critic_id="test-critic",
        validator_id="test-validator",
        verification_evidence_sha256="b" * 64,
        evidence_refs=("evidence:1",),
        candidate_sha256=definition.content_hash,
    )
    return registry.register_candidate(owner_ref, definition, evidence)


def completed_trajectory(mission_id=MISSION):
    events = []
    previous_hash = ""
    for event_type in (EventType.MISSION_STARTED, EventType.GOAL_VERIFIED, EventType.MISSION_COMPLETED):
        event = TrajectoryEvent(event_type, mission_id, "request-1", previous_hash=previous_hash)
        events.append(event.to_dict())
        previous_hash = event.event_hash
    return events


def test_skill_candidate_is_versioned_owner_scoped_and_not_executable_until_owner_approval(tmp_path):
    registry = make_registry(tmp_path)
    definition = make_definition()
    candidate = register_candidate(registry, definition)
    assert candidate.status is SkillStatus.CANDIDATE
    assert registry.get_active(OWNER, definition.skill_id) is None
    assert registry.get_revision("other-owner", definition.skill_id, 1) is None
    assert registry.get_active("other-owner", definition.skill_id) is None
    with pytest.raises(SkillAuthorizationError, match="not configured"):
        registry.approve(OWNER, definition.skill_id, 1)

    approved = make_registry(tmp_path, authorizer=owner_grant).approve(OWNER, definition.skill_id, 1)
    assert approved.status is SkillStatus.APPROVED
    assert make_registry(tmp_path).get_active(OWNER, definition.skill_id).definition.content_hash == definition.content_hash
    assert any(event["action"] == "approved" and event["decision_id"] == "decision:approve:host-research:1" for event in make_registry(tmp_path).events(OWNER, definition.skill_id))


def test_registry_rejects_tampered_payloads_and_version_rewrites(tmp_path):
    registry = make_registry(tmp_path)
    original = make_definition()
    register_candidate(registry, original)
    with pytest.raises(SkillError, match="immutable"):
        register_candidate(registry, make_definition(content_hint="different content"))
    tampered = make_definition()
    tampered.input_schema["properties"]["query"]["maxLength"] = 1000
    with pytest.raises(ValueError, match="hash mismatch"):
        validate_skill_definition(tampered, {TOOL: REGISTRY[TOOL]})


def test_candidate_validation_checks_deterministic_tool_and_output_fixtures(tmp_path):
    registry = make_registry(tmp_path)
    definition = make_definition()
    bad_test = replace(
        definition.tests[0],
        fixture_outputs={"search-step": {"other": "missing finding"}},
    )
    invalid = replace(definition, tests=(bad_test,), content_hash="")
    with pytest.raises(SkillError, match="binding source"):
        register_candidate(registry, invalid)

    missing_binding = SkillStep(
        step_id="search-step", tool_name=TOOL, action="search",
        argument_bindings={"query": "input.undeclared"},
    )
    invalid = replace(definition, procedure=(missing_binding,), content_hash="")
    with pytest.raises(SkillError, match="undeclared input"):
        register_candidate(registry, invalid)


def test_learning_pipeline_requires_owner_completed_trajectory_critic_and_independent_evidence(tmp_path):
    registry = make_registry(tmp_path)
    definition = make_definition()
    evidence = [{"evidence_id": "evidence:1", "type": "tool_observation", "source": "search", "value_hash": "c" * 64}]
    plan = VerificationPlan(
        validator_id="independent-validator-v1",
        required_evidence=("tool_observation",),
        validator=lambda claim, records: VerificationResult.PASS,
    )
    critic = lambda mission, skill, events, rows: SkillCritique("critic-v1", True, "Procedure matches the validated mission trace")
    pipeline = SkillLearningPipeline(
        registry,
        critic=critic,
        verification_plan=plan,
        mission_owner_resolver=lambda mission_id: OWNER if mission_id == MISSION else "other-owner",
    )
    candidate = pipeline.propose_candidate(
        OWNER,
        MISSION,
        definition,
        trajectory=completed_trajectory(),
        evidence=evidence,
        evidence_refs=("evidence:1",),
    )
    assert candidate.status is SkillStatus.CANDIDATE
    assert "trajectory_sha256=" in candidate.definition.provenance
    assert registry.get_active(OWNER, definition.skill_id) is None
    candidate_event = registry.events(OWNER, definition.skill_id)[0]
    assert candidate_event["details"]["candidate_evidence"]["mission_id"] == MISSION
    assert candidate_event["details"]["candidate_evidence"]["evidence_refs"] == ["evidence:1"]

    with pytest.raises(SkillAuthorizationError, match="mission owner"):
        pipeline.propose_candidate(
            "other-owner", MISSION, make_definition(), trajectory=completed_trajectory(),
            evidence=evidence, evidence_refs=("evidence:1",),
        )
    with pytest.raises(SkillError, match="completed mission"):
        pipeline.propose_candidate(
            OWNER, MISSION, replace(make_definition(), skill_id="never", content_hash=""), trajectory=completed_trajectory()[:1],
            evidence=evidence, evidence_refs=("evidence:1",),
        )

    failed_pipeline = SkillLearningPipeline(
        make_registry(tmp_path / "failed"),
        critic=critic,
        verification_plan=VerificationPlan("independent-validator-v1", validator=lambda claim, records: VerificationResult.FAIL),
        mission_owner_resolver=lambda mission_id: OWNER,
    )
    with pytest.raises(SkillError, match="verification did not pass"):
        failed_pipeline.propose_candidate(
            OWNER, MISSION, make_definition(), trajectory=completed_trajectory(),
            evidence=evidence, evidence_refs=("evidence:1",),
        )


def test_wrong_owner_or_wrong_action_approval_grant_fails_closed(tmp_path):
    definition = make_definition()
    registry = make_registry(tmp_path, authorizer=lambda action, owner, skill, version: SkillApprovalGrant("other", "other", action, "decision"))
    register_candidate(registry, definition)
    with pytest.raises(SkillAuthorizationError, match="owner or action"):
        registry.approve(OWNER, definition.skill_id, 1)
    assert registry.get_active(OWNER, definition.skill_id) is None


def test_versioning_rollback_and_revocation_are_audited_and_effective(tmp_path):
    registry = make_registry(tmp_path, authorizer=owner_grant)
    first = make_definition(version=1)
    second = make_definition(version=2, content_hint="v2")
    register_candidate(registry, first)
    registry.approve(OWNER, first.skill_id, 1)
    register_candidate(registry, second)
    with pytest.raises(SkillError, match="only a registered candidate"):
        registry.approve(OWNER, first.skill_id, 1)
    registry.approve(OWNER, second.skill_id, 2)
    assert registry.get_active(OWNER, first.skill_id).definition.version == 2
    assert registry.rollback(OWNER, first.skill_id, 1).definition.version == 1
    assert registry.get_active(OWNER, first.skill_id).definition.version == 1
    registry.revoke(OWNER, first.skill_id, 1)
    assert registry.get_active(OWNER, first.skill_id) is None
    assert registry.get_revision(OWNER, first.skill_id, 1).status is SkillStatus.REVOKED


def test_executor_uses_snapshot_scope_dispatcher_evidence_and_append_only_run_events(tmp_path):
    registry = make_registry(tmp_path, authorizer=owner_grant)
    definition = make_definition()
    register_candidate(registry, definition)
    registry.approve(OWNER, definition.skill_id, 1)
    snapshot = make_snapshot()
    delegated = DelegationScope.from_snapshot(snapshot)
    context = SkillExecutionContext(snapshot, delegated, "agent-1", "task-1", "req-1")
    calls = []

    def dispatcher(call_context, step, arguments, tool_spec):
        assert call_context.snapshot is context.snapshot
        assert call_context.skill_id == definition.skill_id
        assert call_context.skill_version == definition.version
        assert call_context.skill_content_hash == definition.content_hash
        assert step.tool_name == tool_spec.name == TOOL
        valid, reason, _ = tool_spec.validate_input(dict(arguments))
        assert valid, reason
        calls.append(dict(arguments))
        return SkillStepReceipt({"finding": "validated by host evidence chain"}, ("evidence:1",))

    result = SkillExecutor(registry, dispatcher).execute(OWNER, definition.skill_id, {"query": "test target"}, context)
    assert result.status == "SUCCEEDED"
    assert result.result == {"finding": "validated by host evidence chain"}
    assert result.evidence_refs == ("evidence:1",)
    assert calls == [{"query": "test target"}]
    events = registry.run_events(OWNER, mission_id=MISSION, agent_id="agent-1")
    assert [event["status"] for event in events] == ["STARTED", "SUCCEEDED"]
    assert events[0]["details"]["input_hash"]
    assert "test target" not in json.dumps(events)


def test_executor_rejects_scope_or_tool_expansion_before_dispatch(tmp_path):
    registry = make_registry(tmp_path, authorizer=owner_grant)
    definition = make_definition(allowed_scope=("outside:example.test",))
    register_candidate(registry, definition)
    registry.approve(OWNER, definition.skill_id, 1)
    snapshot = make_snapshot()
    # A forged wider child record cannot exceed the immutable mission snapshot.
    scope = DelegationScope(
        owner_identity_ref=OWNER, mission_id=MISSION, target_identity=snapshot.target_identity,
        root_authorization_hash=snapshot.authorization_hash, parent_grant_hash=snapshot.authorization_hash,
        scope=("outside:example.test",), allowed_tools=(TOOL,), allowed_actions=("search",),
    )
    context = SkillExecutionContext(snapshot, scope, "agent-1", "task-1", "req-1")
    called = []
    with pytest.raises(SkillAuthorizationError, match="mission or delegated"):
        SkillExecutor(registry, lambda *args: called.append(args)).execute(OWNER, definition.skill_id, {"query": "x"}, context)
    assert not called

    allowed_definition = make_definition()
    other = replace(allowed_definition, skill_id="other-skill", content_hash="")
    register_candidate(registry, other)
    registry.approve(OWNER, other.skill_id, 1)
    no_tool_snapshot = make_snapshot(tools=())
    no_tool_context = SkillExecutionContext(no_tool_snapshot, DelegationScope.from_snapshot(no_tool_snapshot), "agent-1", "task-2", "req-2")
    with pytest.raises(SkillAuthorizationError, match="explicit mission/delegated"):
        SkillExecutor(registry, lambda *args: called.append(args)).execute(OWNER, other.skill_id, {"query": "x"}, no_tool_context)


def test_executor_requires_evidence_and_records_failure(tmp_path):
    registry = make_registry(tmp_path, authorizer=owner_grant)
    definition = make_definition()
    register_candidate(registry, definition)
    registry.approve(OWNER, definition.skill_id, 1)
    snapshot = make_snapshot()
    context = SkillExecutionContext(snapshot, DelegationScope.from_snapshot(snapshot), "agent-1", "task-1", "req-1")
    executor = SkillExecutor(registry, lambda *args: SkillStepReceipt({"finding": "unsupported"}, ()))
    with pytest.raises(SkillError, match="expected evidence"):
        executor.execute(OWNER, definition.skill_id, {"query": "test"}, context)
    states = [event["status"] for event in registry.run_events(OWNER, mission_id=MISSION)]
    assert states == ["STARTED", "FAILED"]


def test_executor_refuses_revoked_skill_and_records_no_dispatch(tmp_path):
    registry = make_registry(tmp_path, authorizer=owner_grant)
    definition = make_definition()
    register_candidate(registry, definition)
    registry.approve(OWNER, definition.skill_id, 1)
    registry.revoke(OWNER, definition.skill_id, 1)
    snapshot = make_snapshot()
    context = SkillExecutionContext(snapshot, DelegationScope.from_snapshot(snapshot), "agent-1", "task-1", "req-1")
    called = []
    with pytest.raises(SkillAuthorizationError, match="no active"):
        SkillExecutor(registry, lambda *args: called.append(args)).execute(OWNER, definition.skill_id, {"query": "test"}, context)
    assert not called


def test_cancellation_is_observed_between_steps(tmp_path):
    registry = make_registry(tmp_path, authorizer=owner_grant)
    definition = make_definition()
    register_candidate(registry, definition)
    registry.approve(OWNER, definition.skill_id, 1)
    snapshot = make_snapshot()
    context = SkillExecutionContext(snapshot, DelegationScope.from_snapshot(snapshot), "agent-1", "task-1", "req-1", is_cancelled=lambda: True)
    called = []
    with pytest.raises(InterruptedError, match="cancelled"):
        SkillExecutor(registry, lambda *args: called.append(args)).execute(OWNER, definition.skill_id, {"query": "test"}, context)
    assert not called
    assert registry.run_events(OWNER, mission_id=MISSION)[-1]["status"] == "CANCELLED"
