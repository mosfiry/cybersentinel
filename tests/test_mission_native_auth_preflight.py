from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent.agent_core import AgentCore
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import ModelTurn, ToolCallProposal, derive_action_id
from agent.planning import Plan, PlanStep
from owner_session_testutils import allow_owner_sessions
from runtime_authorization import make_test_snapshot, mission_model_tools
from security.authorization import authorize_tool
from security.mission_authorization import MissionAuthorizationError, MissionAuthorizationSnapshot
from tools.registry import execute as execute_tool


def _owner_context(monkeypatch, request_id: str):
    allow_owner_sessions(monkeypatch, "valid-owner")
    context, _policy_context = AgentCore._auth("status", "valid-owner", request_id)
    return context


def _expired_snapshot(tmp_path: Path, *, mission_id: str) -> MissionAuthorizationSnapshot:
    now = datetime.now(timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity="test-owner",
        mission_id=mission_id,
        target_identity="test-target",
        scope=("workspace",),
        allowed_actions=("status",),
        forbidden_actions=(),
        allowed_tools=("status",),
        time_window={"timezone": "UTC"},
        max_duration=60,
        rate_limits={"status": 1},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("test-target",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(tmp_path.resolve())},
        policy_version="test-policy-v1",
        owner_approval="test-owner-approval",
        created_at=(now - timedelta(seconds=20)).isoformat(),
        expires_at=(now - timedelta(seconds=1)).isoformat(),
    )


def test_tool_registry_types_expired_mission_authorization_before_dispatch(tmp_path, monkeypatch):
    request_id = "expired-registry-auth-request"
    context = _owner_context(monkeypatch, request_id)
    decision = authorize_tool("status", context=context).decision
    assert decision is not None
    snapshot = _expired_snapshot(tmp_path, mission_id="expired-registry-mission")

    class UnusedFence:
        calls = 0

        def assert_dispatch(self, **_kwargs):
            self.calls += 1

    fence = UnusedFence()
    with pytest.raises(MissionAuthorizationError) as caught:
        execute_tool(
            "status",
            None,
            authorization_decision=decision,
            request_id=request_id,
            mission_authorization=snapshot,
            mission_id="expired-registry-mission",
            target_identity="test-target",
            execution_fence=fence,
        )

    assert caught.value.code == "authorization_expired"
    assert str(caught.value) == "mission authorization blocked: authorization snapshot expired or not active"
    assert fence.calls == 0


class _OneStatusProposal:
    def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version, timeout_seconds=None):
        proposal = ToolCallProposal.create(
            "status",
            {},
            mission_id=mission_id,
            run_id=run_id,
            turn_id=turn_id,
            plan_version=plan_version,
            step_id="observe-status",
            tool_call_id="expired-status-call",
        )
        return ModelTurn(turn_id, tool_calls=(proposal,))


def test_native_mission_marks_expired_pre_dispatch_auth_as_reauth_required(tmp_path, monkeypatch):
    request_id = "expired-native-auth-request"
    context = _owner_context(monkeypatch, request_id)
    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    runtime = MissionRuntime(
        store,
        executor=lambda *_args: {},
        authorization_snapshot_factory=make_test_snapshot,
    )
    plan = Plan.initial("Check status").replan(
        steps=(PlanStep("observe-status", "read status", action="status"),),
        reason="authorization expiry regression",
    )
    mission = runtime.create(
        "Check status",
        "Check status",
        plan,
        request_id=request_id,
        owner_identity_ref="test-owner",
        authorization_context=context.to_dict(),
        completion_criteria=[{"criterion_id": "status-snapshot", "check": "status_snapshot"}],
    )

    def reject_before_dispatch(*_args, **_kwargs):
        raise MissionAuthorizationError(
            "mission authorization blocked: authorization snapshot expired or not active",
            code="authorization_expired",
        )

    monkeypatch.setattr(runtime, "_execute_native_tool", reject_before_dispatch)
    result = runtime.run_model_loop(
        mission.mission_id,
        _OneStatusProposal(),
        tools=mission_model_tools("status"),
        run_id="expired-native-auth-run",
        max_turns=2,
    )

    assert result.status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert result.error == "mission authorization blocked: authorization snapshot expired or not active"
    assert result.checkpoint == {
        "status": "not_dispatched",
        "tool_call_id": "expired-status-call",
        "action_id": derive_action_id(result.mission_id, "expired-native-auth-run:turn:1", "expired-status-call"),
        "step_id": "observe-status",
        "run_id": "expired-native-auth-run",
        "turn_id": "expired-native-auth-run:turn:1",
        "plan_version": result.plan.version,
        "reason_code": "authorization_expired",
    }
    assert result.action_history == []
    assert result.observations == []
    assert result.evidence == []
    assert result.retry_count == 0
    failure = result.failures[-1]
    assert failure["class"] == "AUTHORIZATION"
    assert failure["kind"] == "OWNER_REAUTH_REQUIRED"
    assert failure["error_type"] == "MissionAuthorizationError"
    assert failure["reason"] == result.error
    assert failure["request_id"] == request_id
    assert failure["mission_id"] == result.mission_id
    assert failure["run_id"] == "expired-native-auth-run"
    assert failure["turn_id"] == "expired-native-auth-run:turn:1"
    assert failure["tool_call_id"] == "expired-status-call"
    assert failure["retry_policy"] == {
        "action": "OWNER_REAUTH_REQUIRED",
        "retryable": False,
        "attempts": 0,
        "requires_owner_reauth": True,
    }
    assert not any(item["to"] == MissionStatus.RECOVERY_REQUIRED.value for item in result.transitions)
    persisted = store.load(mission.mission_id)
    assert persisted is not None and persisted.status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert persisted.checkpoint == result.checkpoint
    assert persisted.failures == result.failures


def test_unknown_tool_exception_preserves_error_and_requires_reconciliation(tmp_path, monkeypatch):
    request_id = "unknown-native-outcome-request"
    context = _owner_context(monkeypatch, request_id)
    store = MissionStore(Path(tmp_path) / "unknown-outcome.sqlite3")
    runtime = MissionRuntime(
        store,
        executor=lambda *_args: {},
        authorization_snapshot_factory=make_test_snapshot,
    )
    plan = Plan.initial("Check status").replan(
        steps=(PlanStep("observe-status", "read status", action="status"),),
        reason="unknown native outcome regression",
    )
    mission = runtime.create(
        "Check status",
        "Check status",
        plan,
        request_id=request_id,
        owner_identity_ref="test-owner",
        authorization_context=context.to_dict(),
    )
    tool_error = "tool outcome receipt disconnected"

    def fail_after_dispatch(*_args, **_kwargs):
        raise RuntimeError(tool_error)

    monkeypatch.setattr(runtime, "_execute_native_tool", fail_after_dispatch)
    result = runtime.run_model_loop(
        mission.mission_id,
        _OneStatusProposal(),
        tools=mission_model_tools("status"),
        run_id="unknown-native-outcome-run",
        max_turns=2,
    )

    assert result.status is MissionStatus.RECOVERY_REQUIRED
    assert result.checkpoint["status"] == "in_flight"
    assert result.action_history == []
    assert result.observations == []
    assert result.evidence == []
    failure = result.failures[-1]
    assert failure["class"] == "UNKNOWN"
    assert failure["kind"] == "NATIVE_TOOL_OUTCOME_UNKNOWN"
    assert failure["error_type"] == "RuntimeError"
    assert failure["error"] == tool_error
    assert failure["reason"] == "native tool outcome is ambiguous: RuntimeError"
    assert failure["request_id"] == request_id
    assert failure["mission_id"] == result.mission_id
    assert failure["run_id"] == "unknown-native-outcome-run"
    assert failure["turn_id"] == "unknown-native-outcome-run:turn:1"
    assert failure["tool_call_id"] == "expired-status-call"
    assert failure["retry_policy"] == {
        "action": "RECONCILIATION_REQUIRED",
        "retryable": False,
        "attempts": 0,
    }
    persisted = store.load(mission.mission_id)
    assert persisted is not None and persisted.status is MissionStatus.RECOVERY_REQUIRED
    assert persisted.checkpoint == result.checkpoint
    assert persisted.failures == result.failures


def test_native_run_project_tests_preflight_block_survives_reopen_without_scope_bypass(tmp_path, monkeypatch):
    from dataclasses import replace

    from owner_session_testutils import persist_canonical_scope, workspace_scope_context
    from workspace import Workspace
    from workspace.process_sandbox import SandboxAvailability

    request_id = "native-preflight-persistence-request"
    owner_session_token = "valid-native-preflight-owner"
    allow_owner_sessions(monkeypatch, owner_session_token)
    persisted_scope = persist_canonical_scope(
        monkeypatch,
        tmp_path,
        owner_session_token=owner_session_token,
        target_id="test-target",
    )
    base_context, _policy_context = AgentCore._auth(
        "run_project_tests",
        owner_session_token,
        request_id,
    )
    auth_context = replace(base_context, scope_snapshot=persisted_scope)
    assert authorize_tool(
        ["run_project_tests", "bounded-fixture"],
        context=auth_context,
    ).allowed is True

    workspace_root = Path(tmp_path) / "bounded-workspace"
    workspace_root.mkdir()
    mission_scope = workspace_scope_context(persisted_scope, workspace_root)
    store_path = Path(tmp_path) / "native-preflight.sqlite3"
    store = MissionStore(store_path)
    runtime = MissionRuntime(
        store,
        executor=lambda *_args, **_kwargs: pytest.fail("native preflight must block before tool dispatch"),
        authorization_snapshot_factory=lambda mission: make_test_snapshot(
            mission,
            root=str(workspace_root),
        ),
    )
    plan = Plan.initial("Run the bounded local project test under Owner scope").replan(
        steps=(
            PlanStep(
                "run-project-tests",
                "Run the bounded local project test",
                action="run_project_tests",
                retry_policy={"arguments": {"query": "bounded-fixture"}},
            ),
        ),
        reason="native preflight restart regression",
    )
    mission = runtime.create(
        "Run the bounded local project test under Owner scope",
        "run the bounded local project test",
        plan,
        mission_id="native-preflight-blocked-mission",
        request_id=request_id,
        owner_identity_ref="owner:1",
        authorization_context=auth_context.to_dict(),
        scope_snapshot=mission_scope,
    )

    class OneProjectTestProposal:
        calls = 0

        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version, timeout_seconds=None):
            self.calls += 1
            proposal = ToolCallProposal.create(
                "run_project_tests",
                {"query": "bounded-fixture"},
                mission_id=mission_id,
                run_id=run_id,
                turn_id=turn_id,
                plan_version=plan_version,
                step_id="run-project-tests",
                tool_call_id="native-preflight-test-call",
            )
            return ModelTurn(turn_id, tool_calls=(proposal,))

    availability = SandboxAvailability(
        False,
        "windows-appcontainer-job",
        "backend_unavailable",
        "windows_appcontainer_backend_unimplemented",
        "required Windows process sandbox is unavailable",
    )
    monkeypatch.setattr(
        Workspace,
        "process_sandbox_availability",
        staticmethod(lambda: availability),
    )
    monkeypatch.setattr(
        runtime,
        "_execute_native_tool",
        lambda *_args, **_kwargs: pytest.fail("preflight rejection must precede native tool dispatch"),
    )
    model = OneProjectTestProposal()
    blocked = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=mission_model_tools("run_project_tests"),
        run_id="native-preflight-run",
        max_turns=1,
    )

    assert model.calls == 1
    assert blocked.status is MissionStatus.RESOURCE_BLOCKED
    assert blocked.owner_identity_ref == "owner:1"
    assert blocked.scope_snapshot == mission_scope
    assert blocked.checkpoint["status"] == "not_dispatched"
    assert blocked.checkpoint["reason_code"] == "backend_unavailable"
    assert blocked.checkpoint["kind"] == "PROCESS_SANDBOX_UNAVAILABLE"
    assert blocked.checkpoint["attempt_source"] == "model_turn"
    assert blocked.checkpoint["dispatch_attempted"] is False
    assert blocked.checkpoint["process_started"] is False
    assert blocked.checkpoint["process_start_confirmed"] is False
    assert blocked.checkpoint["blocked_tool_call_ids"] == ["native-preflight-test-call"]
    assert len(blocked.checkpoint["attempt_id"]) == 64
    assert blocked.checkpoint["blocked_action_ids"]
    assert blocked.checkpoint["blocked_step_ids"]
    assert blocked.evidence == []
    assert blocked.action_history == []
    assert not any(
        event["event"] in {"GoalVerified", "MissionCompleted"}
        for event in blocked.trajectory
    )
    failure = blocked.failures[-1]
    assert failure["mission_id"] == blocked.mission_id
    assert failure["request_id"] == request_id
    assert failure["attempt_source"] == "model_turn"
    assert failure["run_id"] == "native-preflight-run"
    assert failure["kind"] == "PROCESS_SANDBOX_UNAVAILABLE"
    assert failure["dispatch_attempted"] is False
    assert failure["process_started"] is False
    assert failure["process_start_confirmed"] is False
    assert failure["blocked_tool_call_ids"] == ["native-preflight-test-call"]
    assert failure["attempt_id"] == blocked.checkpoint["attempt_id"]
    assert failure["blocked_action_ids"] == blocked.checkpoint["blocked_action_ids"]
    assert failure["blocked_step_ids"] == blocked.checkpoint["blocked_step_ids"]
    proposal_event = next(event for event in blocked.trajectory if event["event"] == "ToolProposed")
    proposal = proposal_event["data"]
    assert proposal_event["mission_id"] == blocked.mission_id
    assert proposal_event["request_id"] == request_id
    assert proposal["mission_id"] == blocked.mission_id
    assert proposal["request_id"] == request_id
    assert proposal["run_id"] == blocked.checkpoint["run_id"]
    assert proposal["turn_id"] == blocked.checkpoint["turn_id"]
    assert proposal["tool_call_id"] in blocked.checkpoint["blocked_tool_call_ids"]
    assert proposal["action_id"] in blocked.checkpoint["blocked_action_ids"]
    assert proposal["step_id"] in blocked.checkpoint["blocked_step_ids"]
    diagnosed = next(
        event for event in blocked.trajectory if event["event"] == "FailureDiagnosed"
    )
    assert diagnosed["data"]["attempt_source"] == "model_turn"
    assert diagnosed["data"]["kind"] == "PROCESS_SANDBOX_UNAVAILABLE"
    assert diagnosed["data"]["dispatch_attempted"] is False
    assert diagnosed["data"]["process_started"] is False
    assert diagnosed["data"]["process_start_confirmed"] is False
    assert diagnosed["data"]["attempt_id"] == blocked.checkpoint["attempt_id"]
    assert diagnosed["data"]["blocked_tool_call_ids"] == blocked.checkpoint["blocked_tool_call_ids"]

    reopened_store = MissionStore(store_path)
    restored = reopened_store.load(mission.mission_id)
    assert restored is not None and restored.verify_integrity()
    assert restored.status is MissionStatus.RESOURCE_BLOCKED
    assert restored.owner_identity_ref == "owner:1"
    assert restored.scope_snapshot == mission_scope
    assert restored.checkpoint == blocked.checkpoint
    assert restored.failures == blocked.failures
    assert restored.checkpoint["attempt_id"] == blocked.checkpoint["attempt_id"]
    assert restored.checkpoint["attempt_source"] == "model_turn"

    class MustNotCallReplacementModel:
        calls = 0

        def complete(self, *_args, **_kwargs):
            self.calls += 1
            raise AssertionError("terminal preflight block must not be replayed after model replacement")

    replacement_model = MustNotCallReplacementModel()
    restarted_runtime = MissionRuntime(
        reopened_store,
        executor=lambda *_args, **_kwargs: pytest.fail("restart must not dispatch the blocked tool"),
        authorization_snapshot_factory=lambda restored_mission: make_test_snapshot(
            restored_mission,
            root=str(workspace_root),
        ),
    )
    after_model_replacement = restarted_runtime.run_model_loop(
        mission.mission_id,
        replacement_model,
        tools=mission_model_tools("run_project_tests"),
        run_id="replacement-model-run",
        max_turns=1,
    )
    assert replacement_model.calls == 0
    assert after_model_replacement.status is MissionStatus.RESOURCE_BLOCKED
    assert after_model_replacement.checkpoint == blocked.checkpoint
    assert after_model_replacement.checkpoint["attempt_source"] == "model_turn"
    assert after_model_replacement.checkpoint["dispatch_attempted"] is False
    assert after_model_replacement.checkpoint["process_started"] is False
    assert after_model_replacement.checkpoint["process_start_confirmed"] is False
    assert after_model_replacement.checkpoint["attempt_id"] == blocked.checkpoint["attempt_id"]
    assert restored.checkpoint["kind"] == "PROCESS_SANDBOX_UNAVAILABLE"
    assert after_model_replacement.checkpoint["kind"] == "PROCESS_SANDBOX_UNAVAILABLE"
