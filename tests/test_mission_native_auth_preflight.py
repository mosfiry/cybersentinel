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
