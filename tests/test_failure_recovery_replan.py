from __future__ import annotations
from runtime_authorization import make_test_snapshot
"""Round 2 P0-4 - deterministic failure -> recovery -> replan semantics.

Exercises the real MissionRuntime with the real RecoveryPolicy. Invariants:
- an exception during a side-effecting tool is AMBIGUOUS, never a failure that
  permits blind retry: the mission goes to RECOVERY_REQUIRED with an in-flight
  checkpoint and reconciliation is mandatory.
- reconciliation as not-executed permits exactly one safe retry.
- a deterministic failed tool result is a failure observation, never evidence.
- recovery is bounded: no infinite retry loop exists in the policy matrix.
"""


from pathlib import Path

import pytest

from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import (
    FailureClass,
    Plan,
    PlanStep,
    RecoveryAction,
    RecoveryPolicy,
)


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime):
    plan = Plan.initial("recover the mission").replan(
        steps=(PlanStep("observe", "observe", action="status"),), reason="test"
    )
    return runtime.create(
        "recover the mission",
        "recover the mission",
        plan,
        completion_criteria=[{"criterion_id": "goal"}],
    )


def _call(mission_id, run_id, turn_id, plan_version, n):
    return ToolCallProposal.create(
        "status",
        {},
        mission_id=mission_id,
        run_id=run_id,
        turn_id=turn_id,
        plan_version=plan_version,
        step_id="observe",
        action_id="a%d" % n,
        tool_call_id="call_%03d" % n,
    )


def test_recovery_policy_matrix_is_deterministic():
    policy = RecoveryPolicy()
    assert policy.action_for(FailureClass.AUTHORIZATION, 0) is RecoveryAction.OWNER_INPUT_REQUIRED
    assert policy.action_for(FailureClass.SCOPE, 0) is RecoveryAction.SCOPE_BLOCKED
    assert policy.action_for(FailureClass.RESOURCE, 0) is RecoveryAction.RESOURCE_BLOCKED
    assert policy.action_for(FailureClass.TRANSIENT, 0) is RecoveryAction.RETRY
    assert policy.action_for(FailureClass.NETWORK, 0) is RecoveryAction.RETRY
    assert policy.action_for(FailureClass.PROVIDER, 0) is RecoveryAction.RETRY
    assert policy.action_for(FailureClass.COMPILATION, 0) is RecoveryAction.REPLAN
    assert policy.action_for(FailureClass.TEST_FAILURE, 0) is RecoveryAction.REPLAN
    assert policy.action_for(FailureClass.LOGIC, 0) is RecoveryAction.REPLAN


def test_recovery_policy_never_retries_forever():
    policy = RecoveryPolicy()
    for failure in (FailureClass.TRANSIENT, FailureClass.NETWORK, FailureClass.PROVIDER):
        assert policy.action_for(failure, policy.max_retries) is RecoveryAction.FAIL
        assert policy.action_for(failure, policy.max_retries + 10) is RecoveryAction.FAIL
    for failure in (FailureClass.COMPILATION, FailureClass.TEST_FAILURE, FailureClass.LOGIC):
        assert policy.action_for(failure, policy.max_retries) is RecoveryAction.FAIL
    assert policy.action_for(FailureClass.TOOL, 0) is RecoveryAction.FAIL
    assert policy.action_for(FailureClass.UNKNOWN, 0) is RecoveryAction.FAIL


def _ambiguous_execution_runtime(tmp_path, monkeypatch, exception):
    import tools.registry

    calls = []

    def boom(*args, **kwargs):
        calls.append(args)
        raise exception

    monkeypatch.setattr(tools.registry, "execute", boom)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)

    class OneShotModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(
                turn_id,
                tool_calls=(_call(mission_id, run_id, turn_id, plan_version, 1),),
            )

    result = runtime.run_model_loop(mission.mission_id, OneShotModel(), tools=[{"name": "status"}], max_turns=5)
    return runtime, mission, result, calls


def test_tool_exception_is_ambiguous_and_requires_recovery(tmp_path, monkeypatch):
    runtime, mission, result, calls = _ambiguous_execution_runtime(tmp_path, monkeypatch, RuntimeError("process died during side effect"))
    assert calls, "the side effect must have been attempted before the ambiguity"
    assert result.status is MissionStatus.RECOVERY_REQUIRED
    assert "ambiguous" in result.error
    assert result.checkpoint.get("status") == "in_flight"
    assert result.checkpoint.get("tool_call_id") == "call_001"
    assert result.is_terminal


def test_tool_timeout_is_ambiguous_and_requires_recovery(tmp_path, monkeypatch):
    from tools.registry import ToolTimeout

    runtime, mission, result, calls = _ambiguous_execution_runtime(tmp_path, monkeypatch, ToolTimeout("tool status timed out after 30s"))
    assert result.status is MissionStatus.RECOVERY_REQUIRED
    assert result.checkpoint.get("status") == "in_flight"
    assert result.is_terminal


def test_reconcile_requires_an_in_flight_checkpoint(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(ValueError):
        runtime.reconcile_in_flight(mission.mission_id, executed=False)


def test_reconcile_not_executed_permits_exactly_one_safe_retry(tmp_path, monkeypatch):
    import tools.registry

    runtime, mission, result, _ = _ambiguous_execution_runtime(tmp_path, monkeypatch, RuntimeError("crash"))
    assert result.status is MissionStatus.RECOVERY_REQUIRED

    reconciled = runtime.reconcile_in_flight(mission.mission_id, executed=False)
    assert reconciled.status is MissionStatus.READY
    assert reconciled.checkpoint.get("status") == "reconciled_not_executed"
    assert reconciled.checkpoint.get("reconciled") is True
    assert not reconciled.is_terminal

    # reconciliation is single-shot: a second reconciliation is refused
    with pytest.raises(ValueError):
        runtime.reconcile_in_flight(mission.mission_id, executed=False)

    executed = []

    def ok(name, argument, **kwargs):
        executed.append(name)
        return {"ok": True, "criterion_id": "goal", "source": "retry-after-reconciliation"}

    monkeypatch.setattr(tools.registry, "execute", ok)

    class RetryModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            if len(executed) < 1:
                return ModelTurn(
                    turn_id,
                    tool_calls=(_call(mission_id, run_id, turn_id, plan_version, 2),),
                )
            return ModelTurn(turn_id, content="goal reached", finish_reason="stop")

    resumed = runtime.run_model_loop(mission.mission_id, RetryModel(), tools=[{"name": "status"}], max_turns=5)
    assert executed == ["status"], "exactly one safe retry after reconciliation"
    assert resumed.status is MissionStatus.GOAL_COMPLETED


def test_reconcile_executed_records_evidence_without_replay(tmp_path, monkeypatch):
    import tools.registry

    runtime, mission, result, calls = _ambiguous_execution_runtime(tmp_path, monkeypatch, RuntimeError("crash"))
    assert result.status is MissionStatus.RECOVERY_REQUIRED

    reconciled = runtime.reconcile_in_flight(
        mission.mission_id,
        executed=True,
        observation={"success": True, "criterion_id": "goal", "source": "external_receipt_confirmed"},
    )
    assert reconciled.checkpoint.get("status") == "completed"
    assert reconciled.checkpoint.get("reconciled") is True
    assert any(item.get("source") == "external_receipt_confirmed" and item.get("passed") for item in reconciled.evidence)

    execute_calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: execute_calls.append(a) or {"ok": True})

    class FinalModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, content="mission complete", finish_reason="stop")

    finished = runtime.run_model_loop(mission.mission_id, FinalModel(), tools=[{"name": "status"}], max_turns=3)
    assert execute_calls == [], "a reconciled side effect is never replayed"
    assert finished.status is MissionStatus.GOAL_COMPLETED


def test_deterministic_failed_result_is_failure_observation_not_evidence(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(
        tools.registry,
        "execute",
        lambda *a, **k: {"ok": False, "error": "deterministic failure", "error_type": "provider_unavailable"},
    )
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)

    class FailingThenFinalModel:
        def __init__(self):
            self.count = 0

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            self.count += 1
            if self.count == 1:
                return ModelTurn(
                    turn_id,
                    tool_calls=(_call(mission_id, run_id, turn_id, plan_version, 1),),
                )
            return ModelTurn(turn_id, content="I could not gather evidence", finish_reason="stop")

    result = runtime.run_model_loop(mission.mission_id, FailingThenFinalModel(), tools=[{"name": "status"}], max_turns=4)
    assert result.observations and result.observations[0].get("ok") is False
    assert not any(item.get("criterion_id") == "goal" and item.get("passed") for item in result.evidence), "a failed tool result must never become verification evidence"
    assert result.status is MissionStatus.READY, "an unverifiable final claim must not complete the mission"
    assert "lacked deterministic goal evidence" in result.error


def test_unavailable_tool_is_rejected_at_authorization(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: calls.append(a) or {"ok": True})
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)

    class UnknownToolModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(
                turn_id,
                tool_calls=(
                    ToolCallProposal.create(
                        "definitely_not_a_tool",
                        {},
                        mission_id=mission_id,
                        run_id=run_id,
                        turn_id=turn_id,
                        plan_version=plan_version,
                        tool_call_id="call_001",
                    ),
                ),
            )

    result = runtime.run_model_loop(mission.mission_id, UnknownToolModel(), tools=[], max_turns=1)
    assert calls == [], "an unknown tool must never reach execution"
    # Security ordering is intentional: the Owner snapshot gate runs before
    # tool resolution, so a model-proposed tool outside the Owner allowlist is
    # rejected deterministically as TOOL_NOT_ALLOWED and never reaches the
    # registry ("unknown tool" applies only to allowlisted-but-unregistered
    # tools, which the registry itself rejects with ValueError).
    assert result.progress["model_loop"]["tool_results"][0]["error"].startswith("TOOL_NOT_ALLOWED:")
    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED
