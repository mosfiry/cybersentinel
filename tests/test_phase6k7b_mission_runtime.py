from __future__ import annotations
from runtime_authorization import make_test_snapshot

from pathlib import Path
import pytest

from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.execution_fence import ExecutionFenceError
from agent.planning import FailureClass, Plan, PlanStep


def runtime(tmp_path, executor, **kwargs):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=executor, **kwargs, authorization_snapshot_factory=make_test_snapshot)


def test_end_to_end_observation_failure_replan_verify_and_persistence(tmp_path):
    calls = []

    def execute(mission, step, action_id):
        calls.append((mission.plan.version, step.step_id))
        if len(calls) == 1:
            return {"success": False, "failure_class": "COMPILATION", "error": "compiler error", "source": "build"}
        return {"success": True, "source": "pytest", "result": {"ok": True, "returncode": 0, "timed_out": False}}

    def replan(mission, observation):
        return mission.plan.replan(steps=(PlanStep("repair-2-1", "run project tests", action="run_project_tests"),), reason="execute deterministic verifier")

    plan = Plan.initial("run tests to verify artifact").replan(steps=(PlanStep("build", "build", action="build", verification=("tests",)),), reason="initial plan")
    rt = runtime(tmp_path, execute, replanner=replan)
    mission = rt.create("run tests to verify artifact", "run tests to verify artifact", plan, completion_criteria=[{"criterion_id": "tests", "description": "tests pass", "check": "pytest"}])
    after_failure = rt.run_slice(mission.mission_id)
    assert after_failure.status is MissionStatus.READY
    assert after_failure.plan.version == 3
    assert after_failure.observations[0]["error"] == "compiler error"
    assert after_failure.failures[0]["class"] == FailureClass.COMPILATION.value

    completed = rt.run_to_completion(mission.mission_id)
    assert completed.status is MissionStatus.GOAL_COMPLETED
    assert completed.verification_state["verified"] is True
    assert len(completed.plan_history) == 2
    assert MissionStore(Path(tmp_path) / "missions.sqlite3").load(mission.mission_id).status is MissionStatus.GOAL_COMPLETED
    assert calls == [(2, "build"), (3, "repair-2-1")]


def test_new_runtime_instance_resumes_after_simulated_process_crash(tmp_path):
    attempts = {"count": 0}

    def crashing_executor(mission, step, action_id):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("simulated crash")
        return {"success": True, "criterion_id": "step", "source": "executor"}

    plan = Plan.initial("resume").replan(steps=(PlanStep("step", "step", action="run"),), reason="initial")
    first = runtime(tmp_path, crashing_executor)
    mission = first.create("resume", "resume", plan)
    crashed = first.run_slice(mission.mission_id)
    assert crashed.status is MissionStatus.RUNNING
    assert crashed.checkpoint["status"] == "in_flight"

    second = runtime(tmp_path, crashing_executor)
    recovery_required = second.run_to_completion(mission.mission_id)
    assert recovery_required.status is MissionStatus.RECOVERY_REQUIRED
    assert len(recovery_required.action_history) == 0
    assert attempts["count"] == 1

    with pytest.raises(ExecutionFenceError, match="authenticated Owner"):
        second.reconcile_in_flight(mission.mission_id, executed=False)
    still_quarantined = second.run_to_completion(mission.mission_id)
    assert still_quarantined.status is MissionStatus.RECOVERY_REQUIRED
    assert len(still_quarantined.action_history) == 0
    assert attempts["count"] == 1


def test_in_flight_receipt_reconciliation_prevents_duplicate_side_effect(tmp_path):
    calls = []

    def execute(mission, step, action_id):
        calls.append(action_id)
        raise RuntimeError("crash after external side effect")

    plan = Plan.initial("receipt").replan(steps=(PlanStep("step", "step", action="run"),), reason="initial")
    rt = runtime(tmp_path, execute)
    mission = rt.create("receipt", "receipt", plan)
    rt.run_slice(mission.mission_id)
    assert rt.run_slice(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    with pytest.raises(ExecutionFenceError, match="authenticated Owner"):
        rt.reconcile_in_flight(mission.mission_id, executed=True, observation={"success": True, "criterion_id": "step", "source": "receipt"})
    still_quarantined = rt.run_to_completion(mission.mission_id)
    assert still_quarantined.status is MissionStatus.RECOVERY_REQUIRED
    assert still_quarantined.evidence == []
    assert calls == ["%s:2:step:0" % mission.mission_id]


def test_goal_verification_blocks_completion_until_required_evidence(tmp_path):
    def execute(mission, step, action_id):
        return {"success": True, "criterion_id": "implementation", "source": "builder"}

    plan = Plan.initial("deliver").replan(steps=(PlanStep("implementation", "implementation", action="build"),), reason="initial")
    rt = runtime(tmp_path, execute)
    mission = rt.create("deliver", "deliver", plan, completion_criteria=[
        {"criterion_id": "implementation", "required": True},
        {"criterion_id": "tests", "required": True},
    ])
    after_step = rt.run_slice(mission.mission_id)
    assert after_step.status is MissionStatus.READY
    checked = rt.run_slice(mission.mission_id)
    assert checked.status is MissionStatus.RUNNING
    assert checked.verification_state["missing_criteria"] == ["implementation", "tests"]
    assert checked.status is not MissionStatus.GOAL_COMPLETED


def test_authorization_intervention_persists_and_allow_resumes(tmp_path, monkeypatch):
    executed = []

    def execute(mission, step, action_id):
        executed.append(action_id)
        return {"success": True, "source": "run_project_tests", "result": {"ok": True, "returncode": 0, "timed_out": False}}

    plan = Plan.initial("run tests after owner approval").replan(steps=(PlanStep("sensitive", "sensitive", action="run_project_tests", authorization_requirement="owner"),), reason="initial")
    rt = runtime(tmp_path, execute)
    mission = rt.create("do sensitive", "run tests after owner approval", plan, completion_criteria=[{"criterion_id": "tests", "check": "pytest_success"}])
    blocked = rt.run_slice(mission.mission_id)
    assert blocked.status is MissionStatus.OWNER_INPUT_REQUIRED
    assert executed == []

    denied = rt.provide_owner_decision(mission.mission_id, allow=False)
    assert denied.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert executed == []

    mission2 = rt.create("do sensitive 2", "run tests after owner approval", plan, completion_criteria=[{"criterion_id": "tests", "check": "pytest_success"}])
    assert rt.run_slice(mission2.mission_id).status is MissionStatus.OWNER_INPUT_REQUIRED
    import security.owner_policy as policy
    from security.authorization_context import AuthorizationContext
    monkeypatch.setattr(policy, "STATE_PATH", Path(tmp_path) / "owner-policy.json")
    request_id = "mission-owner-request"
    evidence = policy._issue_evidence("username_password", request_id, "mission-proof")
    auth = AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=policy.capture_policy_snapshot(request_id, evidence))
    rt.provide_owner_decision(mission2.mission_id, allow=True, authorization_context=auth.to_dict())
    completed = rt.run_to_completion(mission2.mission_id)
    assert completed.status is MissionStatus.GOAL_COMPLETED
    assert len(executed) == 1


def test_idempotency_does_not_repeat_completed_sensitive_action(tmp_path):
    calls = []

    def execute(mission, step, action_id):
        calls.append(action_id)
        return {"success": True, "criterion_id": "step", "source": "tool"}

    plan = Plan.initial("once").replan(steps=(PlanStep("step", "step", action="tool"),), reason="initial")
    rt = runtime(tmp_path, execute)
    mission = rt.create("once", "once", plan)
    rt.run_slice(mission.mission_id)
    loaded = MissionStore(Path(tmp_path) / "missions.sqlite3").load(mission.mission_id)
    loaded.current_step = 0
    loaded.status = MissionStatus.READY
    MissionStore(Path(tmp_path) / "missions.sqlite3").save(loaded)
    rt.run_slice(mission.mission_id)
    assert len(calls) == 1
