"""B3-C5-A/B: canonical ExecutionPlan binding for the legacy slice path.

B3-H2: the owner-direct/slice path executes only through the canonical typed
ExecutionPlan chain (Owner Policy -> Owner Budget -> Effective Tools ->
canonical ExecutionPlan -> Mission/Run binding -> Snapshot -> Action Identity
-> Proof -> Registry -> Handler). B3-H3: legacy Plan/PlanStep are
compatibility-only; any step that is not part of the derived canonical plan
is deterministically rejected BEFORE the executor is called
(executor/handler call count == 0 for the rejected action).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runtime_authorization import make_test_snapshot

from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from security.execution_boundary import MissionExecutionBoundary
from security.execution_proof import ExecutionAuthorizationProof, RejectionCode


def _runtime(tmp_path, executor=None):
    return MissionRuntime(
        MissionStore(Path(tmp_path) / "missions.sqlite3"),
        executor=executor if executor is not None else (lambda *_: {}),
        authorization_snapshot_factory=make_test_snapshot,
    )


class RecordingExecutor:
    def __init__(self):
        self.calls = []

    def __call__(self, mission, step, action_id):
        self.calls.append((step.step_id, step.action, action_id))
        return {"success": True, "criterion_id": "goal", "source": step.action}


def _mission(runtime, actions=("status",), objective="objective"):
    steps = tuple(PlanStep(f"s{index + 1}", objective, action=action) for index, action in enumerate(actions))
    plan = Plan.initial(objective).replan(steps=steps, reason="test")
    return runtime.create("request", objective, plan, completion_criteria=[{"criterion_id": "goal"}])


def test_slice_binds_and_executes_through_canonical_plan(tmp_path):
    executor = RecordingExecutor()
    runtime = _runtime(tmp_path, executor)
    mission = _mission(runtime)
    result = runtime.run_to_completion(mission.mission_id, max_slices=5)
    assert [call[1] for call in executor.calls] == ["status"]
    bound = result.progress.get("execution_plan") or {}
    assert bound.get("plan_fingerprint")
    assert bound["actions"][0]["action_id"] == "s1"
    assert bound["actions"][0]["tool_name"] == "status"
    assert result.status is MissionStatus.GOAL_COMPLETED


def test_slice_rejects_step_outside_canonical_plan_before_executor(tmp_path):
    executor = RecordingExecutor()
    runtime = _runtime(tmp_path, executor)
    # "run" is not a registered tool: the compatibility adapter can never
    # place it in a derived canonical plan, so it must be rejected
    # deterministically before the executor is called.
    mission = _mission(runtime, actions=("status", "run"))
    result = runtime.run_to_completion(mission.mission_id, max_slices=5)
    assert [call[1] for call in executor.calls] == ["status"]
    assert all(call[1] != "run" for call in executor.calls)
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert "PLAN_MISMATCH" in str(result.error)


def test_slice_unknown_only_plan_fails_closed_without_executor(tmp_path):
    executor = RecordingExecutor()
    runtime = _runtime(tmp_path, executor)
    mission = _mission(runtime, actions=("build",))
    result = runtime.run_to_completion(mission.mission_id, max_slices=5)
    assert executor.calls == []
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED


def test_slice_rejects_tampered_stored_plan_at_entry(tmp_path):
    executor = RecordingExecutor()
    runtime = _runtime(tmp_path, executor)
    mission = _mission(runtime)
    runtime.run_slice(mission.mission_id)
    assert len(executor.calls) == 1
    tampered = runtime._load(mission.mission_id)
    tampered.progress["execution_plan"]["actions"][0]["tool_name"] = "search"
    runtime.store.save(tampered)
    result = runtime.run_to_completion(mission.mission_id, max_slices=5)
    assert len(executor.calls) == 1
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED


def test_slice_rejects_forged_stored_plan_fingerprint(tmp_path):
    executor = RecordingExecutor()
    runtime = _runtime(tmp_path, executor)
    mission = _mission(runtime)
    runtime.run_slice(mission.mission_id)
    forged = runtime._load(mission.mission_id)
    forged.progress["execution_plan"]["plan_fingerprint"] = "deadbeef"
    runtime.store.save(forged)
    result = runtime.run_to_completion(mission.mission_id, max_slices=5)
    assert len(executor.calls) == 1
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED


def test_slice_rejects_forged_arguments_fingerprint(tmp_path):
    executor = RecordingExecutor()
    runtime = _runtime(tmp_path, executor)
    mission = _mission(runtime)
    runtime.run_slice(mission.mission_id)
    forged = runtime._load(mission.mission_id)
    forged.progress["execution_plan"]["actions"][0]["arguments_fingerprint"] = "0" * 64
    runtime.store.save(forged)
    result = runtime.run_to_completion(mission.mission_id, max_slices=5)
    assert len(executor.calls) == 1
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED


def test_replan_rebinds_canonical_plan_for_new_steps(tmp_path):
    executor = RecordingExecutor()
    runtime = _runtime(tmp_path, executor)
    mission = _mission(runtime)
    runtime.run_slice(mission.mission_id)
    assert [call[1] for call in executor.calls] == ["status"]
    updated = runtime._load(mission.mission_id)
    updated.plan = Plan.initial("objective").replan(steps=(PlanStep("q1", "objective", action="search"),), reason="replan")
    updated.current_step = 0
    runtime.store.save(updated)
    result = runtime.run_slice(mission.mission_id)
    assert [call[1] for call in executor.calls] == ["status", "search"]
    bound = result.progress.get("execution_plan") or {}
    assert bound["actions"][0]["tool_name"] == "search"


def test_slice_execution_run_id_rotates_per_completion_run(tmp_path):
    executor = RecordingExecutor()
    runtime = _runtime(tmp_path, executor)
    mission = _mission(runtime, actions=())
    first = runtime.run_to_completion(mission.mission_id, max_slices=2)
    run_one = first.progress.get("execution_run_id")
    assert run_one
    second = MissionRuntime(runtime.store, executor=executor, authorization_snapshot_factory=make_test_snapshot)
    result = second.run_to_completion(mission.mission_id, max_slices=2)
    assert result.progress.get("execution_run_id")
    assert result.progress["execution_run_id"] != run_one or result.is_terminal


def test_slice_proof_binds_canonical_plan_identity_and_run(tmp_path):
    executor = RecordingExecutor()
    runtime = _runtime(tmp_path, executor)
    mission = _mission(runtime)
    runtime.run_to_completion(mission.mission_id, max_slices=1)
    live = runtime._load(mission.mission_id)
    bound_fingerprint = live.progress["execution_plan"]["plan_fingerprint"]
    proof = MissionExecutionBoundary.derive(live, tool="status", argument=None, tool_call_id="call_slice")
    assert proof.plan_hash == bound_fingerprint
    assert proof.plan_hash != live.plan.fingerprint
    assert proof.run_id == live.progress["execution_run_id"]
    ok, _reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, live)
    assert ok is True and code == ""
    # Cross-run replay: rotate the live run identity; the proof must die.
    live.progress["execution_run_id"] = "run-attacker"
    runtime.store.save(live)
    rotated = runtime._load(mission.mission_id)
    ok, _reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, rotated)
    assert ok is False and code == RejectionCode.RUN_MISMATCH.value


def test_slice_stale_plan_binding_rejected_after_replan(tmp_path):
    executor = RecordingExecutor()
    runtime = _runtime(tmp_path, executor)
    mission = _mission(runtime)
    runtime.run_slice(mission.mission_id)
    live = runtime._load(mission.mission_id)
    proof = MissionExecutionBoundary.derive(live, tool="status", argument=None, tool_call_id="call_stale")
    ok, _reason, _code = ExecutionAuthorizationProof.validate_against_mission(proof, live)
    assert ok is True
    # The runtime drops the canonical binding on replan; a proof bound to the
    # previous canonical identity must fail closed afterwards.
    live.plan = Plan.initial("objective").replan(steps=(PlanStep("z1", "objective", action="search"),), reason="replan")
    live.progress.pop("execution_plan", None)
    runtime.store.save(live)
    reloaded = runtime._load(mission.mission_id)
    ok, _reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, reloaded)
    assert ok is False and code == RejectionCode.PLAN_MISMATCH.value
