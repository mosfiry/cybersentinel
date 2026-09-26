from __future__ import annotations
from runtime_authorization import make_test_snapshot

from pathlib import Path

from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from agent.state import MissionState


def _runtime(tmp_path, executor, replanner=None):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=executor, replanner=replanner, authorization_snapshot_factory=make_test_snapshot)


def test_agent_state_projection_contains_auditable_fields(tmp_path):
    rt = _runtime(tmp_path, lambda m, s, a: {"success": True, "criterion_id": "goal"})
    plan = Plan.initial("goal").replan(steps=(PlanStep("s", "observe", action="status"),), reason="initial")
    mission = rt.create("Owner goal", "goal", plan, request_id="r", policy_snapshot={"policy_version": "1"})
    state = MissionState.from_mission(mission)
    data = state.to_dict()
    assert data["owner_instruction"] == "Owner goal"
    assert data["active_plan"]["objective"] == "goal"
    assert "verification_state" in data
    assert "loop_detection_state" in data


def test_trajectory_is_typed_and_persisted(tmp_path):
    rt = _runtime(tmp_path, lambda m, s, a: {"success": True, "criterion_id": "goal"})
    plan = Plan.initial("goal").replan(steps=(PlanStep("s", "observe", action="status"),), reason="initial")
    mission = rt.create("Owner goal", "goal", plan, request_id="r")
    done = rt.run_to_completion(mission.mission_id)
    events = [item["event"] for item in done.trajectory]
    assert "MissionStarted" in events
    assert "StepSelected" in events
    assert "ObservationReceived" in events
    assert "GoalVerified" in events
    restored = rt.store.load(done.mission_id)
    assert restored.trajectory == done.trajectory


def test_malformed_or_unknown_action_replans_instead_of_silent_success(tmp_path):
    calls = {"n": 0}
    def execute(mission, step, action_id):
        calls["n"] += 1
        return {"success": True, "criterion_id": "mission-goal", "source": "status"}
    def replan(mission, observation):
        return mission.plan.replan(steps=(PlanStep("recovered", "recover", action="status"),), reason="malformed proposal")
    rt = _runtime(tmp_path, execute, replan)
    plan = Plan.initial("goal").replan(steps=(PlanStep("bad", "bad", action="__planning_failure__"),), reason="initial")
    mission = rt.create("Owner goal", "goal", plan)
    result = rt.run_to_completion(mission.mission_id)
    assert result.plan.version >= 2
    assert result.status is MissionStatus.GOAL_COMPLETED
    assert any(event["event"] == "ReplanTriggered" for event in result.trajectory)
    # B3-C5/B3-H3: the unknown action is rejected by the canonical execution
    # plan gate BEFORE the executor is called, so only the recovered
    # registered action ever executes; the rejected action has exactly zero
    # executor/handler calls.
    assert calls["n"] == 1


def test_dead_loop_becomes_explicit_failure(tmp_path):
    def execute(mission, step, action_id):
        return {"success": False, "failure_class": "LOGIC", "error": "same failure"}
    def same_plan(mission, observation):
        return mission.plan
    rt = _runtime(tmp_path, execute, same_plan)
    plan = Plan.initial("goal").replan(steps=(PlanStep("same", "same", action="status"),), reason="initial")
    mission = rt.create("Owner goal", "goal", plan, max_iterations=20)
    result = rt.run_to_completion(mission.mission_id)
    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert "dead loop" in result.error


def test_authorization_missing_stops_before_executor(tmp_path):
    executed = []
    rt = _runtime(tmp_path, lambda m, s, a: executed.append(a) or {"success": True})
    plan = Plan.initial("goal").replan(steps=(PlanStep("restricted", "restricted", action="status", authorization_requirement="owner"),), reason="initial")
    mission = rt.create("Owner goal", "goal", plan)
    result = rt.run_slice(mission.mission_id)
    assert result.status is MissionStatus.OWNER_INPUT_REQUIRED
    assert executed == []
