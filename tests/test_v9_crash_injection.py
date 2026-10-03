from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from runtime_authorization import make_test_snapshot, mission_model_tools, valid_status_snapshot
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.planning import Plan, PlanStep


class SimulatedProcessDeath(BaseException):
    """Bypass ordinary exception handling to model abrupt process termination."""


def _runtime(db_path: Path, executor):
    return MissionRuntime(
        MissionStore(db_path),
        executor=executor,
        authorization_snapshot_factory=make_test_snapshot,
    )


def _create_mission(runtime: MissionRuntime):
    plan = Plan.initial("audit the asset status").replan(
        steps=(PlanStep("observe", "observe", action="status"),),
        reason="V9 crash-injection fixture",
    )
    return runtime.create(
        "audit the asset status",
        "audit the asset status",
        plan,
        completion_criteria=[{"criterion_id": "status", "check": "status_snapshot"}],
    )


def _future_time() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


@pytest.mark.parametrize("checkpoint_status", ["in_flight", "in_flight_parallel"])
@pytest.mark.parametrize("resume_entrypoint", ["plan_loop", "model_loop"])
def test_every_resume_entrypoint_quarantines_every_inflight_checkpoint(
    tmp_path, checkpoint_status, resume_entrypoint
):
    executor_calls = []
    runtime = _runtime(tmp_path / "missions.sqlite3", lambda *args: executor_calls.append(args) or {"success": True})
    mission = _create_mission(runtime)
    mission.checkpoint = (
        {"status": "in_flight", "tool_call_id": "single-call", "action_id": "single-action"}
        if checkpoint_status == "in_flight"
        else {
            "status": "in_flight_parallel",
            "tool_call_ids": ["parallel-a", "parallel-b"],
            "ambiguous_tool_call_ids": ["parallel-a", "parallel-b"],
        }
    )
    runtime.store.save(mission)

    class NeverCallModel:
        calls = 0

        def complete(self, *args, **kwargs):
            self.calls += 1
            raise AssertionError("a quarantined checkpoint must not request another model proposal")

    model = NeverCallModel()
    if resume_entrypoint == "plan_loop":
        resumed = runtime.run_slice(mission.mission_id)
    else:
        resumed = runtime.run_model_loop(
            mission.mission_id,
            model,
            tools=mission_model_tools("status"),
            max_turns=3,
        )

    assert resumed.status is MissionStatus.RECOVERY_REQUIRED
    assert resumed.checkpoint["status"] == checkpoint_status
    assert executor_calls == []
    assert model.calls == 0


@pytest.mark.parametrize("crash_point", ["before_effect", "after_effect", "after_return_before_save"])
def test_worker_restart_quarantines_writeahead_crashes_without_replay(tmp_path, crash_point):
    mission_db = tmp_path / "missions.sqlite3"
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    effects = []

    def first_executor(*args):
        if crash_point == "before_effect":
            raise SimulatedProcessDeath("death after durable intent, before effect")
        effects.append("external-effect")
        if crash_point == "after_effect":
            raise SimulatedProcessDeath("death after effect, before result")
        return {"success": True, "result": valid_status_snapshot(), "source": "fixture"}

    first_runtime = _runtime(mission_db, first_executor)
    mission = _create_mission(first_runtime)
    available_at = datetime.now(timezone.utc).isoformat()
    queue.enqueue(mission.mission_id, available_at=available_at)
    if crash_point == "after_return_before_save":
        def crash_during_interpretation(*args, **kwargs):
            raise SimulatedProcessDeath("death after executor return, before durable observation save")

        first_runtime._interpret_observation = crash_during_interpretation

    first_worker = MissionWorker(
        queue,
        lambda: first_runtime,
        worker_id="worker-before-crash",
        lease_seconds=300,
    )
    with pytest.raises(SimulatedProcessDeath):
        first_worker.run_once(now=available_at, max_slices=5)

    persisted = MissionStore(mission_db).load(mission.mission_id)
    assert persisted is not None
    assert persisted.checkpoint["status"] == "in_flight"
    claimed = queue.get(mission.mission_id)
    assert claimed.state is WorkerMissionState.EXECUTING
    assert claimed.lease_owner == "worker-before-crash"

    recovered = queue.recover_after_restart(now=_future_time())
    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.QUEUED
    assert recovered[0].lease_epoch > claimed.lease_epoch

    def forbidden_replay(*args):
        effects.append("replayed-effect")
        return {"success": True, "result": valid_status_snapshot(), "source": "replay-fixture"}

    restarted_worker = MissionWorker(
        queue,
        lambda: _runtime(mission_db, forbidden_replay),
        worker_id="worker-after-restart",
        lease_seconds=300,
    )
    result = restarted_worker.run_once(now=_future_time(), max_slices=5)

    assert result is not None
    assert result.state is WorkerMissionState.WAITING_FOR_TOOL
    assert result.lease_owner is None
    assert result.lease_expires_at is None
    assert effects == ([] if crash_point == "before_effect" else ["external-effect"])
    assert queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert restarted_worker.run_once(now=_future_time(), max_slices=5) is None

    parked = MissionStore(mission_db).load(mission.mission_id)
    assert parked.status is MissionStatus.RECOVERY_REQUIRED
    assert parked.checkpoint["status"] == "in_flight"


@pytest.mark.parametrize("ack_crash_point", ["before_commit", "after_commit_before_return"])
def test_terminal_mission_does_not_repeat_effect_after_queue_ack_crash(
    tmp_path, ack_crash_point
):
    mission_db = tmp_path / "missions.sqlite3"
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    effects = []

    def executor(*args):
        effects.append("effect-once")
        return {"success": True, "result": valid_status_snapshot(), "source": "fixture"}

    first_runtime = _runtime(mission_db, executor)
    mission = _create_mission(first_runtime)
    available_at = datetime.now(timezone.utc).isoformat()
    queue.enqueue(mission.mission_id, available_at=available_at)
    original_update = queue.update

    def crash_at_queue_ack(*args, **kwargs):
        if ack_crash_point == "after_commit_before_return":
            original_update(*args, **kwargs)
        raise SimulatedProcessDeath("death at queue acknowledgment boundary")

    queue.update = crash_at_queue_ack
    first_worker = MissionWorker(queue, lambda: first_runtime, worker_id="worker-ack", lease_seconds=300)
    with pytest.raises(SimulatedProcessDeath):
        first_worker.run_once(now=available_at, max_slices=5)

    persisted_mission = MissionStore(mission_db).load(mission.mission_id)
    assert persisted_mission.status is MissionStatus.GOAL_COMPLETED
    assert effects == ["effect-once"]
    observed_queue = queue.get(mission.mission_id)
    if ack_crash_point == "after_commit_before_return":
        assert observed_queue.state is WorkerMissionState.COMPLETED
        queue.update = original_update
        assert MissionWorker(queue, lambda: _runtime(mission_db, lambda *a: pytest.fail("replay")), worker_id="worker-check", lease_seconds=300).run_once() is None
    else:
        assert observed_queue.state is WorkerMissionState.EXECUTING
        queue.update = original_update
        queue.recover_after_restart(now=_future_time())
        restarted_worker = MissionWorker(
            queue,
            lambda: _runtime(mission_db, lambda *a: pytest.fail("terminal mission must not replay")),
            worker_id="worker-after-ack-crash",
            lease_seconds=300,
        )
        completed = restarted_worker.run_once(now=_future_time(), max_slices=5)
        assert completed is not None
        assert completed.state is WorkerMissionState.COMPLETED
    assert effects == ["effect-once"]


def test_parallel_dispatch_crash_is_durable_and_never_replayed(tmp_path, monkeypatch):
    import tools.registry

    mission_db = tmp_path / "missions.sqlite3"
    first_runtime = _runtime(mission_db, lambda *args: pytest.fail("plan executor must not run"))
    mission = _create_mission(first_runtime)
    dispatches = []

    def parallel_executor(name, argument, **kwargs):
        dispatches.append(argument)
        raise SimulatedProcessDeath("parallel worker died during dispatch")

    monkeypatch.setattr(tools.registry, "execute", parallel_executor)

    class ParallelModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            calls = tuple(
                ToolCallProposal.create(
                    "status",
                    {},
                    mission_id=mission_id,
                    run_id=run_id,
                    turn_id=turn_id,
                    plan_version=plan_version,
                    step_id="observe",
                    tool_call_id=f"parallel-{label}",
                )
                for label in ("a", "b")
            )
            return ModelTurn(turn_id, tool_calls=calls)

    with pytest.raises(SimulatedProcessDeath):
        first_runtime.run_model_loop(
            mission.mission_id,
            ParallelModel(),
            tools=mission_model_tools("status"),
            max_turns=3,
        )

    crashed = MissionStore(mission_db).load(mission.mission_id)
    assert crashed.checkpoint["status"] == "in_flight_parallel"
    assert crashed.checkpoint["tool_call_ids"] == ["parallel-a", "parallel-b"]
    assert dispatches
    dispatch_count = len(dispatches)

    restarted = _runtime(mission_db, lambda *args: pytest.fail("plan executor must not run"))

    class NeverCallModel:
        def complete(self, *args, **kwargs):
            pytest.fail("model must not be called while parallel calls are ambiguous")

    recovered = restarted.run_model_loop(
        mission.mission_id,
        NeverCallModel(),
        tools=mission_model_tools("status"),
        max_turns=3,
    )
    assert recovered.status is MissionStatus.RECOVERY_REQUIRED
    assert recovered.checkpoint["status"] == "in_flight_parallel"
    # A different public runtime entrypoint must also honor the same checkpoint.
    recovered_again = restarted.run_slice(mission.mission_id)
    assert recovered_again.status is MissionStatus.RECOVERY_REQUIRED
    assert recovered_again.checkpoint["status"] == "in_flight_parallel"
    assert len(dispatches) == dispatch_count
