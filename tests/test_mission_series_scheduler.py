from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from agent.mission import MissionStatus
from agent.mission_runtime import MissionRuntime
from agent.mission_series_scheduler import MissionSeriesScheduler
from agent.mission_worker import MissionWorker, WorkerMissionState
from agent.planning import Plan, PlanStep
from test_v9_scheduled_authorization import _fixture
from runtime_authorization import make_test_snapshot


def _anchor() -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()


def test_recurring_series_persists_restarts_retries_dispatch_and_cancels_future_occurrence(tmp_path, monkeypatch):
    store, runtime, queue, original_scheduler, service, first, original_worker, executions = _fixture(
        tmp_path, monkeypatch
    )
    original_worker.stop()

    import core.engine
    from runtime_authorization import valid_status_snapshot

    monkeypatch.setattr(core.engine, "status", valid_status_snapshot)
    owner_request = objective = "check system status on a bounded recurring schedule"
    plan = Plan.initial(objective).replan(
        steps=(PlanStep("scheduled-status", objective, action="status"),),
        reason="bounded scheduler acceptance",
    )
    criteria = [{"criterion_id": "status", "check": "status_snapshot"}]
    first.owner_request = owner_request
    first.objective = objective
    first.plan = plan
    first.completion_criteria = criteria
    store.save(first)
    scope = first.scope_snapshot
    missions = [first]
    for index in range(2, 5):
        missions.append(
            runtime.create(
                owner_request,
                objective,
                plan,
                request_id=f"v9-series-request-{index}",
                owner_identity_ref="owner:1",
                scope_snapshot=scope,
                completion_criteria=criteria,
            )
        )

    fault = {"armed": False, "fired": False}

    def fail_once(boundary: str) -> None:
        if boundary == "after_queue_promotion" and fault["armed"] and not fault["fired"]:
            fault["fired"] = True
            fault["armed"] = False
            raise RuntimeError("injected_series_dispatch_failure")

    scheduler = MissionSeriesScheduler(
        original_scheduler.db_path,
        queue,
        mission_store=store,
        fault_injector=fail_once,
    )
    service.scheduler = scheduler
    occurrence_ids = [item.mission_id for item in missions[:3]]
    retry_id = missions[3].mission_id

    def execute(_mission, step, _action_id, *, execution_fence=None, timeout_seconds=None):
        assert execution_fence is not None
        assert timeout_seconds is not None and timeout_seconds > 0
        executions.append(step.step_id)
        if _mission.mission_id == occurrence_ids[1]:
            return {"success": False, "failure_class": "UNKNOWN", "error": "injected_worker_failure"}
        return {"success": True, "criterion_id": "done", "source": "series-worker"}

    def runtime_factory():
        return MissionRuntime(
            store,
            executor=execute,
            authorization_snapshot_factory=make_test_snapshot,
            require_authorization_snapshot=True,
            require_execution_fence=True,
        )

    worker = MissionWorker(queue, runtime_factory, scheduler=scheduler)
    worker.recover_after_restart()
    series_id = "v52-recurring-series"
    anchor = _anchor()

    def simulate_process_death_after_child_commit(*_args):
        raise SystemExit("simulated_process_death_after_child_schedule_commit")

    monkeypatch.setattr(scheduler, "_mark_series_scheduled", simulate_process_death_after_child_commit)
    with pytest.raises(SystemExit, match="simulated_process_death_after_child_schedule_commit"):
        service.schedule_mission_series(
            occurrence_ids,
            owner_session_token="current-owner-session",
            run_at=anchor,
            interval_seconds=1,
            retry_mission_ids=[retry_id],
            schedule_id=series_id,
        )
    interrupted = scheduler.get_series(series_id)
    assert interrupted["state"] == "preparing"
    assert interrupted["active_schedule_id"] == series_id + ":occ:1"
    assert scheduler.get(series_id + ":occ:1").state is WorkerMissionState.SCHEDULED

    recovered_scheduler = MissionSeriesScheduler(
        original_scheduler.db_path,
        queue,
        mission_store=store,
        fault_injector=fail_once,
    )
    worker.scheduler = recovered_scheduler
    recovered_scheduler.advance_series(now=anchor)
    created = recovered_scheduler.get_series(series_id)
    assert created["state"] == "scheduled"
    assert created["active_schedule_id"] == series_id + ":occ:1"
    assert recovered_scheduler.get(series_id + ":occ:1").state is WorkerMissionState.SCHEDULED

    def run_until_terminal(mission_id: str, active_worker: MissionWorker):
        for _ in range(8):
            active_worker.run_once()
            current = store.load(mission_id)
            if current.is_terminal:
                return current
        current = store.load(mission_id)
        raise AssertionError(
            f"scheduled Mission did not terminate: status={current.status.value}, "
            f"step={current.current_step}, error={current.error!r}, queue={queue.get(mission_id).state.value}"
        )

    first_result = run_until_terminal(occurrence_ids[0], worker)
    assert first_result.status is MissionStatus.GOAL_COMPLETED
    worker.stop()

    # A fresh scheduler/worker process boundary must recover the persisted series.
    fault["armed"] = True
    restarted_scheduler = MissionSeriesScheduler(
        original_scheduler.db_path,
        queue,
        mission_store=store,
        fault_injector=fail_once,
    )
    restarted_worker = MissionWorker(queue, runtime_factory, scheduler=restarted_scheduler)
    restarted_worker.recover_after_restart()
    persisted = restarted_scheduler.get_series(series_id)
    assert persisted["occurrence_index"] == 0
    assert persisted["active_mission_id"] == occurrence_ids[0]

    # The next tick recognizes occurrence 1's durable completion, schedules
    # occurrence 2, and atomically rolls back the injected promotion failure.
    with pytest.raises(RuntimeError, match="injected_series_dispatch_failure"):
        restarted_worker.run_once()
    occurrence2_schedule = restarted_scheduler.get(series_id + ":occ:2")
    assert occurrence2_schedule.state is WorkerMissionState.SCHEDULED
    assert queue.get(occurrence_ids[1]).state is WorkerMissionState.SCHEDULED
    assert store.load(occurrence_ids[1]).status is MissionStatus.READY

    # This injected tool failure is consumed by the real MissionRuntime; the
    # scheduler then executes a separately Owner-authorized retry Mission.
    second_result = run_until_terminal(occurrence_ids[1], restarted_worker)
    assert second_result.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert fault["fired"] is True
    retry_result = run_until_terminal(retry_id, restarted_worker)
    assert retry_result.status is MissionStatus.GOAL_COMPLETED

    # Cancel before another scheduler tick: occurrence 3 remains authorized but
    # is never placed on the queue or executed.
    cancelled = restarted_scheduler.cancel_series(series_id)
    assert cancelled["state"] == "cancelled"
    with sqlite3.connect(queue.db_path) as db:
        future_queue = db.execute(
            "SELECT 1 FROM mission_queue WHERE mission_id=?", (occurrence_ids[2],)
        ).fetchone()
    assert future_queue is None
    assert store.load(occurrence_ids[2]).status is MissionStatus.READY
    assert store.load(retry_id).status is MissionStatus.GOAL_COMPLETED

    snapshots = [store.load(mission_id).authorization_snapshot for mission_id in occurrence_ids + [retry_id]]
    assert all(item["mission_id"] == mission_id for item, mission_id in zip(snapshots, occurrence_ids + [retry_id]))
    scopes = [scheduler._scope_snapshot_hash(store.load(mission_id)) for mission_id in occurrence_ids + [retry_id]]
    assert len(set(scopes)) == 1
    assert len(executions) == 3
    assert restarted_scheduler.get_series(series_id)["state"] == "cancelled"
