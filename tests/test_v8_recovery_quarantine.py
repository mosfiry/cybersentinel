from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from agent.mission import MissionStatus
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState


def test_recovery_required_releases_claim_and_stays_quarantined(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    started = datetime.now(timezone.utc)
    started_text = started.isoformat()
    queue.enqueue("ambiguous-mission", available_at=started_text)
    calls: list[str] = []

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            calls.append(mission_id)
            return SimpleNamespace(
                status=MissionStatus.RECOVERY_REQUIRED,
                evidence=[],
                error="in-flight tool outcome is unknown",
            )

    worker = MissionWorker(queue, lambda: Runtime(), worker_id="recovery-worker")
    parked = worker.run_once(now=started_text)

    assert parked is not None
    assert parked.state is WorkerMissionState.WAITING_FOR_TOOL
    assert parked.last_error == "in-flight tool outcome is unknown"
    assert parked.lease_owner is None
    assert parked.lease_expires_at is None
    assert parked.claimed_at is None

    restart_time = (started + timedelta(hours=1)).isoformat()
    assert queue.recover_after_restart(now=restart_time) == []
    assert queue.claim_next(now=restart_time, worker_id="another-worker") is None
    assert worker.run_once(now=restart_time) is None
    assert queue.get("ambiguous-mission") == parked
    assert calls == ["ambiguous-mission"]


# V8 strict-worker recovery fixtures exercise the same MissionStore-backed queue
# used by production rather than relying on a non-fenced in-memory fake.
def _strict_ready_mission(tmp_path, *, mission_id="restart-owner-mission"):
    from agent.mission import MissionStore
    from agent.mission_runtime import MissionRuntime
    from agent.planning import Plan, PlanStep
    from runtime_authorization import make_test_snapshot

    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    runtime = MissionRuntime(
        store,
        executor=lambda *_args, **_kwargs: {"success": True},
        authorization_snapshot_factory=make_test_snapshot,
        require_authorization_snapshot=True,
        require_execution_fence=True,
    )
    plan = Plan.initial("restart authorization").replan(
        steps=(PlanStep("step-1", "perform the authorized action", action="status"),),
        reason="test",
    )
    mission = runtime.create(
        "restart authorization",
        "restart authorization",
        plan,
        mission_id=mission_id,
        request_id=f"request-{mission_id}",
        owner_identity_ref="owner:1",
    )
    queue = MissionQueue(
        Path(tmp_path) / "queue.sqlite3",
        require_execution_fence=True,
        mission_store=store,
    )
    return store, mission, queue


def test_strict_worker_requires_restart_recovery_before_first_poll(tmp_path):
    import pytest

    from agent.execution_fence import ExecutionFenceError

    store, mission, queue = _strict_ready_mission(tmp_path)
    queue.enqueue(mission.mission_id)
    calls = []
    worker = MissionWorker(
        queue,
        lambda: calls.append("runtime") or SimpleNamespace(
            run_to_completion=lambda *_args, **_kwargs: pytest.fail("must not dispatch")
        ),
        worker_id="strict-restart-worker",
    )

    with pytest.raises(ExecutionFenceError, match="restart recovery"):
        worker.run_once()

    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED
    assert calls == []
    recovered = worker.recover_after_restart()
    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert worker.run_once() is None
    assert calls == []


def test_restart_recovery_preserves_inflight_effect_as_recovery_required(tmp_path):
    from agent.mission import MissionStore

    store, mission, queue = _strict_ready_mission(tmp_path)
    mission.transition(MissionStatus.RUNNING, "simulated execution before crash")
    mission.checkpoint = {
        "status": "in_flight",
        "action_id": "execution-1",
        "step_id": "step-1",
        "plan_version": mission.plan.version,
        "effect_id": "effect-1",
        "effect_state": "UNKNOWN",
    }
    store.save(mission)
    queue.enqueue(mission.mission_id, state=WorkerMissionState.WAITING_FOR_TOOL)
    worker = MissionWorker(queue, lambda: object(), worker_id="strict-restart-worker")

    recovered = worker.recover_after_restart()

    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.WAITING_FOR_TOOL
    persisted = store.load(mission.mission_id)
    assert persisted.status is MissionStatus.RECOVERY_REQUIRED
    assert persisted.checkpoint["effect_id"] == "effect-1"
    assert persisted.checkpoint["status"] == "in_flight"


def test_expired_strict_claim_is_quarantined_not_requeued(tmp_path):
    from datetime import datetime, timedelta, timezone

    from agent.execution_fence import ExecutionFence

    store, mission, queue = _strict_ready_mission(tmp_path)
    queue.enqueue(mission.mission_id)
    identity = queue.register_worker("old-owner-worker")
    supervisor_fence = ExecutionFence.for_worker(queue, identity)
    claimed_at = datetime.now(timezone.utc)
    claim = queue.claim_next(
        now=claimed_at.isoformat(),
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=1,
        execution_fence=supervisor_fence,
    )
    assert claim is not None
    replacement = MissionWorker(queue, lambda: object(), worker_id="old-owner-worker")
    later = (claimed_at + timedelta(seconds=2)).isoformat()

    recovered = replacement.recover_after_restart(now=later)

    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert recovered[0].lease_owner is None
    assert recovered[0].lease_expires_at is None


def test_live_strict_lease_is_not_stolen_but_is_quarantined_after_expiry(tmp_path):
    from datetime import datetime, timedelta, timezone

    from agent.execution_fence import ExecutionFence

    store, mission, queue = _strict_ready_mission(tmp_path)
    queue.enqueue(mission.mission_id)
    identity = queue.register_worker("live-lease-worker")
    fence = ExecutionFence.for_worker(queue, identity)
    claimed_at = datetime.now(timezone.utc)
    claim = queue.claim_next(
        now=claimed_at.isoformat(),
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=60,
        execution_fence=fence,
    )
    assert claim is not None
    replacement = MissionWorker(queue, lambda: object(), worker_id="live-lease-worker")

    assert replacement.recover_after_restart(
        now=(claimed_at + timedelta(seconds=1)).isoformat()
    ) == []
    assert queue.get(mission.mission_id).state is WorkerMissionState.EXECUTING
    assert store.load(mission.mission_id).status is MissionStatus.READY

    assert replacement.run_once(now=(claimed_at + timedelta(seconds=61)).isoformat()) is None
    parked = queue.get(mission.mission_id)
    assert parked.state is WorkerMissionState.NEEDS_INPUT
    assert parked.lease_owner is None
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
