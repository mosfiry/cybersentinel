from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from threading import Thread
from time import sleep
from types import SimpleNamespace

import pytest

from agent.mission import Mission, MissionStatus
from agent.planning import Plan
from agent.mission_worker import MissionQueue, MissionScheduler, MissionWorker, QueueCapacityError, WorkerMissionState

NOW = "2026-09-29T00:00:00+00:00"


@dataclass
class StubMission:
    status: MissionStatus
    error: str = ""
    evidence: list | None = None
    checkpoint: dict | None = None


class StubStore:
    def __init__(self, mission):
        self.mission = mission

    def load(self, _mission_id):
        return self.mission

    def save(self, mission):
        self.mission = mission
        return mission


def test_enqueue_is_idempotent_while_execution_lease_is_owned(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queued = queue.enqueue("mission-1", available_at=NOW)
    claimed = queue.claim_next(now=NOW, worker_id="worker-a", lease_seconds=120)
    assert claimed.state is WorkerMissionState.EXECUTING
    assert claimed.attempts == 1

    same = queue.enqueue("mission-1")
    assert same.state is WorkerMissionState.EXECUTING
    assert same.lease_owner == "worker-a"
    assert same.lease_expires_at == claimed.lease_expires_at
    assert same.attempts == 1

    recovered = queue.recover_expired(now="2026-09-29T00:02:01+00:00")
    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.QUEUED
    assert recovered[0].lease_owner is None
    assert queue.claim_next(now="2026-09-29T00:02:02+00:00", worker_id="worker-b") is not None


def test_legacy_queue_schema_migrates_lease_columns_idempotently(tmp_path):
    database = tmp_path / "legacy-queue.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE mission_queue (mission_id TEXT PRIMARY KEY, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, available_at TEXT NOT NULL, claimed_at TEXT, last_error TEXT NOT NULL DEFAULT '')")

    MissionQueue(database)
    MissionQueue(database)
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(mission_queue)")}
    assert {"lease_owner", "lease_expires_at"}.issubset(columns)


def test_queue_capacity_is_atomic_and_pending_reenqueue_does_not_consume_another_slot(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    queue = MissionQueue(tmp_path / "bounded-queue.sqlite3", max_pending=1)
    queue.enqueue("mission-existing", available_at=NOW)

    with pytest.raises(QueueCapacityError, match="mission_queue_capacity_exceeded"):
        queue.enqueue("mission-new", available_at=NOW)
    assert queue.enqueue("mission-existing", available_at=NOW).state is WorkerMissionState.QUEUED

    queue.update("mission-existing", WorkerMissionState.COMPLETED)
    barrier = __import__("threading").Barrier(2)

    def enqueue(mission_id):
        barrier.wait()
        try:
            queue.enqueue(mission_id, available_at=NOW)
            return "accepted"
        except QueueCapacityError:
            return "full"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(enqueue, ("mission-a", "mission-b")))
    assert sorted(outcomes) == ["accepted", "full"]
    active = [item for item in queue.list() if item.state not in {WorkerMissionState.COMPLETED, WorkerMissionState.FAILED, WorkerMissionState.CANCELLED, WorkerMissionState.NEEDS_INPUT, WorkerMissionState.PARTIAL_SUCCESS}]
    assert len(active) == 1


def test_scheduler_rejects_unimplemented_nonzero_retry_limit(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    scheduler = MissionScheduler(tmp_path / "scheduler.sqlite3", queue)
    with pytest.raises(ValueError, match="scheduled retries are unavailable"):
        scheduler.schedule("mission-1", run_at=NOW, retry_limit=2)
    with pytest.raises(ValueError, match="recurring schedules are unavailable"):
        scheduler.schedule("mission-1", run_at=NOW, interval_seconds=60)


def test_worker_renews_lease_while_executor_is_blocked(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    started_at = datetime.now(timezone.utc)
    queue.enqueue("mission-long-action", available_at=started_at.isoformat())
    outcomes = []

    def slow_resume(*_args):
        sleep(1.2)
        return StubMission(MissionStatus.GOAL_COMPLETED)

    worker = MissionWorker(queue, runtime_factory=lambda: None, worker_id="worker-a", lease_seconds=0.6, resume_callback=slow_resume)
    thread = Thread(target=lambda: outcomes.append(worker.run_once(now=started_at.isoformat(), max_slices=1)))
    thread.start()
    sleep(0.75)
    reclaimed = queue.claim_next(
        now=(started_at + timedelta(seconds=0.75)).isoformat(),
        worker_id="worker-b",
        lease_seconds=0.6,
    )
    assert reclaimed is None
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert outcomes[0].state is WorkerMissionState.COMPLETED


def test_worker_renews_lease_while_runtime_factory_is_blocked(tmp_path):
    queue = MissionQueue(tmp_path / "runtime-factory-lease.sqlite3")
    started_at = datetime.now(timezone.utc)
    queue.enqueue("mission-slow-runtime-factory", available_at=started_at.isoformat())
    outcomes = []

    def slow_factory():
        sleep(1.2)
        return None

    worker = MissionWorker(
        queue,
        runtime_factory=slow_factory,
        worker_id="worker-a",
        lease_seconds=0.6,
        resume_callback=lambda *_args: StubMission(MissionStatus.GOAL_COMPLETED),
    )
    thread = Thread(target=lambda: outcomes.append(worker.run_once(now=started_at.isoformat(), max_slices=1)))
    thread.start()
    sleep(0.75)
    reclaimed = queue.claim_next(
        now=(started_at + timedelta(seconds=0.75)).isoformat(),
        worker_id="worker-b",
        lease_seconds=0.6,
    )
    assert reclaimed is None
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert outcomes[0].state is WorkerMissionState.COMPLETED


def test_worker_does_not_publish_result_after_heartbeat_store_failure(tmp_path):
    queue = MissionQueue(tmp_path / "heartbeat-failure.sqlite3")
    queue.enqueue("mission-heartbeat-failure", available_at=NOW)

    def broken_heartbeat(*_args, **_kwargs):
        raise OSError("queue store unavailable")

    queue.heartbeat = broken_heartbeat
    worker = MissionWorker(
        queue,
        runtime_factory=lambda: None,
        worker_id="worker-a",
        lease_seconds=0.03,
        resume_callback=lambda *_args: (sleep(0.08) or StubMission(MissionStatus.GOAL_COMPLETED)),
    )

    result = worker.run_once(now=NOW, max_slices=1)
    assert result is not None
    assert result.state is WorkerMissionState.EXECUTING
    assert result.lease_owner == "worker-a"


def test_bridge_resume_does_not_reauthorize_mission_owned_by_worker(monkeypatch):
    import bridge

    mission = SimpleNamespace(
        status=MissionStatus.RUNNING,
        checkpoint={},
        to_public_dict=lambda: {"mission_id": "mission-live", "status": "RUNNING"},
    )

    class Queue:
        def get(self, mission_id):
            assert mission_id == "mission-live"
            return SimpleNamespace(state=WorkerMissionState.EXECUTING, attempts=1, available_at=NOW)

        def enqueue(self, _mission_id):
            pytest.fail("an executing mission must not be enqueued again")

    service = SimpleNamespace(
        mission=lambda mission_id, *, owner_identity: mission,
        queue=Queue(),
    )
    monkeypatch.setattr(bridge.AgentCore, "resume_mission", lambda *_args, **_kwargs: pytest.fail("must not reauthorize an active mission"))

    result = bridge.Handler._reauthorize_and_enqueue(
        bridge.Handler.__new__(bridge.Handler),
        "mission-live",
        {"owner_id": "owner-1", "session_id": "session-1"},
        service,
    )

    assert result == {
        "mission": {"mission_id": "mission-live", "status": "RUNNING"},
        "queue": {"state": WorkerMissionState.EXECUTING.value, "attempts": 1, "available_at": NOW},
    }


def test_restart_recovery_clears_worker_lease_but_not_mission_truth(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-2", available_at=NOW)
    claimed = queue.claim_next(now=NOW, worker_id="worker-a")
    assert claimed.lease_owner == "worker-a"
    recovered = queue.recover_after_restart()
    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.QUEUED
    assert recovered[0].lease_owner is None
    assert recovered[0].last_error == "worker restart recovery"


def test_bounded_active_work_releases_lease_and_resumes_to_truthful_completion(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-3", available_at=NOW)
    outcomes = iter((MissionStatus.RUNNING, MissionStatus.GOAL_COMPLETED))
    worker = MissionWorker(
        queue,
        runtime_factory=lambda: None,
        worker_id="worker-a",
        resume_callback=lambda *_args: StubMission(next(outcomes)),
    )

    first = worker.run_once(now=NOW, max_slices=1)
    assert first.state is WorkerMissionState.QUEUED
    assert first.lease_owner is None
    second = worker.run_once(now="2026-09-29T00:00:02+00:00", max_slices=1)
    assert second.state is WorkerMissionState.COMPLETED
    assert second.lease_owner is None


def test_pause_releases_worker_lease_and_resume_can_requeue(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-4", available_at=NOW)
    worker = MissionWorker(
        queue,
        runtime_factory=lambda: None,
        worker_id="worker-a",
        resume_callback=lambda *_args: StubMission(MissionStatus.PAUSED),
    )
    paused = worker.run_once(now=NOW, max_slices=1)
    assert paused.state is WorkerMissionState.PAUSED
    assert paused.lease_owner is None
    assert queue.enqueue("mission-4").state is WorkerMissionState.QUEUED


def test_worker_exception_with_inflight_checkpoint_waits_for_reconciliation(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-5", available_at=NOW)
    mission = Mission.create("request", "objective", Plan.initial("objective"), mission_id="mission-5")
    mission.checkpoint = {"status": "in_flight"}
    worker = MissionWorker(
        queue,
        runtime_factory=lambda: SimpleNamespace(store=StubStore(mission)),
        worker_id="worker-a",
        resume_callback=lambda *_args: (_ for _ in ()).throw(RuntimeError("receipt unavailable")),
    )
    result = worker.run_once(now=NOW, max_slices=1)
    assert result.state is WorkerMissionState.WAITING_FOR_TOOL
    assert result.lease_owner is None
    assert result.last_error == "ambiguous in-flight execution requires reconciliation"
    assert mission.status is MissionStatus.RECOVERY_REQUIRED


def test_worker_returning_recovery_required_releases_lease_until_explicit_requeue(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-6", available_at=NOW)
    mission = StubMission(MissionStatus.RECOVERY_REQUIRED, error="reconciliation required")
    executions = []

    def resume(mission_id, *_args):
        executions.append(mission_id)
        return mission

    worker = MissionWorker(queue, runtime_factory=lambda: None, worker_id="worker-a", resume_callback=resume)
    result = worker.run_once(now=NOW, max_slices=1)

    assert result.state is WorkerMissionState.WAITING_FOR_TOOL
    assert result.lease_owner is None
    assert result.lease_expires_at is None
    assert mission.status is MissionStatus.RECOVERY_REQUIRED
    assert result.attempts == 1
    assert queue.claim_next(now="2026-09-29T00:02:01+00:00", worker_id="worker-b") is None
    assert worker.run_once(now="2026-09-29T00:02:02+00:00", max_slices=1) is None
    assert queue.get("mission-6").attempts == 1
    assert executions == ["mission-6"]


def test_queue_and_scheduler_databases_are_private_and_symlinks_rejected(tmp_path):
    queue_path = tmp_path / "queue.sqlite3"
    scheduler_path = tmp_path / "scheduler.sqlite3"
    queue = MissionQueue(queue_path)
    MissionScheduler(scheduler_path, queue)
    assert queue_path.stat().st_mode & 0o777 == 0o600
    assert scheduler_path.stat().st_mode & 0o777 == 0o600

    outside = tmp_path / "outside.sqlite3"
    outside.write_bytes(b"not a database")
    link = tmp_path / "linked.sqlite3"
    link.symlink_to(outside)
    with pytest.raises(OSError):
        MissionQueue(link)


def test_frontend_does_not_turn_worker_or_mission_unknown_into_success():
    source = Path("web/app.js").read_text(encoding="utf-8")
    assert 'selectedMission.status === "GOAL_COMPLETED"' in source
    assert 'verification.verified === true' in source
    assert 'mission?.status || "unknown"' in source
    assert 'item.status || "completed"' not in source
    assert 'verification?.verified ?? true' not in source
    assert "localStorage.setItem(CONVERSATION_STORAGE_KEY" in source
    assert "localStorage.getItem(CONVERSATION_STORAGE_KEY" in source
