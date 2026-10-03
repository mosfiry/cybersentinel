from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent.mission_worker import LeaseLostError, MissionQueue, MissionWorker, WorkerMissionState
from agent.runtime_supervisor import RuntimeSupervisor, SupervisorState


BASE = "2026-01-01T00:00:00+00:00"


def _at(seconds: int) -> str:
    return (datetime.fromisoformat(BASE) + timedelta(seconds=seconds)).isoformat()


def _claim(queue: MissionQueue, identity, *, now: str, lease_seconds: int = 1):
    item = queue.claim_next(
        now=now,
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=lease_seconds,
    )
    assert item is not None
    return item


def test_worker_generation_increments_atomically_and_survives_database_reopen(tmp_path):
    db_path = tmp_path / "queue.sqlite3"
    first_queue = MissionQueue(db_path)
    first = first_queue.register_worker("stable-worker")
    reopened = MissionQueue(db_path)
    second = reopened.register_worker("stable-worker")

    assert first.runtime_generation == 1
    assert second.runtime_generation == 2
    assert first.worker_instance_id != second.worker_instance_id
    with __import__("sqlite3").connect(db_path) as db:
        states = db.execute(
            "SELECT runtime_generation,state FROM mission_worker_generations WHERE worker_id=? ORDER BY runtime_generation",
            ("stable-worker",),
        ).fetchall()
    assert states == [(1, "SUPERSEDED"), (2, "ACTIVE")]


def test_restarted_generation_rejects_stale_claim_heartbeat_update_and_release(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("fenced", available_at=BASE)
    first = queue.register_worker("same-logical-id")
    old_claim = _claim(queue, first, now=BASE, lease_seconds=1)
    second = queue.register_worker("same-logical-id")
    queue.recover_expired(now=_at(2))
    new_claim = _claim(queue, second, now=_at(2), lease_seconds=60)
    before = queue.get("fenced")

    assert second.runtime_generation == first.runtime_generation + 1
    assert new_claim.lease_epoch > old_claim.lease_epoch
    assert new_claim.worker_instance_id == second.worker_instance_id
    assert new_claim.runtime_generation == second.runtime_generation
    for mutation in (
        lambda: queue.heartbeat(
            "fenced", worker_id=first.worker_id,
            worker_instance_id=first.worker_instance_id,
            runtime_generation=first.runtime_generation,
            lease_epoch=old_claim.lease_epoch, now=_at(2),
        ),
        lambda: queue.update(
            "fenced", WorkerMissionState.COMPLETED, worker_id=first.worker_id,
            worker_instance_id=first.worker_instance_id,
            runtime_generation=first.runtime_generation,
            lease_epoch=old_claim.lease_epoch, now=_at(2),
        ),
        lambda: queue.release(
            "fenced", WorkerMissionState.QUEUED, worker_id=first.worker_id,
            worker_instance_id=first.worker_instance_id,
            runtime_generation=first.runtime_generation,
            lease_epoch=old_claim.lease_epoch, now=_at(2),
        ),
    ):
        with pytest.raises(LeaseLostError, match="generation"):
            mutation()
    assert queue.get("fenced") == before


def test_superseded_generation_cannot_claim_even_when_work_is_queued(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("ready", available_at=BASE)
    old = queue.register_worker("stable")
    current = queue.register_worker("stable")

    with pytest.raises(LeaseLostError, match="generation"):
        queue.claim_next(
            now=BASE, worker_id=old.worker_id,
            worker_instance_id=old.worker_instance_id,
            runtime_generation=old.runtime_generation,
        )
    assert queue.get("ready").state is WorkerMissionState.QUEUED
    assert _claim(queue, current, now=BASE).runtime_generation == current.runtime_generation


def test_supervisor_uses_durable_generation_and_retires_it_on_stop(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    worker = MissionWorker(queue, lambda: object(), worker_id="supervised")
    supervisor = RuntimeSupervisor(worker, poll_interval_seconds=0)
    identity = worker.identity

    health = supervisor.serve_forever(max_iterations=0)

    assert health["state"] == SupervisorState.STOPPED.value
    assert health["worker_instance_id"] == identity.worker_instance_id
    assert health["runtime_generation"] == identity.runtime_generation
    with pytest.raises(LeaseLostError, match="generation"):
        queue.claim_next(
            now=BASE, worker_id=identity.worker_id,
            worker_instance_id=identity.worker_instance_id,
            runtime_generation=identity.runtime_generation,
        )
