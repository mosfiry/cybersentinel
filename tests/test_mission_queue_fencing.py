from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path
import sqlite3
from threading import Barrier

import pytest

from agent.mission_worker import (
    LeaseClaimSnapshot,
    LeaseLostError,
    LeaseStatus,
    MissionQueue,
    WorkerMissionState,
)
from api.missions import MissionService


BASE = "2026-01-01T00:00:00+00:00"


def _claim(queue: MissionQueue, *, at: str = BASE, worker: str = "worker", seconds: int = 10):
    result = queue.claim_next(now=at, worker_id=worker, lease_seconds=seconds)
    assert result is not None and result.lease_claim is not None
    return result


def _assert_rejected(operation, status: LeaseStatus):
    with pytest.raises(LeaseLostError) as rejected:
        operation()
    assert rejected.value.lease_status is status


def test_expired_claim_cannot_heartbeat_after_same_worker_reclaim(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-aba", available_at=BASE)

    first = _claim(queue, worker="same-worker", seconds=1)
    queue.recover_expired(now="2026-01-01T00:00:01+00:00")
    second = _claim(queue, at="2026-01-01T00:00:01+00:00", worker="same-worker", seconds=10)

    assert first.lease_claim is not None and second.lease_claim is not None
    assert first.lease_claim.generation == 1
    assert second.lease_claim.generation == 2
    assert first.lease_claim.lease_id != second.lease_claim.lease_id
    assert first.lease_claim.worker_id == second.lease_claim.worker_id
    assert queue.lease_status(first.lease_claim, now="2026-01-01T00:00:01.500000+00:00") is LeaseStatus.FENCED_WORKER

    old = first.lease_claim
    _assert_rejected(lambda: queue.heartbeat(old, now="2026-01-01T00:00:01.500000+00:00"), LeaseStatus.FENCED_WORKER)
    _assert_rejected(lambda: queue.update("mission-aba", WorkerMissionState.PLANNING, claim=old), LeaseStatus.FENCED_WORKER)
    _assert_rejected(lambda: queue.release(old, now="2026-01-01T00:00:01.500000+00:00"), LeaseStatus.FENCED_WORKER)
    _assert_rejected(lambda: queue.acknowledge(old, WorkerMissionState.COMPLETED), LeaseStatus.FENCED_WORKER)
    assert queue.get("mission-aba").lease_claim == second.lease_claim


def test_expiry_rejects_every_sensitive_operation_before_recovery(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-expiry", available_at=BASE)
    claim = _claim(queue, seconds=1).lease_claim
    assert claim is not None
    deadline = "2026-01-01T00:00:01+00:00"

    assert queue.lease_status(claim, now=deadline) is LeaseStatus.LEASE_EXPIRED
    _assert_rejected(lambda: queue.heartbeat(claim, now=deadline), LeaseStatus.LEASE_EXPIRED)
    _assert_rejected(lambda: queue.update("mission-expiry", WorkerMissionState.PLANNING, claim=claim, now=deadline), LeaseStatus.LEASE_EXPIRED)
    _assert_rejected(lambda: queue.release(claim, now=deadline), LeaseStatus.LEASE_EXPIRED)
    _assert_rejected(lambda: queue.acknowledge(claim, WorkerMissionState.COMPLETED, now=deadline), LeaseStatus.LEASE_EXPIRED)
    assert queue.get("mission-expiry").state is WorkerMissionState.EXECUTING


def test_claim_snapshot_is_immutable_and_heartbeat_returns_a_new_current_snapshot(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-heartbeat", available_at=BASE)
    first = _claim(queue, seconds=1)
    original = first.lease_claim
    assert original is not None
    assert (original.mission_id, original.worker_id, original.generation, original.acquired_at, original.expires_at) == (
        "mission-heartbeat", "worker", 1, BASE, "2026-01-01T00:00:01+00:00"
    )
    with pytest.raises(FrozenInstanceError):
        original.expires_at = "tampered"  # type: ignore[misc]

    renewed = queue.heartbeat(original, now="2026-01-01T00:00:00.500000+00:00", lease_seconds=10)
    assert renewed.lease_claim is not None
    assert renewed.lease_claim.lease_id == original.lease_id
    assert renewed.lease_claim.generation == original.generation
    assert original.expires_at == "2026-01-01T00:00:01+00:00"
    assert renewed.lease_claim.expires_at == "2026-01-01T00:00:10.500000+00:00"
    assert queue.lease_status(renewed.lease_claim, now="2026-01-01T00:00:00.600000+00:00") is LeaseStatus.LEASE_VALID
    _assert_rejected(
        lambda: queue.update("mission-heartbeat", WorkerMissionState.PLANNING, claim=original, now="2026-01-01T00:00:00.600000+00:00"),
        LeaseStatus.LEASE_LOST,
    )


def test_release_requeue_and_restart_never_reset_generation_or_reactivate_old_id(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-monotonic", available_at=BASE)
    first = _claim(queue, seconds=30).lease_claim
    assert first is not None

    released = queue.release(first, now="2026-01-01T00:00:01+00:00")
    assert released.lease_claim is None
    assert released.lease_owner is None
    assert queue.lease_status(first, now="2026-01-01T00:00:02+00:00") is LeaseStatus.LEASE_REVOKED

    second = _claim(queue, at="2026-01-01T00:00:02+00:00", seconds=30).lease_claim
    assert second is not None
    assert second.generation == 2
    assert second.lease_id != first.lease_id
    queue.enqueue("mission-monotonic", available_at="2026-01-01T00:00:03+00:00")
    assert queue.get("mission-monotonic").lease_claim is None

    third = _claim(queue, at="2026-01-01T00:00:03+00:00", seconds=30).lease_claim
    assert third is not None and third.generation == 3
    queue.recover_after_restart()
    assert queue.get("mission-monotonic").lease_claim is None
    fourth = _claim(queue, at="2026-01-01T00:00:04+00:00", seconds=30).lease_claim
    assert fourth is not None and fourth.generation == 4
    assert len({first.lease_id, second.lease_id, third.lease_id, fourth.lease_id}) == 4


def test_legacy_lease_columns_migrate_without_losing_data_or_authorizing_old_claims(tmp_path):
    db_path = Path(tmp_path) / "legacy.sqlite3"
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE mission_queue (mission_id TEXT PRIMARY KEY, state TEXT NOT NULL, "
            "attempts INTEGER NOT NULL DEFAULT 0, available_at TEXT NOT NULL, claimed_at TEXT, "
            "last_error TEXT NOT NULL DEFAULT '', lease_owner TEXT, lease_expires_at TEXT)"
        )
        db.execute(
            "INSERT INTO mission_queue VALUES(?,?,?,?,?,?,?,?)",
            ("legacy", "executing", 1, BASE, BASE, "", "legacy-worker", "2026-01-01T00:00:02+00:00"),
        )

    queue = MissionQueue(db_path)
    migrated = queue.get("legacy")
    assert migrated.lease_owner == "legacy-worker"
    assert migrated.lease_expires_at == "2026-01-01T00:00:02+00:00"
    assert migrated.lease_claim is None
    with sqlite3.connect(db_path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(mission_queue)")}
        preserved = db.execute("SELECT lease_owner,lease_expires_at,lease_generation FROM mission_queue WHERE mission_id='legacy'").fetchone()
    assert {"lease_owner", "lease_expires_at", "lease_id", "lease_generation", "lease_acquired_at", "lease_heartbeat_at"} <= columns
    assert preserved == ("legacy-worker", "2026-01-01T00:00:02+00:00", 0)

    legacy_guess = LeaseClaimSnapshot("legacy", "legacy-worker", "", 0, BASE, "2026-01-01T00:00:02+00:00")
    _assert_rejected(lambda: queue.heartbeat(legacy_guess, now="2026-01-01T00:00:01+00:00"), LeaseStatus.LEASE_REVOKED)
    queue.recover_expired(now="2026-01-01T00:00:02+00:00")
    current = _claim(queue, at="2026-01-01T00:00:02+00:00", worker="new-worker")
    assert current.lease_claim is not None and current.lease_claim.generation == 1


def test_sqlite_claim_contention_has_one_deterministic_winner(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-contended", available_at=BASE)
    barrier = Barrier(2)

    def claim(worker_id: str):
        barrier.wait(timeout=5)
        return queue.claim_next(now=BASE, worker_id=worker_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, ("worker-a", "worker-b")))

    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    assert winners[0].lease_claim is not None and winners[0].lease_claim.generation == 1
    assert queue.get("mission-contended").attempts == 1


def test_start_mission_public_payload_does_not_gain_lease_tokens(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    payload = MissionService(None, queue).start_mission("mission-public")

    assert set(payload) == {
        "mission_id", "state", "attempts", "available_at", "claimed_at",
        "last_error", "lease_owner", "lease_expires_at",
    }
    assert not {"lease_id", "lease_claim", "lease_generation", "generation", "task_id"} & payload.keys()
