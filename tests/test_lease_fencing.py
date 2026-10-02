import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from agent.mission import MissionStatus
from agent.mission_worker import LeaseLostError, MissionQueue, MissionWorker, WorkerMissionState


BASE = "2026-01-01T00:00:00+00:00"


def _at(seconds: int) -> str:
    return (datetime.fromisoformat(BASE) + timedelta(seconds=seconds)).isoformat()


def _claim(queue: MissionQueue, *, now: str, worker_id: str, lease_seconds: int = 60):
    item = queue.claim_next(now=now, worker_id=worker_id, lease_seconds=lease_seconds)
    assert item is not None
    return item


def test_legacy_queue_migration_preserves_rows_and_claim_epoch_is_monotonic(tmp_path):
    db_path = tmp_path / "legacy-queue.sqlite3"
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE mission_queue (mission_id TEXT PRIMARY KEY, state TEXT NOT NULL, "
            "attempts INTEGER NOT NULL DEFAULT 0, available_at TEXT NOT NULL, claimed_at TEXT, "
            "last_error TEXT NOT NULL DEFAULT '', lease_owner TEXT, lease_expires_at TEXT)"
        )
        db.execute(
            "INSERT INTO mission_queue(mission_id,state,attempts,available_at,last_error) "
            "VALUES(?,?,?,?,?)",
            ("migrate", WorkerMissionState.QUEUED.value, 4, BASE, "preserve me"),
        )

    queue = MissionQueue(db_path)
    before = queue.get("migrate")
    assert before.attempts == 4
    assert before.last_error == "preserve me"
    assert before.lease_epoch == 0
    reopened = MissionQueue(db_path)
    assert reopened.get("migrate") == before

    first = _claim(queue, now=BASE, worker_id="same-worker", lease_seconds=1)
    assert first.lease_epoch == 1
    recovered = queue.recover_expired(now=_at(2))
    assert len(recovered) == 1
    assert recovered[0].lease_epoch > first.lease_epoch
    second = _claim(queue, now=_at(2), worker_id="same-worker")
    assert second.lease_epoch > recovered[0].lease_epoch
    assert second.attempts == 6


def test_restart_recovery_does_not_steal_a_live_lease(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("live", available_at=BASE)
    claim = _claim(queue, now=BASE, worker_id="worker-a", lease_seconds=60)

    assert queue.recover_after_restart(now=_at(30)) == []
    still_live = queue.get("live")
    assert still_live.state is WorkerMissionState.EXECUTING
    assert still_live.lease_owner == "worker-a"
    assert still_live.lease_epoch == claim.lease_epoch
    renewed = queue.heartbeat("live", worker_id="worker-a", lease_epoch=claim.lease_epoch, now=_at(30))
    assert renewed.lease_owner == "worker-a"
    assert renewed.lease_epoch == claim.lease_epoch
    assert renewed.lease_expires_at == _at(90)

    recovered = queue.recover_after_restart(now=_at(91))
    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.QUEUED
    assert recovered[0].lease_owner is None
    assert recovered[0].lease_epoch > claim.lease_epoch


def test_restart_recovery_leaves_non_executable_waiting_rows_unchanged(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("reconcile", available_at=BASE, state=WorkerMissionState.WAITING_FOR_TOOL)

    assert queue.recover_after_restart(now=_at(3600)) == []
    waiting = queue.get("reconcile")
    assert waiting.state is WorkerMissionState.WAITING_FOR_TOOL
    assert waiting.last_error == ""


def test_expired_unreclaimed_claim_cannot_heartbeat_update_or_release(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("expired", available_at=BASE)
    claim = _claim(queue, now=BASE, worker_id="worker-a", lease_seconds=1)
    before = queue.get("expired")

    with pytest.raises(LeaseLostError):
        queue.heartbeat("expired", worker_id="worker-a", lease_epoch=claim.lease_epoch, now=_at(2))
    with pytest.raises(LeaseLostError):
        queue.update("expired", WorkerMissionState.COMPLETED, worker_id="worker-a", lease_epoch=claim.lease_epoch, now=_at(2))
    with pytest.raises(LeaseLostError):
        queue.release("expired", WorkerMissionState.QUEUED, worker_id="worker-a", lease_epoch=claim.lease_epoch, now=_at(2))

    assert queue.get("expired") == before


def test_worker_mutations_fail_closed_when_claim_epoch_is_missing(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("missing-epoch", available_at=BASE)
    claim = _claim(queue, now=BASE, worker_id="worker-a")

    with pytest.raises(LeaseLostError, match="epoch"):
        queue.heartbeat("missing-epoch", worker_id="worker-a", now=BASE)
    with pytest.raises(LeaseLostError, match="epoch"):
        queue.update("missing-epoch", WorkerMissionState.COMPLETED, worker_id="worker-a", now=BASE)
    with pytest.raises(LeaseLostError, match="epoch"):
        queue.release("missing-epoch", WorkerMissionState.QUEUED, worker_id="worker-a", now=BASE)

    assert queue.get("missing-epoch").lease_epoch == claim.lease_epoch


def test_current_claim_can_release_to_reconciliation_without_acknowledging_success(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("release", available_at=BASE)
    claim = _claim(queue, now=BASE, worker_id="worker-a")

    released = queue.release(
        "release",
        WorkerMissionState.WAITING_FOR_TOOL,
        worker_id="worker-a",
        lease_epoch=claim.lease_epoch,
        now=BASE,
        error="external effect outcome is unknown",
    )
    assert released.state is WorkerMissionState.WAITING_FOR_TOOL
    assert released.last_error == "external effect outcome is unknown"
    assert released.lease_owner is None
    assert released.lease_expires_at is None
    assert released.lease_epoch == claim.lease_epoch


def test_stale_epoch_for_same_worker_id_cannot_mutate_reclaimed_claim(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("same-id", available_at=BASE)
    old_claim = _claim(queue, now=BASE, worker_id="worker-a", lease_seconds=1)
    queue.recover_expired(now=_at(2))
    new_claim = _claim(queue, now=_at(2), worker_id="worker-a", lease_seconds=60)
    assert new_claim.lease_epoch > old_claim.lease_epoch
    before = queue.get("same-id")

    with pytest.raises(LeaseLostError):
        queue.heartbeat("same-id", worker_id="worker-a", lease_epoch=old_claim.lease_epoch, now=_at(2))
    with pytest.raises(LeaseLostError):
        queue.update("same-id", WorkerMissionState.COMPLETED, worker_id="worker-a", lease_epoch=old_claim.lease_epoch, now=_at(2))
    with pytest.raises(LeaseLostError):
        queue.release("same-id", WorkerMissionState.QUEUED, worker_id="worker-a", lease_epoch=old_claim.lease_epoch, now=_at(2))

    assert queue.get("same-id") == before


def test_worker_heartbeat_uses_live_clock_not_claim_timestamp(tmp_path):
    claim_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    expected_expiry = (datetime.fromisoformat(claim_time) + timedelta(seconds=60)).isoformat()
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("frozen-clock", available_at=claim_time)

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            assert mission_id == "frozen-clock"
            heartbeat()
            pytest.fail("an expired lease heartbeat must be rejected")

    result = MissionWorker(queue, lambda: Runtime(), worker_id="worker-a", lease_seconds=60).run_once(now=claim_time)
    assert result.state is WorkerMissionState.EXECUTING
    assert result.lease_owner == "worker-a"
    assert result.lease_expires_at == expected_expiry


def test_worker_stale_completion_cannot_ack_reclaimed_same_worker_lease(tmp_path):
    started = datetime.now(timezone.utc)
    claim_time = started.isoformat()
    takeover_time = (started + timedelta(seconds=2)).isoformat()
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("stale-completion", available_at=claim_time)
    completed = SimpleNamespace(
        status=MissionStatus.GOAL_COMPLETED,
        evidence=[{"criterion_id": "goal"}],
        error="",
    )

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            assert mission_id == "stale-completion"
            queue.recover_expired(now=takeover_time)
            replacement = queue.claim_next(now=takeover_time, worker_id="worker-a", lease_seconds=60)
            assert replacement is not None
            assert replacement.lease_epoch > 1
            return completed

    result = MissionWorker(queue, lambda: Runtime(), worker_id="worker-a", lease_seconds=1).run_once(now=claim_time)
    assert result.state is WorkerMissionState.EXECUTING
    assert result.lease_owner == "worker-a"
    assert result.lease_epoch > 1
    assert result.last_error == "worker lease expired"
