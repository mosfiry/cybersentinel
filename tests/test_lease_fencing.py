from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from agent.mission import Mission, MissionStatus
from agent.mission_worker import LeaseLostError, MissionQueue, MissionWorker, WorkerMissionState
from agent.planning import Plan

NOW = "2026-09-29T00:00:00+00:00"


def _at(seconds: int) -> str:
    base = datetime.fromisoformat(NOW)
    return (base + timedelta(seconds=seconds)).isoformat()


def test_claim_assigns_monotonic_lease_epoch(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m1", available_at=NOW)
    first = queue.claim_next(now=NOW, worker_id="a", lease_seconds=120)
    assert first.lease_epoch == 1
    assert first.attempts == 1
    queue.recover_expired(now=_at(121))
    second = queue.claim_next(now=_at(122), worker_id="b", lease_seconds=120)
    # recover_expired advanced the epoch to 2; the reclaiming claim advances it to 3.
    assert second.lease_epoch == 3
    assert second.attempts == 2


def test_stale_worker_epoch_cannot_update_release_or_heartbeat(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m2", available_at=NOW)
    a = queue.claim_next(now=NOW, worker_id="a", lease_seconds=120)
    queue.recover_expired(now=_at(121))
    b = queue.claim_next(now=_at(122), worker_id="b", lease_seconds=120)
    with pytest.raises(LeaseLostError):
        queue.update("m2", WorkerMissionState.COMPLETED, worker_id="a", lease_epoch=a.lease_epoch, now=_at(123))
    with pytest.raises(LeaseLostError):
        queue.release("m2", WorkerMissionState.QUEUED, worker_id="a", lease_epoch=a.lease_epoch, now=_at(123))
    with pytest.raises(LeaseLostError):
        queue.heartbeat("m2", worker_id="a", now=_at(123), lease_epoch=a.lease_epoch)
    current = queue.get("m2")
    assert current.lease_owner == "b"
    assert current.lease_epoch == b.lease_epoch
    assert current.state is WorkerMissionState.EXECUTING


def test_expired_lease_cannot_be_reextended_by_heartbeat(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m3", available_at=NOW)
    a = queue.claim_next(now=NOW, worker_id="a", lease_seconds=120)
    with pytest.raises(LeaseLostError):
        queue.heartbeat("m3", worker_id="a", now=_at(121), lease_epoch=a.lease_epoch)
    assert queue.get("m3").lease_expires_at == a.lease_expires_at


def test_expired_lease_cannot_write_outcome_before_reclaim(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m4", available_at=NOW)
    a = queue.claim_next(now=NOW, worker_id="a", lease_seconds=120)
    with pytest.raises(LeaseLostError):
        queue.update("m4", WorkerMissionState.COMPLETED, worker_id="a", lease_epoch=a.lease_epoch, now=_at(121))
    with pytest.raises(LeaseLostError):
        queue.release("m4", WorkerMissionState.QUEUED, worker_id="a", lease_epoch=a.lease_epoch, now=_at(121))
    assert queue.get("m4").state is WorkerMissionState.EXECUTING


def test_legacy_caller_without_epoch_is_expiry_fenced(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m5", available_at=NOW)
    queue.claim_next(now=NOW, worker_id="a", lease_seconds=120)
    with pytest.raises(LeaseLostError):
        queue.update("m5", WorkerMissionState.COMPLETED, worker_id="a", now=_at(121))


def test_valid_lease_operations_still_succeed(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m6", available_at=NOW)
    a = queue.claim_next(now=NOW, worker_id="a", lease_seconds=120)
    hb = queue.heartbeat("m6", worker_id="a", now=_at(60), lease_epoch=a.lease_epoch)
    assert hb.lease_expires_at > a.lease_expires_at
    released = queue.release("m6", WorkerMissionState.QUEUED, worker_id="a", available_at=_at(61), lease_epoch=a.lease_epoch, now=_at(61))
    assert released.state is WorkerMissionState.QUEUED
    assert released.lease_owner is None


def test_same_worker_identity_cannot_write_with_stale_epoch(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m7", available_at=NOW)
    first = queue.claim_next(now=NOW, worker_id="a", lease_seconds=60)
    queue.release("m7", WorkerMissionState.QUEUED, worker_id="a", lease_epoch=first.lease_epoch, now=_at(10))
    second = queue.claim_next(now=_at(11), worker_id="a", lease_seconds=60)
    assert second.lease_epoch == first.lease_epoch + 1
    with pytest.raises(LeaseLostError):
        queue.update("m7", WorkerMissionState.COMPLETED, worker_id="a", lease_epoch=first.lease_epoch, now=_at(12))
    assert queue.get("m7").lease_epoch == second.lease_epoch
    assert queue.get("m7").state is WorkerMissionState.EXECUTING


def test_concurrent_claims_have_exactly_one_winner(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m8", available_at=NOW)
    a = queue.claim_next(now=NOW, worker_id="a", lease_seconds=120)
    b = queue.claim_next(now=NOW, worker_id="b", lease_seconds=120)
    assert (a is None) != (b is None)


def test_restart_recovery_advances_epoch_and_fences_stale_writer(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m9", available_at=NOW)
    a = queue.claim_next(now=NOW, worker_id="a", lease_seconds=120)
    recovered = queue.recover_after_restart()
    assert recovered[0].lease_epoch == a.lease_epoch + 1
    b = queue.claim_next(now=_at(1), worker_id="b", lease_seconds=120)
    assert b.lease_epoch == a.lease_epoch + 2
    with pytest.raises(LeaseLostError):
        queue.update("m9", WorkerMissionState.COMPLETED, worker_id="a", lease_epoch=a.lease_epoch, now=_at(2))


def test_stale_ack_after_reclaim_does_not_duplicate_completion(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m10", available_at=NOW)
    a = queue.claim_next(now=NOW, worker_id="a", lease_seconds=120)
    queue.recover_expired(now=_at(121))
    b = queue.claim_next(now=_at(122), worker_id="b", lease_seconds=120)
    with pytest.raises(LeaseLostError):
        queue.update("m10", WorkerMissionState.COMPLETED, worker_id="a", lease_epoch=a.lease_epoch, now=_at(123))
    done = queue.update("m10", WorkerMissionState.COMPLETED, worker_id="b", lease_epoch=b.lease_epoch, now=_at(123))
    assert done.state is WorkerMissionState.COMPLETED
    assert done.lease_owner is None
    with pytest.raises(LeaseLostError):
        queue.update("m10", WorkerMissionState.COMPLETED, worker_id="b", lease_epoch=b.lease_epoch, now=_at(124))


def test_worker_crash_after_inflight_side_effect_requires_recovery(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m11", available_at=NOW)
    mission = Mission.create("request", "objective", Plan.initial("objective"), mission_id="m11")
    mission.checkpoint = {"status": "in_flight"}
    store = SimpleNamespace(load=lambda _mid: mission, save=lambda m: m)
    runtime = SimpleNamespace(store=store)

    def explode(*_args, **_kwargs):
        raise RuntimeError("ambiguous external execution")

    worker = MissionWorker(queue, runtime_factory=lambda: runtime, worker_id="a", lease_seconds=120, resume_callback=explode)
    result = worker.run_once(now=NOW, max_slices=1)
    assert result.state is WorkerMissionState.WAITING_FOR_TOOL
    assert result.lease_owner is None
    assert result.last_error == "ambiguous in-flight execution requires reconciliation"
    assert mission.status is MissionStatus.RECOVERY_REQUIRED
    # duplicate delivery converges through recovery, never through silent completion
    queue.recover_after_restart()
    nxt = queue.claim_next(now=_at(122), worker_id="b", lease_seconds=120)
    assert nxt.attempts == 2
