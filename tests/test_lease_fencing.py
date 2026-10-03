import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from agent.mission import MissionStatus
from agent.mission_worker import LeaseLostError, MissionQueue, MissionScheduler, MissionWorker, WorkerMissionState


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
    assert datetime.fromisoformat(renewed.lease_expires_at) == datetime.fromisoformat(_at(90))

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
    runtime_created = []

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            assert mission_id == "frozen-clock"
            heartbeat()
            pytest.fail("an expired lease heartbeat must be rejected")

    def runtime_factory():
        runtime_created.append(True)
        return Runtime()

    result = MissionWorker(queue, runtime_factory, worker_id="worker-a", lease_seconds=60).run_once(now=claim_time)
    assert result.state is WorkerMissionState.EXECUTING
    assert result.lease_owner == "worker-a"
    assert datetime.fromisoformat(result.lease_expires_at) == datetime.fromisoformat(expected_expiry)
    assert runtime_created == []


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
            replacement_identity = queue.register_worker("worker-a")
            replacement = queue.claim_next(
                now=takeover_time,
                worker_id="worker-a",
                worker_instance_id=replacement_identity.worker_instance_id,
                runtime_generation=replacement_identity.runtime_generation,
                lease_seconds=60,
            )
            assert replacement is not None
            assert replacement.lease_epoch > 1
            return completed

    result = MissionWorker(queue, lambda: Runtime(), worker_id="worker-a", lease_seconds=1).run_once(now=claim_time)
    assert result.state is WorkerMissionState.EXECUTING
    assert result.lease_owner == "worker-a"
    assert result.lease_epoch > 1
    assert result.last_error == "worker lease expired"



def test_queue_eligibility_normalizes_offset_timestamps(tmp_path):
    queue = MissionQueue(tmp_path / "offset-eligibility.sqlite3")
    queue.enqueue("offset-due", available_at="2026-01-01T01:00:00+01:00")

    claim = queue.claim_next(
        now="2026-01-01T00:30:00+00:00",
        worker_id="worker-a",
        lease_seconds=60,
    )

    assert claim is not None
    assert claim.available_at == "2026-01-01T00:00:00.000000+00:00"
    assert claim.lease_expires_at == "2026-01-01T00:31:00.000000+00:00"


def test_expired_lease_cannot_be_renewed_across_offset_formats(tmp_path):
    queue = MissionQueue(tmp_path / "offset-expiry.sqlite3")
    queue.enqueue("offset-expiry", available_at=BASE)
    claim = _claim(
        queue,
        now="2026-01-01T01:00:00+01:00",
        worker_id="worker-a",
        lease_seconds=60,
    )
    assert claim.lease_expires_at == "2026-01-01T00:01:00.000000+00:00"

    with pytest.raises(LeaseLostError):
        queue.heartbeat(
            "offset-expiry",
            worker_id="worker-a",
            lease_epoch=claim.lease_epoch,
            now="2026-01-01T00:02:00+00:00",
        )

    assert queue.get("offset-expiry") == claim


def test_legacy_offset_lease_rows_migrate_before_expiry_comparison(tmp_path):
    db_path = tmp_path / "legacy-offset-queue.sqlite3"
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE mission_queue (mission_id TEXT PRIMARY KEY, state TEXT NOT NULL, "
            "attempts INTEGER NOT NULL DEFAULT 0, available_at TEXT NOT NULL, claimed_at TEXT, "
            "last_error TEXT NOT NULL DEFAULT '', lease_owner TEXT, lease_expires_at TEXT)"
        )
        db.execute(
            "INSERT INTO mission_queue(mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                "legacy-offset",
                WorkerMissionState.EXECUTING.value,
                1,
                "2026-01-01T01:00:00+01:00",
                "2026-01-01T01:00:00+01:00",
                "",
                "worker-a",
                "2026-01-01T01:01:00+01:00",
            ),
        )

    queue = MissionQueue(db_path)
    before = queue.get("legacy-offset")
    assert before.available_at == "2026-01-01T00:00:00.000000+00:00"
    assert before.claimed_at == "2026-01-01T00:00:00.000000+00:00"
    assert before.lease_expires_at == "2026-01-01T00:01:00.000000+00:00"

    recovered = queue.recover_expired(now="2026-01-01T00:02:00+00:00")
    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.QUEUED
    assert recovered[0].lease_epoch == before.lease_epoch + 1


def test_naive_queue_timestamps_fail_before_mutation(tmp_path):
    queue = MissionQueue(tmp_path / "naive-time.sqlite3")
    queue.enqueue("safe", available_at=BASE)

    with pytest.raises(ValueError, match="timezone"):
        queue.claim_next(now="2026-01-01T00:00:00", worker_id="worker-a")
    with pytest.raises(ValueError, match="timezone"):
        queue.enqueue("naive", available_at="2026-01-01T00:00:00")

    assert queue.get("safe").state is WorkerMissionState.QUEUED
    assert queue.get("safe").lease_epoch == 0
    with pytest.raises(KeyError):
        queue.get("naive")


def test_claim_returns_its_transaction_snapshot_without_post_commit_refetch(tmp_path, monkeypatch):
    queue = MissionQueue(tmp_path / "claim-snapshot.sqlite3")
    queue.enqueue("snapshot", available_at=BASE)

    def unexpected_refetch(_mission_id):
        pytest.fail("claim_next must return the claim snapshot captured inside its write transaction")

    monkeypatch.setattr(queue, "get", unexpected_refetch)
    claim = queue.claim_next(now=BASE, worker_id="worker-a", lease_seconds=60)

    assert claim is not None
    assert claim.lease_owner == "worker-a"
    assert claim.lease_epoch == 1


def test_update_without_owner_and_epoch_cannot_mutate_a_live_claim(tmp_path):
    queue = MissionQueue(tmp_path / "unfenced-update.sqlite3")
    queue.enqueue("unfenced", available_at=BASE)
    claim = _claim(queue, now=BASE, worker_id="worker-a")

    with pytest.raises(LeaseLostError, match="owner"):
        queue.update("unfenced", WorkerMissionState.COMPLETED)

    assert queue.get("unfenced") == claim


def test_worker_does_not_construct_runtime_when_initial_lease_validation_fails(tmp_path, monkeypatch):
    queue = MissionQueue(tmp_path / "worker-preflight.sqlite3")
    queue.enqueue("preflight", available_at=datetime.now(timezone.utc).isoformat())
    runtime_created = []

    def lose_lease(*_args, **_kwargs):
        raise LeaseLostError("lease was superseded before runtime start")

    monkeypatch.setattr(queue, "heartbeat", lose_lease)
    worker = MissionWorker(
        queue,
        lambda: runtime_created.append(True),
        worker_id="worker-a",
        lease_seconds=60,
    )

    result = worker.run_once()

    assert result is not None
    assert result.state is WorkerMissionState.WAITING_FOR_TOOL
    assert result.lease_owner is None
    assert result.claim_phase == "NONE"
    assert runtime_created == []


def test_scheduler_due_time_compares_equivalent_offset_instants(tmp_path):
    queue = MissionQueue(tmp_path / "schedule-offset-queue.sqlite3")
    scheduler = MissionScheduler(tmp_path / "schedule-offset.sqlite3", queue)
    scheduler.schedule("offset-schedule", run_at="2026-01-01T01:00:00+01:00", schedule_id="offset")

    dispatched = scheduler.dispatch_due(now="2026-01-01T00:30:00+00:00")

    assert [item.schedule_id for item in dispatched] == ["offset"]
    assert queue.get("offset-schedule").state is WorkerMissionState.QUEUED


def test_scheduler_migrates_legacy_offset_due_times(tmp_path):
    schedule_path = tmp_path / "legacy-schedule.sqlite3"
    with sqlite3.connect(schedule_path) as db:
        db.execute(
            "CREATE TABLE mission_schedules (schedule_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, "
            "next_run_at TEXT NOT NULL, interval_seconds INTEGER, retry_limit INTEGER NOT NULL, "
            "retries INTEGER NOT NULL, state TEXT NOT NULL)"
        )
        db.execute(
            "INSERT INTO mission_schedules VALUES(?,?,?,?,?,?,?)",
            (
                "legacy-offset",
                "legacy-scheduled-mission",
                "2026-01-01T01:00:00+01:00",
                None,
                0,
                0,
                WorkerMissionState.SCHEDULED.value,
            ),
        )

    queue = MissionQueue(tmp_path / "legacy-schedule-queue.sqlite3")
    scheduler = MissionScheduler(schedule_path, queue)
    assert scheduler.get("legacy-offset").next_run_at == "2026-01-01T00:00:00.000000+00:00"

    dispatched = scheduler.dispatch_due(now="2026-01-01T00:30:00+00:00")

    assert [item.schedule_id for item in dispatched] == ["legacy-offset"]
    assert queue.get("legacy-scheduled-mission").state is WorkerMissionState.QUEUED
