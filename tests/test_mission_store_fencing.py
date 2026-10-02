from __future__ import annotations

import json
import sqlite3

import pytest

from agent.mission import Mission, MissionStore
from agent.mission_worker import (
    LeaseLostError,
    LeaseStatus,
    MissionQueue,
)
from agent.planning import Plan


BASE = "2026-01-01T00:00:00+00:00"


def _queue_claim(queue: MissionQueue, *, now: str, worker_id: str, lease_seconds: int = 30):
    item = queue.claim_next(now=now, worker_id=worker_id, lease_seconds=lease_seconds)
    assert item is not None and item.lease_claim is not None
    return item.lease_claim


def _mission_row(db_path, mission_id: str):
    with sqlite3.connect(db_path) as db:
        return db.execute(
            "SELECT payload, revision FROM missions WHERE mission_id=?",
            (mission_id,),
        ).fetchone()


def _ownership_row(db_path, mission_id: str):
    with sqlite3.connect(db_path) as db:
        return db.execute(
            "SELECT state, attempts, lease_owner, lease_expires_at, lease_id, "
            "lease_generation, lease_acquired_at, lease_heartbeat_at "
            "FROM mission_queue WHERE mission_id=?",
            (mission_id,),
        ).fetchone()


def test_stale_claim_cannot_save_mission_after_reclaim_and_current_claim_can(tmp_path):
    authority = tmp_path / "mission-runtime.sqlite3"
    store = MissionStore(authority)
    queue = MissionQueue(authority)
    mission = Mission.create("owner request", "objective", Plan.initial("objective"))
    store.save(mission)
    queue.enqueue(mission.mission_id, available_at=BASE)

    claim_a = _queue_claim(queue, now=BASE, worker_id="worker-a", lease_seconds=1)
    assert claim_a.generation == 1
    queue.recover_expired(now="2026-01-01T00:00:01+00:00")
    claim_b = _queue_claim(
        queue,
        now="2026-01-01T00:00:01+00:00",
        worker_id="worker-b",
    )
    assert claim_b.generation == 2

    stale_a = store.load(mission.mission_id)
    current_b = store.load(mission.mission_id)
    assert stale_a is not None and current_b is not None
    stale_a.error = "written by stale A"
    current_b.error = "written by current B"

    before_mission = _mission_row(authority, mission.mission_id)
    before_ownership = _ownership_row(authority, mission.mission_id)
    with pytest.raises(LeaseLostError) as rejected:
        store.save(stale_a, claim=claim_a, now="2026-01-01T00:00:01.500000+00:00")
    assert rejected.value.lease_status is LeaseStatus.FENCED_WORKER
    assert _mission_row(authority, mission.mission_id) == before_mission
    assert _ownership_row(authority, mission.mission_id) == before_ownership

    revision_before_b_save = current_b.revision
    store.save(current_b, claim=claim_b, now="2026-01-01T00:00:02+00:00")
    persisted = store.load(mission.mission_id)
    assert persisted is not None
    assert persisted.error == "written by current B"
    assert persisted.revision == revision_before_b_save + 1
    assert _ownership_row(authority, mission.mission_id) == before_ownership


def test_fenced_mission_save_rolls_back_on_sqlite_failure(tmp_path):
    authority = tmp_path / "mission-runtime.sqlite3"
    store = MissionStore(authority)
    queue = MissionQueue(authority)
    mission = Mission.create("owner request", "objective", Plan.initial("objective"))
    store.save(mission)
    queue.enqueue(mission.mission_id, available_at=BASE)
    claim = _queue_claim(queue, now=BASE, worker_id="worker-b")

    before_mission = _mission_row(authority, mission.mission_id)
    before_ownership = _ownership_row(authority, mission.mission_id)
    with sqlite3.connect(authority) as db:
        db.execute(
            "CREATE TRIGGER reject_mission_revision BEFORE UPDATE ON missions "
            "BEGIN SELECT RAISE(ABORT, 'injected sqlite rollback'); END"
        )

    updated = store.load(mission.mission_id)
    assert updated is not None
    updated.error = "must roll back"
    with pytest.raises(sqlite3.IntegrityError, match="injected sqlite rollback"):
        store.save(updated, claim=claim, now=BASE)

    assert _mission_row(authority, mission.mission_id) == before_mission
    assert _ownership_row(authority, mission.mission_id) == before_ownership
    persisted = store.load(mission.mission_id)
    assert persisted is not None and persisted.error == ""


def test_revision_schema_migration_is_additive_and_idempotent(tmp_path):
    db_path = tmp_path / "legacy-missions.sqlite3"
    mission = Mission.create("owner request", "objective", Plan.initial("objective"))
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE missions (mission_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
        )
        db.execute(
            "INSERT INTO missions(mission_id, payload) VALUES(?, ?)",
            (mission.mission_id, json.dumps(mission.to_dict(), ensure_ascii=False)),
        )

    first = MissionStore(db_path)
    loaded = first.load(mission.mission_id)
    assert loaded is not None and loaded.revision == 0
    assert "revision" not in loaded.to_dict()
    first.save(loaded)
    expected = _mission_row(db_path, mission.mission_id)

    second = MissionStore(db_path)
    restarted = second.load(mission.mission_id)
    assert restarted is not None and restarted.revision == 1
    assert _mission_row(db_path, mission.mission_id) == expected
    with sqlite3.connect(db_path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(missions)")}
    assert {"mission_id", "payload", "revision"} <= columns


def test_mission_worker_fences_runtime_save_after_deterministic_reclaim(tmp_path):
    from agent.mission_worker import MissionWorker

    authority = tmp_path / "mission-runtime.sqlite3"
    store = MissionStore(authority)
    queue = MissionQueue(authority)
    mission = Mission.create("owner request", "objective", Plan.initial("objective"))
    store.save(mission)
    queue.enqueue(mission.mission_id, available_at=BASE)

    class ReclaimDuringExecution:
        def __init__(self):
            self.store = MissionStore(authority)

        def run_to_completion(self, mission_id, *, max_slices=None, heartbeat=None):
            queue.recover_expired(now="2026-01-01T00:00:01+00:00")
            newer = queue.claim_next(
                now="2026-01-01T00:00:01+00:00",
                worker_id="worker-b",
                lease_seconds=30,
            )
            assert newer is not None and newer.lease_claim is not None
            assert newer.lease_claim.generation == 2
            stale = self.store.load(mission_id)
            assert stale is not None
            stale.error = "stale A from MissionWorker"
            self.store.save(stale)
            return stale

    worker = MissionWorker(
        queue,
        ReclaimDuringExecution,
        worker_id="worker-a",
        lease_seconds=1,
    )
    result = worker.run_once(now=BASE)

    persisted = store.load(mission.mission_id)
    assert persisted is not None and persisted.error == ""
    assert result is not None and result.lease_claim is not None
    assert result.lease_claim.worker_id == "worker-b"
    assert result.lease_claim.generation == 2


def test_mission_worker_refuses_split_mission_and_queue_authority(tmp_path):
    from agent.mission_worker import MissionWorker

    queue = MissionQueue(tmp_path / "queue.sqlite3")
    store = MissionStore(tmp_path / "missions.sqlite3")
    mission = Mission.create("owner request", "objective", Plan.initial("objective"))
    store.save(mission)
    queue.enqueue(mission.mission_id, available_at=BASE)
    executions = []

    class Runtime:
        def __init__(self):
            self.store = MissionStore(tmp_path / "missions.sqlite3")

        def run_to_completion(self, mission_id, *, max_slices=None, heartbeat=None):
            executions.append(mission_id)
            return self.store.load(mission_id)

    worker = MissionWorker(queue, Runtime, worker_id="worker-a")
    with pytest.raises(ValueError, match="share one SQLite authority file"):
        worker.run_once(now=BASE)

    assert executions == []
    persisted = store.load(mission.mission_id)
    assert persisted is not None and persisted.error == ""


def test_mission_worker_refuses_runtime_with_unfenced_store(tmp_path):
    from agent.mission_worker import MissionWorker

    authority = tmp_path / "mission-runtime.sqlite3"
    queue = MissionQueue(authority)
    mission = Mission.create("owner request", "objective", Plan.initial("objective"))
    MissionStore(authority).save(mission)
    queue.enqueue(mission.mission_id, available_at=BASE)
    executions = []

    class Runtime:
        store = object()

        def run_to_completion(self, mission_id, *, max_slices=None, heartbeat=None):
            executions.append(mission_id)
            return mission

    worker = MissionWorker(queue, Runtime, worker_id="worker-a")
    with pytest.raises(ValueError, match="fenced MissionStore"):
        worker.run_once(now=BASE)

    assert executions == []
