from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable
import json
import sqlite3
import uuid

from .mission import MissionStatus, MissionStore


class WorkerMissionState(str, Enum):
    QUEUED = "queued"
    PLANNING = "planning"
    WAITING_FOR_TOOL = "waiting_for_tool"
    EXECUTING = "executing"
    WAITING_FOR_MODEL = "waiting_for_model"
    PAUSED = "paused"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    PARTIAL_SUCCESS = "partial_success"
    NEEDS_INPUT = "needs_input"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SLEEPING = "sleeping"
    SCHEDULED = "scheduled"


class LeaseStatus(str, Enum):
    LEASE_VALID = "LEASE_VALID"
    LEASE_EXPIRED = "LEASE_EXPIRED"
    LEASE_LOST = "LEASE_LOST"
    LEASE_REVOKED = "LEASE_REVOKED"
    STALE_WORKER = "STALE_WORKER"
    FENCED_WORKER = "FENCED_WORKER"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


class LeaseLostError(PermissionError):
    """Raised when a queue operation is not authorized by its current lease."""

    def __init__(self, message: str, *, lease_status: LeaseStatus = LeaseStatus.LEASE_LOST):
        super().__init__(message)
        self.lease_status = lease_status


DEFAULT_WORKER_LEASE_SECONDS = 120
_TERMINAL_QUEUE_STATES = frozenset({
    WorkerMissionState.COMPLETED.value,
    WorkerMissionState.FAILED.value,
    WorkerMissionState.CANCELLED.value,
    WorkerMissionState.NEEDS_INPUT.value,
    WorkerMissionState.PARTIAL_SUCCESS.value,
})


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _current_timestamp(value: str | None) -> str:
    return _format_timestamp(_parse_timestamp(value)) if value is not None else datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class LeaseClaimSnapshot:
    """Immutable identity and expiry snapshot for one queue claim."""

    mission_id: str
    worker_id: str
    lease_id: str
    generation: int
    acquired_at: str
    expires_at: str


@dataclass(frozen=True)
class QueueItem:
    mission_id: str
    state: WorkerMissionState
    attempts: int
    available_at: str
    claimed_at: str | None = None
    last_error: str = ""
    lease_owner: str | None = None
    lease_expires_at: str | None = None
    lease_claim: LeaseClaimSnapshot | None = None

    def public_dict(self) -> dict[str, Any]:
        """Preserve the pre-M1 MissionService payload without exposing fencing tokens."""
        return {
            "mission_id": self.mission_id,
            "state": self.state,
            "attempts": self.attempts,
            "available_at": self.available_at,
            "claimed_at": self.claimed_at,
            "last_error": self.last_error,
            "lease_owner": self.lease_owner,
            "lease_expires_at": self.lease_expires_at,
        }


class MissionQueue:
    """Durable queue metadata; mission truth remains in MissionStore."""

    _SELECT_ITEM = (
        "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,"
        "lease_owner,lease_expires_at,lease_id,lease_generation,"
        "lease_acquired_at,lease_heartbeat_at FROM mission_queue WHERE mission_id=?"
    )

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS mission_queue ("
                "mission_id TEXT PRIMARY KEY, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, "
                "available_at TEXT NOT NULL, claimed_at TEXT, last_error TEXT NOT NULL DEFAULT '')"
            )
            existing = {row[1] for row in db.execute("PRAGMA table_info(mission_queue)")}
            migrations = (
                ("lease_owner", "TEXT"),
                ("lease_expires_at", "TEXT"),
                ("lease_id", "TEXT"),
                ("lease_generation", "INTEGER NOT NULL DEFAULT 0"),
                ("lease_acquired_at", "TEXT"),
                ("lease_heartbeat_at", "TEXT"),
            )
            for column, definition in migrations:
                if column not in existing:
                    db.execute(f"ALTER TABLE mission_queue ADD COLUMN {column} {definition}")

    @staticmethod
    def _item_from_row(row: tuple[Any, ...] | None) -> QueueItem | None:
        if row is None:
            return None
        lease_claim = None
        if row[6] is not None and row[8] is not None and row[7] is not None and row[10] is not None:
            lease_claim = LeaseClaimSnapshot(
                mission_id=row[0],
                worker_id=row[6],
                lease_id=row[8],
                generation=int(row[9]),
                acquired_at=row[10],
                expires_at=row[7],
            )
        return QueueItem(
            row[0], WorkerMissionState(row[1]), row[2], row[3], row[4], row[5],
            row[6], row[7], lease_claim,
        )

    @classmethod
    def _get_item(cls, db: sqlite3.Connection, mission_id: str) -> QueueItem:
        item = cls._item_from_row(db.execute(cls._SELECT_ITEM, (mission_id,)).fetchone())
        if item is None:
            raise KeyError("unknown queued mission")
        return item

    def enqueue(self, mission_id: str, *, available_at: str | None = None, state: WorkerMissionState = WorkerMissionState.QUEUED) -> QueueItem:
        if not mission_id.strip():
            raise ValueError("mission_id required")
        available = available_at or datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO mission_queue(mission_id,state,attempts,available_at,claimed_at,last_error) "
                "VALUES(?,?,?,?,NULL,'') ON CONFLICT(mission_id) DO UPDATE SET "
                "state=excluded.state,available_at=excluded.available_at,claimed_at=NULL,last_error='',"
                "lease_owner=NULL,lease_expires_at=NULL,lease_id=NULL,lease_acquired_at=NULL,lease_heartbeat_at=NULL",
                (mission_id, state.value, 0, available),
            )
            return self._get_item(db, mission_id)

    def get(self, mission_id: str) -> QueueItem:
        with sqlite3.connect(self.db_path) as db:
            return self._get_item(db, mission_id)

    def claim_next(self, *, now: str | None = None, worker_id: str = "worker", lease_seconds: int = 60) -> QueueItem | None:
        if not worker_id.strip():
            raise ValueError("worker_id required")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        claimed_at = now or datetime.now(timezone.utc).isoformat()
        moment = _current_timestamp(claimed_at)
        expiry = _format_timestamp(_parse_timestamp(moment) + timedelta(seconds=lease_seconds))
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT mission_id,available_at FROM mission_queue WHERE state IN (?, ?, ?)",
                (WorkerMissionState.QUEUED.value, WorkerMissionState.SCHEDULED.value,
                 WorkerMissionState.SLEEPING.value),
            ).fetchall()
            due_rows = [row for row in rows if _parse_timestamp(row[1]) <= _parse_timestamp(moment)]
            if not due_rows:
                return None
            mission_id, _ = min(due_rows, key=lambda row: (_parse_timestamp(row[1]), row[0]))
            lease_id = uuid.uuid4().hex
            updated = db.execute(
                "UPDATE mission_queue SET state=?,attempts=attempts+1,claimed_at=?,lease_owner=?,"
                "lease_expires_at=?,lease_id=?,lease_generation=COALESCE(lease_generation,0)+1,"
                "lease_acquired_at=?,lease_heartbeat_at=? WHERE mission_id=? AND state IN (?, ?, ?)",
                (WorkerMissionState.EXECUTING.value, claimed_at, worker_id, expiry, lease_id,
                 moment, moment, mission_id, WorkerMissionState.QUEUED.value,
                 WorkerMissionState.SCHEDULED.value, WorkerMissionState.SLEEPING.value),
            )
            if updated.rowcount != 1:
                return None
            return self._get_item(db, mission_id)

    @staticmethod
    def _claim_status(row: tuple[Any, ...] | None, claim: LeaseClaimSnapshot, now: str) -> LeaseStatus:
        if row is None:
            return LeaseStatus.LEASE_LOST
        current_generation = int(row[9] or 0)
        if claim.generation < current_generation:
            return LeaseStatus.FENCED_WORKER
        if claim.generation > current_generation:
            return LeaseStatus.LEASE_LOST
        if _parse_timestamp(claim.expires_at) <= _parse_timestamp(now):
            return LeaseStatus.LEASE_EXPIRED
        current_owner, current_expiry, current_lease_id, acquired_at = row[6], row[7], row[8], row[10]
        if current_lease_id is None or current_owner is None:
            return LeaseStatus.LEASE_REVOKED
        if current_lease_id != claim.lease_id or acquired_at != claim.acquired_at:
            return LeaseStatus.FENCED_WORKER
        if current_owner != claim.worker_id:
            return LeaseStatus.STALE_WORKER
        if current_expiry != claim.expires_at:
            return LeaseStatus.LEASE_LOST
        if _parse_timestamp(current_expiry) <= _parse_timestamp(now):
            return LeaseStatus.LEASE_EXPIRED
        return LeaseStatus.LEASE_VALID

    @classmethod
    def _require_current_claim(cls, db: sqlite3.Connection, claim: LeaseClaimSnapshot, now: str) -> None:
        if not isinstance(claim, LeaseClaimSnapshot):
            raise LeaseLostError("a lease claim snapshot is required", lease_status=LeaseStatus.LEASE_LOST)
        row = db.execute(cls._SELECT_ITEM, (claim.mission_id,)).fetchone()
        status = cls._claim_status(row, claim, now)
        if status is not LeaseStatus.LEASE_VALID:
            raise LeaseLostError(f"worker lease is not current: {status.value}", lease_status=status)

    def lease_status(self, claim: LeaseClaimSnapshot, *, now: str | None = None) -> LeaseStatus:
        """Return the formal status of a snapshot without mutating queue state."""
        moment = _current_timestamp(now)
        with sqlite3.connect(self.db_path) as db:
            row = db.execute(self._SELECT_ITEM, (claim.mission_id,)).fetchone()
        return self._claim_status(row, claim, moment)

    def update(self, mission_id: str, state: WorkerMissionState, *, claim: LeaseClaimSnapshot, available_at: str | None = None, error: str = "", now: str | None = None) -> QueueItem:
        if claim.mission_id != mission_id:
            raise LeaseLostError("claim belongs to another mission", lease_status=LeaseStatus.LEASE_LOST)
        moment = _current_timestamp(now)
        terminal = state.value in _TERMINAL_QUEUE_STATES
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current_claim(db, claim, moment)
            if terminal:
                updated = db.execute(
                    "UPDATE mission_queue SET state=?,available_at=COALESCE(?,available_at),last_error=?,"
                    "claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL,lease_id=NULL,"
                    "lease_acquired_at=NULL,lease_heartbeat_at=NULL WHERE mission_id=? AND lease_id=? "
                    "AND lease_generation=? AND lease_owner=? AND lease_acquired_at=? AND lease_expires_at=?",
                    (state.value, available_at, error, mission_id, claim.lease_id, claim.generation,
                     claim.worker_id, claim.acquired_at, claim.expires_at),
                )
            else:
                updated = db.execute(
                    "UPDATE mission_queue SET state=?,available_at=COALESCE(?,available_at),last_error=? "
                    "WHERE mission_id=? AND lease_id=? AND lease_generation=? AND lease_owner=? "
                    "AND lease_acquired_at=? AND lease_expires_at=?",
                    (state.value, available_at, error, mission_id, claim.lease_id, claim.generation,
                     claim.worker_id, claim.acquired_at, claim.expires_at),
                )
            if updated.rowcount != 1:
                raise LeaseLostError("worker lease changed during queue update", lease_status=LeaseStatus.LEASE_LOST)
            return self._get_item(db, mission_id)

    def acknowledge(self, claim: LeaseClaimSnapshot, state: WorkerMissionState, *, error: str = "", now: str | None = None) -> QueueItem:
        """Apply a terminal queue acknowledgement only for the current live claim."""
        if state.value not in _TERMINAL_QUEUE_STATES:
            raise ValueError("acknowledgement requires a terminal queue state")
        return self.update(claim.mission_id, state, claim=claim, error=error, now=now)

    def release(self, claim: LeaseClaimSnapshot, *, now: str | None = None, available_at: str | None = None, error: str = "") -> QueueItem:
        """Requeue a live claim without resetting its monotonic generation."""
        moment = _current_timestamp(now)
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current_claim(db, claim, moment)
            updated = db.execute(
                "UPDATE mission_queue SET state=?,available_at=COALESCE(?,available_at),last_error=?,"
                "claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL,lease_id=NULL,"
                "lease_acquired_at=NULL,lease_heartbeat_at=NULL WHERE mission_id=? AND lease_id=? "
                "AND lease_generation=? AND lease_owner=? AND lease_acquired_at=? AND lease_expires_at=?",
                (WorkerMissionState.QUEUED.value, available_at, error, claim.mission_id,
                 claim.lease_id, claim.generation, claim.worker_id, claim.acquired_at, claim.expires_at),
            )
            if updated.rowcount != 1:
                raise LeaseLostError("worker lease changed during release", lease_status=LeaseStatus.LEASE_LOST)
            return self._get_item(db, claim.mission_id)

    def heartbeat(self, claim: LeaseClaimSnapshot, *, now: str | None = None, lease_seconds: int = 60) -> QueueItem:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        moment = _current_timestamp(now)
        expiry = _format_timestamp(_parse_timestamp(moment) + timedelta(seconds=lease_seconds))
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current_claim(db, claim, moment)
            updated = db.execute(
                "UPDATE mission_queue SET lease_expires_at=?,lease_heartbeat_at=? WHERE mission_id=? "
                "AND lease_id=? AND lease_generation=? AND lease_owner=? AND lease_acquired_at=? "
                "AND lease_expires_at=?",
                (expiry, moment, claim.mission_id, claim.lease_id, claim.generation,
                 claim.worker_id, claim.acquired_at, claim.expires_at),
            )
            if updated.rowcount != 1:
                raise LeaseLostError("worker lease changed during heartbeat", lease_status=LeaseStatus.LEASE_LOST)
            return self._get_item(db, claim.mission_id)

    def recover_expired(self, *, now: str | None = None) -> list[QueueItem]:
        moment = _current_timestamp(now)
        expired_ids: list[str] = []
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT mission_id,lease_expires_at FROM mission_queue WHERE state=? "
                "AND lease_expires_at IS NOT NULL",
                (WorkerMissionState.EXECUTING.value,),
            ).fetchall()
            for mission_id, expires_at in rows:
                if _parse_timestamp(expires_at) <= _parse_timestamp(moment):
                    db.execute(
                        "UPDATE mission_queue SET state=?,claimed_at=NULL,lease_owner=NULL,"
                        "lease_expires_at=NULL,lease_id=NULL,lease_acquired_at=NULL,"
                        "lease_heartbeat_at=NULL,last_error=? WHERE mission_id=? AND state=? AND lease_expires_at=?",
                        (WorkerMissionState.QUEUED.value, "worker lease expired", mission_id,
                         WorkerMissionState.EXECUTING.value, expires_at),
                    )
                    expired_ids.append(mission_id)
        return [self.get(mission_id) for mission_id in expired_ids]

    def recover_after_restart(self) -> list[QueueItem]:
        active_states = (
            WorkerMissionState.EXECUTING.value,
            WorkerMissionState.PLANNING.value,
            WorkerMissionState.WAITING_FOR_TOOL.value,
            WorkerMissionState.WAITING_FOR_MODEL.value,
        )
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT mission_id FROM mission_queue WHERE state IN (?, ?, ?, ?)", active_states
            ).fetchall()
            db.execute(
                "UPDATE mission_queue SET state=?,claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL,"
                "lease_id=NULL,lease_acquired_at=NULL,lease_heartbeat_at=NULL,last_error=? "
                "WHERE state IN (?, ?, ?, ?)",
                (WorkerMissionState.QUEUED.value, "worker restart recovery", *active_states),
            )
        return [self.get(row[0]) for row in rows]

    def list(self, states: tuple[WorkerMissionState, ...] | None = None) -> list[QueueItem]:
        query = "SELECT mission_id FROM mission_queue"
        args: tuple[str, ...] = ()
        if states:
            query += " WHERE state IN (" + ",".join("?" for _ in states) + ")"
            args = tuple(item.value for item in states)
        query += " ORDER BY available_at,mission_id"
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute(query, args).fetchall()
        return [self.get(row[0]) for row in rows]


class MissionWorker:
    """Single-step worker adapter; a supervisor may call run_once repeatedly."""

    def __init__(self, queue: MissionQueue, runtime_factory: Callable[[], Any], *, worker_id: str = "worker", lease_seconds: int = DEFAULT_WORKER_LEASE_SECONDS):
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self.queue = queue
        self.runtime_factory = runtime_factory
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds

    def enqueue(self, mission_id: str) -> QueueItem:
        return self.queue.enqueue(mission_id)

    def recover_after_restart(self) -> list[QueueItem]:
        return self.queue.recover_after_restart()

    def run_once(self, *, now: str | None = None, max_slices: int | None = None) -> QueueItem | None:
        item = self.queue.claim_next(now=now, worker_id=self.worker_id, lease_seconds=self.lease_seconds)
        if item is None:
            return None
        claim = item.lease_claim
        if claim is None:
            raise LeaseLostError("claim returned without a lease snapshot", lease_status=LeaseStatus.LEASE_LOST)
        runtime = self.runtime_factory()
        fenced_store = None
        runtime_store = getattr(runtime, "store", None)
        if runtime_store is not None:
            if not isinstance(runtime_store, MissionStore):
                raise ValueError("worker runtime must provide a fenced MissionStore")
            if Path(runtime_store.db_path).resolve() != Path(self.queue.db_path).resolve():
                raise ValueError("fenced mission writes require mission and queue to share one SQLite authority file")
            fenced_store = runtime_store.with_claim(claim, now=now)
            runtime.store = fenced_store

        def heartbeat() -> None:
            nonlocal claim
            renewed = self.queue.heartbeat(claim, now=now, lease_seconds=self.lease_seconds)
            if renewed.lease_claim is None:
                raise LeaseLostError("heartbeat returned without a lease snapshot", lease_status=LeaseStatus.LEASE_LOST)
            claim = renewed.lease_claim
            if fenced_store is not None:
                fenced_store.set_claim(claim)

        try:
            try:
                mission = runtime.run_to_completion(item.mission_id, max_slices=max_slices, heartbeat=heartbeat)
            except TypeError as exc:
                if "heartbeat" not in str(exc):
                    raise
                mission = runtime.run_to_completion(item.mission_id, max_slices=max_slices)
        except LeaseLostError:
            # A lease may be reclaimed while this worker is between slices. The
            # stale worker must not overwrite the queue outcome or report FAILED.
            return self.queue.get(item.mission_id)
        except Exception as exc:
            try:
                return self.queue.update(
                    item.mission_id, WorkerMissionState.FAILED, error=f"{type(exc).__name__}: {exc}", claim=claim, now=now
                )
            except LeaseLostError:
                return self.queue.get(item.mission_id)
        state = {
            MissionStatus.GOAL_COMPLETED: WorkerMissionState.COMPLETED,
            MissionStatus.OWNER_INPUT_REQUIRED: WorkerMissionState.NEEDS_INPUT,
            MissionStatus.AUTHORIZATION_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.RECOVERY_REQUIRED: WorkerMissionState.WAITING_FOR_TOOL,
            MissionStatus.CANCELLED: WorkerMissionState.CANCELLED,
            MissionStatus.FAILED_RETRY_EXHAUSTED: WorkerMissionState.FAILED,
            MissionStatus.SCOPE_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.SAFETY_BLOCKED: WorkerMissionState.FAILED,
        }.get(mission.status, WorkerMissionState.PARTIAL_SUCCESS if mission.evidence else WorkerMissionState.FAILED)
        try:
            if state.value in _TERMINAL_QUEUE_STATES:
                return self.queue.acknowledge(claim, state, error=mission.error, now=now)
            return self.queue.update(item.mission_id, state, error=mission.error, claim=claim, now=now)
        except LeaseLostError:
            # A long-running handler may finish after another worker reclaimed
            # the lease; never let the stale result overwrite that worker.
            return self.queue.get(item.mission_id)


@dataclass(frozen=True)
class MissionSchedule:
    schedule_id: str
    mission_id: str
    next_run_at: str
    interval_seconds: int | None = None
    retry_limit: int = 0
    retries: int = 0
    state: WorkerMissionState = WorkerMissionState.SCHEDULED


class MissionScheduler:
    """Persistent schedule records that enqueue missions; no hidden execution thread."""

    def __init__(self, db_path: str | Path, queue: MissionQueue):
        self.db_path = str(db_path)
        self.queue = queue
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS mission_schedules (schedule_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, next_run_at TEXT NOT NULL, interval_seconds INTEGER, retry_limit INTEGER NOT NULL, retries INTEGER NOT NULL, state TEXT NOT NULL)")

    def schedule(self, mission_id: str, *, run_at: str, interval_seconds: int | None = None, retry_limit: int = 0, schedule_id: str | None = None) -> MissionSchedule:
        if interval_seconds is not None and interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        item = MissionSchedule(schedule_id or uuid.uuid4().hex, mission_id, run_at, interval_seconds, retry_limit)
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT INTO mission_schedules VALUES(?,?,?,?,?,?,?)", (item.schedule_id, item.mission_id, item.next_run_at, item.interval_seconds, item.retry_limit, item.retries, item.state.value))
        return item

    def get(self, schedule_id: str) -> MissionSchedule:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT schedule_id,mission_id,next_run_at,interval_seconds,retry_limit,retries,state FROM mission_schedules WHERE schedule_id=?", (schedule_id,)).fetchone()
        if row is None:
            raise KeyError("unknown schedule")
        return MissionSchedule(row[0], row[1], row[2], row[3], row[4], row[5], WorkerMissionState(row[6]))

    def dispatch_due(self, *, now: str) -> list[MissionSchedule]:
        current = datetime.fromisoformat(now.replace("Z", "+00:00"))
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT schedule_id FROM mission_schedules WHERE state=? AND next_run_at<=? ORDER BY next_run_at,schedule_id", (WorkerMissionState.SCHEDULED.value, now)).fetchall()
        dispatched = []
        for (schedule_id,) in rows:
            item = self.get(schedule_id)
            self.queue.enqueue(item.mission_id, available_at=now, state=WorkerMissionState.QUEUED)
            if item.interval_seconds:
                next_run = (current + timedelta(seconds=item.interval_seconds)).isoformat()
                with sqlite3.connect(self.db_path) as db:
                    db.execute("UPDATE mission_schedules SET next_run_at=?,retries=0 WHERE schedule_id=?", (next_run, schedule_id))
            else:
                with sqlite3.connect(self.db_path) as db:
                    db.execute("UPDATE mission_schedules SET state=? WHERE schedule_id=?", (WorkerMissionState.COMPLETED.value, schedule_id))
            dispatched.append(self.get(schedule_id))
        return dispatched

    def mark_missed(self, schedule_id: str, *, now: str) -> MissionSchedule:
        item = self.get(schedule_id)
        if datetime.fromisoformat(now.replace("Z", "+00:00")) <= datetime.fromisoformat(item.next_run_at.replace("Z", "+00:00")):
            return item
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE mission_schedules SET state=? WHERE schedule_id=?", (WorkerMissionState.SLEEPING.value, schedule_id))
        return self.get(schedule_id)


__all__ = ["LeaseClaimSnapshot", "LeaseLostError", "LeaseStatus", "MissionQueue", "MissionSchedule", "MissionScheduler", "MissionWorker", "QueueItem", "WorkerMissionState"]
