from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable
import json
import sqlite3
import uuid

from .mission import MissionStatus


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


class LeaseLostError(PermissionError):
    """Raised when a worker no longer owns the current live queue lease."""


DEFAULT_WORKER_LEASE_SECONDS = 120


def _utc_datetime(value: str | None, *, field_name: str) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp with timezone")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp with timezone") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


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
    lease_epoch: int = 0


class MissionQueue:
    """Durable queue metadata; mission truth remains in MissionStore."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS mission_queue (mission_id TEXT PRIMARY KEY, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, available_at TEXT NOT NULL, claimed_at TEXT, last_error TEXT NOT NULL DEFAULT '')")
            columns = {row[1] for row in db.execute("PRAGMA table_info(mission_queue)")}
            for column, definition in (
                ("lease_owner", "TEXT"),
                ("lease_expires_at", "TEXT"),
                ("lease_epoch", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if column not in columns:
                    db.execute(f"ALTER TABLE mission_queue ADD COLUMN {column} {definition}")
                    columns.add(column)
            for mission_id, available_at, claimed_at, lease_expires_at in db.execute(
                "SELECT mission_id,available_at,claimed_at,lease_expires_at FROM mission_queue"
            ).fetchall():
                normalized_available = _utc_text(_utc_datetime(available_at, field_name="available_at"))
                normalized_claimed = _utc_text(_utc_datetime(claimed_at, field_name="claimed_at")) if claimed_at is not None else None
                normalized_expiry = _utc_text(_utc_datetime(lease_expires_at, field_name="lease_expires_at")) if lease_expires_at is not None else None
                if (available_at, claimed_at, lease_expires_at) != (normalized_available, normalized_claimed, normalized_expiry):
                    db.execute(
                        "UPDATE mission_queue SET available_at=?,claimed_at=?,lease_expires_at=? WHERE mission_id=?",
                        (normalized_available, normalized_claimed, normalized_expiry, mission_id),
                    )

    @staticmethod
    def _item_from_row(row: Any) -> QueueItem:
        return QueueItem(
            row[0],
            WorkerMissionState(row[1]),
            int(row[2]),
            row[3],
            row[4],
            row[5],
            row[6],
            row[7],
            int(row[8]),
        )

    def enqueue(self, mission_id: str, *, available_at: str | None = None, state: WorkerMissionState = WorkerMissionState.QUEUED) -> QueueItem:
        if not mission_id.strip():
            raise ValueError("mission_id required")
        available = _utc_text(_utc_datetime(available_at, field_name="available_at"))
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO mission_queue(mission_id,state,attempts,available_at,claimed_at,last_error) VALUES(?,?,?,?,NULL,'') ON CONFLICT(mission_id) DO UPDATE SET state=excluded.state,available_at=excluded.available_at,claimed_at=NULL,last_error='',lease_owner=NULL,lease_expires_at=NULL WHERE mission_queue.state != ?", (mission_id, state.value, 0, available, WorkerMissionState.EXECUTING.value))
            row = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch FROM mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError("unknown queued mission")
            item = self._item_from_row(row)
        return item

    def get(self, mission_id: str) -> QueueItem:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch FROM mission_queue WHERE mission_id=?", (mission_id,)).fetchone()
        if row is None:
            raise KeyError("unknown queued mission")
        return self._item_from_row(row)

    def claim_next(self, *, now: str | None = None, worker_id: str = "worker", lease_seconds: int = 60) -> QueueItem | None:
        if not worker_id.strip():
            raise ValueError("worker_id required")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        moment_dt = _utc_datetime(now, field_name="now")
        moment = _utc_text(moment_dt)
        expiry = _utc_text(moment_dt + timedelta(seconds=lease_seconds))
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT mission_id FROM mission_queue WHERE state IN (?, ?, ?) AND available_at <= ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?) ORDER BY available_at,mission_id LIMIT 1", (WorkerMissionState.QUEUED.value, WorkerMissionState.SCHEDULED.value, WorkerMissionState.SLEEPING.value, moment, moment)).fetchone()
            if row is None:
                return None
            mission_id = row[0]
            updated = db.execute(
                "UPDATE mission_queue SET state=?, attempts=attempts+1, claimed_at=?, lease_owner=?, lease_expires_at=?, lease_epoch=lease_epoch+1 "
                "WHERE mission_id=? AND state IN (?, ?, ?) AND available_at <= ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?)",
                (
                    WorkerMissionState.EXECUTING.value,
                    moment,
                    worker_id,
                    expiry,
                    mission_id,
                    WorkerMissionState.QUEUED.value,
                    WorkerMissionState.SCHEDULED.value,
                    WorkerMissionState.SLEEPING.value,
                    moment,
                    moment,
                ),
            )
            if updated.rowcount != 1:
                raise LeaseLostError("queue claim changed before commit")
            claimed = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch FROM mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if claimed is None:
                raise KeyError("unknown queued mission")
            return self._item_from_row(claimed)

    def update(
        self,
        mission_id: str,
        state: WorkerMissionState,
        *,
        available_at: str | None = None,
        error: str = "",
        worker_id: str | None = None,
        lease_epoch: int | None = None,
        now: str | None = None,
    ) -> QueueItem:
        if not isinstance(worker_id, str) or not worker_id.strip():
            raise LeaseLostError("worker mutation requires a lease owner")
        if lease_epoch is None:
            raise LeaseLostError("worker mutation requires a lease epoch")
        moment = _utc_text(_utc_datetime(now, field_name="now"))
        next_available = _utc_text(_utc_datetime(available_at, field_name="available_at")) if available_at is not None else None
        terminal = state.value in {"completed", "failed", "cancelled", "needs_input", "partial_success"}
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            if terminal:
                updated = db.execute(
                    "UPDATE mission_queue SET state=?,available_at=COALESCE(?,available_at),last_error=?,"
                    "claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL "
                    "WHERE mission_id=? AND lease_owner=? AND state=? AND lease_epoch=? AND lease_expires_at > ?",
                    (state.value, next_available, error, mission_id, worker_id, WorkerMissionState.EXECUTING.value, lease_epoch, moment),
                )
            else:
                updated = db.execute(
                    "UPDATE mission_queue SET state=?,available_at=COALESCE(?,available_at),last_error=? "
                    "WHERE mission_id=? AND lease_owner=? AND state=? AND lease_epoch=? AND lease_expires_at > ?",
                    (state.value, next_available, error, mission_id, worker_id, WorkerMissionState.EXECUTING.value, lease_epoch, moment),
                )
            if updated.rowcount != 1:
                raise LeaseLostError("worker lease is expired, superseded, or no longer current")
            row = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch FROM mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError("unknown queued mission")
            item = self._item_from_row(row)
        return item

    def release(
        self,
        mission_id: str,
        state: WorkerMissionState,
        *,
        worker_id: str,
        lease_epoch: int | None = None,
        available_at: str | None = None,
        error: str = "",
        now: str | None = None,
    ) -> QueueItem:
        """Release a current live claim into an explicit nonterminal state."""
        if state.value in {"completed", "failed", "cancelled", "needs_input", "partial_success", "executing"}:
            raise ValueError("release requires a nonterminal, non-executing state")
        if not worker_id.strip():
            raise LeaseLostError("worker mutation requires a lease owner")
        if lease_epoch is None:
            raise LeaseLostError("worker mutation requires a lease epoch")
        moment = _utc_text(_utc_datetime(now, field_name="now"))
        next_available = _utc_text(_utc_datetime(available_at, field_name="available_at")) if available_at is not None else None
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            updated = db.execute(
                "UPDATE mission_queue SET state=?,available_at=COALESCE(?,available_at),last_error=?,"
                "claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL "
                "WHERE mission_id=? AND lease_owner=? AND state=? AND lease_epoch=? AND lease_expires_at > ?",
                (state.value, next_available, error, mission_id, worker_id, WorkerMissionState.EXECUTING.value, lease_epoch, moment),
            )
            if updated.rowcount != 1:
                raise LeaseLostError("worker lease is expired, superseded, or no longer current")
            row = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch FROM mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError("unknown queued mission")
            item = self._item_from_row(row)
        return item

    def heartbeat(self, mission_id: str, *, worker_id: str, lease_epoch: int | None = None, now: str | None = None, lease_seconds: int = 60) -> QueueItem:
        if not worker_id.strip():
            raise LeaseLostError("worker heartbeat requires a lease owner")
        if lease_epoch is None:
            raise LeaseLostError("worker heartbeat requires a lease epoch")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        moment_dt = _utc_datetime(now, field_name="now")
        moment = _utc_text(moment_dt)
        expiry = _utc_text(moment_dt + timedelta(seconds=lease_seconds))
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            updated = db.execute(
                "UPDATE mission_queue SET lease_expires_at=? WHERE mission_id=? AND state=? AND lease_owner=? "
                "AND lease_epoch=? AND lease_expires_at > ?",
                (expiry, mission_id, WorkerMissionState.EXECUTING.value, worker_id, lease_epoch, moment),
            )
            if updated.rowcount != 1:
                raise LeaseLostError("worker lease is expired, superseded, or no longer current")
            row = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch FROM mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError("unknown queued mission")
            item = self._item_from_row(row)
        return item

    def recover_expired(self, *, now: str | None = None) -> list[QueueItem]:
        moment = _utc_text(_utc_datetime(now, field_name="now"))
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT mission_id FROM mission_queue WHERE state=? AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?", (WorkerMissionState.EXECUTING.value, moment)).fetchall()
            if not rows:
                return []
            updated = db.execute(
                "UPDATE mission_queue SET state=?, claimed_at=NULL, lease_owner=NULL, lease_expires_at=NULL, lease_epoch=lease_epoch+1, last_error=? "
                "WHERE state=? AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?",
                (WorkerMissionState.QUEUED.value, "worker lease expired", WorkerMissionState.EXECUTING.value, moment),
            )
            if updated.rowcount != len(rows):
                raise LeaseLostError("expired lease set changed during recovery")
            recovered = []
            for (mission_id,) in rows:
                row = db.execute(
                    "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch FROM mission_queue WHERE mission_id=?",
                    (mission_id,),
                ).fetchone()
                if row is None:
                    raise KeyError("unknown queued mission")
                recovered.append(self._item_from_row(row))
            return recovered

    def recover_after_restart(self, *, now: str | None = None) -> list[QueueItem]:
        """Recover only expired executing leases; never steal a live claim at startup."""
        return self.recover_expired(now=now)

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

    def recover_after_restart(self, *, now: str | None = None) -> list[QueueItem]:
        return self.queue.recover_after_restart(now=now)

    def run_once(self, *, now: str | None = None, max_slices: int | None = None) -> QueueItem | None:
        # `now` is a claim-time override only. Renewals and writes use live UTC
        # time so a frozen caller timestamp cannot keep an expired lease alive.
        item = self.queue.claim_next(now=now, worker_id=self.worker_id, lease_seconds=self.lease_seconds)
        if item is None:
            return None

        def heartbeat() -> None:
            self.queue.heartbeat(
                item.mission_id,
                worker_id=self.worker_id,
                lease_epoch=item.lease_epoch,
                lease_seconds=self.lease_seconds,
            )

        try:
            heartbeat()
            runtime = self.runtime_factory()
            heartbeat()
            mission = runtime.run_to_completion(item.mission_id, max_slices=max_slices, heartbeat=heartbeat)
        except LeaseLostError:
            # A lease may be reclaimed while this worker is between slices. The
            # stale worker must not overwrite the queue outcome or report FAILED.
            return self.queue.get(item.mission_id)
        except Exception:
            # An unexpected runtime exception may follow an external effect.
            # Never convert that ambiguity into FAILED or retry it automatically,
            # and do not persist exception text that could contain sensitive data.
            try:
                return self.queue.release(
                    item.mission_id,
                    WorkerMissionState.WAITING_FOR_TOOL,
                    error="worker runtime failed; execution outcome requires reconciliation",
                    worker_id=self.worker_id,
                    lease_epoch=item.lease_epoch,
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
            return self.queue.update(
                item.mission_id,
                state,
                error=mission.error,
                worker_id=self.worker_id,
                lease_epoch=item.lease_epoch,
            )
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
            for schedule_id, next_run_at in db.execute("SELECT schedule_id,next_run_at FROM mission_schedules").fetchall():
                normalized = _utc_text(_utc_datetime(next_run_at, field_name="next_run_at"))
                if next_run_at != normalized:
                    db.execute("UPDATE mission_schedules SET next_run_at=? WHERE schedule_id=?", (normalized, schedule_id))

    def schedule(self, mission_id: str, *, run_at: str, interval_seconds: int | None = None, retry_limit: int = 0, schedule_id: str | None = None) -> MissionSchedule:
        if interval_seconds is not None and interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        normalized_run_at = _utc_text(_utc_datetime(run_at, field_name="run_at"))
        item = MissionSchedule(schedule_id or uuid.uuid4().hex, mission_id, normalized_run_at, interval_seconds, retry_limit)
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
        current = _utc_datetime(now, field_name="now")
        current_text = _utc_text(current)
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT schedule_id FROM mission_schedules WHERE state=? AND next_run_at<=? ORDER BY next_run_at,schedule_id", (WorkerMissionState.SCHEDULED.value, current_text)).fetchall()
        dispatched = []
        for (schedule_id,) in rows:
            item = self.get(schedule_id)
            self.queue.enqueue(item.mission_id, available_at=now, state=WorkerMissionState.QUEUED)
            if item.interval_seconds:
                next_run = _utc_text(current + timedelta(seconds=item.interval_seconds))
                with sqlite3.connect(self.db_path) as db:
                    db.execute("UPDATE mission_schedules SET next_run_at=?,retries=0 WHERE schedule_id=?", (next_run, schedule_id))
            else:
                with sqlite3.connect(self.db_path) as db:
                    db.execute("UPDATE mission_schedules SET state=? WHERE schedule_id=?", (WorkerMissionState.COMPLETED.value, schedule_id))
            dispatched.append(self.get(schedule_id))
        return dispatched

    def mark_missed(self, schedule_id: str, *, now: str) -> MissionSchedule:
        item = self.get(schedule_id)
        if _utc_datetime(now, field_name="now") <= _utc_datetime(item.next_run_at, field_name="next_run_at"):
            return item
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE mission_schedules SET state=? WHERE schedule_id=?", (WorkerMissionState.SLEEPING.value, schedule_id))
        return self.get(schedule_id)


__all__ = ["MissionQueue", "MissionQueue", "MissionSchedule", "MissionScheduler", "MissionWorker", "QueueItem", "WorkerMissionState"]
