from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable
import json
import os
import sqlite3
import stat
from threading import Event, Thread
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
    """Raised when a worker heartbeat no longer owns the queue lease."""


DEFAULT_WORKER_LEASE_SECONDS = 120
DEFAULT_MAX_PENDING_MISSIONS = 10


class QueueCapacityError(RuntimeError):
    """Raised when accepting another mission would exceed the durable queue bound."""


def _secure_database_file(path: str | Path) -> str:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(target, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise PermissionError("mission queue database must be a regular file owned by the application user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    return str(target)


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


class MissionQueue:
    """Durable queue metadata; mission truth remains in MissionStore."""

    def __init__(self, db_path: str | Path, *, max_pending: int = DEFAULT_MAX_PENDING_MISSIONS):
        if type(max_pending) is not int or max_pending < 1:
            raise ValueError("max_pending must be a positive integer")
        self.max_pending = max_pending
        self.db_path = _secure_database_file(db_path)
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS mission_queue (mission_id TEXT PRIMARY KEY, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, available_at TEXT NOT NULL, claimed_at TEXT, last_error TEXT NOT NULL DEFAULT '')")
            columns = {row[1] for row in db.execute("PRAGMA table_info(mission_queue)")}
            for column, definition in (("lease_owner", "TEXT"), ("lease_expires_at", "TEXT")):
                if column not in columns:
                    db.execute(f"ALTER TABLE mission_queue ADD COLUMN {column} {definition}")
                    columns.add(column)

    def enqueue(self, mission_id: str, *, available_at: str | None = None, state: WorkerMissionState = WorkerMissionState.QUEUED) -> QueueItem:
        if not mission_id.strip():
            raise ValueError("mission_id required")
        available = available_at or datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT state FROM mission_queue WHERE mission_id=?", (mission_id,)).fetchone()
            if current and current[0] == WorkerMissionState.EXECUTING.value:
                return self.get(mission_id)
            if current and current[0] == WorkerMissionState.CANCELLED.value:
                return self.get(mission_id)
            terminal_states = (WorkerMissionState.COMPLETED.value, WorkerMissionState.PARTIAL_SUCCESS.value, WorkerMissionState.NEEDS_INPUT.value, WorkerMissionState.FAILED.value, WorkerMissionState.CANCELLED.value)
            if current is None or current[0] in terminal_states:
                active_count = int(db.execute("SELECT COUNT(*) FROM mission_queue WHERE state NOT IN (?,?,?,?,?)", terminal_states).fetchone()[0])
                if active_count >= self.max_pending:
                    raise QueueCapacityError("mission_queue_capacity_exceeded")
            db.execute("INSERT INTO mission_queue(mission_id,state,attempts,available_at,claimed_at,last_error) VALUES(?,?,?,?,NULL,'') ON CONFLICT(mission_id) DO UPDATE SET state=excluded.state,available_at=excluded.available_at,claimed_at=NULL,last_error='',lease_owner=NULL,lease_expires_at=NULL", (mission_id, state.value, 0, available))
        return self.get(mission_id)

    def get(self, mission_id: str) -> QueueItem:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at FROM mission_queue WHERE mission_id=?", (mission_id,)).fetchone()
        if row is None:
            raise KeyError("unknown queued mission")
        return QueueItem(row[0], WorkerMissionState(row[1]), row[2], row[3], row[4], row[5], row[6], row[7])

    def claim_next(self, *, now: str | None = None, worker_id: str = "worker", lease_seconds: int = 60) -> QueueItem | None:
        moment = now or datetime.now(timezone.utc).isoformat()
        expiry = (datetime.fromisoformat(moment.replace("Z", "+00:00")) + timedelta(seconds=lease_seconds)).isoformat()
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT mission_id FROM mission_queue WHERE state IN (?, ?, ?) AND available_at <= ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?) ORDER BY available_at,mission_id LIMIT 1", (WorkerMissionState.QUEUED.value, WorkerMissionState.SCHEDULED.value, WorkerMissionState.SLEEPING.value, moment, moment)).fetchone()
            if row is None:
                return None
            mission_id = row[0]
            db.execute("UPDATE mission_queue SET state=?, attempts=attempts+1, claimed_at=?, lease_owner=?, lease_expires_at=? WHERE mission_id=?", (WorkerMissionState.EXECUTING.value, moment, worker_id, expiry, mission_id))
        return self.get(mission_id)

    def update(self, mission_id: str, state: WorkerMissionState, *, available_at: str | None = None, error: str = "", worker_id: str | None = None) -> QueueItem:
        with sqlite3.connect(self.db_path) as db:
            terminal = state.value in {"completed", "failed", "cancelled", "needs_input", "partial_success"}
            if worker_id is not None:
                if terminal:
                    updated = db.execute("UPDATE mission_queue SET state=?, available_at=COALESCE(?,available_at), last_error=?, claimed_at=NULL, lease_owner=NULL, lease_expires_at=NULL WHERE mission_id=? AND lease_owner=? AND state=?", (state.value, available_at, error, mission_id, worker_id, WorkerMissionState.EXECUTING.value))
                else:
                    updated = db.execute("UPDATE mission_queue SET state=?, available_at=COALESCE(?,available_at), last_error=? WHERE mission_id=? AND lease_owner=?", (state.value, available_at, error, mission_id, worker_id))
                if updated.rowcount != 1:
                    raise LeaseLostError("worker lease is not owned")
            else:
                db.execute("UPDATE mission_queue SET state=?, available_at=COALESCE(?,available_at), last_error=?, claimed_at=CASE WHEN ? IN ('completed','failed','cancelled','needs_input','partial_success') THEN NULL ELSE claimed_at END, lease_owner=CASE WHEN ? IN ('completed','failed','cancelled','needs_input','partial_success') THEN NULL ELSE lease_owner END, lease_expires_at=CASE WHEN ? IN ('completed','failed','cancelled','needs_input','partial_success') THEN NULL ELSE lease_expires_at END WHERE mission_id=?", (state.value, available_at, error, state.value, state.value, state.value, mission_id))
        return self.get(mission_id)

    def sync_control_state(self, mission_id: str, state: WorkerMissionState) -> QueueItem:
        """Reconcile an idle queue item without stealing an executing worker lease."""
        if state not in {WorkerMissionState.PAUSED, WorkerMissionState.CANCELLED}:
            raise ValueError("control sync only accepts paused or cancelled states")
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state FROM mission_queue WHERE mission_id=?", (mission_id,)).fetchone()
            if row is None:
                raise KeyError("unknown queued mission")
            if row[0] != WorkerMissionState.EXECUTING.value:
                db.execute(
                    "UPDATE mission_queue SET state=?,last_error=?,claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL WHERE mission_id=?",
                    (state.value, "mission paused" if state is WorkerMissionState.PAUSED else "mission cancelled", mission_id),
                )
        return self.get(mission_id)

    def release(self, mission_id: str, state: WorkerMissionState, *, worker_id: str, available_at: str | None = None, error: str = "") -> QueueItem:
        """Atomically relinquish an owned lease for resumable/nonterminal work."""
        if state in {WorkerMissionState.COMPLETED, WorkerMissionState.FAILED, WorkerMissionState.CANCELLED, WorkerMissionState.NEEDS_INPUT, WorkerMissionState.PARTIAL_SUCCESS}:
            raise ValueError("terminal queue states must use update")
        with sqlite3.connect(self.db_path) as db:
            updated = db.execute("UPDATE mission_queue SET state=?,available_at=COALESCE(?,available_at),last_error=?,claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL WHERE mission_id=? AND lease_owner=? AND state=?", (state.value, available_at, error, mission_id, worker_id, WorkerMissionState.EXECUTING.value))
            if updated.rowcount != 1:
                raise LeaseLostError("worker lease is not owned")
        return self.get(mission_id)

    def heartbeat(self, mission_id: str, *, worker_id: str, now: str | None = None, lease_seconds: int = 60) -> QueueItem:
        moment = now or datetime.now(timezone.utc).isoformat()
        expiry = (datetime.fromisoformat(moment.replace("Z", "+00:00")) + timedelta(seconds=lease_seconds)).isoformat()
        with sqlite3.connect(self.db_path) as db:
            updated = db.execute("UPDATE mission_queue SET lease_expires_at=? WHERE mission_id=? AND state=? AND lease_owner=?", (expiry, mission_id, WorkerMissionState.EXECUTING.value, worker_id))
            if updated.rowcount != 1:
                raise LeaseLostError("worker lease is not owned")
        return self.get(mission_id)

    def recover_expired(self, *, now: str | None = None) -> list[QueueItem]:
        moment = now or datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT mission_id FROM mission_queue WHERE state=? AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?", (WorkerMissionState.EXECUTING.value, moment)).fetchall()
            db.execute("UPDATE mission_queue SET state=?, claimed_at=NULL, lease_owner=NULL, lease_expires_at=NULL, last_error=? WHERE state=? AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?", (WorkerMissionState.QUEUED.value, "worker lease expired", WorkerMissionState.EXECUTING.value, moment))
        return [self.get(row[0]) for row in rows]

    def recover_after_restart(self) -> list[QueueItem]:
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT mission_id FROM mission_queue WHERE state IN (?, ?, ?, ?)", (WorkerMissionState.EXECUTING.value, WorkerMissionState.PLANNING.value, WorkerMissionState.WAITING_FOR_TOOL.value, WorkerMissionState.WAITING_FOR_MODEL.value)).fetchall()
            db.execute("UPDATE mission_queue SET state=?, claimed_at=NULL, lease_owner=NULL, lease_expires_at=NULL, last_error=? WHERE state IN (?, ?, ?, ?)", (WorkerMissionState.QUEUED.value, "worker restart recovery", WorkerMissionState.EXECUTING.value, WorkerMissionState.PLANNING.value, WorkerMissionState.WAITING_FOR_TOOL.value, WorkerMissionState.WAITING_FOR_MODEL.value))
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

    def __init__(self, queue: MissionQueue, runtime_factory: Callable[[], Any], *, worker_id: str = "worker", lease_seconds: int = DEFAULT_WORKER_LEASE_SECONDS, resume_callback: Callable[[str, int | None, Callable[[], None]], Any] | None = None):
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self.queue = queue
        self.runtime_factory = runtime_factory
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.resume_callback = resume_callback

    def enqueue(self, mission_id: str) -> QueueItem:
        return self.queue.enqueue(mission_id)

    def recover_after_restart(self) -> list[QueueItem]:
        return self.queue.recover_after_restart()

    def run_once(self, *, now: str | None = None, max_slices: int | None = None) -> QueueItem | None:
        item = self.queue.claim_next(now=now, worker_id=self.worker_id, lease_seconds=self.lease_seconds)
        if item is None:
            return None
        runtime = None
        heartbeat_stop = Event()
        lease_lost = Event()
        heartbeat_interval = max(0.01, min(self.lease_seconds / 3, 30.0))

        def keep_lease_alive() -> None:
            while not heartbeat_stop.wait(heartbeat_interval):
                try:
                    self.queue.heartbeat(item.mission_id, worker_id=self.worker_id, lease_seconds=self.lease_seconds)
                except LeaseLostError:
                    lease_lost.set()
                    return
                except Exception:
                    # A transient queue-store failure makes lease ownership
                    # uncertain too. Do not let this worker publish a result.
                    lease_lost.set()
                    return

        heartbeat_thread = Thread(target=keep_lease_alive, name=f"mission-lease-{item.mission_id[:12]}", daemon=True)
        heartbeat_thread.start()
        try:
            runtime = self.runtime_factory()
            if lease_lost.is_set():
                return self.queue.get(item.mission_id)
            heartbeat = lambda: self.queue.heartbeat(item.mission_id, worker_id=self.worker_id, lease_seconds=self.lease_seconds)
            try:
                if self.resume_callback is not None:
                    mission = self.resume_callback(item.mission_id, max_slices, heartbeat)
                else:
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
            store = getattr(runtime, "store", None)
            mission = store.load(item.mission_id) if store is not None else None
            if mission is not None and (
                mission.status is MissionStatus.RECOVERY_REQUIRED
                or (mission.checkpoint or {}).get("status") in {"in_flight", "in_flight_parallel"}
            ):
                if mission.status is not MissionStatus.RECOVERY_REQUIRED and not mission.is_terminal:
                    try:
                        mission.transition(MissionStatus.RECOVERY_REQUIRED, "worker exception left an ambiguous in-flight execution")
                        store.save(mission)
                    except Exception:
                        # A concurrent checkpoint update is safer than a stale
                        # worker overwriting the authoritative persisted mission.
                        pass
                try:
                    return self.queue.release(item.mission_id, WorkerMissionState.WAITING_FOR_TOOL, worker_id=self.worker_id, error="ambiguous in-flight execution requires reconciliation")
                except LeaseLostError:
                    return self.queue.get(item.mission_id)
            if mission is not None and mission.status is MissionStatus.PAUSED:
                try:
                    return self.queue.release(item.mission_id, WorkerMissionState.PAUSED, worker_id=self.worker_id, error="mission paused")
                except LeaseLostError:
                    return self.queue.get(item.mission_id)
            if mission is not None and mission.status is MissionStatus.OWNER_INPUT_REQUIRED:
                return self.queue.update(item.mission_id, WorkerMissionState.NEEDS_INPUT, error="Owner authorization requires renewal", worker_id=self.worker_id)
            return self.queue.update(item.mission_id, WorkerMissionState.FAILED, error=type(exc).__name__, worker_id=self.worker_id)
        finally:
            heartbeat_stop.set()
            heartbeat_thread.join(timeout=max(0.2, heartbeat_interval + 0.2))
        if lease_lost.is_set():
            return self.queue.get(item.mission_id)
        state = {
            MissionStatus.GOAL_COMPLETED: WorkerMissionState.COMPLETED,
            MissionStatus.PAUSED: WorkerMissionState.PAUSED,
            MissionStatus.OWNER_INPUT_REQUIRED: WorkerMissionState.NEEDS_INPUT,
            MissionStatus.AUTHORIZATION_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.RECOVERY_REQUIRED: WorkerMissionState.WAITING_FOR_TOOL,
            MissionStatus.CANCELLED: WorkerMissionState.CANCELLED,
            MissionStatus.FAILED_RETRY_EXHAUSTED: WorkerMissionState.FAILED,
            MissionStatus.SCOPE_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.SAFETY_BLOCKED: WorkerMissionState.FAILED,
        }.get(mission.status)
        if state is None:
            moment = now or datetime.now(timezone.utc).isoformat()
            available = (datetime.fromisoformat(moment.replace("Z", "+00:00")) + timedelta(seconds=1)).isoformat()
            try:
                return self.queue.release(item.mission_id, WorkerMissionState.QUEUED, worker_id=self.worker_id, available_at=available, error="mission remains active; continuing from persisted checkpoint")
            except LeaseLostError:
                return self.queue.get(item.mission_id)
        if state is WorkerMissionState.PAUSED:
            try:
                return self.queue.release(item.mission_id, WorkerMissionState.PAUSED, worker_id=self.worker_id, error="mission paused by Owner")
            except LeaseLostError:
                return self.queue.get(item.mission_id)
        if state is WorkerMissionState.WAITING_FOR_TOOL:
            try:
                return self.queue.release(item.mission_id, state, worker_id=self.worker_id, error=mission.error)
            except LeaseLostError:
                return self.queue.get(item.mission_id)
        try:
            return self.queue.update(item.mission_id, state, error=mission.error, worker_id=self.worker_id)
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
        self.db_path = _secure_database_file(db_path)
        self.queue = queue
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS mission_schedules (schedule_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, next_run_at TEXT NOT NULL, interval_seconds INTEGER, retry_limit INTEGER NOT NULL, retries INTEGER NOT NULL, state TEXT NOT NULL)")

    def schedule(self, mission_id: str, *, run_at: str, interval_seconds: int | None = None, retry_limit: int = 0, schedule_id: str | None = None) -> MissionSchedule:
        if interval_seconds is not None:
            raise ValueError("recurring schedules are unavailable; interval_seconds must be omitted")
        if type(retry_limit) is not int or retry_limit != 0:
            raise ValueError("scheduled retries are unavailable; retry_limit must be 0")
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


__all__ = ["MissionQueue", "MissionSchedule", "MissionScheduler", "MissionWorker", "QueueCapacityError", "QueueItem", "WorkerMissionState"]
