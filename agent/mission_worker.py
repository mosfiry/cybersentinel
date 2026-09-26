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

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS mission_queue (mission_id TEXT PRIMARY KEY, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, available_at TEXT NOT NULL, claimed_at TEXT, last_error TEXT NOT NULL DEFAULT '')")
            for column, definition in (("lease_owner", "TEXT"), ("lease_expires_at", "TEXT")):
                try:
                    db.execute(f"ALTER TABLE mission_queue ADD COLUMN {column} {definition}")
                except sqlite3.OperationalError:
                    pass

    def enqueue(self, mission_id: str, *, available_at: str | None = None, state: WorkerMissionState = WorkerMissionState.QUEUED) -> QueueItem:
        if not mission_id.strip():
            raise ValueError("mission_id required")
        available = available_at or datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as db:
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
            terminal = state.value in {"completed", "failed", "cancelled", "needs_input", "partial_success", "paused"}
            release_lease = terminal or state in {WorkerMissionState.QUEUED, WorkerMissionState.SLEEPING}
            if worker_id is not None:
                if release_lease:
                    updated = db.execute("UPDATE mission_queue SET state=?, available_at=COALESCE(?,available_at), last_error=?, claimed_at=NULL, lease_owner=NULL, lease_expires_at=NULL WHERE mission_id=? AND lease_owner=? AND state=?", (state.value, available_at, error, mission_id, worker_id, WorkerMissionState.EXECUTING.value))
                else:
                    updated = db.execute("UPDATE mission_queue SET state=?, available_at=COALESCE(?,available_at), last_error=? WHERE mission_id=? AND lease_owner=?", (state.value, available_at, error, mission_id, worker_id))
                if updated.rowcount != 1:
                    raise PermissionError("worker lease is not owned")
            else:
                db.execute("UPDATE mission_queue SET state=?, available_at=COALESCE(?,available_at), last_error=?, claimed_at=CASE WHEN ? THEN NULL ELSE claimed_at END, lease_owner=CASE WHEN ? THEN NULL ELSE lease_owner END, lease_expires_at=CASE WHEN ? THEN NULL ELSE lease_expires_at END WHERE mission_id=?", (state.value, available_at, error, int(release_lease), int(release_lease), int(release_lease), mission_id))
        return self.get(mission_id)

    def heartbeat(self, mission_id: str, *, worker_id: str, now: str | None = None, lease_seconds: int = 60) -> QueueItem:
        moment = now or datetime.now(timezone.utc).isoformat()
        expiry = (datetime.fromisoformat(moment.replace("Z", "+00:00")) + timedelta(seconds=lease_seconds)).isoformat()
        with sqlite3.connect(self.db_path) as db:
            updated = db.execute("UPDATE mission_queue SET lease_expires_at=? WHERE mission_id=? AND state=? AND lease_owner=?", (expiry, mission_id, WorkerMissionState.EXECUTING.value, worker_id))
            if updated.rowcount != 1:
                raise PermissionError("worker lease is not owned")
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

    def __init__(self, queue: MissionQueue, runtime_factory: Callable[[], Any], *, worker_id: str = "worker"):
        self.queue = queue
        self.runtime_factory = runtime_factory
        self.worker_id = worker_id

    def enqueue(self, mission_id: str) -> QueueItem:
        return self.queue.enqueue(mission_id)

    def recover_after_restart(self) -> list[QueueItem]:
        return self.queue.recover_after_restart()

    def control_graph(self, mission_id: str, command: str, *, authorization_context: Any) -> Any:
        """Apply a typed Owner decision to the canonical runtime and durable queue."""
        mission = self.runtime_factory().control_graph(mission_id, command, authorization_context=authorization_context)
        queue_state = {"pause": WorkerMissionState.PAUSED, "resume": WorkerMissionState.QUEUED, "cancel": WorkerMissionState.CANCELLED}.get(command)
        if queue_state is None:
            raise ValueError("unknown graph control")
        try:
            current = self.queue.get(mission_id)
        except KeyError:
            if command in {"pause", "cancel"}:
                return mission
            current = self.queue.enqueue(mission_id, state=WorkerMissionState.PAUSED)
        if command == "resume" and current.state is not WorkerMissionState.PAUSED:
            raise ValueError("only a paused queue item can be resumed")
        self.queue.update(mission_id, queue_state, error="")
        return mission

    def reconcile_graph_node(self, mission_id: str, node_id: str, *, executed: bool, result: Any = None, authorization_context: Any) -> Any:
        mission = self.runtime_factory().reconcile_graph_node(mission_id, node_id, executed=executed, result=result, authorization_context=authorization_context)
        current = self.queue.get(mission_id)
        if not mission.checkpoint.get("orchestration", {}).get("recovery_required") and current.state is WorkerMissionState.WAITING_FOR_TOOL:
            queue_state = {
                MissionStatus.PAUSED: WorkerMissionState.PAUSED,
                MissionStatus.CANCELLED: WorkerMissionState.CANCELLED,
            }.get(mission.status, WorkerMissionState.QUEUED)
            self.queue.update(mission_id, queue_state, error="")
        return mission

    def run_once(self, *, now: str | None = None, max_slices: int | None = None) -> QueueItem | None:
        item = self.queue.claim_next(now=now, worker_id=self.worker_id)
        if item is None:
            return None
        runtime = self.runtime_factory()
        try:
            store = getattr(runtime, "store", None)
            if store is not None:
                mission_record = store.load(item.mission_id)
                if mission_record is None or mission_record.progress.get("execution_mode") != "dag":
                    return self.queue.update(item.mission_id, WorkerMissionState.FAILED, error="worker refuses to execute a mission without a persisted deterministic DAG", worker_id=self.worker_id)
            try:
                mission = runtime.run_to_completion(item.mission_id, max_slices=max_slices, heartbeat=lambda: self.queue.heartbeat(item.mission_id, worker_id=self.worker_id))
            except TypeError as exc:
                if "heartbeat" not in str(exc):
                    raise
                mission = runtime.run_to_completion(item.mission_id, max_slices=max_slices)
        except Exception as exc:
            return self.queue.update(item.mission_id, WorkerMissionState.FAILED, error=f"{type(exc).__name__}: {exc}", worker_id=self.worker_id)
        state = {
            MissionStatus.PAUSED: WorkerMissionState.PAUSED,
            MissionStatus.CANCELLING: WorkerMissionState.CANCELLING,
            MissionStatus.READY: WorkerMissionState.QUEUED,
            MissionStatus.RUNNING: WorkerMissionState.QUEUED,
            MissionStatus.GOAL_COMPLETED: WorkerMissionState.COMPLETED,
            MissionStatus.OWNER_INPUT_REQUIRED: WorkerMissionState.NEEDS_INPUT,
            MissionStatus.AUTHORIZATION_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.RECOVERY_REQUIRED: WorkerMissionState.WAITING_FOR_TOOL,
            MissionStatus.BUDGET_BLOCKED: WorkerMissionState.NEEDS_INPUT,
            MissionStatus.VERIFICATION_BLOCKED: WorkerMissionState.NEEDS_INPUT,
            MissionStatus.RESOURCE_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.SAFETY_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.CANCELLED: WorkerMissionState.CANCELLED,
            MissionStatus.FAILED_RETRY_EXHAUSTED: WorkerMissionState.FAILED,
            MissionStatus.SCOPE_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.SAFETY_BLOCKED: WorkerMissionState.FAILED,
        }.get(mission.status, WorkerMissionState.PARTIAL_SUCCESS if mission.evidence else WorkerMissionState.FAILED)
        try:
            return self.queue.update(item.mission_id, state, error=mission.error, worker_id=self.worker_id)
        except PermissionError:
            current = self.queue.get(item.mission_id)
            if current.state in {WorkerMissionState.PAUSED, WorkerMissionState.CANCELLED, WorkerMissionState.QUEUED, WorkerMissionState.WAITING_FOR_TOOL}:
                return current
            raise


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


__all__ = ["MissionQueue", "MissionQueue", "MissionSchedule", "MissionScheduler", "MissionWorker", "QueueItem", "WorkerMissionState"]
