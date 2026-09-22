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


class MissionQueue:
    """Durable queue metadata; mission truth remains in MissionStore."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS mission_queue (mission_id TEXT PRIMARY KEY, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, available_at TEXT NOT NULL, claimed_at TEXT, last_error TEXT NOT NULL DEFAULT '')")

    def enqueue(self, mission_id: str, *, available_at: str | None = None, state: WorkerMissionState = WorkerMissionState.QUEUED) -> QueueItem:
        if not mission_id.strip():
            raise ValueError("mission_id required")
        available = available_at or datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT INTO mission_queue(mission_id,state,attempts,available_at,claimed_at,last_error) VALUES(?,?,?,?,NULL,'') ON CONFLICT(mission_id) DO UPDATE SET state=excluded.state,available_at=excluded.available_at,claimed_at=NULL", (mission_id, state.value, 0, available))
        return self.get(mission_id)

    def get(self, mission_id: str) -> QueueItem:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT mission_id,state,attempts,available_at,claimed_at,last_error FROM mission_queue WHERE mission_id=?", (mission_id,)).fetchone()
        if row is None:
            raise KeyError("unknown queued mission")
        return QueueItem(row[0], WorkerMissionState(row[1]), row[2], row[3], row[4], row[5])

    def claim_next(self, *, now: str | None = None) -> QueueItem | None:
        moment = now or datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT mission_id FROM mission_queue WHERE state IN (?, ?, ?) AND available_at <= ? ORDER BY available_at,mission_id LIMIT 1", (WorkerMissionState.QUEUED.value, WorkerMissionState.SCHEDULED.value, WorkerMissionState.SLEEPING.value, moment)).fetchone()
            if row is None:
                return None
            mission_id = row[0]
            db.execute("UPDATE mission_queue SET state=?, attempts=attempts+1, claimed_at=? WHERE mission_id=?", (WorkerMissionState.EXECUTING.value, moment, mission_id))
        return self.get(mission_id)

    def update(self, mission_id: str, state: WorkerMissionState, *, available_at: str | None = None, error: str = "") -> QueueItem:
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE mission_queue SET state=?, available_at=COALESCE(?,available_at), last_error=?, claimed_at=CASE WHEN ? IN ('completed','failed','cancelled','needs_input','partial_success') THEN NULL ELSE claimed_at END WHERE mission_id=?", (state.value, available_at, error, state.value, mission_id))
        return self.get(mission_id)

    def recover_after_restart(self) -> list[QueueItem]:
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT mission_id FROM mission_queue WHERE state IN (?, ?, ?, ?)", (WorkerMissionState.EXECUTING.value, WorkerMissionState.PLANNING.value, WorkerMissionState.WAITING_FOR_TOOL.value, WorkerMissionState.WAITING_FOR_MODEL.value)).fetchall()
            db.execute("UPDATE mission_queue SET state=?, claimed_at=NULL, last_error=? WHERE state IN (?, ?, ?, ?)", (WorkerMissionState.QUEUED.value, "worker restart recovery", WorkerMissionState.EXECUTING.value, WorkerMissionState.PLANNING.value, WorkerMissionState.WAITING_FOR_TOOL.value, WorkerMissionState.WAITING_FOR_MODEL.value))
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

    def __init__(self, queue: MissionQueue, runtime_factory: Callable[[], Any]):
        self.queue = queue
        self.runtime_factory = runtime_factory

    def enqueue(self, mission_id: str) -> QueueItem:
        return self.queue.enqueue(mission_id)

    def recover_after_restart(self) -> list[QueueItem]:
        return self.queue.recover_after_restart()

    def run_once(self, *, now: str | None = None, max_slices: int | None = None) -> QueueItem | None:
        item = self.queue.claim_next(now=now)
        if item is None:
            return None
        runtime = self.runtime_factory()
        try:
            mission = runtime.run_to_completion(item.mission_id, max_slices=max_slices)
        except Exception as exc:
            return self.queue.update(item.mission_id, WorkerMissionState.FAILED, error=f"{type(exc).__name__}: {exc}")
        state = {
            MissionStatus.GOAL_COMPLETED: WorkerMissionState.COMPLETED,
            MissionStatus.OWNER_INPUT_REQUIRED: WorkerMissionState.NEEDS_INPUT,
            MissionStatus.AUTHORIZATION_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.CANCELLED: WorkerMissionState.CANCELLED,
            MissionStatus.FAILED_RETRY_EXHAUSTED: WorkerMissionState.FAILED,
            MissionStatus.SCOPE_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.SAFETY_BLOCKED: WorkerMissionState.FAILED,
        }.get(mission.status, WorkerMissionState.PARTIAL_SUCCESS if mission.evidence else WorkerMissionState.FAILED)
        return self.queue.update(item.mission_id, state, error=mission.error)


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
