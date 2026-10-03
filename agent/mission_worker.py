from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable
from contextlib import nullcontext
import json
import sqlite3
import uuid

from .execution_fence import ExecutionFence, ExecutionFenceError
from .mission import MissionClaimBinding, MissionStatus


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
    worker_instance_id: str | None = None
    runtime_generation: int = 0
    claim_phase: str = "NONE"
    claim_fence_id: str = ""


@dataclass(frozen=True)
class WorkerIdentity:
    worker_id: str
    worker_instance_id: str
    runtime_generation: int


class MissionQueue:
    """Durable queue metadata; mission truth remains in MissionStore."""

    def __init__(self, db_path: str | Path, *, require_execution_fence: bool = False, mission_store: Any | None = None):
        self.db_path = str(db_path)
        self.require_execution_fence = bool(require_execution_fence)
        self.mission_store = mission_store
        if self.require_execution_fence and self.mission_store is None:
            raise ExecutionFenceError("strict MissionQueue requires its authoritative MissionStore")
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS mission_queue (mission_id TEXT PRIMARY KEY, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, available_at TEXT NOT NULL, claimed_at TEXT, last_error TEXT NOT NULL DEFAULT '')")
            db.execute("CREATE TABLE IF NOT EXISTS mission_worker_generations (worker_id TEXT NOT NULL, runtime_generation INTEGER NOT NULL, worker_instance_id TEXT NOT NULL UNIQUE, state TEXT NOT NULL, started_at TEXT NOT NULL, PRIMARY KEY(worker_id,runtime_generation))")
            columns = {row[1] for row in db.execute("PRAGMA table_info(mission_queue)")}
            for column, definition in (
                ("lease_owner", "TEXT"),
                ("lease_expires_at", "TEXT"),
                ("lease_epoch", "INTEGER NOT NULL DEFAULT 0"),
                ("worker_instance_id", "TEXT"),
                ("runtime_generation", "INTEGER NOT NULL DEFAULT 0"),
                ("claim_phase", "TEXT NOT NULL DEFAULT 'NONE'"),
                ("claim_fence_id", "TEXT NOT NULL DEFAULT ''"),
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
            row[9],
            int(row[10]),
            str(row[11]),
            str(row[12]),
        )

    def register_worker(self, worker_id: str) -> WorkerIdentity:
        """Atomically allocate a new durable generation for a logical worker."""
        if not isinstance(worker_id, str) or not worker_id.strip() or len(worker_id) > 128:
            raise ValueError("worker_id must be a non-empty string of at most 128 characters")
        instance_id = uuid.uuid4().hex
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT runtime_generation FROM mission_worker_generations WHERE worker_id=? ORDER BY runtime_generation DESC LIMIT 1",
                (worker_id,),
            ).fetchone()
            generation = int(previous[0]) + 1 if previous else 1
            db.execute(
                "UPDATE mission_worker_generations SET state='SUPERSEDED' WHERE worker_id=? AND state='ACTIVE'",
                (worker_id,),
            )
            db.execute(
                "INSERT INTO mission_worker_generations(worker_id,runtime_generation,worker_instance_id,state,started_at) VALUES(?,?,?,'ACTIVE',?)",
                (worker_id, generation, instance_id, _utc_text(datetime.now(timezone.utc))),
            )
        return WorkerIdentity(worker_id, instance_id, generation)

    @staticmethod
    def _assert_worker_generation(db: sqlite3.Connection, worker_instance_id: str, runtime_generation: int | None) -> int:
        row = db.execute(
            "SELECT worker_id,runtime_generation,state FROM mission_worker_generations WHERE worker_instance_id=?",
            (worker_instance_id,),
        ).fetchone()
        if row is None:
            # Preserve the low-level queue API for legacy callers and migration
            # tests, but never allow a known logical worker to bypass registration.
            logical = db.execute(
                "SELECT 1 FROM mission_worker_generations WHERE worker_id=? LIMIT 1",
                (worker_instance_id,),
            ).fetchone()
            if logical or runtime_generation is not None:
                raise LeaseLostError("worker instance is not the registered current generation")
            return 0
        worker_id, generation, state = str(row[0]), int(row[1]), str(row[2])
        current = db.execute(
            "SELECT runtime_generation,worker_instance_id,state FROM mission_worker_generations WHERE worker_id=? ORDER BY runtime_generation DESC LIMIT 1",
            (worker_id,),
        ).fetchone()
        if (
            state != "ACTIVE"
            or runtime_generation is None
            or int(runtime_generation) != generation
            or current is None
            or int(current[0]) != generation
            or str(current[1]) != worker_instance_id
            or str(current[2]) != "ACTIVE"
        ):
            raise LeaseLostError("worker instance is not the registered current generation")
        return generation

    def validate_execution_fence(self, fence: ExecutionFence, *, db: sqlite3.Connection | None = None, allow_claimed: bool = False) -> None:
        """Read authoritative queue facts and let ExecutionFence compare them centrally."""
        if not isinstance(fence, ExecutionFence) or fence.queue is not self:
            raise ExecutionFenceError("execution fence belongs to another queue")
        context = nullcontext(db) if db is not None else sqlite3.connect(self.db_path)
        with context as connection:
            target_path = str(Path(self.db_path).resolve())
            schema = None
            for _seq, name, path in connection.execute("PRAGMA database_list"):
                if path and str(Path(path).resolve()) == target_path:
                    schema = '"' + str(name).replace('"', '""') + '"'
                    break
            if schema is None:
                raise ExecutionFenceError("queue database is not attached to the validation transaction")
            registered = connection.execute(
                f"SELECT worker_id,runtime_generation,worker_instance_id,state FROM {schema}.mission_worker_generations WHERE worker_instance_id=?",
                (fence.worker_instance_id,),
            ).fetchone()
            if registered is None:
                raise ExecutionFenceError("execution fence worker instance is not registered")
            current = connection.execute(
                f"SELECT runtime_generation,worker_instance_id,state FROM {schema}.mission_worker_generations WHERE worker_id=? ORDER BY runtime_generation DESC LIMIT 1",
                (fence.worker_id,),
            ).fetchone()
            state: dict[str, Any] = {
                "registered_worker_id": str(registered[0]),
                "registered_runtime_generation": int(registered[1]),
                "registered_worker_instance_id": str(registered[2]),
                "worker_state": str(registered[3]),
                "current_runtime_generation": int(current[0]) if current else None,
                "current_worker_instance_id": str(current[1]) if current else None,
                "current_worker_state": str(current[2]) if current else None,
            }
            if fence.lease_epoch is not None:
                if not fence.mission_id:
                    raise ExecutionFenceError("execution fence mission is missing")
                row = connection.execute(
                    f"SELECT mission_id,state,lease_owner,lease_epoch,lease_expires_at,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM {schema}.mission_queue WHERE mission_id=?",
                    (fence.mission_id,),
                ).fetchone()
                if row is None:
                    raise ExecutionFenceError("execution fence queue mission is missing")
                state.update({
                    "queue_mission_id": str(row[0]),
                    "queue_state": str(row[1]),
                    "lease_owner": row[2],
                    "lease_epoch": int(row[3]),
                    "lease_expires_at": row[4],
                    "queue_worker_instance_id": row[5],
                    "queue_runtime_generation": int(row[6]),
                    "claim_phase": str(row[7]),
                    "claim_fence_id": str(row[8]),
                })
        fence.assert_queue_state(state, allow_claimed=allow_claimed)

    def deactivate_worker(self, identity: WorkerIdentity, *, execution_fence: ExecutionFence | None = None) -> None:
        """Retire a normally stopped generation without releasing its lease."""
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            if self.require_execution_fence and execution_fence is None:
                raise ExecutionFenceError("worker retirement requires an execution fence")
            if execution_fence is not None:
                if execution_fence.worker_instance_id != identity.worker_instance_id:
                    raise ExecutionFenceError("worker retirement identity mismatch")
                execution_fence.assert_current(db=db)
            updated = db.execute(
                "UPDATE mission_worker_generations SET state='STOPPED' WHERE worker_id=? AND runtime_generation=? AND worker_instance_id=? AND state='ACTIVE'",
                (identity.worker_id, identity.runtime_generation, identity.worker_instance_id),
            )
            if updated.rowcount != 1:
                raise LeaseLostError("worker generation was superseded before shutdown")

    def enqueue(self, mission_id: str, *, available_at: str | None = None, state: WorkerMissionState = WorkerMissionState.QUEUED) -> QueueItem:
        if not mission_id.strip():
            raise ValueError("mission_id required")
        available = _utc_text(_utc_datetime(available_at, field_name="available_at"))
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO mission_queue(mission_id,state,attempts,available_at,claimed_at,last_error) VALUES(?,?,?,?,NULL,'') ON CONFLICT(mission_id) DO UPDATE SET state=excluded.state,available_at=excluded.available_at,claimed_at=NULL,last_error='',lease_owner=NULL,lease_expires_at=NULL,worker_instance_id=NULL,runtime_generation=0,claim_phase='NONE',claim_fence_id='' WHERE mission_queue.state != ?", (mission_id, state.value, 0, available, WorkerMissionState.EXECUTING.value))
            row = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError("unknown queued mission")
            item = self._item_from_row(row)
        return item

    def get(self, mission_id: str) -> QueueItem:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM mission_queue WHERE mission_id=?", (mission_id,)).fetchone()
        if row is None:
            raise KeyError("unknown queued mission")
        return self._item_from_row(row)

    def claim_next(self, *, now: str | None = None, worker_id: str = "worker", lease_seconds: int = 60, worker_instance_id: str | None = None, runtime_generation: int | None = None, execution_fence: ExecutionFence | None = None) -> QueueItem | None:
        if not worker_id.strip():
            raise ValueError("worker_id required")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        moment_dt = _utc_datetime(now, field_name="now")
        moment = _utc_text(moment_dt)
        expiry = _utc_text(moment_dt + timedelta(seconds=lease_seconds))
        instance_id = worker_instance_id or worker_id
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            if self.require_execution_fence and execution_fence is None:
                raise ExecutionFenceError("queue claim requires an execution fence")
            if execution_fence is not None:
                if execution_fence.mission_id is not None or execution_fence.worker_id != worker_id or execution_fence.worker_instance_id != instance_id or (runtime_generation is not None and execution_fence.runtime_generation != runtime_generation):
                    raise ExecutionFenceError("queue claim identity does not match execution fence")
                execution_fence.assert_current(db=db)
                generation = execution_fence.runtime_generation
            else:
                generation = self._assert_worker_generation(db, instance_id, runtime_generation)
            row = db.execute("SELECT mission_id FROM mission_queue WHERE state IN (?, ?, ?) AND available_at <= ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?) ORDER BY available_at,mission_id LIMIT 1", (WorkerMissionState.QUEUED.value, WorkerMissionState.SCHEDULED.value, WorkerMissionState.SLEEPING.value, moment, moment)).fetchone()
            if row is None:
                return None
            mission_id = row[0]
            updated = db.execute(
                "UPDATE mission_queue SET state=?, attempts=attempts+1, claimed_at=?, lease_owner=?, lease_expires_at=?, worker_instance_id=?, runtime_generation=?, lease_epoch=lease_epoch+1,claim_phase='CLAIMED',claim_fence_id='' "
                "WHERE mission_id=? AND state IN (?, ?, ?) AND available_at <= ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?)",
                (
                    WorkerMissionState.EXECUTING.value,
                    moment,
                    worker_id,
                    expiry,
                    instance_id,
                    generation,
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
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if claimed is None:
                raise KeyError("unknown queued mission")
            item = self._item_from_row(claimed)
            lease_fence = (
                execution_fence.with_lease(item)
                if execution_fence is not None
                else ExecutionFence(
                    queue=self,
                    worker_id=worker_id,
                    worker_instance_id=instance_id,
                    runtime_generation=generation,
                    mission_id=mission_id,
                    lease_epoch=item.lease_epoch,
                )
            )
            db.execute(
                "UPDATE mission_queue SET claim_fence_id=? WHERE mission_id=? AND lease_epoch=? AND claim_phase='CLAIMED'",
                (lease_fence.lease_binding_id, mission_id, item.lease_epoch),
            )
            claimed = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if claimed is None:
                raise KeyError("unknown queued mission")
            return self._item_from_row(claimed)

    def mark_claim_bound(self, execution_fence: ExecutionFence, *, mission_store: Any | None = None) -> QueueItem:
        """Verify MissionStore's complete durable marker before allowing dispatch."""
        if not execution_fence.mission_id or execution_fence.lease_epoch is None:
            raise ExecutionFenceError("claim binding requires a leased mission fence")
        if self.require_execution_fence and self.mission_store is None:
            raise ExecutionFenceError("strict queue claim binding requires its configured MissionStore")
        if self.mission_store is not None and mission_store is not None and self.mission_store is not mission_store:
            raise ExecutionFenceError("claim binding MissionStore does not match strict queue configuration")
        store = self.mission_store or mission_store
        if self.require_execution_fence and store is None:
            raise ExecutionFenceError("strict queue claim binding requires MissionStore verification")

        with sqlite3.connect(self.db_path, timeout=30) as db:
            mission_schema = None
            schemas = ["main"]
            if store is not None:
                from pathlib import Path

                queue_path = str(Path(self.db_path).resolve())
                mission_path = str(Path(store.db_path).resolve())
                if queue_path != mission_path:
                    db.execute("ATTACH DATABASE ? AS mission_store_db", (mission_path,))
                    schemas.append("mission_store_db")
                for schema in schemas:
                    mode = str(db.execute(f"PRAGMA {schema}.journal_mode").fetchone()[0]).lower()
                    if mode not in {"delete", "truncate", "persist"}:
                        raise ExecutionFenceError("claim binding requires rollback-journal mode for queue and mission stores")
                for _seq, name, path in db.execute("PRAGMA database_list"):
                    if path and str(Path(path).resolve()) == mission_path:
                        mission_schema = '"' + str(name).replace('"', '""') + '"'
                        break
                if mission_schema is None:
                    raise ExecutionFenceError("MissionStore database is not attached to claim transaction")

            db.execute("BEGIN IMMEDIATE")
            execution_fence.assert_current(db=db, allow_claimed=True)
            if store is not None:
                import json
                from .mission import Mission

                row = db.execute(
                    f"SELECT payload FROM {mission_schema}.missions WHERE mission_id=?",
                    (execution_fence.mission_id,),
                ).fetchone()
                if row is None:
                    raise ExecutionFenceError("MissionStore record is missing for queue claim binding")
                try:
                    mission = Mission.from_dict(json.loads(row[0]))
                except (KeyError, TypeError, ValueError) as exc:
                    raise ExecutionFenceError("MissionStore record is invalid for queue claim binding") from exc
                execution_fence.assert_current(mission=mission, db=db, allow_claimed=True)
                marker = mission.progress.get("active_execution_claim")
                expected = execution_fence.metadata()
                if (
                    not isinstance(marker, dict)
                    or marker.get("lease_binding_id") != execution_fence.lease_binding_id
                    or any(marker.get(key) != value for key, value in expected.items())
                ):
                    raise ExecutionFenceError("MissionStore claim marker does not match the complete execution fence")

            updated = db.execute(
                "UPDATE mission_queue SET claim_phase='BOUND' WHERE mission_id=? AND state=? AND lease_owner=? AND lease_epoch=? AND worker_instance_id=? AND runtime_generation=? AND claim_fence_id=? AND claim_phase IN ('CLAIMED','BOUND')",
                (
                    execution_fence.mission_id,
                    WorkerMissionState.EXECUTING.value,
                    execution_fence.worker_id,
                    execution_fence.lease_epoch,
                    execution_fence.worker_instance_id,
                    execution_fence.runtime_generation,
                    execution_fence.lease_binding_id,
                ),
            )
            if updated.rowcount != 1:
                raise LeaseLostError("mission claim changed before binding")
            row = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM mission_queue WHERE mission_id=?",
                (execution_fence.mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError("unknown queued mission")
            return self._item_from_row(row)

    def abort_unstarted_claim(self, execution_fence: ExecutionFence, *, error: str) -> QueueItem:
        """Quarantine a claim that could not bind MissionStore before dispatch."""
        if not execution_fence.mission_id or execution_fence.lease_epoch is None:
            raise ExecutionFenceError("claim abort requires a leased mission fence")
        moment = _utc_text(datetime.now(timezone.utc))
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            execution_fence.assert_current(db=db, allow_claimed=True)
            updated = db.execute(
                "UPDATE mission_queue SET state=?,available_at=?,last_error=?,claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL,worker_instance_id=NULL,runtime_generation=0,claim_phase='NONE',claim_fence_id='' WHERE mission_id=? AND state=? AND lease_owner=? AND lease_epoch=? AND worker_instance_id=? AND runtime_generation=? AND claim_fence_id=? AND claim_phase IN ('CLAIMED','BOUND')",
                (
                    WorkerMissionState.WAITING_FOR_TOOL.value,
                    moment,
                    error[:500],
                    execution_fence.mission_id,
                    WorkerMissionState.EXECUTING.value,
                    execution_fence.worker_id,
                    execution_fence.lease_epoch,
                    execution_fence.worker_instance_id,
                    execution_fence.runtime_generation,
                    execution_fence.lease_binding_id,
                ),
            )
            if updated.rowcount != 1:
                raise LeaseLostError("unstarted mission claim is no longer current")
            row = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM mission_queue WHERE mission_id=?",
                (execution_fence.mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError("unknown queued mission")
            return self._item_from_row(row)

    def finalize_unstarted_claim(self, execution_fence: ExecutionFence, state: WorkerMissionState, *, error: str) -> QueueItem:
        """Repair queue state from an already-persisted terminal mission without redispatch."""
        if state not in {
            WorkerMissionState.COMPLETED,
            WorkerMissionState.FAILED,
            WorkerMissionState.CANCELLED,
            WorkerMissionState.NEEDS_INPUT,
            WorkerMissionState.PARTIAL_SUCCESS,
            WorkerMissionState.WAITING_FOR_TOOL,
        }:
            raise ValueError("terminal reconciliation requires a terminal or quarantined queue state")
        if not execution_fence.mission_id or execution_fence.lease_epoch is None:
            raise ExecutionFenceError("terminal reconciliation requires a leased mission fence")
        moment = _utc_text(datetime.now(timezone.utc))
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            execution_fence.assert_current(db=db, allow_claimed=True)
            updated = db.execute(
                "UPDATE mission_queue SET state=?,last_error=?,claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL,worker_instance_id=NULL,runtime_generation=0,claim_phase='NONE',claim_fence_id='' WHERE mission_id=? AND state=? AND lease_owner=? AND lease_epoch=? AND worker_instance_id=? AND runtime_generation=? AND lease_expires_at>? AND claim_fence_id=? AND claim_phase IN ('CLAIMED','BOUND')",
                (
                    state.value,
                    error[:500],
                    execution_fence.mission_id,
                    WorkerMissionState.EXECUTING.value,
                    execution_fence.worker_id,
                    execution_fence.lease_epoch,
                    execution_fence.worker_instance_id,
                    execution_fence.runtime_generation,
                    moment,
                    execution_fence.lease_binding_id,
                ),
            )
            if updated.rowcount != 1:
                raise LeaseLostError("terminal mission claim is no longer current")
            row = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM mission_queue WHERE mission_id=?",
                (execution_fence.mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError("unknown queued mission")
            return self._item_from_row(row)

    def update(
        self,
        mission_id: str,
        state: WorkerMissionState,
        *,
        available_at: str | None = None,
        error: str = "",
        worker_id: str | None = None,
        lease_epoch: int | None = None,
        runtime_generation: int | None = None,
        worker_instance_id: str | None = None,
        execution_fence: ExecutionFence | None = None,
        now: str | None = None,
    ) -> QueueItem:
        if not isinstance(worker_id, str) or not worker_id.strip():
            raise LeaseLostError("worker mutation requires a lease owner")
        if lease_epoch is None:
            raise LeaseLostError("worker mutation requires a lease epoch")
        moment = _utc_text(_utc_datetime(now, field_name="now"))
        next_available = _utc_text(_utc_datetime(available_at, field_name="available_at")) if available_at is not None else None
        terminal = state.value in {"completed", "failed", "cancelled", "needs_input", "partial_success"}
        instance_id = worker_instance_id or worker_id
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            if self.require_execution_fence and execution_fence is None:
                raise ExecutionFenceError("queue update requires an execution fence")
            if execution_fence is not None:
                if execution_fence.mission_id != mission_id or execution_fence.worker_id != worker_id or execution_fence.worker_instance_id != instance_id or execution_fence.lease_epoch != lease_epoch:
                    raise ExecutionFenceError("queue update identity does not match execution fence")
                execution_fence.assert_current(db=db)
                generation = execution_fence.runtime_generation
            else:
                generation = self._assert_worker_generation(db, instance_id, runtime_generation)
            if terminal:
                updated = db.execute(
                    "UPDATE mission_queue SET state=?,available_at=COALESCE(?,available_at),last_error=?,"
                    "claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL,worker_instance_id=NULL,runtime_generation=0,claim_phase='NONE',claim_fence_id='' "
                    "WHERE mission_id=? AND lease_owner=? AND state=? AND lease_epoch=? AND worker_instance_id=? AND runtime_generation=? AND lease_expires_at > ?",
                    (state.value, next_available, error, mission_id, worker_id, WorkerMissionState.EXECUTING.value, lease_epoch, instance_id, generation, moment),
                )
            else:
                updated = db.execute(
                    "UPDATE mission_queue SET state=?,available_at=COALESCE(?,available_at),last_error=? "
                    "WHERE mission_id=? AND lease_owner=? AND state=? AND lease_epoch=? AND worker_instance_id=? AND runtime_generation=? AND lease_expires_at > ?",
                    (state.value, next_available, error, mission_id, worker_id, WorkerMissionState.EXECUTING.value, lease_epoch, instance_id, generation, moment),
                )
            if updated.rowcount != 1:
                raise LeaseLostError("worker lease is expired, superseded, or no longer current")
            row = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM mission_queue WHERE mission_id=?",
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
        runtime_generation: int | None = None,
        worker_instance_id: str | None = None,
        execution_fence: ExecutionFence | None = None,
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
        instance_id = worker_instance_id or worker_id
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            if self.require_execution_fence and execution_fence is None:
                raise ExecutionFenceError("queue release requires an execution fence")
            if execution_fence is not None:
                if execution_fence.mission_id != mission_id or execution_fence.worker_id != worker_id or execution_fence.worker_instance_id != instance_id or execution_fence.lease_epoch != lease_epoch:
                    raise ExecutionFenceError("queue release identity does not match execution fence")
                execution_fence.assert_current(db=db)
                generation = execution_fence.runtime_generation
            else:
                generation = self._assert_worker_generation(db, instance_id, runtime_generation)
            updated = db.execute(
                "UPDATE mission_queue SET state=?,available_at=COALESCE(?,available_at),last_error=?,"
                "claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL,worker_instance_id=NULL,runtime_generation=0,claim_phase='NONE',claim_fence_id='' "
                "WHERE mission_id=? AND lease_owner=? AND state=? AND lease_epoch=? AND worker_instance_id=? AND runtime_generation=? AND lease_expires_at > ?",
                (state.value, next_available, error, mission_id, worker_id, WorkerMissionState.EXECUTING.value, lease_epoch, instance_id, generation, moment),
            )
            if updated.rowcount != 1:
                raise LeaseLostError("worker lease is expired, superseded, or no longer current")
            row = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError("unknown queued mission")
            item = self._item_from_row(row)
        return item

    def heartbeat(self, mission_id: str, *, worker_id: str, lease_epoch: int | None = None, runtime_generation: int | None = None, worker_instance_id: str | None = None, execution_fence: ExecutionFence | None = None, now: str | None = None, lease_seconds: int = 60, allow_claimed: bool = False) -> QueueItem:
        if not worker_id.strip():
            raise LeaseLostError("worker heartbeat requires a lease owner")
        if lease_epoch is None:
            raise LeaseLostError("worker heartbeat requires a lease epoch")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        moment_dt = _utc_datetime(now, field_name="now")
        moment = _utc_text(moment_dt)
        expiry = _utc_text(moment_dt + timedelta(seconds=lease_seconds))
        instance_id = worker_instance_id or worker_id
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            if self.require_execution_fence and execution_fence is None:
                raise ExecutionFenceError("queue heartbeat requires an execution fence")
            if execution_fence is not None:
                if execution_fence.mission_id != mission_id or execution_fence.worker_id != worker_id or execution_fence.worker_instance_id != instance_id or execution_fence.lease_epoch != lease_epoch:
                    raise ExecutionFenceError("queue heartbeat identity does not match execution fence")
                execution_fence.assert_current(db=db, allow_claimed=allow_claimed)
                generation = execution_fence.runtime_generation
            else:
                generation = self._assert_worker_generation(db, instance_id, runtime_generation)
            updated = db.execute(
                "UPDATE mission_queue SET lease_expires_at=? WHERE mission_id=? AND state=? AND lease_owner=? "
                "AND lease_epoch=? AND worker_instance_id=? AND runtime_generation=? AND lease_expires_at > ?",
                (expiry, mission_id, WorkerMissionState.EXECUTING.value, worker_id, lease_epoch, instance_id, generation, moment),
            )
            if updated.rowcount != 1:
                raise LeaseLostError("worker lease is expired, superseded, or no longer current")
            row = db.execute(
                "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                raise KeyError("unknown queued mission")
            item = self._item_from_row(row)
        return item

    def _recover_strict(self, *, now: str | None, execution_fence: ExecutionFence | None, include_pending: bool) -> list[QueueItem]:
        """Atomically quarantine strict Owner missions at a restart/recovery boundary."""
        if execution_fence is None or execution_fence.lease_epoch is not None:
            raise ExecutionFenceError("strict mission recovery requires a supervisor identity fence")
        if self.mission_store is None:
            raise ExecutionFenceError("strict mission recovery requires its authoritative MissionStore")
        from pathlib import Path
        from .mission import Mission, TERMINAL_MISSION_STATUSES

        moment = _utc_text(_utc_datetime(now, field_name="now"))
        queue_path = str(Path(self.db_path).resolve())
        mission_path = str(Path(self.mission_store.db_path).resolve())
        with sqlite3.connect(self.db_path, timeout=30) as db:
            if queue_path != mission_path:
                db.execute("ATTACH DATABASE ? AS mission_store_db", (mission_path,))
            mission_schema = None
            for _sequence, name, path in db.execute("PRAGMA database_list"):
                if path and str(Path(path).resolve()) == mission_path:
                    mission_schema = '"' + str(name).replace('"', '""') + '"'
                    break
            if mission_schema is None:
                raise ExecutionFenceError("MissionStore is not attached to the restart recovery transaction")
            for schema in ("main", mission_schema):
                mode = str(db.execute(f"PRAGMA {schema}.journal_mode").fetchone()[0]).lower()
                if mode not in {"delete", "truncate", "persist"}:
                    raise ExecutionFenceError("restart recovery requires rollback-journal mode for queue and mission stores")

            db.execute("BEGIN IMMEDIATE")
            execution_fence.assert_current(db=db)
            columns = "mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id"
            if include_pending:
                pending_states = (
                    WorkerMissionState.QUEUED.value,
                    WorkerMissionState.SCHEDULED.value,
                    WorkerMissionState.SLEEPING.value,
                    WorkerMissionState.PLANNING.value,
                    WorkerMissionState.WAITING_FOR_TOOL.value,
                    WorkerMissionState.WAITING_FOR_MODEL.value,
                    WorkerMissionState.PAUSED.value,
                )
                placeholders = ",".join("?" for _ in pending_states)
                query = (
                    f"SELECT {columns} FROM mission_queue WHERE state IN ({placeholders}) "
                    "OR (state=? AND lease_expires_at IS NOT NULL AND lease_expires_at<=?) ORDER BY available_at,mission_id"
                )
                args = (*pending_states, WorkerMissionState.EXECUTING.value, moment)
            else:
                query = (
                    f"SELECT {columns} FROM mission_queue WHERE state=? "
                    "AND lease_expires_at IS NOT NULL AND lease_expires_at<=? ORDER BY available_at,mission_id"
                )
                args = (WorkerMissionState.EXECUTING.value, moment)
            rows = db.execute(query, args).fetchall()
            recovered: list[QueueItem] = []
            for queue_row in rows:
                item = self._item_from_row(queue_row)
                expired_claim = (
                    item.state is WorkerMissionState.EXECUTING
                    and item.lease_expires_at is not None
                    and _utc_datetime(item.lease_expires_at, field_name="lease_expires_at") <= _utc_datetime(moment, field_name="now")
                )
                mission_row = db.execute(
                    f"SELECT payload FROM {mission_schema}.missions WHERE mission_id=?",
                    (item.mission_id,),
                ).fetchone()
                if mission_row is None:
                    raise ExecutionFenceError("MissionStore record is missing during strict restart recovery")
                try:
                    encoded_before = str(mission_row[0])
                    mission = Mission.from_dict(json.loads(encoded_before))
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ExecutionFenceError("MissionStore record is invalid during strict restart recovery") from exc

                checkpoint_status = str((mission.checkpoint or {}).get("status", ""))
                in_flight = checkpoint_status in {"in_flight", "in_flight_parallel"}
                recovery_required = in_flight or mission.status is MissionStatus.RECOVERY_REQUIRED
                mission_changed = False
                if recovery_required:
                    if mission.status not in TERMINAL_MISSION_STATUSES:
                        mission.error = "worker restarted with an in-flight execution; effect reconciliation required"
                        mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error, restart_recovery=True)
                        mission_changed = True
                    if mission.status is not MissionStatus.RECOVERY_REQUIRED and mission.status in TERMINAL_MISSION_STATUSES:
                        # A genuinely terminal mission is not rewritten merely because a stale checkpoint remains.
                        recovery_required = False

                if not recovery_required and not mission.is_terminal:
                    mission.error = "Owner reauthorization required after worker restart"
                    mission.transition(MissionStatus.OWNER_REAUTH_REQUIRED, mission.error, restart_recovery=True)
                    mission.recovery_events.append({"event": "owner_reauthorization_required", "reason": "worker_restart"})
                    mission_changed = True

                active_claim = mission.progress.pop("active_execution_claim", None)
                if active_claim is not None:
                    mission_changed = True
                    if not mission.recovery_events or mission.recovery_events[-1].get("event") != "owner_reauthorization_required":
                        mission.recovery_events.append({"event": "worker_claim_retired", "reason": "worker_restart"})

                if mission_changed:
                    payload = mission.to_dict()
                    encoded_after = json.dumps(payload, ensure_ascii=False)
                    updated_mission = db.execute(
                        f"UPDATE {mission_schema}.missions SET payload=? WHERE mission_id=? AND payload=?",
                        (encoded_after, item.mission_id, encoded_before),
                    )
                    if updated_mission.rowcount != 1:
                        raise LeaseLostError("mission changed during strict restart recovery")

                if mission.status is MissionStatus.RECOVERY_REQUIRED:
                    next_state = WorkerMissionState.WAITING_FOR_TOOL
                elif mission.status is MissionStatus.OWNER_REAUTH_REQUIRED or mission.status is MissionStatus.OWNER_INPUT_REQUIRED:
                    next_state = WorkerMissionState.NEEDS_INPUT
                elif mission.status is MissionStatus.GOAL_COMPLETED:
                    next_state = WorkerMissionState.COMPLETED
                elif mission.status is MissionStatus.CANCELLED:
                    next_state = WorkerMissionState.CANCELLED
                elif mission.is_terminal:
                    next_state = WorkerMissionState.FAILED
                else:
                    # This branch is unreachable for a valid nonterminal mission,
                    # but conservatively prevents a malformed state from dispatch.
                    next_state = WorkerMissionState.NEEDS_INPUT

                reason = (
                    "external effect requires reconciliation"
                    if next_state is WorkerMissionState.WAITING_FOR_TOOL
                    else "Owner reauthorization required after worker restart"
                    if next_state is WorkerMissionState.NEEDS_INPUT
                    else item.last_error
                )
                epoch = item.lease_epoch + 1 if expired_claim else item.lease_epoch
                updated_queue = db.execute(
                    "UPDATE mission_queue SET state=?,lease_epoch=?,claimed_at=NULL,lease_owner=NULL,lease_expires_at=NULL,worker_instance_id=NULL,runtime_generation=0,claim_phase='NONE',claim_fence_id='',last_error=? WHERE mission_id=? AND state=? AND lease_epoch=?",
                    (next_state.value, epoch, str(reason)[:500], item.mission_id, item.state.value, item.lease_epoch),
                )
                if updated_queue.rowcount != 1:
                    raise LeaseLostError("queue item changed during strict restart recovery")
                final_row = db.execute(f"SELECT {columns} FROM mission_queue WHERE mission_id=?", (item.mission_id,)).fetchone()
                if final_row is None:
                    raise KeyError("unknown queued mission")
                recovered.append(self._item_from_row(final_row))
            return recovered

    def recover_expired(self, *, now: str | None = None, execution_fence: ExecutionFence | None = None) -> list[QueueItem]:
        if self.require_execution_fence:
            return self._recover_strict(now=now, execution_fence=execution_fence, include_pending=False)
        moment = _utc_text(_utc_datetime(now, field_name="now"))
        with sqlite3.connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT mission_id FROM mission_queue WHERE state=? AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?", (WorkerMissionState.EXECUTING.value, moment)).fetchall()
            if not rows:
                return []
            updated = db.execute(
                "UPDATE mission_queue SET state=?, claimed_at=NULL, lease_owner=NULL, lease_expires_at=NULL, worker_instance_id=NULL, runtime_generation=0, lease_epoch=lease_epoch+1, last_error=?,claim_phase='NONE',claim_fence_id='' "
                "WHERE state=? AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?",
                (WorkerMissionState.QUEUED.value, "worker lease expired", WorkerMissionState.EXECUTING.value, moment),
            )
            if updated.rowcount != len(rows):
                raise LeaseLostError("expired lease set changed during recovery")
            recovered = []
            for (mission_id,) in rows:
                row = db.execute(
                    "SELECT mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id FROM mission_queue WHERE mission_id=?",
                    (mission_id,),
                ).fetchone()
                if row is None:
                    raise KeyError("unknown mission")
                recovered.append(self._item_from_row(row))
            return recovered

    def recover_after_restart(self, *, now: str | None = None, execution_fence: ExecutionFence | None = None) -> list[QueueItem]:
        """Recover leases and quarantine durable Owner work before the first poll."""
        if self.require_execution_fence:
            return self._recover_strict(now=now, execution_fence=execution_fence, include_pending=True)
        return self.recover_expired(now=now, execution_fence=execution_fence)

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
        self.identity = queue.register_worker(worker_id)
        self.identity_fence = ExecutionFence.for_worker(queue, self.identity)
        self.logical_worker_id = self.identity.worker_id
        self.worker_instance_id = self.identity.worker_instance_id
        self.runtime_generation = self.identity.runtime_generation
        self.worker_id = self.identity.worker_id
        self.lease_seconds = lease_seconds
        self._recovery_complete = not queue.require_execution_fence

    def enqueue(self, mission_id: str) -> QueueItem:
        return self.queue.enqueue(mission_id)

    def recover_after_restart(self, *, now: str | None = None) -> list[QueueItem]:
        recovered = self.queue.recover_after_restart(now=now, execution_fence=self.identity_fence)
        self._recovery_complete = True
        return recovered

    def stop(self) -> None:
        self.queue.deactivate_worker(self.identity, execution_fence=self.identity_fence)

    def run_once(self, *, now: str | None = None, max_slices: int | None = None) -> QueueItem | None:
        if self.queue.require_execution_fence and not self._recovery_complete:
            raise ExecutionFenceError("strict worker startup restart recovery must complete before polling")
        if self.queue.require_execution_fence:
            # Expired claims can become recoverable after startup; quarantine
            # them before any subsequent claim instead of returning them to QUEUED.
            self.queue.recover_expired(now=now, execution_fence=self.identity_fence)
        # `now` is a claim-time override only. Renewals and writes use live UTC
        # time so a frozen caller timestamp cannot keep an expired lease alive.
        item = self.queue.claim_next(now=now, worker_id=self.worker_id, lease_seconds=self.lease_seconds, worker_instance_id=self.worker_instance_id, runtime_generation=self.runtime_generation, execution_fence=self.identity_fence)
        if item is None:
            return None
        execution_fence = self.identity_fence.with_lease(item)
        claim_bound = False

        def heartbeat(*, allow_claimed: bool = False) -> None:
            self.queue.heartbeat(
                item.mission_id,
                worker_id=self.worker_id,
                lease_epoch=item.lease_epoch,
                runtime_generation=self.runtime_generation,
                worker_instance_id=self.worker_instance_id,
                execution_fence=execution_fence,
                lease_seconds=self.lease_seconds,
                allow_claimed=allow_claimed,
            )

        try:
            # The initial renewal verifies a live CLAIMED lease before runtime
            # construction; it does not authorize dispatch.
            heartbeat(allow_claimed=True)
            runtime = self.runtime_factory()
            set_fence = getattr(runtime, "set_execution_fence", None)
            if callable(set_fence):
                set_fence(execution_fence)
            elif self.queue.require_execution_fence:
                raise ExecutionFenceError("strict worker runtime does not accept execution fences")
            bind_claim = getattr(runtime, "bind_execution_claim", None)
            if callable(bind_claim):
                binding = bind_claim(item.mission_id, execution_fence)
                if isinstance(binding, MissionClaimBinding) and binding.terminal_status is not None:
                    terminal_queue_state = {
                        MissionStatus.GOAL_COMPLETED: WorkerMissionState.COMPLETED,
                        MissionStatus.OWNER_INPUT_REQUIRED: WorkerMissionState.NEEDS_INPUT,
                        MissionStatus.OWNER_REAUTH_REQUIRED: WorkerMissionState.NEEDS_INPUT,
                        MissionStatus.AUTHORIZATION_BLOCKED: WorkerMissionState.FAILED,
                        MissionStatus.RECOVERY_REQUIRED: WorkerMissionState.WAITING_FOR_TOOL,
                        MissionStatus.CANCELLED: WorkerMissionState.CANCELLED,
                        MissionStatus.FAILED_RETRY_EXHAUSTED: WorkerMissionState.FAILED,
                        MissionStatus.SCOPE_BLOCKED: WorkerMissionState.FAILED,
                        MissionStatus.SAFETY_BLOCKED: WorkerMissionState.FAILED,
                        MissionStatus.RESOURCE_BLOCKED: WorkerMissionState.FAILED,
                    }.get(binding.terminal_status, WorkerMissionState.FAILED)
                    return self.queue.finalize_unstarted_claim(
                        execution_fence,
                        terminal_queue_state,
                        error=f"mission already terminal: {binding.terminal_status.value}",
                    )
                if self.queue.require_execution_fence:
                    # The runtime's MissionStore must have committed the full
                    # marker and advanced the queue through its strict verifier.
                    self.queue.validate_execution_fence(execution_fence)
                elif self.queue.get(item.mission_id).claim_phase != "BOUND":
                    self.queue.mark_claim_bound(execution_fence)
            elif self.queue.require_execution_fence:
                raise ExecutionFenceError("strict worker runtime cannot durably bind mission state")
            else:
                self.queue.mark_claim_bound(execution_fence)
            claim_bound = True
            heartbeat()
            mission = runtime.run_to_completion(item.mission_id, max_slices=max_slices, heartbeat=heartbeat)
        except (LeaseLostError, ExecutionFenceError):
            # Before BOUND, no runtime slice or handler has run; quarantine this
            # lease if it is still current. After BOUND, stale ownership must not
            # modify the replacement worker's outcome.
            if not claim_bound:
                try:
                    return self.queue.abort_unstarted_claim(
                        execution_fence,
                        error="mission claim could not be durably bound before dispatch",
                    )
                except (LeaseLostError, ExecutionFenceError):
                    pass
            return self.queue.get(item.mission_id)
        except Exception:
            if not claim_bound:
                try:
                    return self.queue.abort_unstarted_claim(
                        execution_fence,
                        error="worker could not bind mission claim before dispatch",
                    )
                except (LeaseLostError, ExecutionFenceError):
                    return self.queue.get(item.mission_id)
            # An unexpected runtime exception may follow an external effect.
            # Never convert that ambiguity into FAILED or retry it automatically.
            try:
                return self.queue.release(
                    item.mission_id,
                    WorkerMissionState.WAITING_FOR_TOOL,
                    error="worker runtime failed; execution outcome requires reconciliation",
                    worker_id=self.worker_id,
                    lease_epoch=item.lease_epoch,
                    runtime_generation=self.runtime_generation,
                    worker_instance_id=self.worker_instance_id,
                    execution_fence=execution_fence,
                )
            except (LeaseLostError, ExecutionFenceError):
                return self.queue.get(item.mission_id)
        state = {
            MissionStatus.GOAL_COMPLETED: WorkerMissionState.COMPLETED,
            MissionStatus.OWNER_INPUT_REQUIRED: WorkerMissionState.NEEDS_INPUT,
            MissionStatus.OWNER_REAUTH_REQUIRED: WorkerMissionState.NEEDS_INPUT,
            MissionStatus.AUTHORIZATION_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.RECOVERY_REQUIRED: WorkerMissionState.WAITING_FOR_TOOL,
            MissionStatus.CANCELLED: WorkerMissionState.CANCELLED,
            MissionStatus.FAILED_RETRY_EXHAUSTED: WorkerMissionState.FAILED,
            MissionStatus.SCOPE_BLOCKED: WorkerMissionState.FAILED,
            MissionStatus.SAFETY_BLOCKED: WorkerMissionState.FAILED,
        }.get(mission.status, WorkerMissionState.PARTIAL_SUCCESS if mission.evidence else WorkerMissionState.FAILED)
        # Recovery-required work is quarantined, not held under a live claim.
        # WAITING_FOR_TOOL is non-claimable until an authorized resolver changes
        # the queue state; release clears stale ownership while preserving epoch.
        persist_state = self.queue.release if state is WorkerMissionState.WAITING_FOR_TOOL else self.queue.update
        try:
            return persist_state(
                item.mission_id,
                state,
                error=mission.error,
                worker_id=self.worker_id,
                lease_epoch=item.lease_epoch,
                runtime_generation=self.runtime_generation,
                worker_instance_id=self.worker_instance_id,
                execution_fence=execution_fence,
            )
        except (LeaseLostError, ExecutionFenceError):
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


__all__ = ["ExecutionFence", "ExecutionFenceError", "MissionQueue", "MissionSchedule", "MissionScheduler", "MissionWorker", "QueueItem", "WorkerIdentity", "WorkerMissionState"]
