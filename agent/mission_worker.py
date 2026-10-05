from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable
from contextlib import contextmanager, nullcontext
import hashlib
import json
import sqlite3
import threading
import uuid

from .execution_fence import ExecutionFence, ExecutionFenceError
from .mission import Mission, MissionClaimBinding, MissionStatus


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
            for mission_id, state_value, available_at, claimed_at, lease_expires_at, lease_owner in db.execute(
                "SELECT mission_id,state,available_at,claimed_at,lease_expires_at,lease_owner FROM mission_queue"
            ).fetchall():
                try:
                    WorkerMissionState(state_value)
                    if available_at is None:
                        raise ValueError("available_at is missing")
                    normalized_available = _utc_text(_utc_datetime(available_at, field_name="available_at"))
                    normalized_claimed = _utc_text(_utc_datetime(claimed_at, field_name="claimed_at")) if claimed_at is not None else None
                    normalized_expiry = _utc_text(_utc_datetime(lease_expires_at, field_name="lease_expires_at")) if lease_expires_at is not None else None
                except (TypeError, ValueError):
                    db.execute(
                        "UPDATE mission_queue SET state=?,available_at=?,claimed_at=NULL,last_error=?,lease_owner=NULL,lease_expires_at=NULL,worker_instance_id=NULL,runtime_generation=0,claim_phase='NONE',claim_fence_id='' WHERE mission_id=?",
                        (
                            WorkerMissionState.WAITING_FOR_TOOL.value,
                            _utc_text(datetime.now(timezone.utc)),
                            "malformed persisted queue state/timestamp; manual recovery required",
                            mission_id,
                        ),
                    )
                    continue
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
            # SCHEDULED rows are never directly claimable. Only the Owner-bound
            # scheduler may validate their snapshot and atomically promote them
            # to QUEUED; otherwise a direct queue poll would bypass V9.
            claimable_states = (WorkerMissionState.QUEUED.value, WorkerMissionState.SLEEPING.value)
            placeholders = ",".join("?" for _ in claimable_states)
            row = db.execute(
                f"SELECT mission_id FROM mission_queue WHERE state IN ({placeholders}) AND available_at <= ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?) ORDER BY available_at,mission_id LIMIT 1",
                (*claimable_states, moment, moment),
            ).fetchone()
            if row is None:
                return None
            mission_id = row[0]
            updated = db.execute(
                "UPDATE mission_queue SET state=?, attempts=attempts+1, claimed_at=?, lease_owner=?, lease_expires_at=?, worker_instance_id=?, runtime_generation=?, lease_epoch=lease_epoch+1,claim_phase='CLAIMED',claim_fence_id='' "
                f"WHERE mission_id=? AND state IN ({placeholders}) AND available_at <= ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?)",
                (
                    WorkerMissionState.EXECUTING.value,
                    moment,
                    worker_id,
                    expiry,
                    instance_id,
                    generation,
                    mission_id,
                    *claimable_states,
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

    def __init__(self, queue: MissionQueue, runtime_factory: Callable[[], Any], *, worker_id: str = "worker", lease_seconds: int = DEFAULT_WORKER_LEASE_SECONDS, scheduler: Any | None = None, outcome_recorder: Callable[[str], Any] | None = None):
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self.queue = queue
        self.runtime_factory = runtime_factory
        if scheduler is not None and getattr(scheduler, "queue", None) is not queue:
            raise ValueError("worker scheduler must use the same MissionQueue")
        if (
            queue.require_execution_fence
            and scheduler is not None
            and getattr(scheduler, "mission_store", None) is not queue.mission_store
        ):
            raise ExecutionFenceError("strict worker scheduler must use the authoritative MissionStore")
        self.scheduler = scheduler
        if outcome_recorder is not None and not callable(outcome_recorder):
            raise TypeError("outcome_recorder must be callable")
        self.outcome_recorder = outcome_recorder
        self.outcome_recording_failures = 0
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

    def _record_terminal_outcome(self, mission_id: str) -> None:
        if self.outcome_recorder is None:
            return
        try:
            self.outcome_recorder(mission_id)
        except Exception:
            # Evaluation is observational only; never turn a committed Mission
            # result or ambiguous effect into an execution retry.
            self.outcome_recording_failures += 1

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
        if self.scheduler is not None:
            schedule_now = _utc_text(_utc_datetime(now, field_name="now"))
            self.scheduler.dispatch_due(now=schedule_now)
        # `now` is a claim-time override only. Renewals and writes use live UTC
        # time so a frozen caller timestamp cannot keep an expired lease alive.
        item = self.queue.claim_next(now=now, worker_id=self.worker_id, lease_seconds=self.lease_seconds, worker_instance_id=self.worker_instance_id, runtime_generation=self.runtime_generation, execution_fence=self.identity_fence)
        if item is None:
            return None
        execution_fence = self.identity_fence.with_lease(item)
        claim_bound = False
        heartbeat_lock = threading.Lock()
        heartbeat_stop = threading.Event()
        heartbeat_lost = threading.Event()
        heartbeat_thread: threading.Thread | None = None

        def heartbeat(*, allow_claimed: bool = False) -> None:
            if heartbeat_lost.is_set():
                raise LeaseLostError("worker lease heartbeat was lost")
            with heartbeat_lock:
                if heartbeat_lost.is_set():
                    raise LeaseLostError("worker lease heartbeat was lost")
                try:
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
                except Exception:
                    heartbeat_lost.set()
                    raise

        def keep_lease_alive() -> None:
            interval = min(30.0, max(0.1, self.lease_seconds / 3.0))
            while not heartbeat_stop.wait(interval):
                try:
                    heartbeat()
                except Exception:
                    # The runtime-facing heartbeat observes this flag and
                    # fails closed before the next protected dispatch/write.
                    return

        def stop_lease_keepalive() -> None:
            heartbeat_stop.set()
            if heartbeat_thread is not None and heartbeat_thread is not threading.current_thread():
                heartbeat_thread.join(timeout=min(10.0, max(1.0, self.lease_seconds / 3.0 + 1.0)))

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
                    self._record_terminal_outcome(item.mission_id)
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
            heartbeat_thread = threading.Thread(
                target=keep_lease_alive,
                name="mission-lease-keepalive",
                daemon=True,
            )
            heartbeat_thread.start()
            mission = runtime.run_to_completion(item.mission_id, max_slices=max_slices, heartbeat=heartbeat)
        except (LeaseLostError, ExecutionFenceError):
            stop_lease_keepalive()
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
            stop_lease_keepalive()
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
        if getattr(mission, "is_terminal", False):
            self._record_terminal_outcome(item.mission_id)
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
        finally:
            stop_lease_keepalive()


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

    def __init__(
        self,
        db_path: str | Path,
        queue: MissionQueue,
        *,
        mission_store: Any | None = None,
        fault_injector: Callable[[str], None] | None = None,
    ):
        self.db_path = str(db_path)
        self.queue = queue
        self.mission_store = mission_store or queue.mission_store
        self.fault_injector = fault_injector
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS mission_schedules ("
                "schedule_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, next_run_at TEXT NOT NULL, "
                "interval_seconds INTEGER, retry_limit INTEGER NOT NULL, retries INTEGER NOT NULL, state TEXT NOT NULL, "
                "owner_identity_ref TEXT NOT NULL DEFAULT '', authorization_hash TEXT NOT NULL DEFAULT '', "
                "authorization_version INTEGER NOT NULL DEFAULT 0, authorization_expires_at TEXT NOT NULL DEFAULT '', "
                "mission_integrity_hash TEXT NOT NULL DEFAULT '', scope_snapshot_hash TEXT NOT NULL DEFAULT '')"
            )
            columns = {row[1] for row in db.execute("PRAGMA table_info(mission_schedules)")}
            for column, definition in (
                ("owner_identity_ref", "TEXT NOT NULL DEFAULT ''"),
                ("authorization_hash", "TEXT NOT NULL DEFAULT ''"),
                ("authorization_version", "INTEGER NOT NULL DEFAULT 0"),
                ("authorization_expires_at", "TEXT NOT NULL DEFAULT ''"),
                ("mission_integrity_hash", "TEXT NOT NULL DEFAULT ''"),
                ("scope_snapshot_hash", "TEXT NOT NULL DEFAULT ''"),
            ):
                if column not in columns:
                    db.execute(f"ALTER TABLE mission_schedules ADD COLUMN {column} {definition}")
            for schedule_id, next_run_at, state_value in db.execute(
                "SELECT schedule_id,next_run_at,state FROM mission_schedules"
            ).fetchall():
                try:
                    schedule_state = WorkerMissionState(state_value)
                except (TypeError, ValueError):
                    db.execute(
                        "UPDATE mission_schedules SET state=? WHERE schedule_id=?",
                        (WorkerMissionState.NEEDS_INPUT.value, schedule_id),
                    )
                    continue
                if schedule_state is not WorkerMissionState.SCHEDULED:
                    continue
                try:
                    if next_run_at is None:
                        raise ValueError("next_run_at is missing")
                    normalized = _utc_text(_utc_datetime(next_run_at, field_name="next_run_at"))
                except (TypeError, ValueError):
                    db.execute(
                        "UPDATE mission_schedules SET state=? WHERE schedule_id=? AND state=?",
                        (WorkerMissionState.NEEDS_INPUT.value, schedule_id, WorkerMissionState.SCHEDULED.value),
                    )
                    continue
                if next_run_at != normalized:
                    db.execute("UPDATE mission_schedules SET next_run_at=? WHERE schedule_id=?", (normalized, schedule_id))

    @staticmethod
    def _quoted_schema(name: str) -> str:
        return '"' + str(name).replace('"', '""') + '"'

    @classmethod
    def _attach_database(cls, db: sqlite3.Connection, path: str | Path, alias: str) -> str:
        resolved = str(Path(path).resolve())
        for _sequence, name, existing_path in db.execute("PRAGMA database_list"):
            if existing_path and str(Path(existing_path).resolve()) == resolved:
                return cls._quoted_schema(str(name))
        db.execute(f"ATTACH DATABASE ? AS {alias}", (resolved,))
        return cls._quoted_schema(alias)

    @contextmanager
    def _attached_transaction(self):
        if self.mission_store is None:
            raise ExecutionFenceError("Owner-bound scheduling requires its authoritative MissionStore")
        import core.db as core_db

        owner_auth_path = Path(core_db.DB_PATH)
        if not owner_auth_path.exists():
            raise ExecutionFenceError("Owner authentication store is unavailable for scheduled dispatch")
        db = sqlite3.connect(self.db_path, timeout=30)
        try:
            queue_schema = self._attach_database(db, self.queue.db_path, "schedule_queue")
            mission_schema = self._attach_database(db, self.mission_store.db_path, "schedule_missions")
            owner_schema = self._attach_database(db, owner_auth_path, "schedule_owner_auth")
            schemas = {"main", queue_schema, mission_schema, owner_schema}
            for schema in schemas:
                mode = str(db.execute(f"PRAGMA {schema}.journal_mode").fetchone()[0]).lower()
                if mode not in {"delete", "truncate", "persist"}:
                    raise ExecutionFenceError("scheduled mission handoff requires rollback-journal mode for every participating store")
            db.execute("BEGIN IMMEDIATE")
            yield db, queue_schema, mission_schema, owner_schema
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _load_mission(db: sqlite3.Connection, mission_schema: str, mission_id: str) -> tuple[Mission, str]:
        import json

        row = db.execute(
            f"SELECT payload FROM {mission_schema}.missions WHERE mission_id=?", (mission_id,)
        ).fetchone()
        if row is None:
            raise KeyError("scheduled mission is missing from MissionStore")
        encoded = str(row[0])
        try:
            mission = Mission.from_dict(json.loads(encoded))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ExecutionFenceError("scheduled MissionStore record is invalid") from exc
        if mission.mission_id != mission_id:
            raise ExecutionFenceError("scheduled MissionStore identity mismatch")
        return mission, encoded

    @staticmethod
    def _scope_snapshot_hash(mission: Mission) -> str:
        scope = mission.scope_snapshot
        if not isinstance(scope, dict) or not scope:
            raise PermissionError("scheduled Mission ScopeSnapshot is required")
        target_id = scope.get("target_id")
        scope_names = scope.get("scope")
        if (
            not isinstance(target_id, str)
            or not target_id.strip()
            or len(target_id) > 256
            or not isinstance(scope_names, list)
            or not scope_names
            or len(scope_names) > 128
            or any(not isinstance(item, str) or not item.strip() or len(item) > 256 for item in scope_names)
        ):
            raise PermissionError("scheduled Mission ScopeSnapshot is malformed")
        try:
            encoded = json.dumps(
                scope,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise PermissionError("scheduled Mission ScopeSnapshot is not canonical JSON") from exc
        if len(encoded) > 64 * 1024:
            raise PermissionError("scheduled Mission ScopeSnapshot exceeds the size limit")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _validate_snapshot(
        mission: Mission,
        *,
        db: sqlite3.Connection,
        owner_schema: str,
        owner_identity_ref: str,
        authorization_hash: str,
        authorization_version: int,
        authorization_expires_at: str,
        at: str,
    ):
        from security.mission_authorization import MissionAuthorizationSnapshot

        if not mission.owner_identity_ref or mission.owner_identity_ref != owner_identity_ref:
            raise PermissionError("scheduled mission Owner binding changed")
        if not isinstance(mission.authorization_snapshot, dict):
            raise PermissionError("scheduled mission authorization snapshot is missing")
        try:
            snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot))
        except (KeyError, TypeError, ValueError) as exc:
            raise PermissionError("scheduled mission authorization snapshot is invalid") from exc
        if not isinstance(mission.provenance, dict) or not isinstance(mission.progress, dict):
            raise PermissionError("scheduled mission authorization provenance is invalid")
        if mission.checkpoint is not None and not isinstance(mission.checkpoint, dict):
            raise PermissionError("scheduled mission checkpoint is invalid")
        provenance_version = mission.provenance.get("authorization_snapshot_version", 0)
        if (
            snapshot.authorization_hash != authorization_hash
            or type(authorization_version) is not int
            or type(snapshot.version) is not int
            or type(provenance_version) is not int
            or snapshot.version != authorization_version
            or snapshot.expires_at != authorization_expires_at
            or provenance_version != snapshot.version
        ):
            raise PermissionError("scheduled mission authorization snapshot changed")
        valid, reason = snapshot.validate_for_mission(
            mission_id=mission.mission_id,
            owner_identity=owner_identity_ref,
            target_identity=snapshot.target_identity,
            version=authorization_version,
            at=at,
        )
        if not valid:
            raise PermissionError(reason)

        policy = mission.policy_snapshot if isinstance(mission.policy_snapshot, dict) else {}
        raw_evidence = policy.get("authentication")
        if not isinstance(raw_evidence, dict):
            raise PermissionError("scheduled mission Owner authentication evidence is missing")
        session_id = raw_evidence.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            raise PermissionError("scheduled mission Owner session binding is missing")
        try:
            evidence_method = str(raw_evidence["method"])
            evidence_authenticated_at = datetime.fromisoformat(str(raw_evidence["authenticated_at"]))
            evidence_expires_at = datetime.fromisoformat(str(raw_evidence["expires_at"]))
            evidence_proof = str(raw_evidence["proof_fingerprint"])
            evidence_request_id = str(raw_evidence["request_id"])
            evidence_nonce = str(raw_evidence["nonce"])
            evidence_signature = str(raw_evidence["signature"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PermissionError("scheduled mission Owner authentication evidence is invalid") from exc
        current_time = _utc_datetime(at, field_name="at")
        if evidence_authenticated_at.tzinfo is None:
            evidence_authenticated_at = evidence_authenticated_at.replace(tzinfo=timezone.utc)
        if evidence_expires_at.tzinfo is None:
            evidence_expires_at = evidence_expires_at.replace(tzinfo=timezone.utc)
        # OwnerAuthenticationEvidence's HMAC key is process-local. The bridge
        # authorizes and snapshots the request; the independent worker verifies
        # the immutable evidence bindings against the live Owner session store.
        if (
            evidence_proof != snapshot.owner_approval
            or evidence_request_id != mission.request_id
            or str(raw_evidence["expires_at"]) != snapshot.expires_at
            or len(evidence_nonce) < 24
            or len(evidence_signature) != 64
            or any(char not in "0123456789abcdef" for char in evidence_signature.lower())
            or evidence_authenticated_at > current_time
            or evidence_expires_at <= current_time
        ):
            raise PermissionError("scheduled mission Owner authentication evidence is stale or mismatched")
        try:
            session_row = db.execute(
                f"SELECT s.owner_id,s.status,s.expires_at,s.auth_method,a.status "
                f"FROM {owner_schema}.owner_sessions s "
                f"JOIN {owner_schema}.owner_accounts a ON a.owner_id=s.owner_id "
                "WHERE s.session_id=?",
                (session_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise PermissionError("scheduled mission Owner session store is unavailable") from exc
        if session_row is None or session_row[1] != "active" or session_row[4] != "active":
            raise PermissionError("scheduled mission Owner session is revoked or unavailable")
        try:
            session_expiry = datetime.fromisoformat(str(session_row[2]))
        except (TypeError, ValueError) as exc:
            raise PermissionError("scheduled mission Owner session expiry is invalid") from exc
        if session_expiry.tzinfo is None:
            session_expiry = session_expiry.replace(tzinfo=timezone.utc)
        if (
            session_expiry <= current_time
            or str(session_row[3]) != evidence_method
            or f"owner:{int(session_row[0])}" != owner_identity_ref
        ):
            raise PermissionError("scheduled mission Owner session is expired or mismatched")
        return snapshot

    def _call_fault_injector(self, boundary: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(boundary)

    def cancel_scheduled(self, mission_id: str) -> int:
        """Retire pending due rows before an authenticated Owner starts/resumes a mission."""
        if self.mission_store is None:
            raise ExecutionFenceError("Owner-bound schedule cancellation requires its authoritative MissionStore")
        if not isinstance(mission_id, str) or not mission_id.strip():
            raise ValueError("mission_id required")
        with sqlite3.connect(self.db_path, timeout=30) as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE mission_schedules SET state=? WHERE mission_id=? AND state=?",
                (
                    WorkerMissionState.CANCELLED.value,
                    mission_id,
                    WorkerMissionState.SCHEDULED.value,
                ),
            )
            db.commit()
            return changed.rowcount

    def schedule(
        self,
        mission_id: str,
        *,
        run_at: str,
        interval_seconds: int | None = None,
        retry_limit: int = 0,
        schedule_id: str | None = None,
        owner_identity_ref: str | None = None,
        authorization_snapshot: Any | None = None,
    ) -> MissionSchedule:
        if not isinstance(mission_id, str) or not mission_id.strip():
            raise ValueError("mission_id required")
        if interval_seconds is not None and (not isinstance(interval_seconds, int) or interval_seconds <= 0):
            raise ValueError("interval_seconds must be positive")
        if not isinstance(retry_limit, int) or retry_limit < 0:
            raise ValueError("retry_limit must be a non-negative integer")
        normalized_run_at = _utc_text(_utc_datetime(run_at, field_name="run_at"))
        new_schedule_id = schedule_id or uuid.uuid4().hex
        if not isinstance(new_schedule_id, str) or not new_schedule_id.strip() or len(new_schedule_id) > 128:
            raise ValueError("schedule_id must be a non-empty string of at most 128 characters")
        item = MissionSchedule(new_schedule_id, mission_id, normalized_run_at, interval_seconds, retry_limit)
        if self.mission_store is None:
            raise ExecutionFenceError("Owner-bound scheduling requires its authoritative MissionStore")

        from security.mission_authorization import MissionAuthorizationSnapshot

        if interval_seconds is not None:
            raise ValueError("recurring missions require a new Owner-authorized mission identity per occurrence")
        if retry_limit != 0:
            raise ValueError("scheduled mission retries are not supported")
        if not isinstance(owner_identity_ref, str) or not owner_identity_ref.strip():
            raise PermissionError("Owner identity is required for a mission-bound schedule")
        try:
            supplied_snapshot = (
                authorization_snapshot
                if isinstance(authorization_snapshot, MissionAuthorizationSnapshot)
                else MissionAuthorizationSnapshot.from_dict(dict(authorization_snapshot))
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PermissionError("Owner authorization snapshot is required for a mission-bound schedule") from exc

        current = _utc_text(datetime.now(timezone.utc))
        with self._attached_transaction() as (db, queue_schema, mission_schema, owner_schema):
            mission, _encoded = self._load_mission(db, mission_schema, mission_id)
            if not mission.verify_integrity() or len(mission.integrity_hash) != 64:
                raise PermissionError("scheduled Mission integrity is unavailable")
            mission_integrity_hash = mission.integrity_hash
            scope_snapshot_hash = self._scope_snapshot_hash(mission)
            persisted = self._validate_snapshot(
                mission,
                db=db,
                owner_schema=owner_schema,
                owner_identity_ref=owner_identity_ref,
                authorization_hash=supplied_snapshot.authorization_hash,
                authorization_version=supplied_snapshot.version,
                authorization_expires_at=supplied_snapshot.expires_at,
                at=current,
            )
            if persisted.to_dict() != supplied_snapshot.to_dict():
                raise PermissionError("scheduled authorization differs from the persisted mission snapshot")
            if _utc_datetime(normalized_run_at, field_name="run_at") >= _utc_datetime(persisted.expires_at, field_name="authorization_expires_at"):
                raise PermissionError("schedule due time is outside the Owner authorization window")
            if (
                mission.status is not MissionStatus.READY
                or mission.progress.get("pause_requested")
                or mission.progress.get("owner_cancel_requested")
                or mission.progress.get("active_execution_claim")
                or str((mission.checkpoint or {}).get("status", "")) in {"in_flight", "in_flight_parallel"}
            ):
                raise ValueError("mission is not in a schedulable READY state")

            queue_row = db.execute(
                f"SELECT state,lease_owner,lease_expires_at FROM {queue_schema}.mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if queue_row is not None:
                if queue_row[1] is not None or WorkerMissionState(queue_row[0]) is WorkerMissionState.EXECUTING:
                    raise PermissionError("active worker lease blocks scheduling")
                if WorkerMissionState(queue_row[0]) not in {
                    WorkerMissionState.QUEUED,
                    WorkerMissionState.NEEDS_INPUT,
                    WorkerMissionState.SCHEDULED,
                }:
                    raise ValueError("queue state is not eligible for a scheduled handoff")
            active = db.execute(
                "SELECT 1 FROM mission_schedules WHERE mission_id=? AND state=? LIMIT 1",
                (mission_id, WorkerMissionState.SCHEDULED.value),
            ).fetchone()
            if active is not None:
                db.execute(
                    "UPDATE mission_schedules SET state=? WHERE mission_id=? AND state=?",
                    (WorkerMissionState.CANCELLED.value, mission_id, WorkerMissionState.SCHEDULED.value),
                )
            db.execute(
                "INSERT INTO mission_schedules(schedule_id,mission_id,next_run_at,interval_seconds,retry_limit,retries,state,owner_identity_ref,authorization_hash,authorization_version,authorization_expires_at,mission_integrity_hash,scope_snapshot_hash) VALUES(?,?,?,?,?,?,?, ?,?,?,?,?,?)",
                (
                    item.schedule_id,
                    item.mission_id,
                    item.next_run_at,
                    None,
                    item.retry_limit,
                    item.retries,
                    item.state.value,
                    owner_identity_ref,
                    persisted.authorization_hash,
                    persisted.version,
                    persisted.expires_at,
                    mission_integrity_hash,
                    scope_snapshot_hash,
                ),
            )
            self._call_fault_injector("after_schedule_insert")
            if queue_row is None:
                db.execute(
                    f"INSERT INTO {queue_schema}.mission_queue(mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id) VALUES(?,?,?,?,NULL,'',NULL,NULL,0,NULL,0,'NONE','')",
                    (mission_id, WorkerMissionState.SCHEDULED.value, 0, normalized_run_at),
                )
            else:
                changed = db.execute(
                    f"UPDATE {queue_schema}.mission_queue SET state=?,available_at=?,claimed_at=NULL,last_error='',lease_owner=NULL,lease_expires_at=NULL,worker_instance_id=NULL,runtime_generation=0,claim_phase='NONE',claim_fence_id='' WHERE mission_id=? AND state=? AND lease_owner IS NULL",
                    (WorkerMissionState.SCHEDULED.value, normalized_run_at, mission_id, str(queue_row[0])),
                )
                if changed.rowcount != 1:
                    raise LeaseLostError("queue state changed during scheduled handoff")
            self._call_fault_injector("after_queue_scheduled")
        return item

    def get(self, schedule_id: str) -> MissionSchedule:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT schedule_id,mission_id,next_run_at,interval_seconds,retry_limit,retries,state FROM mission_schedules WHERE schedule_id=?", (schedule_id,)).fetchone()
        if row is None:
            raise KeyError("unknown schedule")
        return MissionSchedule(row[0], row[1], row[2], row[3], row[4], row[5], WorkerMissionState(row[6]))

    def dispatch_due(self, *, now: str, limit: int = 100) -> list[MissionSchedule]:
        if self.mission_store is None:
            raise ExecutionFenceError("Owner-bound dispatch requires its authoritative MissionStore")
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("schedule dispatch limit must be between 1 and 1000")
        current = _utc_datetime(now, field_name="now")
        current_text = _utc_text(current)
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute(
                "SELECT schedule_id FROM mission_schedules WHERE state=? AND (next_run_at<=? OR typeof(next_run_at)!='text' OR julianday(next_run_at) IS NULL) ORDER BY next_run_at,schedule_id LIMIT ?",
                (WorkerMissionState.SCHEDULED.value, current_text, limit),
            ).fetchall()
        dispatched = []
        for (schedule_id,) in rows:
            if self._dispatch_due_bound(schedule_id, now=current_text):
                dispatched.append(self.get(schedule_id))
        return dispatched

    @staticmethod
    def _quarantine_queue_row(db, queue_schema: str, mission_id: str, queue_row, *, now: str, reason: str) -> None:
        if queue_row is None:
            db.execute(
                f"INSERT INTO {queue_schema}.mission_queue(mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id) VALUES(?,?,?,?,NULL,?,NULL,NULL,0,NULL,0,'NONE','')",
                (mission_id, WorkerMissionState.NEEDS_INPUT.value, 0, now, reason),
            )
            return
        changed = db.execute(
            f"UPDATE {queue_schema}.mission_queue SET state=?,claimed_at=NULL,last_error=?,lease_owner=NULL,lease_expires_at=NULL,worker_instance_id=NULL,runtime_generation=0,claim_phase='NONE',claim_fence_id='' WHERE mission_id=? AND state IS ? AND lease_owner IS NULL",
            (WorkerMissionState.NEEDS_INPUT.value, reason, mission_id, queue_row[0]),
        )
        if changed.rowcount != 1:
            raise LeaseLostError("queue changed during scheduled authorization quarantine")

    def _quarantine_due_record(
        self, db, queue_schema: str, schedule_id: str, mission_id: str, *, now: str, reason: str
    ) -> None:
        queue_row = db.execute(
            f"SELECT state,lease_owner,lease_epoch FROM {queue_schema}.mission_queue WHERE mission_id=?",
            (mission_id,),
        ).fetchone()
        if queue_row is None or queue_row[1] is None:
            self._quarantine_queue_row(db, queue_schema, mission_id, queue_row, now=now, reason=reason)
        db.execute(
            "UPDATE mission_schedules SET state=? WHERE schedule_id=? AND state=?",
            (WorkerMissionState.NEEDS_INPUT.value, schedule_id, WorkerMissionState.SCHEDULED.value),
        )

    def _dispatch_due_bound(self, schedule_id: str, *, now: str) -> bool:
        with self._attached_transaction() as (db, queue_schema, mission_schema, owner_schema):
            row = db.execute(
                "SELECT schedule_id,mission_id,next_run_at,state,owner_identity_ref,authorization_hash,authorization_version,authorization_expires_at,mission_integrity_hash,scope_snapshot_hash "
                "FROM mission_schedules WHERE schedule_id=?",
                (schedule_id,),
            ).fetchone()
            if row is None or row[3] != WorkerMissionState.SCHEDULED.value:
                return False
            mission_id = str(row[1])
            try:
                if row[2] is None:
                    raise ValueError("scheduled next_run_at is missing")
                due_at = _utc_datetime(row[2], field_name="scheduled next_run_at")
            except (TypeError, ValueError):
                self._quarantine_due_record(
                    db,
                    queue_schema,
                    schedule_id,
                    mission_id,
                    now=now,
                    reason="scheduled due time is malformed; Owner review required",
                )
                return True
            if due_at > _utc_datetime(now, field_name="now"):
                return False
            schedule_owner, snapshot_hash = str(row[4]), str(row[5])
            snapshot_version = row[6] if type(row[6]) is int else -1
            snapshot_expiry = str(row[7])
            scheduled_mission_hash = str(row[8] or "")
            scheduled_scope_hash = str(row[9] or "")
            try:
                mission, encoded_before = self._load_mission(db, mission_schema, mission_id)
            except (KeyError, ExecutionFenceError, TypeError, ValueError, AttributeError):
                self._quarantine_due_record(
                    db,
                    queue_schema,
                    schedule_id,
                    mission_id,
                    now=now,
                    reason="scheduled mission payload is unavailable or malformed; manual recovery required",
                )
                return True

            queue_row = db.execute(
                f"SELECT state,lease_owner,lease_epoch FROM {queue_schema}.mission_queue WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if mission.is_terminal and mission.status is not MissionStatus.OWNER_REAUTH_REQUIRED:
                db.execute(
                    "UPDATE mission_schedules SET state=? WHERE schedule_id=? AND state=?",
                    (WorkerMissionState.CANCELLED.value, schedule_id, WorkerMissionState.SCHEDULED.value),
                )
                return True
            if queue_row is not None and queue_row[1] is not None:
                db.execute(
                    "UPDATE mission_schedules SET state=? WHERE schedule_id=? AND state=?",
                    (WorkerMissionState.CANCELLED.value, schedule_id, WorkerMissionState.SCHEDULED.value),
                )
                return True
            queue_state_invalid = False
            if queue_row is None:
                queue_state = None
            else:
                try:
                    queue_state = WorkerMissionState(queue_row[0])
                except (TypeError, ValueError):
                    queue_state = None
                    queue_state_invalid = True
            if not queue_state_invalid and queue_state in {
                WorkerMissionState.NEEDS_INPUT,
                WorkerMissionState.WAITING_FOR_TOOL,
            }:
                db.execute(
                    "UPDATE mission_schedules SET state=? WHERE schedule_id=? AND state=?",
                    (WorkerMissionState.NEEDS_INPUT.value, schedule_id, WorkerMissionState.SCHEDULED.value),
                )
                return True
            if not queue_state_invalid and queue_state is not None and queue_state is not WorkerMissionState.SCHEDULED:
                db.execute(
                    "UPDATE mission_schedules SET state=? WHERE schedule_id=? AND state=?",
                    (WorkerMissionState.CANCELLED.value, schedule_id, WorkerMissionState.SCHEDULED.value),
                )
                return True

            try:
                if (
                    not isinstance(mission.progress, dict)
                    or (mission.checkpoint is not None and not isinstance(mission.checkpoint, dict))
                    or not isinstance(mission.transitions, list)
                    or not isinstance(mission.recovery_events, list)
                ):
                    raise PermissionError("scheduled mission runtime state is malformed")
                if queue_state_invalid:
                    raise PermissionError("scheduled queue state is malformed")
                if (
                    not mission.verify_integrity()
                    or len(scheduled_mission_hash) != 64
                    or scheduled_mission_hash != mission.integrity_hash
                    or scheduled_scope_hash != self._scope_snapshot_hash(mission)
                ):
                    raise PermissionError("scheduled Mission integrity or ScopeSnapshot changed")
                self._validate_snapshot(
                    mission,
                    db=db,
                    owner_schema=owner_schema,
                    owner_identity_ref=schedule_owner,
                    authorization_hash=snapshot_hash,
                    authorization_version=snapshot_version,
                    authorization_expires_at=snapshot_expiry,
                    at=now,
                )
                if (
                    mission.status is not MissionStatus.READY
                    or mission.progress.get("pause_requested")
                    or mission.progress.get("owner_cancel_requested")
                    or mission.progress.get("active_execution_claim")
                    or str((mission.checkpoint or {}).get("status", "")) in {"in_flight", "in_flight_parallel"}
                ):
                    raise PermissionError("mission is not eligible for scheduled execution")
            except (PermissionError, TypeError, ValueError, AttributeError, KeyError):
                runtime_state_malformed = (
                    not isinstance(mission.progress, dict)
                    or (mission.checkpoint is not None and not isinstance(mission.checkpoint, dict))
                    or not isinstance(mission.transitions, list)
                    or not isinstance(mission.recovery_events, list)
                )
                if runtime_state_malformed:
                    recovery_reason = "scheduled mission runtime state is malformed; manual recovery required"
                    if not mission.is_terminal and mission.status is not MissionStatus.RECOVERY_REQUIRED:
                        prior_status = mission.status.value
                        mission.status = MissionStatus.RECOVERY_REQUIRED
                        mission.error = recovery_reason
                        if isinstance(mission.transitions, list):
                            mission.transitions.append(
                                {
                                    "from": prior_status,
                                    "to": MissionStatus.RECOVERY_REQUIRED.value,
                                    "reason": recovery_reason,
                                    "data": {"schedule_id": schedule_id},
                                    "iteration": mission.iteration_count,
                                }
                            )
                        if isinstance(mission.recovery_events, list):
                            mission.recovery_events.append(
                                {"event": "scheduled_runtime_state_malformed", "schedule_id": schedule_id}
                            )
                        encoded_after = json.dumps(mission.to_dict(), ensure_ascii=False)
                        changed = db.execute(
                            f"UPDATE {mission_schema}.missions SET payload=? WHERE mission_id=? AND payload=?",
                            (encoded_after, mission_id, encoded_before),
                        )
                        if changed.rowcount != 1:
                            raise LeaseLostError("mission changed during malformed-state quarantine")
                    if queue_row is None or queue_row[1] is None:
                        self._quarantine_queue_row(
                            db,
                            queue_schema,
                            mission_id,
                            queue_row,
                            now=now,
                            reason=recovery_reason,
                        )
                    db.execute(
                        "UPDATE mission_schedules SET state=? WHERE schedule_id=? AND state=?",
                        (WorkerMissionState.NEEDS_INPUT.value, schedule_id, WorkerMissionState.SCHEDULED.value),
                    )
                    return True

                progress = mission.progress if isinstance(mission.progress, dict) else {}
                checkpoint = mission.checkpoint if isinstance(mission.checkpoint, dict) else {}
                in_flight = (
                    mission.status is MissionStatus.RECOVERY_REQUIRED
                    or str(checkpoint.get("status", "")) in {"in_flight", "in_flight_parallel"}
                    or bool(progress.get("active_execution_claim"))
                )
                if not in_flight and not mission.is_terminal:
                    mission.error = "scheduled Owner authorization is stale, expired, or mismatched"
                    mission.transition(
                        MissionStatus.OWNER_REAUTH_REQUIRED,
                        mission.error,
                        schedule_id=schedule_id,
                    )
                    mission.recovery_events.append(
                        {"event": "scheduled_authorization_blocked", "schedule_id": schedule_id}
                    )
                    payload = mission.to_dict()
                    encoded_after = json.dumps(payload, ensure_ascii=False)
                    changed = db.execute(
                        f"UPDATE {mission_schema}.missions SET payload=? WHERE mission_id=? AND payload=?",
                        (encoded_after, mission_id, encoded_before),
                    )
                    if changed.rowcount != 1:
                        raise LeaseLostError("mission changed during scheduled authorization quarantine")
                if not in_flight:
                    self._quarantine_queue_row(
                        db,
                        queue_schema,
                        mission_id,
                        queue_row,
                        now=now,
                        reason="Owner reauthorization required for scheduled mission",
                    )
                db.execute(
                    "UPDATE mission_schedules SET state=? WHERE schedule_id=? AND state=?",
                    (WorkerMissionState.NEEDS_INPUT.value, schedule_id, WorkerMissionState.SCHEDULED.value),
                )
                return True

            if queue_row is None:
                db.execute(
                    f"INSERT INTO {queue_schema}.mission_queue(mission_id,state,attempts,available_at,claimed_at,last_error,lease_owner,lease_expires_at,lease_epoch,worker_instance_id,runtime_generation,claim_phase,claim_fence_id) VALUES(?,?,?,?,NULL,'',NULL,NULL,0,NULL,0,'NONE','')",
                    (mission_id, WorkerMissionState.QUEUED.value, 0, now),
                )
            else:
                changed = db.execute(
                    f"UPDATE {queue_schema}.mission_queue SET state=?,available_at=?,claimed_at=NULL,last_error='',lease_owner=NULL,lease_expires_at=NULL,worker_instance_id=NULL,runtime_generation=0,claim_phase='NONE',claim_fence_id='' WHERE mission_id=? AND state=? AND lease_owner IS NULL",
                    (WorkerMissionState.QUEUED.value, now, mission_id, str(queue_row[0])),
                )
                if changed.rowcount != 1:
                    raise LeaseLostError("queue changed during scheduled dispatch")
            self._call_fault_injector("after_queue_promotion")
            db.execute(
                "UPDATE mission_schedules SET state=? WHERE schedule_id=? AND state=?",
                (WorkerMissionState.COMPLETED.value, schedule_id, WorkerMissionState.SCHEDULED.value),
            )
            return True

    def mark_missed(self, schedule_id: str, *, now: str) -> MissionSchedule:
        item = self.get(schedule_id)
        if _utc_datetime(now, field_name="now") <= _utc_datetime(item.next_run_at, field_name="next_run_at"):
            return item
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE mission_schedules SET state=? WHERE schedule_id=?", (WorkerMissionState.SLEEPING.value, schedule_id))
        return self.get(schedule_id)


__all__ = ["ExecutionFence", "ExecutionFenceError", "MissionQueue", "MissionSchedule", "MissionScheduler", "MissionWorker", "QueueItem", "WorkerIdentity", "WorkerMissionState"]
