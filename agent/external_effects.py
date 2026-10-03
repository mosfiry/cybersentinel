from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence
import hashlib
import json
import re
import sqlite3

from .execution_fence import ExecutionFence, ExecutionFenceError


class EffectState(StrEnum):
    PLANNED = "PLANNED"
    RESERVED = "RESERVED"
    DISPATCHED = "DISPATCHED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    AMBIGUOUS = "AMBIGUOUS"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    UNKNOWN = "UNKNOWN"


_KNOWN_STATES = frozenset(state.value for state in EffectState)
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_CODE_RE = re.compile(r"^[A-Z0-9_]{1,64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class EffectLedgerError(RuntimeError):
    """Base error for durable external-effect ledger operations."""


class EffectRecoveryRequired(EffectLedgerError):
    """Dispatch must stop because its outcome cannot safely be replayed."""

    def __init__(self, effect_id: str, state: str, reason_code: str):
        self.effect_id = effect_id
        self.state = str(state)
        self.reason_code = reason_code
        super().__init__(f"effect {effect_id} is {self.state}; recovery is required")


class EffectDispatchBlocked(EffectRecoveryRequired):
    """A durable intent already exists and does not permit another dispatch."""

    def __init__(self, effect_id: str, state: str):
        super().__init__(effect_id, state, "DUPLICATE_DISPATCH_BLOCKED")


class EffectIdentityConflict(EffectRecoveryRequired):
    """One mission execution attempted to reuse its effect identity with new input."""

    def __init__(self, effect_id: str, state: str):
        super().__init__(effect_id, state, "EFFECT_IDENTITY_CONFLICT")


class EffectTransitionError(EffectLedgerError):
    """A requested state change is not valid for the observed effect state."""


@dataclass(frozen=True)
class ExternalEffect:
    effect_id: str
    mission_id: str
    task_id: str
    task_version: int
    execution_id: str
    request_id: str
    operation: str
    operation_fingerprint: str
    argument_sha256: str
    provider: str
    idempotency_key: str | None
    idempotency_supported: bool
    created_at: str
    updated_at: str
    state: str
    evidence_ref: str
    fence_ref: str
    authorization_hash: str
    worker_id: str
    worker_instance_id: str
    runtime_generation: int
    lease_epoch: int
    dispatch_id: str
    result_sha256: str
    error_code: str

    @property
    def requires_reconciliation(self) -> bool:
        return self.state in {
            EffectState.DISPATCHED,
            EffectState.AMBIGUOUS,
            EffectState.UNKNOWN,
            EffectState.RECOVERY_REQUIRED,
        } or self.state not in _KNOWN_STATES

    @property
    def safe_before_dispatch(self) -> bool:
        return self.state in {EffectState.PLANNED, EffectState.RESERVED}


class ExternalEffectLedger:
    """Durable write-ahead effect ledger stored alongside the fenced mission queue.

    Raw arguments, provider responses, exception messages, and credentials are
    never stored. The ledger retains fingerprints and outcome digests instead.
    Records have no automatic expiry: retention must outlive every redelivery
    and recovery path for the associated mission execution.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="microseconds")

    @staticmethod
    def _canonical_hash(value: Any) -> str:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=lambda item: f"<unserializable:{type(item).__name__}>",
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_code(value: str) -> str:
        if not isinstance(value, str) or not _CODE_RE.fullmatch(value):
            return "UNCLASSIFIED"
        return value

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _ensure_schema(db: sqlite3.Connection) -> None:
        journal_mode = str(db.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        if journal_mode not in {"delete", "truncate", "persist"}:
            raise EffectLedgerError("effect ledger requires durable rollback-journal SQLite mode")
        db.execute(
            """CREATE TABLE IF NOT EXISTS external_effects (
                effect_id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                task_version INTEGER NOT NULL,
                execution_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                operation_fingerprint TEXT NOT NULL,
                argument_sha256 TEXT NOT NULL,
                provider TEXT NOT NULL,
                idempotency_key TEXT,
                idempotency_supported INTEGER NOT NULL CHECK(idempotency_supported IN (0,1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                state TEXT NOT NULL,
                evidence_ref TEXT NOT NULL,
                fence_ref TEXT NOT NULL,
                authorization_hash TEXT NOT NULL,
                worker_id TEXT NOT NULL,
                worker_instance_id TEXT NOT NULL,
                runtime_generation INTEGER NOT NULL,
                lease_epoch INTEGER NOT NULL,
                dispatch_id TEXT NOT NULL DEFAULT '',
                result_sha256 TEXT NOT NULL DEFAULT '',
                error_code TEXT NOT NULL DEFAULT '',
                UNIQUE(mission_id, task_id, task_version, execution_id)
            )"""
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_external_effects_mission_state "
            "ON external_effects(mission_id, state, created_at)"
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS external_effect_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                effect_id TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                event_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                fence_ref TEXT NOT NULL,
                dispatch_id TEXT NOT NULL DEFAULT '',
                result_sha256 TEXT NOT NULL DEFAULT '',
                error_code TEXT NOT NULL DEFAULT ''
            )"""
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_external_effect_events_effect "
            "ON external_effect_events(effect_id, event_id)"
        )
        db.execute(
            """CREATE TRIGGER IF NOT EXISTS external_effect_events_no_update
               BEFORE UPDATE ON external_effect_events
               BEGIN SELECT RAISE(ABORT, 'external effect events are append-only'); END"""
        )
        db.execute(
            """CREATE TRIGGER IF NOT EXISTS external_effect_events_no_delete
               BEFORE DELETE ON external_effect_events
               BEGIN SELECT RAISE(ABORT, 'external effect events are append-only'); END"""
        )

    @staticmethod
    def _effect_from_row(row: sqlite3.Row) -> ExternalEffect:
        return ExternalEffect(
            effect_id=str(row["effect_id"]),
            mission_id=str(row["mission_id"]),
            task_id=str(row["task_id"]),
            task_version=int(row["task_version"]),
            execution_id=str(row["execution_id"]),
            request_id=str(row["request_id"]),
            operation=str(row["operation"]),
            operation_fingerprint=str(row["operation_fingerprint"]),
            argument_sha256=str(row["argument_sha256"]),
            provider=str(row["provider"]),
            idempotency_key=str(row["idempotency_key"]) if row["idempotency_key"] is not None else None,
            idempotency_supported=bool(row["idempotency_supported"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            state=str(row["state"]),
            evidence_ref=str(row["evidence_ref"]),
            fence_ref=str(row["fence_ref"]),
            authorization_hash=str(row["authorization_hash"]),
            worker_id=str(row["worker_id"]),
            worker_instance_id=str(row["worker_instance_id"]),
            runtime_generation=int(row["runtime_generation"]),
            lease_epoch=int(row["lease_epoch"]),
            dispatch_id=str(row["dispatch_id"]),
            result_sha256=str(row["result_sha256"]),
            error_code=str(row["error_code"]),
        )

    @staticmethod
    def _get_in_transaction(db: sqlite3.Connection, effect_id: str) -> sqlite3.Row | None:
        return db.execute("SELECT * FROM external_effects WHERE effect_id=?", (effect_id,)).fetchone()

    @staticmethod
    def _table_exists(db: sqlite3.Connection, table_name: str) -> bool:
        return db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
        ).fetchone() is not None

    @staticmethod
    def _append_event(
        db: sqlite3.Connection,
        *,
        effect_id: str,
        from_state: str | None,
        to_state: str,
        event_type: str,
        fence_ref: str,
        dispatch_id: str = "",
        result_sha256: str = "",
        error_code: str = "",
    ) -> None:
        db.execute(
            """INSERT INTO external_effect_events
               (effect_id,from_state,to_state,event_type,created_at,fence_ref,
                dispatch_id,result_sha256,error_code)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                effect_id,
                from_state,
                to_state,
                event_type,
                ExternalEffectLedger._now(),
                fence_ref,
                dispatch_id,
                result_sha256,
                error_code,
            ),
        )

    @staticmethod
    def _validate_inputs(
        fence: ExecutionFence,
        *,
        operation: str,
        operation_fingerprint: str,
        provider: str,
        argument_sha256: str,
        idempotency_supported: bool,
    ) -> dict[str, Any]:
        if not isinstance(fence, ExecutionFence):
            raise ExecutionFenceError("effect reservation requires an ExecutionFence")
        if not isinstance(operation, str) or not _IDENTIFIER_RE.fullmatch(operation):
            raise ValueError("effect operation must be a non-empty stable identifier")
        if not isinstance(provider, str) or not _IDENTIFIER_RE.fullmatch(provider):
            raise ValueError("effect provider must be a non-empty stable identifier")
        if not isinstance(operation_fingerprint, str) or not _FINGERPRINT_RE.fullmatch(operation_fingerprint):
            raise ValueError("operation fingerprint must be a lowercase SHA-256 digest")
        if argument_sha256 and (not isinstance(argument_sha256, str) or not _FINGERPRINT_RE.fullmatch(argument_sha256)):
            raise ValueError("argument fingerprint must be a lowercase SHA-256 digest")
        if not isinstance(idempotency_supported, bool):
            raise ValueError("idempotency_supported must be a boolean")
        metadata = fence.metadata()
        for field_name in ("mission_id", "task_id", "execution_id", "request_id", "authorization_hash", "fence_id"):
            if not str(metadata.get(field_name, "")).strip():
                raise ExecutionFenceError(f"effect reservation is missing fenced {field_name}")
        if int(metadata.get("task_version", 0)) <= 0 or int(metadata.get("lease_epoch", 0)) <= 0:
            raise ExecutionFenceError("effect reservation requires a positive task version and lease epoch")
        return metadata

    @staticmethod
    def _effect_id(metadata: Mapping[str, Any], provider: str, operation_fingerprint: str) -> str:
        identity = {
            "mission_id": metadata["mission_id"],
            "task_id": metadata["task_id"],
            "task_version": metadata["task_version"],
            "execution_id": metadata["execution_id"],
            "request_id": metadata["request_id"],
            "provider": provider,
            "operation_fingerprint": operation_fingerprint,
        }
        raw = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "ef_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _fence_reservation(
        fence: ExecutionFence,
        authorization_snapshot: Any | None,
        *,
        effect_id: str,
        provider: str,
        operation: str,
        operation_fingerprint: str,
    ) -> dict[str, Any]:
        return {
            **fence.metadata(),
            "authorization_snapshot": authorization_snapshot,
            "effect_id": effect_id,
            "provider": provider,
            "operation": operation,
            "operation_fingerprint": operation_fingerprint,
        }

    @staticmethod
    def _refresh_fence_fields(db: sqlite3.Connection, fence: ExecutionFence, effect_id: str, now: str) -> None:
        metadata = fence.metadata()
        db.execute(
            """UPDATE external_effects SET updated_at=?,fence_ref=?,authorization_hash=?,
               worker_id=?,worker_instance_id=?,runtime_generation=?,lease_epoch=?
               WHERE effect_id=?""",
            (
                now,
                metadata["fence_id"],
                metadata["authorization_hash"],
                metadata["worker_id"],
                metadata["worker_instance_id"],
                metadata["runtime_generation"],
                metadata["lease_epoch"],
                effect_id,
            ),
        )

    @staticmethod
    def _assert_same_intent(
        record: ExternalEffect,
        *,
        effect_id: str,
        operation: str,
        operation_fingerprint: str,
        argument_sha256: str,
        provider: str,
        idempotency_key: str | None,
        idempotency_supported: bool,
        request_id: str,
    ) -> None:
        if (
            record.effect_id != effect_id
            or record.provider != provider
            or record.operation != operation
            or record.operation_fingerprint != operation_fingerprint
            or record.argument_sha256 != argument_sha256
            or record.idempotency_supported != idempotency_supported
            or record.idempotency_key != idempotency_key
            or record.request_id != request_id
        ):
            raise EffectIdentityConflict(record.effect_id, record.state)

    def _promote_to_reserved(
        self,
        fence: ExecutionFence,
        *,
        effect_id: str,
        operation: str,
        operation_fingerprint: str,
        argument_sha256: str,
        provider: str,
        idempotency_key: str | None,
        idempotency_supported: bool,
        request_id: str,
        authorization_snapshot: Any | None,
    ) -> ExternalEffect:
        with self._transaction() as db:
            self._ensure_schema(db)
            reservation = self._fence_reservation(
                fence,
                authorization_snapshot,
                effect_id=effect_id,
                provider=provider,
                operation=operation,
                operation_fingerprint=operation_fingerprint,
            )
            stamped = fence.assert_effect_reservation(reservation, db=db)
            row = self._get_in_transaction(db, effect_id)
            if row is None:
                raise EffectTransitionError("planned effect disappeared before reservation")
            record = self._effect_from_row(row)
            self._assert_same_intent(
                record,
                effect_id=effect_id,
                operation=operation,
                operation_fingerprint=operation_fingerprint,
                argument_sha256=argument_sha256,
                provider=provider,
                idempotency_key=idempotency_key,
                idempotency_supported=idempotency_supported,
                request_id=request_id,
            )
            now = self._now()
            self._refresh_fence_fields(db, fence, effect_id, now)
            if record.state == EffectState.PLANNED:
                db.execute(
                    "UPDATE external_effects SET state='RESERVED',updated_at=? WHERE effect_id=? AND state='PLANNED'",
                    (now, effect_id),
                )
                self._append_event(
                    db,
                    effect_id=effect_id,
                    from_state=EffectState.PLANNED.value,
                    to_state=EffectState.RESERVED.value,
                    event_type="RESERVED",
                    fence_ref=str(stamped["fence_id"]),
                )
            elif record.state == EffectState.RESERVED:
                self._append_event(
                    db,
                    effect_id=effect_id,
                    from_state=EffectState.RESERVED.value,
                    to_state=EffectState.RESERVED.value,
                    event_type="RESERVATION_REVALIDATED",
                    fence_ref=str(stamped["fence_id"]),
                )
            else:
                raise EffectDispatchBlocked(record.effect_id, record.state)
            return self._effect_from_row(self._get_in_transaction(db, effect_id))

    def reserve(
        self,
        fence: ExecutionFence,
        *,
        operation: str,
        operation_fingerprint: str,
        provider: str,
        argument_sha256: str = "",
        idempotency_supported: bool = False,
        authorization_snapshot: Any | None = None,
        evidence_ref: str | None = None,
    ) -> ExternalEffect:
        """Persist PLANNED then RESERVED before any external/provider handler runs."""
        metadata = self._validate_inputs(
            fence,
            operation=operation,
            operation_fingerprint=operation_fingerprint,
            provider=provider,
            argument_sha256=argument_sha256,
            idempotency_supported=idempotency_supported,
        )
        effect_id = self._effect_id(metadata, provider, operation_fingerprint)
        idem_key = (
            "csfx_" + hashlib.sha256(effect_id.encode("utf-8")).hexdigest()
            if idempotency_supported
            else None
        )
        expected_evidence_ref = f"mission-execution:{metadata['mission_id']}:{metadata['execution_id']}"
        safe_evidence_ref = evidence_ref if evidence_ref is not None else expected_evidence_ref
        if safe_evidence_ref != expected_evidence_ref:
            raise ValueError("effect evidence reference must be the canonical mission-execution reference")
        if len(safe_evidence_ref) > 512:
            raise ValueError("evidence reference exceeds the supported length")
        now = self._now()

        with self._transaction() as db:
            self._ensure_schema(db)
            reservation = self._fence_reservation(
                fence,
                authorization_snapshot,
                effect_id=effect_id,
                provider=provider,
                operation=operation,
                operation_fingerprint=operation_fingerprint,
            )
            stamped = fence.assert_effect_reservation(reservation, db=db)
            existing = db.execute(
                """SELECT * FROM external_effects
                   WHERE mission_id=? AND task_id=? AND task_version=? AND execution_id=?""",
                (metadata["mission_id"], metadata["task_id"], metadata["task_version"], metadata["execution_id"]),
            ).fetchone()
            if existing is not None:
                record = self._effect_from_row(existing)
                self._assert_same_intent(
                    record,
                    effect_id=effect_id,
                    operation=operation,
                    operation_fingerprint=operation_fingerprint,
                    argument_sha256=argument_sha256,
                    provider=provider,
                    idempotency_key=idem_key,
                    idempotency_supported=idempotency_supported,
                    request_id=str(metadata["request_id"]),
                )
                if record.state not in {EffectState.PLANNED, EffectState.RESERVED}:
                    raise EffectDispatchBlocked(record.effect_id, record.state)
                self._refresh_fence_fields(db, fence, record.effect_id, now)
                if record.state == EffectState.RESERVED:
                    self._append_event(
                        db,
                        effect_id=record.effect_id,
                        from_state=EffectState.RESERVED.value,
                        to_state=EffectState.RESERVED.value,
                        event_type="RESERVATION_REVALIDATED",
                        fence_ref=str(stamped["fence_id"]),
                    )

            else:
                db.execute(
                    """INSERT INTO external_effects (
                       effect_id,mission_id,task_id,task_version,execution_id,request_id,
                       operation,operation_fingerprint,argument_sha256,provider,idempotency_key,
                       idempotency_supported,created_at,updated_at,state,evidence_ref,fence_ref,
                       authorization_hash,worker_id,worker_instance_id,runtime_generation,
                       lease_epoch,dispatch_id,result_sha256,error_code)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        effect_id,
                        metadata["mission_id"],
                        metadata["task_id"],
                        metadata["task_version"],
                        metadata["execution_id"],
                        metadata["request_id"],
                        operation,
                        operation_fingerprint,
                        argument_sha256,
                        provider,
                        idem_key,
                        int(idempotency_supported),
                        now,
                        now,
                        EffectState.PLANNED.value,
                        safe_evidence_ref,
                        stamped["fence_id"],
                        stamped["authorization_hash"],
                        stamped["worker_id"],
                        stamped["worker_instance_id"],
                        stamped["runtime_generation"],
                        stamped["lease_epoch"],
                        "",
                        "",
                        "",
                    ),
                )
                self._append_event(
                    db,
                    effect_id=effect_id,
                    from_state=None,
                    to_state=EffectState.PLANNED.value,
                    event_type="PLANNED",
                    fence_ref=str(stamped["fence_id"]),
                )

        return self._promote_to_reserved(
            fence,
            effect_id=effect_id,
            operation=operation,
            operation_fingerprint=operation_fingerprint,
            argument_sha256=argument_sha256,
            provider=provider,
            idempotency_key=idem_key,
            idempotency_supported=idempotency_supported,
            request_id=str(metadata["request_id"]),
            authorization_snapshot=authorization_snapshot,
        )

    def mark_dispatched(
        self,
        effect_id: str,
        fence: ExecutionFence,
        *,
        dispatch_id: str,
        authorization_snapshot: Any | None = None,
    ) -> ExternalEffect:
        if not isinstance(dispatch_id, str) or not dispatch_id.strip() or len(dispatch_id) > 128:
            raise ValueError("dispatch_id must be a non-empty attempt identifier")
        with self._transaction() as db:
            self._ensure_schema(db)
            row = self._get_in_transaction(db, effect_id)
            if row is None:
                raise KeyError("unknown_effect")
            record = self._effect_from_row(row)
            reservation = self._fence_reservation(
                fence,
                authorization_snapshot,
                effect_id=effect_id,
                provider=record.provider,
                operation=record.operation,
                operation_fingerprint=record.operation_fingerprint,
            )
            stamped = fence.assert_effect_reservation(reservation, db=db)
            if record.state != EffectState.RESERVED:
                raise EffectDispatchBlocked(record.effect_id, record.state)
            if record.fence_ref != str(stamped["fence_id"]):
                raise EffectDispatchBlocked(record.effect_id, record.state)
            now = self._now()
            changed = db.execute(
                """UPDATE external_effects SET state='DISPATCHED',dispatch_id=?,updated_at=?
                   WHERE effect_id=? AND state='RESERVED'""",
                (dispatch_id, now, effect_id),
            ).rowcount
            if changed != 1:
                current = self._get_in_transaction(db, effect_id)
                raise EffectDispatchBlocked(effect_id, str(current["state"]))
            self._append_event(
                db,
                effect_id=effect_id,
                from_state=EffectState.RESERVED.value,
                to_state=EffectState.DISPATCHED.value,
                event_type="DISPATCHED",
                fence_ref=str(stamped["fence_id"]),
                dispatch_id=dispatch_id,
            )
            return self._effect_from_row(self._get_in_transaction(db, effect_id))

    def mark_succeeded(
        self,
        effect_id: str,
        fence: ExecutionFence,
        *,
        dispatch_id: str,
        result: Any,
        authorization_snapshot: Any | None = None,
    ) -> ExternalEffect:
        result_sha256 = self._canonical_hash(result)
        with self._transaction() as db:
            self._ensure_schema(db)
            row = self._get_in_transaction(db, effect_id)
            if row is None:
                raise KeyError("unknown_effect")
            record = self._effect_from_row(row)
            reservation = self._fence_reservation(
                fence,
                authorization_snapshot,
                effect_id=effect_id,
                provider=record.provider,
                operation=record.operation,
                operation_fingerprint=record.operation_fingerprint,
            )
            stamped = fence.assert_effect_reservation(reservation, db=db)
            if record.dispatch_id != dispatch_id:
                raise EffectTransitionError("completion dispatch identity does not match the durable attempt")
            if record.state == EffectState.SUCCEEDED:
                if record.result_sha256 == result_sha256:
                    return record
                raise EffectIdentityConflict(record.effect_id, record.state)
            if record.state not in {
                EffectState.DISPATCHED,
                EffectState.AMBIGUOUS,
                EffectState.UNKNOWN,
                EffectState.RECOVERY_REQUIRED,
            }:
                raise EffectTransitionError(f"cannot complete an effect in state {record.state}")
            now = self._now()
            db.execute(
                """UPDATE external_effects SET state='SUCCEEDED',result_sha256=?,error_code='',
                   updated_at=?,fence_ref=? WHERE effect_id=?""",
                (result_sha256, now, stamped["fence_id"], effect_id),
            )
            self._append_event(
                db,
                effect_id=effect_id,
                from_state=record.state,
                to_state=EffectState.SUCCEEDED.value,
                event_type="LATE_RESULT_OBSERVED" if record.state != EffectState.DISPATCHED else "SUCCEEDED",
                fence_ref=str(stamped["fence_id"]),
                dispatch_id=dispatch_id,
                result_sha256=result_sha256,
            )
            return self._effect_from_row(self._get_in_transaction(db, effect_id))

    def mark_recovery_required(
        self,
        effect_id: str,
        fence: ExecutionFence,
        *,
        dispatch_id: str,
        reason_code: str,
        authorization_snapshot: Any | None = None,
    ) -> ExternalEffect:
        safe_reason = self._safe_code(reason_code)
        with self._transaction() as db:
            self._ensure_schema(db)
            row = self._get_in_transaction(db, effect_id)
            if row is None:
                raise KeyError("unknown_effect")
            record = self._effect_from_row(row)
            reservation = self._fence_reservation(
                fence,
                authorization_snapshot,
                effect_id=effect_id,
                provider=record.provider,
                operation=record.operation,
                operation_fingerprint=record.operation_fingerprint,
            )
            stamped = fence.assert_effect_reservation(reservation, db=db)
            if record.dispatch_id != dispatch_id:
                raise EffectTransitionError("recovery dispatch identity does not match the durable attempt")
            if record.state in {EffectState.SUCCEEDED, EffectState.FAILED, EffectState.RECOVERY_REQUIRED}:
                return record
            if record.state not in {EffectState.DISPATCHED, EffectState.AMBIGUOUS, EffectState.UNKNOWN}:
                raise EffectTransitionError(f"cannot require recovery for an effect in state {record.state}")
            now = self._now()
            if record.state == EffectState.DISPATCHED:
                db.execute(
                    "UPDATE external_effects SET state='AMBIGUOUS',updated_at=?,error_code=? WHERE effect_id=?",
                    (now, safe_reason, effect_id),
                )
                self._append_event(
                    db,
                    effect_id=effect_id,
                    from_state=EffectState.DISPATCHED.value,
                    to_state=EffectState.AMBIGUOUS.value,
                    event_type="AMBIGUOUS",
                    fence_ref=str(stamped["fence_id"]),
                    dispatch_id=dispatch_id,
                    error_code=safe_reason,
                )
            recovery_from_state = (
                EffectState.AMBIGUOUS.value
                if record.state == EffectState.DISPATCHED
                else str(record.state)
            )
            db.execute(
                "UPDATE external_effects SET state='RECOVERY_REQUIRED',updated_at=?,error_code=?,fence_ref=? WHERE effect_id=?",
                (now, safe_reason, stamped["fence_id"], effect_id),
            )
            self._append_event(
                db,
                effect_id=effect_id,
                from_state=recovery_from_state,
                to_state=EffectState.RECOVERY_REQUIRED.value,
                event_type="RECOVERY_REQUIRED",
                fence_ref=str(stamped["fence_id"]),
                dispatch_id=dispatch_id,
                error_code=safe_reason,
            )
            return self._effect_from_row(self._get_in_transaction(db, effect_id))

    def mark_unknown(
        self,
        effect_id: str,
        fence: ExecutionFence,
        *,
        dispatch_id: str,
        reason_code: str = "PROVIDER_STATUS_UNKNOWN",
        authorization_snapshot: Any | None = None,
    ) -> ExternalEffect:
        safe_reason = self._safe_code(reason_code)
        with self._transaction() as db:
            self._ensure_schema(db)
            row = self._get_in_transaction(db, effect_id)
            if row is None:
                raise KeyError("unknown_effect")
            record = self._effect_from_row(row)
            reservation = self._fence_reservation(
                fence,
                authorization_snapshot,
                effect_id=effect_id,
                provider=record.provider,
                operation=record.operation,
                operation_fingerprint=record.operation_fingerprint,
            )
            stamped = fence.assert_effect_reservation(reservation, db=db)
            if record.dispatch_id != dispatch_id:
                raise EffectTransitionError("unknown-status dispatch identity does not match the durable attempt")
            if record.state not in {EffectState.DISPATCHED, EffectState.AMBIGUOUS, EffectState.UNKNOWN}:
                raise EffectTransitionError(f"cannot mark an effect unknown from state {record.state}")
            if record.state == EffectState.UNKNOWN:
                return record
            now = self._now()
            db.execute(
                "UPDATE external_effects SET state='UNKNOWN',updated_at=?,error_code=?,fence_ref=? WHERE effect_id=?",
                (now, safe_reason, stamped["fence_id"], effect_id),
            )
            self._append_event(
                db,
                effect_id=effect_id,
                from_state=record.state,
                to_state=EffectState.UNKNOWN.value,
                event_type="UNKNOWN",
                fence_ref=str(stamped["fence_id"]),
                dispatch_id=dispatch_id,
                error_code=safe_reason,
            )
            return self._effect_from_row(self._get_in_transaction(db, effect_id))

    def mark_failed(
        self,
        effect_id: str,
        fence: ExecutionFence,
        *,
        reason_code: str,
        provider_confirmed_no_effect: bool,
        dispatch_id: str = "",
        authorization_snapshot: Any | None = None,
    ) -> ExternalEffect:
        if provider_confirmed_no_effect is not True:
            raise EffectTransitionError("FAILED requires explicit evidence that no effect was applied")
        safe_reason = self._safe_code(reason_code)
        with self._transaction() as db:
            self._ensure_schema(db)
            row = self._get_in_transaction(db, effect_id)
            if row is None:
                raise KeyError("unknown_effect")
            record = self._effect_from_row(row)
            reservation = self._fence_reservation(
                fence,
                authorization_snapshot,
                effect_id=effect_id,
                provider=record.provider,
                operation=record.operation,
                operation_fingerprint=record.operation_fingerprint,
            )
            stamped = fence.assert_effect_reservation(reservation, db=db)
            if record.state != EffectState.RESERVED or dispatch_id:
                raise EffectTransitionError("FAILED is only valid when provider dispatch was provably cancelled before start")
            now = self._now()
            db.execute(
                "UPDATE external_effects SET state='FAILED',updated_at=?,error_code=?,fence_ref=? WHERE effect_id=?",
                (now, safe_reason, stamped["fence_id"], effect_id),
            )
            self._append_event(
                db,
                effect_id=effect_id,
                from_state=record.state,
                to_state=EffectState.FAILED.value,
                event_type="FAILED_CONFIRMED_NO_EFFECT",
                fence_ref=str(stamped["fence_id"]),
                dispatch_id=dispatch_id,
                error_code=safe_reason,
            )
            return self._effect_from_row(self._get_in_transaction(db, effect_id))

    def get(self, effect_id: str) -> ExternalEffect | None:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            if not self._table_exists(connection, "external_effects"):
                return None
            row = connection.execute("SELECT * FROM external_effects WHERE effect_id=?", (effect_id,)).fetchone()
            return self._effect_from_row(row) if row is not None else None
        finally:
            connection.close()

    def list_effects(
        self,
        *,
        mission_id: str | None = None,
        states: Sequence[str | EffectState] | None = None,
        limit: int = 100,
    ) -> list[ExternalEffect]:
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("effect listing limit must be between 1 and 1000")
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            if not self._table_exists(connection, "external_effects"):
                return []
            conditions: list[str] = []
            parameters: list[Any] = []
            if mission_id is not None:
                conditions.append("mission_id=?")
                parameters.append(mission_id)
            if states is not None:
                state_values = [str(item) for item in states]
                if not state_values:
                    return []
                conditions.append(f"state IN ({','.join('?' for _ in state_values)})")
                parameters.extend(state_values)
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            rows = connection.execute(
                f"SELECT * FROM external_effects{where} ORDER BY created_at,effect_id LIMIT ?",
                (*parameters, limit),
            ).fetchall()
            return [self._effect_from_row(row) for row in rows]
        finally:
            connection.close()

    def history(self, effect_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("effect history limit must be between 1 and 1000")
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            if not self._table_exists(connection, "external_effect_events"):
                return []
            rows = connection.execute(
                "SELECT * FROM external_effect_events WHERE effect_id=? ORDER BY event_id LIMIT ?",
                (effect_id, limit),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()


__all__ = [
    "EffectDispatchBlocked",
    "EffectIdentityConflict",
    "EffectLedgerError",
    "EffectRecoveryRequired",
    "EffectState",
    "EffectTransitionError",
    "ExternalEffect",
    "ExternalEffectLedger",
]
