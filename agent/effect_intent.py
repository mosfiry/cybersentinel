from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any
import hashlib
import json
import sqlite3


class ExternalEffectState(str, Enum):
    PREPARED = "PREPARED"
    DISPATCHING = "DISPATCHING"
    CONFIRMED = "CONFIRMED"
    DEFINITE_NOT_SENT = "DEFINITE_NOT_SENT"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class EffectIntentError(RuntimeError):
    """Base error for fenced external-effect intent operations."""


class EffectIntentConflict(EffectIntentError):
    """The requested transition is invalid or conflicts with persisted intent."""


@dataclass(frozen=True)
class ExternalEffectIntent:
    effect_id: str
    idempotency_key: str
    mission_id: str
    task_id: str | None
    request_id: str | None
    logical_action_id: str
    tool_id: str
    payload_digest: str
    state: ExternalEffectState
    current_attempt: int
    claim_generation: int
    receipt_metadata: dict[str, Any] | None
    error: str
    reconciliation_status: str
    created_at: str
    updated_at: str


def canonical_json(value: Any) -> str:
    """Serialize a protocol payload deterministically; reject non-JSON values."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def stable_effect_identity(
    *,
    mission_id: str,
    task_id: str | None,
    request_id: str | None,
    logical_action_id: str,
    tool_id: str,
    payload: Any,
) -> tuple[str, str, str]:
    """Return stable effect/idempotency IDs and a digest, independent of attempts."""
    if not mission_id.strip() or not logical_action_id.strip() or not tool_id.strip():
        raise ValueError("mission_id, logical_action_id, and tool_id are required")
    identity = {
        "mission_id": mission_id,
        "task_id": task_id,
        "request_id": request_id,
        "logical_action_id": logical_action_id,
    }
    effect_id = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    payload_digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return effect_id, f"cybersentinel-effect-v1:{effect_id}", payload_digest


def initialize_effect_intent_schema(db: sqlite3.Connection) -> None:
    """Create M2.c tables additively and idempotently in the authority file."""
    db.execute(
        "CREATE TABLE IF NOT EXISTS external_effect_intents ("
        "effect_id TEXT PRIMARY KEY,"
        "idempotency_key TEXT NOT NULL UNIQUE,"
        "mission_id TEXT NOT NULL,"
        "task_id TEXT,"
        "request_id TEXT,"
        "logical_action_id TEXT NOT NULL,"
        "tool_id TEXT NOT NULL,"
        "payload_digest TEXT NOT NULL,"
        "state TEXT NOT NULL CHECK(state IN "
        "('PREPARED','DISPATCHING','CONFIRMED','DEFINITE_NOT_SENT','FAILED','UNKNOWN')),"
        "current_attempt INTEGER NOT NULL,"
        "receipt_json TEXT,"
        "last_error TEXT NOT NULL DEFAULT '',"
        "reconciliation_status TEXT NOT NULL DEFAULT '',"
        "created_at TEXT NOT NULL,"
        "updated_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS external_effect_intents_mission_state "
        "ON external_effect_intents(mission_id,state)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS external_effect_attempts ("
        "effect_id TEXT NOT NULL,"
        "attempt_number INTEGER NOT NULL,"
        "claim_generation INTEGER NOT NULL,"
        "worker_id TEXT NOT NULL,"
        "lease_id TEXT NOT NULL,"
        "claim_acquired_at TEXT NOT NULL,"
        "claim_expires_at TEXT NOT NULL,"
        "state TEXT NOT NULL CHECK(state IN "
        "('PREPARED','DISPATCHING','CONFIRMED','DEFINITE_NOT_SENT','FAILED','UNKNOWN')),"
        "outcome_claim_generation INTEGER,"
        "outcome_worker_id TEXT,"
        "created_at TEXT NOT NULL,"
        "dispatching_at TEXT,"
        "finished_at TEXT,"
        "proof TEXT NOT NULL DEFAULT '',"
        "PRIMARY KEY(effect_id,attempt_number))"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS external_effect_attempts_generation "
        "ON external_effect_attempts(effect_id,claim_generation)"
    )


def intent_from_row(row: tuple[Any, ...]) -> ExternalEffectIntent:
    receipt = json.loads(row[10]) if row[10] else None
    return ExternalEffectIntent(
        effect_id=str(row[0]),
        idempotency_key=str(row[1]),
        mission_id=str(row[2]),
        task_id=None if row[3] is None else str(row[3]),
        request_id=None if row[4] is None else str(row[4]),
        logical_action_id=str(row[5]),
        tool_id=str(row[6]),
        payload_digest=str(row[7]),
        state=ExternalEffectState(str(row[8])),
        current_attempt=int(row[9]),
        claim_generation=int(row[11]),
        receipt_metadata=receipt,
        error=str(row[12] or ""),
        reconciliation_status=str(row[13] or ""),
        created_at=str(row[14]),
        updated_at=str(row[15]),
    )


INTENT_SELECT = (
    "SELECT i.effect_id,i.idempotency_key,i.mission_id,i.task_id,i.request_id,"
    "i.logical_action_id,i.tool_id,i.payload_digest,i.state,i.current_attempt,"
    "i.receipt_json,a.claim_generation,i.last_error,i.reconciliation_status,"
    "i.created_at,i.updated_at "
    "FROM external_effect_intents AS i "
    "JOIN external_effect_attempts AS a "
    "ON a.effect_id=i.effect_id AND a.attempt_number=i.current_attempt"
)


__all__ = [
    "EffectIntentConflict",
    "EffectIntentError",
    "ExternalEffectIntent",
    "ExternalEffectState",
    "INTENT_SELECT",
    "canonical_json",
    "initialize_effect_intent_schema",
    "intent_from_row",
    "stable_effect_identity",
]


class ExternalEffectIntentRepository:
    """External-effect intent operations on the same SQLite file as MissionStore."""

    def __init__(self, mission_store):
        self._store = mission_store

    def with_claim(self, claim_provider, now_provider):
        return ClaimBoundEffectIntentRepository(self, claim_provider, now_provider)

    @staticmethod
    def _timestamp(value: str | None) -> str:
        from .mission_worker import _current_timestamp
        return _current_timestamp(value)

    def _require_current_mission(self, db, mission, claim, now: str | None) -> None:
        from .mission_worker import (
            LeaseClaimSnapshot,
            LeaseLostError,
            LeaseStatus,
            MissionQueue,
        )
        if not isinstance(claim, LeaseClaimSnapshot):
            raise LeaseLostError("a lease claim snapshot is required", lease_status=LeaseStatus.LEASE_LOST)
        if claim.mission_id != mission.mission_id:
            raise LeaseLostError("claim belongs to another mission", lease_status=LeaseStatus.LEASE_LOST)
        MissionQueue._require_current_claim(db, claim, self._timestamp(now))
        row = db.execute("SELECT payload,revision FROM missions WHERE mission_id=?", (mission.mission_id,)).fetchone()
        if row is None:
            raise KeyError("effect intent requires a persisted mission")
        payload = json.loads(row[0])
        if int(row[1]) != mission.revision or payload.get("integrity_hash") != mission.integrity_hash:
            raise ValueError("stale mission write rejected")

    @staticmethod
    def _select(db, effect_id: str):
        return db.execute(INTENT_SELECT + " WHERE i.effect_id=?", (effect_id,)).fetchone()

    @staticmethod
    def _insert_attempt(db, effect_id: str, attempt_number: int, claim, now: str) -> None:
        db.execute(
            "INSERT INTO external_effect_attempts("
            "effect_id,attempt_number,claim_generation,worker_id,lease_id,claim_acquired_at,"
            "claim_expires_at,state,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (effect_id, attempt_number, claim.generation, claim.worker_id, claim.lease_id,
             claim.acquired_at, claim.expires_at, ExternalEffectState.PREPARED.value, now),
        )

    def get(self, effect_id: str) -> ExternalEffectIntent:
        import sqlite3
        with sqlite3.connect(self._store.db_path) as db:
            row = self._select(db, effect_id)
        if row is None:
            raise KeyError("unknown external effect intent")
        return intent_from_row(row)

    def list_for_mission(self, mission_id: str) -> tuple[ExternalEffectIntent, ...]:
        import sqlite3
        with sqlite3.connect(self._store.db_path) as db:
            rows = db.execute(
                INTENT_SELECT + " WHERE i.mission_id=? ORDER BY i.created_at,i.effect_id",
                (mission_id,),
            ).fetchall()
        return tuple(intent_from_row(row) for row in rows)

    @staticmethod
    def _prepared_mission_candidate(mission, effect_id: str, logical_action_id: str, tool_id: str, claim):
        import copy
        candidate = copy.deepcopy(mission)
        candidate.checkpoint = {
            **dict(candidate.checkpoint or {}),
            "status": "in_flight",
            "effect_id": effect_id,
            "action_id": logical_action_id,
            "tool_id": tool_id,
            "claim_generation": claim.generation,
        }
        return candidate

    def prepare(
        self,
        mission,
        *,
        logical_action_id: str,
        tool_id: str,
        payload: Any,
        claim,
        task_id: str | None = None,
        request_id: str | None = None,
        now: str | None = None,
    ) -> ExternalEffectIntent:
        """Persist PREPARED and a claim-generation attempt before any dispatch."""
        import sqlite3
        task = task_id if task_id is not None else getattr(mission, "task_id", None)
        task = str(task) if task is not None and str(task) else None
        request = request_id if request_id is not None else getattr(mission, "request_id", None)
        request = str(request) if request is not None and str(request) else None
        effect_id, idempotency_key, payload_digest = stable_effect_identity(
            mission_id=str(mission.mission_id),
            task_id=task,
            request_id=request,
            logical_action_id=str(logical_action_id),
            tool_id=str(tool_id),
            payload=payload,
        )
        timestamp = self._timestamp(now)
        candidate = None
        with sqlite3.connect(self._store.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current_mission(db, mission, claim, now)
            row = self._select(db, effect_id)
            if row is None:
                db.execute(
                    "INSERT INTO external_effect_intents("
                    "effect_id,idempotency_key,mission_id,task_id,request_id,logical_action_id,tool_id,"
                    "payload_digest,state,current_attempt,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (effect_id, idempotency_key, mission.mission_id, task, request,
                     logical_action_id, tool_id, payload_digest, ExternalEffectState.PREPARED.value,
                     1, timestamp, timestamp),
                )
                self._insert_attempt(db, effect_id, 1, claim, timestamp)
                candidate = self._prepared_mission_candidate(
                    mission, effect_id, logical_action_id, tool_id, claim
                )
            else:
                existing = intent_from_row(row)
                if (
                    existing.mission_id != mission.mission_id
                    or existing.task_id != task
                    or existing.request_id != request
                    or existing.logical_action_id != logical_action_id
                    or existing.tool_id != tool_id
                    or existing.payload_digest != payload_digest
                    or existing.idempotency_key != idempotency_key
                ):
                    raise EffectIntentConflict("logical action was reused with different identity or payload")
                if existing.state is not ExternalEffectState.PREPARED:
                    raise EffectIntentConflict(
                        f"intent in {existing.state.value} requires explicit reconciliation; it cannot be dispatched"
                    )
                attempt = db.execute(
                    "SELECT claim_generation,worker_id,lease_id,state FROM external_effect_attempts "
                    "WHERE effect_id=? AND attempt_number=?",
                    (effect_id, existing.current_attempt),
                ).fetchone()
                if attempt is None:
                    raise EffectIntentConflict("intent attempt history is incomplete")
                if (
                    int(attempt[0]) == claim.generation
                    and str(attempt[1]) == claim.worker_id
                    and str(attempt[2]) == claim.lease_id
                    and str(attempt[3]) == ExternalEffectState.PREPARED.value
                ):
                    pass
                elif str(attempt[3]) == ExternalEffectState.PREPARED.value:
                    # A persisted PREPARED attempt has not crossed the required durable
                    # DISPATCHING gate; reclaim may safely supersede it under this protocol.
                    db.execute(
                        "UPDATE external_effect_attempts SET state=?,finished_at=?,proof=?,"
                        "outcome_claim_generation=?,outcome_worker_id=? "
                        "WHERE effect_id=? AND attempt_number=? AND state=?",
                        (ExternalEffectState.DEFINITE_NOT_SENT.value, timestamp,
                         "superseded while still PREPARED; dispatch gate was not crossed",
                         claim.generation, claim.worker_id, effect_id, existing.current_attempt,
                         ExternalEffectState.PREPARED.value),
                    )
                    next_attempt = existing.current_attempt + 1
                    self._insert_attempt(db, effect_id, next_attempt, claim, timestamp)
                    db.execute(
                        "UPDATE external_effect_intents SET current_attempt=?,updated_at=? "
                        "WHERE effect_id=? AND state=? AND current_attempt=?",
                        (next_attempt, timestamp, effect_id, ExternalEffectState.PREPARED.value,
                         existing.current_attempt),
                    )
                    candidate = self._prepared_mission_candidate(
                        mission, effect_id, logical_action_id, tool_id, claim
                    )
                else:
                    raise EffectIntentConflict("PREPARED intent has no dispatchable current attempt")
            if candidate is not None:
                integrity_hash, revision = self._store._save_mission_in_transaction(
                    db, candidate, claim=claim, now=now
                )
            result = self._select(db, effect_id)
        if candidate is not None:
            candidate.integrity_hash = integrity_hash
            candidate.revision = revision
            mission.__dict__.update(candidate.__dict__)
        return intent_from_row(result)

    def mark_dispatching(self, mission, effect_id: str, *, claim, now: str | None = None) -> ExternalEffectIntent:
        """Commit DISPATCHING durably; adapters must call this before starting a call."""
        import sqlite3
        timestamp = self._timestamp(now)
        with sqlite3.connect(self._store.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current_mission(db, mission, claim, now)
            row = self._select(db, effect_id)
            if row is None:
                raise KeyError("unknown external effect intent")
            intent = intent_from_row(row)
            if intent.mission_id != mission.mission_id or intent.state is not ExternalEffectState.PREPARED:
                raise EffectIntentConflict("only this mission's PREPARED intent may enter DISPATCHING")
            attempt = db.execute(
                "SELECT claim_generation,worker_id,lease_id,state FROM external_effect_attempts "
                "WHERE effect_id=? AND attempt_number=?",
                (effect_id, intent.current_attempt),
            ).fetchone()
            if (
                attempt is None
                or int(attempt[0]) != claim.generation
                or str(attempt[1]) != claim.worker_id
                or str(attempt[2]) != claim.lease_id
                or str(attempt[3]) != ExternalEffectState.PREPARED.value
            ):
                raise EffectIntentConflict("DISPATCHING requires the current PREPARED claim attempt")
            updated_attempt = db.execute(
                "UPDATE external_effect_attempts SET state=?,dispatching_at=? "
                "WHERE effect_id=? AND attempt_number=? AND state=? AND claim_generation=?",
                (ExternalEffectState.DISPATCHING.value, timestamp, effect_id, intent.current_attempt,
                 ExternalEffectState.PREPARED.value, claim.generation),
            )
            updated_intent = db.execute(
                "UPDATE external_effect_intents SET state=?,updated_at=? "
                "WHERE effect_id=? AND current_attempt=? AND state=?",
                (ExternalEffectState.DISPATCHING.value, timestamp, effect_id, intent.current_attempt,
                 ExternalEffectState.PREPARED.value),
            )
            if updated_attempt.rowcount != 1 or updated_intent.rowcount != 1:
                raise EffectIntentConflict("concurrent or invalid intent transition to DISPATCHING")
            result = self._select(db, effect_id)
        return intent_from_row(result)

    def _record_outcome_in_transaction(
        self,
        db,
        intent: ExternalEffectIntent,
        *,
        claim,
        state: ExternalEffectState,
        now: str,
        reason: str = "",
        proof: str = "",
        receipt_metadata: dict[str, Any] | None = None,
    ) -> None:
        if state not in {
            ExternalEffectState.CONFIRMED,
            ExternalEffectState.DEFINITE_NOT_SENT,
            ExternalEffectState.FAILED,
            ExternalEffectState.UNKNOWN,
        }:
            raise ValueError("outcome state is not terminal")
        if intent.state is not ExternalEffectState.DISPATCHING:
            raise EffectIntentConflict(f"cannot move {intent.state.value} to {state.value}")
        if state is ExternalEffectState.DEFINITE_NOT_SENT and not proof.strip():
            raise ValueError("DEFINITE_NOT_SENT requires adapter proof that the call did not begin")
        if state is ExternalEffectState.FAILED and not reason.strip():
            raise ValueError("FAILED requires a definitive reason")
        if state is ExternalEffectState.UNKNOWN and not reason.strip():
            raise ValueError("UNKNOWN requires an explicit reconciliation reason")
        receipt_json = canonical_json(receipt_metadata) if receipt_metadata is not None else None
        attempt_update = db.execute(
            "UPDATE external_effect_attempts SET state=?,finished_at=?,proof=?,"
            "outcome_claim_generation=?,outcome_worker_id=? "
            "WHERE effect_id=? AND attempt_number=? AND state=?",
            (state.value, now, proof, claim.generation, claim.worker_id, intent.effect_id,
             intent.current_attempt, ExternalEffectState.DISPATCHING.value),
        )
        intent_update = db.execute(
            "UPDATE external_effect_intents SET state=?,receipt_json=?,last_error=?,"
            "reconciliation_status=?,updated_at=? WHERE effect_id=? AND current_attempt=? AND state=?",
            (state.value, receipt_json, reason,
             "OWNER_RECONCILIATION_REQUIRED" if state is ExternalEffectState.UNKNOWN else "",
             now, intent.effect_id, intent.current_attempt, ExternalEffectState.DISPATCHING.value),
        )
        if attempt_update.rowcount != 1 or intent_update.rowcount != 1:
            raise EffectIntentConflict("concurrent or invalid terminal intent transition")

    def mark_definitely_not_sent(
        self, mission, effect_id: str, *, claim, proof: str, reason: str = "", now: str | None = None
    ) -> ExternalEffectIntent:
        import sqlite3
        timestamp = self._timestamp(now)
        with sqlite3.connect(self._store.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current_mission(db, mission, claim, now)
            row = self._select(db, effect_id)
            if row is None:
                raise KeyError("unknown external effect intent")
            intent = intent_from_row(row)
            if intent.mission_id != mission.mission_id:
                raise EffectIntentConflict("intent belongs to another mission")
            self._record_outcome_in_transaction(
                db, intent, claim=claim, state=ExternalEffectState.DEFINITE_NOT_SENT,
                now=timestamp, reason=reason, proof=proof,
            )
            result = self._select(db, effect_id)
        return intent_from_row(result)

    def mark_failed(
        self, mission, effect_id: str, *, claim, reason: str, receipt_metadata: dict[str, Any] | None = None,
        now: str | None = None,
    ) -> ExternalEffectIntent:
        import sqlite3
        timestamp = self._timestamp(now)
        with sqlite3.connect(self._store.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current_mission(db, mission, claim, now)
            row = self._select(db, effect_id)
            if row is None:
                raise KeyError("unknown external effect intent")
            intent = intent_from_row(row)
            if intent.mission_id != mission.mission_id:
                raise EffectIntentConflict("intent belongs to another mission")
            self._record_outcome_in_transaction(
                db, intent, claim=claim, state=ExternalEffectState.FAILED,
                now=timestamp, reason=reason, receipt_metadata=receipt_metadata,
            )
            result = self._select(db, effect_id)
        return intent_from_row(result)

    @staticmethod
    def _recovery_candidate(mission, effect_ids: list[str], reason: str):
        import copy
        from .mission import MissionStatus
        candidate = copy.deepcopy(mission)
        candidate.error = reason
        candidate.recovery_events.append({
            "event": "external_effect_unknown",
            "effect_ids": list(effect_ids),
            "reconciliation": "OWNER_RECONCILIATION_REQUIRED",
        })
        candidate.checkpoint = {
            **dict(candidate.checkpoint or {}),
            "reconciliation_status": "OWNER_RECONCILIATION_REQUIRED",
            "unknown_effect_ids": list(effect_ids),
        }
        candidate.transition(
            MissionStatus.RECOVERY_REQUIRED,
            reason,
            effect_ids=list(effect_ids),
            reconciliation="OWNER_RECONCILIATION_REQUIRED",
        )
        return candidate

    def mark_unknown(
        self, mission, effect_id: str, *, claim, reason: str, now: str | None = None
    ) -> ExternalEffectIntent:
        import sqlite3
        timestamp = self._timestamp(now)
        with sqlite3.connect(self._store.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current_mission(db, mission, claim, now)
            row = self._select(db, effect_id)
            if row is None:
                raise KeyError("unknown external effect intent")
            intent = intent_from_row(row)
            if intent.mission_id != mission.mission_id:
                raise EffectIntentConflict("intent belongs to another mission")
            self._record_outcome_in_transaction(
                db, intent, claim=claim, state=ExternalEffectState.UNKNOWN,
                now=timestamp, reason=reason,
            )
            candidate = self._recovery_candidate(mission, [effect_id], reason)
            integrity_hash, revision = self._store._save_mission_in_transaction(
                db, candidate, claim=claim, now=now
            )
            result = self._select(db, effect_id)
        candidate.integrity_hash = integrity_hash
        candidate.revision = revision
        mission.__dict__.update(candidate.__dict__)
        return intent_from_row(result)

    def recover_dispatching(self, mission, *, claim, now: str | None = None) -> tuple[ExternalEffectIntent, ...]:
        """On restart/reclaim, move every unresulted DISPATCHING effect to UNKNOWN."""
        import sqlite3
        timestamp = self._timestamp(now)
        with sqlite3.connect(self._store.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current_mission(db, mission, claim, now)
            rows = db.execute(
                INTENT_SELECT + " WHERE i.mission_id=? AND i.state=? ORDER BY i.created_at,i.effect_id",
                (mission.mission_id, ExternalEffectState.DISPATCHING.value),
            ).fetchall()
            if not rows:
                return ()
            active = [intent_from_row(row) for row in rows]
            effect_ids = [item.effect_id for item in active]
            reason = "external effect was DISPATCHING at restart; outcome is UNKNOWN and requires reconciliation"
            for intent in active:
                self._record_outcome_in_transaction(
                    db, intent, claim=claim, state=ExternalEffectState.UNKNOWN,
                    now=timestamp, reason=reason,
                )
            candidate = self._recovery_candidate(mission, effect_ids, reason)
            integrity_hash, revision = self._store._save_mission_in_transaction(
                db, candidate, claim=claim, now=now
            )
            results = tuple(intent_from_row(self._select(db, effect_id)) for effect_id in effect_ids)
        candidate.integrity_hash = integrity_hash
        candidate.revision = revision
        mission.__dict__.update(candidate.__dict__)
        return results

    def confirm(
        self,
        mission,
        effect_id: str,
        observation: dict[str, Any],
        *,
        claim,
        action_id: str | None = None,
        step_id: str | None = None,
        now: str | None = None,
    ) -> ExternalEffectIntent:
        """Atomically confirm one current result with its mission/evidence update."""
        import copy
        import sqlite3
        timestamp = self._timestamp(now)
        with sqlite3.connect(self._store.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current_mission(db, mission, claim, now)
            row = self._select(db, effect_id)
            if row is None:
                raise KeyError("unknown external effect intent")
            intent = intent_from_row(row)
            if intent.mission_id != mission.mission_id:
                raise EffectIntentConflict("intent belongs to another mission")
            if intent.state is not ExternalEffectState.DISPATCHING:
                raise EffectIntentConflict(f"cannot confirm intent in {intent.state.value}")
            candidate = copy.deepcopy(mission)
            result = {**dict(observation), "effect_id": effect_id}
            if any(str(item.get("effect_id", "")) == effect_id for item in candidate.observations):
                raise EffectIntentConflict("effect result was already persisted in mission observations")
            logical_action_id = action_id or intent.logical_action_id
            logical_step_id = step_id or str(result.get("step_id") or logical_action_id)
            result.setdefault("action_id", logical_action_id)
            result.setdefault("step_id", logical_step_id)
            result.setdefault("mission_id", mission.mission_id)
            candidate.record_observation(result)
            candidate.record_action(logical_action_id, logical_step_id, "completed", result)
            success = bool(result.get("success", result.get("ok", True)))
            candidate.evidence.append({
                "criterion_id": result.get("criterion_id", logical_step_id),
                "passed": success,
                "source": result.get("source", intent.tool_id),
                "result": result,
                "provenance": {
                    "mission_id": mission.mission_id,
                    "request_id": intent.request_id,
                    "action_id": logical_action_id,
                    "effect_id": effect_id,
                    "claim_generation": claim.generation,
                },
            })
            candidate.checkpoint = {
                **dict(candidate.checkpoint or {}),
                "status": "completed",
                "effect_id": effect_id,
                "action_id": logical_action_id,
                "step_id": logical_step_id,
            }
            self._record_outcome_in_transaction(
                db, intent, claim=claim, state=ExternalEffectState.CONFIRMED,
                now=timestamp, receipt_metadata=result,
            )
            integrity_hash, revision = self._store._save_mission_in_transaction(
                db, candidate, claim=claim, now=now
            )
            result_row = self._select(db, effect_id)
        candidate.integrity_hash = integrity_hash
        candidate.revision = revision
        mission.__dict__.update(candidate.__dict__)
        return intent_from_row(result_row)

    def rearm_definitely_not_sent(
        self, mission, effect_id: str, *, claim, proof: str, now: str | None = None
    ) -> ExternalEffectIntent:
        """Explicitly start a new attempt only after definite-not-sent proof."""
        import sqlite3
        if not proof.strip():
            raise ValueError("explicit retry requires proof that the prior call did not begin")
        timestamp = self._timestamp(now)
        with sqlite3.connect(self._store.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current_mission(db, mission, claim, now)
            row = self._select(db, effect_id)
            if row is None:
                raise KeyError("unknown external effect intent")
            intent = intent_from_row(row)
            if intent.mission_id != mission.mission_id or intent.state is not ExternalEffectState.DEFINITE_NOT_SENT:
                raise EffectIntentConflict("only DEFINITE_NOT_SENT intents may be explicitly re-armed")
            prior_attempt = db.execute(
                "SELECT state FROM external_effect_attempts WHERE effect_id=? AND attempt_number=?",
                (effect_id, intent.current_attempt),
            ).fetchone()
            if prior_attempt is None or str(prior_attempt[0]) != ExternalEffectState.DEFINITE_NOT_SENT.value:
                raise EffectIntentConflict("definite-not-sent attempt history is inconsistent")
            next_attempt = intent.current_attempt + 1
            self._insert_attempt(db, effect_id, next_attempt, claim, timestamp)
            updated = db.execute(
                "UPDATE external_effect_intents SET state=?,current_attempt=?,receipt_json=NULL,"
                "last_error='',reconciliation_status='',updated_at=? WHERE effect_id=? AND state=? AND current_attempt=?",
                (ExternalEffectState.PREPARED.value, next_attempt, timestamp, effect_id,
                 ExternalEffectState.DEFINITE_NOT_SENT.value, intent.current_attempt),
            )
            if updated.rowcount != 1:
                raise EffectIntentConflict("concurrent explicit retry transition")
            db.execute(
                "UPDATE external_effect_attempts SET proof=CASE WHEN proof='' THEN ? "
                "ELSE proof || char(10) || 'explicit retry: ' || ? END "
                "WHERE effect_id=? AND attempt_number=?",
                (proof, proof, effect_id, intent.current_attempt),
            )
            result = self._select(db, effect_id)
        return intent_from_row(result)


class ClaimBoundEffectIntentRepository:
    """MissionWorker-bound facade that injects its latest immutable claim snapshot."""

    def __init__(self, repository: ExternalEffectIntentRepository, claim_provider, now_provider):
        self._repository = repository
        self._claim_provider = claim_provider
        self._now_provider = now_provider

    def _claim(self):
        claim = self._claim_provider()
        if claim is None:
            raise ValueError("claim-bound effect intents require the current worker claim")
        return claim

    def get(self, effect_id: str) -> ExternalEffectIntent:
        return self._repository.get(effect_id)

    def list_for_mission(self, mission_id: str) -> tuple[ExternalEffectIntent, ...]:
        return self._repository.list_for_mission(mission_id)

    def prepare(self, mission, **kwargs):
        return self._repository.prepare(
            mission, claim=self._claim(), now=self._now_provider(), **kwargs
        )

    def mark_dispatching(self, mission, effect_id: str):
        return self._repository.mark_dispatching(
            mission, effect_id, claim=self._claim(), now=self._now_provider()
        )

    def mark_definitely_not_sent(self, mission, effect_id: str, *, proof: str, reason: str = ""):
        return self._repository.mark_definitely_not_sent(
            mission, effect_id, claim=self._claim(), proof=proof, reason=reason, now=self._now_provider()
        )

    def mark_failed(self, mission, effect_id: str, *, reason: str, receipt_metadata=None):
        return self._repository.mark_failed(
            mission, effect_id, claim=self._claim(), reason=reason,
            receipt_metadata=receipt_metadata, now=self._now_provider()
        )

    def mark_unknown(self, mission, effect_id: str, *, reason: str):
        return self._repository.mark_unknown(
            mission, effect_id, claim=self._claim(), reason=reason, now=self._now_provider()
        )

    def recover_dispatching(self, mission):
        return self._repository.recover_dispatching(
            mission, claim=self._claim(), now=self._now_provider()
        )

    def confirm(self, mission, effect_id: str, observation: dict[str, Any], *, action_id=None, step_id=None):
        return self._repository.confirm(
            mission, effect_id, observation, claim=self._claim(), action_id=action_id,
            step_id=step_id, now=self._now_provider()
        )

    def rearm_definitely_not_sent(self, mission, effect_id: str, *, proof: str):
        return self._repository.rearm_definitely_not_sent(
            mission, effect_id, claim=self._claim(), proof=proof, now=self._now_provider()
        )


__all__ += ["ClaimBoundEffectIntentRepository", "ExternalEffectIntentRepository"]
