"""Durable mission events and authority-subordinate in-process hooks.

Subscribers are observers; only explicitly registered before-hooks may veto.
Hooks cannot modify arguments or grant authority, and their authorization is
rechecked on every invocation by a host-supplied authority callback.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping


class EventError(ValueError):
    """An event or event query is invalid."""


class EventConflict(EventError):
    """An idempotency key was reused for a different event."""


class EventIntegrityError(EventError):
    """A persisted event or its hash chain is invalid."""


class HookAuthorizationError(EventError):
    """A hook registration or invocation lacks current authority."""


class IntelligenceEventType(str, Enum):
    MISSION_CREATED = "MissionCreated"
    TASK_STARTED = "TaskStarted"
    TASK_COMPLETED = "TaskCompleted"
    AGENT_STARTED = "AgentStarted"
    AGENT_COMPLETED = "AgentCompleted"
    TOOL_CALLED = "ToolCalled"
    EVIDENCE_CREATED = "EvidenceCreated"
    FINDING_CREATED = "FindingCreated"
    SKILL_USED = "SkillUsed"
    SKILL_LEARNED = "SkillLearned"
    PROVIDER_CHANGED = "ProviderChanged"
    RUNTIME_STARTED = "RuntimeStarted"
    RUNTIME_STOPPED = "RuntimeStopped"
    MISSION_PAUSED = "MissionPaused"
    MISSION_RESUMED = "MissionResumed"
    HOOK_INVOKED = "HookInvoked"
    HOOK_BLOCKED = "HookBlocked"
    HOOK_FAILED = "HookFailed"


class HookPhase(str, Enum):
    BEFORE_MISSION = "before_mission"
    AFTER_MISSION = "after_mission"
    BEFORE_TOOL = "before_tool"
    AFTER_TOOL = "after_tool"
    BEFORE_PROVIDER = "before_provider"
    AFTER_PROVIDER = "after_provider"
    EVIDENCE_CREATED = "evidence_created"
    FINDING_CREATED = "finding_created"
    SKILL_CANDIDATE_CREATED = "skill_candidate_created"


_PRE_EFFECT_PHASES = {HookPhase.BEFORE_MISSION, HookPhase.BEFORE_TOOL, HookPhase.BEFORE_PROVIDER}
_SENSITIVE_KEY = re.compile(r"(?:password|passwd|token|secret|credential|authorization|api[_-]?key|cookie|private[_-]?key)", re.I)
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\b(?:sk-[A-Za-z0-9]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b"),
    re.compile(r"(?i)(\b(?:password|passwd|token|secret|api[_-]?key)=)[^\s&]+"),
)


def _identity(value: str, label: str, *, optional: bool = False) -> str:
    if optional and value == "":
        return ""
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise EventError(f"{label} must be non-empty text of at most 256 characters")
    if any(ord(char) < 0x20 for char in value):
        raise EventError(f"{label} contains control characters")
    return value.strip()


def _sanitize(value: Any, *, depth: int = 0) -> Any:
    if depth > 12:
        raise EventError("event data exceeds maximum nesting depth")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise EventError("event data cannot contain non-finite numbers")
        return value
    if isinstance(value, str):
        if len(value) > 16_384:
            raise EventError("event text exceeds the configured size limit")
        result = value
        for pattern in _SENSITIVE_VALUE_PATTERNS:
            result = pattern.sub(lambda match: (match.group(1) if match.lastindex else "") + "[REDACTED]", result)
        return result
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        if len(value) > 256:
            raise EventError("event object contains too many fields")
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise EventError("event object keys must be bounded strings")
            output[key] = "[REDACTED]" if _SENSITIVE_KEY.search(key) else _sanitize(item, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise EventError("event list contains too many items")
        return [_sanitize(item, depth=depth + 1) for item in value]
    raise EventError("event data must contain JSON-compatible values")


def _canonical(value: Any, label: str, limit: int = 32_768) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EventError(f"{label} must be canonical JSON") from exc
    if len(encoded) > limit:
        raise EventError(f"{label} exceeds the configured size limit")
    return encoded


def _event_input_hash(event_type: str, request_id: str, task_id: str, agent_id: str, payload: Mapping[str, Any]) -> str:
    normalized = {"event_type": event_type, "request_id": request_id, "task_id": task_id, "agent_id": agent_id, "payload": payload}
    return hashlib.sha256(_canonical(normalized, "event input").encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EventRecord:
    event_id: str
    owner_identity_ref: str
    mission_id: str
    sequence: int
    event_type: IntelligenceEventType
    request_id: str
    task_id: str
    agent_id: str
    idempotency_key: str
    created_at: str
    payload: Mapping[str, Any]
    input_sha256: str
    previous_hash: str
    event_hash: str


class EventStore:
    """Append-only, owner/mission-filtered event journal with verifiable chains."""

    SCHEMA_VERSION = 1
    MAX_PAGE_SIZE = 500

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd = os.open(self.db_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        self._initialize()
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.db_path), timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection, connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > self.SCHEMA_VERSION:
                raise EventError("event database schema is newer than this application")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS mission_events (
                    event_id TEXT PRIMARY KEY,
                    owner_identity_ref TEXT NOT NULL,
                    mission_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    input_sha256 TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    UNIQUE(owner_identity_ref, mission_id, sequence),
                    UNIQUE(owner_identity_ref, mission_id, idempotency_key)
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS mission_events_timeline "
                "ON mission_events(owner_identity_ref, mission_id, sequence)"
            )
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS mission_events_no_update BEFORE UPDATE ON mission_events "
                "BEGIN SELECT RAISE(ABORT, 'mission events are append-only'); END"
            )
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS mission_events_no_delete BEFORE DELETE ON mission_events "
                "BEGIN SELECT RAISE(ABORT, 'mission events are append-only'); END"
            )
            connection.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")

    @staticmethod
    def _record_hash(
        *, event_id: str, owner_identity_ref: str, mission_id: str, sequence: int,
        event_type: str, request_id: str, task_id: str, agent_id: str,
        idempotency_key: str, created_at: str, payload: Mapping[str, Any],
        input_sha256: str, previous_hash: str,
    ) -> str:
        data = {
            "event_id": event_id, "owner_identity_ref": owner_identity_ref,
            "mission_id": mission_id, "sequence": sequence, "event_type": event_type,
            "request_id": request_id, "task_id": task_id, "agent_id": agent_id,
            "idempotency_key": idempotency_key, "created_at": created_at,
            "payload": payload, "input_sha256": input_sha256, "previous_hash": previous_hash,
        }
        return hashlib.sha256(_canonical(data, "event record").encode("utf-8")).hexdigest()

    def append(
        self,
        *,
        owner_identity_ref: str,
        mission_id: str,
        event_type: IntelligenceEventType,
        idempotency_key: str,
        payload: Mapping[str, Any] | None = None,
        request_id: str = "",
        task_id: str = "",
        agent_id: str = "",
    ) -> EventRecord:
        owner = _identity(owner_identity_ref, "owner identity")
        mission = _identity(mission_id, "mission id", optional=True)
        request = _identity(request_id, "request id", optional=True)
        task = _identity(task_id, "task id", optional=True)
        agent = _identity(agent_id, "agent id", optional=True)
        key = _identity(idempotency_key, "idempotency key")
        if not isinstance(event_type, IntelligenceEventType):
            raise EventError("event_type must be an IntelligenceEventType")
        if payload is not None and not isinstance(payload, Mapping):
            raise EventError("event payload must be an object")
        safe_payload = _sanitize(payload or {})
        payload_json = _canonical(safe_payload, "event payload")
        input_digest = _event_input_hash(event_type.value, request, task, agent, safe_payload)
        event_id = f"event_{uuid.uuid4().hex}"
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM mission_events WHERE owner_identity_ref = ? AND mission_id = ? AND idempotency_key = ?",
                (owner, mission, key),
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(existing["input_sha256"], input_digest):
                    connection.rollback()
                    raise EventConflict("idempotency key was already used for a different event")
                record = self._decode(existing)
                connection.commit()
                return record
            previous = connection.execute(
                "SELECT sequence, event_hash FROM mission_events WHERE owner_identity_ref = ? AND mission_id = ? "
                "ORDER BY sequence DESC LIMIT 1", (owner, mission),
            ).fetchone()
            sequence = 1 if previous is None else int(previous["sequence"]) + 1
            previous_hash = "" if previous is None else str(previous["event_hash"])
            record_hash = self._record_hash(
                event_id=event_id, owner_identity_ref=owner, mission_id=mission, sequence=sequence,
                event_type=event_type.value, request_id=request, task_id=task, agent_id=agent,
                idempotency_key=key, created_at=created_at, payload=safe_payload,
                input_sha256=input_digest, previous_hash=previous_hash,
            )
            connection.execute(
                """INSERT INTO mission_events (
                    event_id, owner_identity_ref, mission_id, sequence, event_type,
                    request_id, task_id, agent_id, idempotency_key, created_at,
                    payload_json, input_sha256, previous_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (event_id, owner, mission, sequence, event_type.value, request, task, agent,
                 key, created_at, payload_json, input_digest, previous_hash, record_hash),
            )
            connection.commit()
        return EventRecord(event_id, owner, mission, sequence, event_type, request, task, agent,
                           key, created_at, _freeze(safe_payload), input_digest, previous_hash, record_hash)

    @classmethod
    def _decode(cls, row: sqlite3.Row) -> EventRecord:
        try:
            payload = json.loads(row["payload_json"])
            if not isinstance(payload, dict):
                raise EventIntegrityError("event payload is not an object")
            safe_payload = _sanitize(payload)
            if safe_payload != payload:
                raise EventIntegrityError("event payload contains unredacted sensitive material")
            input_digest = _event_input_hash(row["event_type"], row["request_id"], row["task_id"], row["agent_id"], payload)
            if not hmac.compare_digest(input_digest, row["input_sha256"]):
                raise EventIntegrityError("event input failed its SHA-256 integrity check")
            expected = cls._record_hash(
                event_id=row["event_id"], owner_identity_ref=row["owner_identity_ref"],
                mission_id=row["mission_id"], sequence=int(row["sequence"]),
                event_type=row["event_type"], request_id=row["request_id"], task_id=row["task_id"],
                agent_id=row["agent_id"], idempotency_key=row["idempotency_key"],
                created_at=row["created_at"], payload=payload,
                input_sha256=row["input_sha256"], previous_hash=row["previous_hash"],
            )
            if not hmac.compare_digest(expected, row["event_hash"]):
                raise EventIntegrityError("event failed its SHA-256 integrity check")
            return EventRecord(
                row["event_id"], row["owner_identity_ref"], row["mission_id"], int(row["sequence"]),
                IntelligenceEventType(row["event_type"]), row["request_id"], row["task_id"],
                row["agent_id"], row["idempotency_key"], row["created_at"], _freeze(payload),
                row["input_sha256"], row["previous_hash"], row["event_hash"],
            )
        except EventIntegrityError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise EventIntegrityError("event record is malformed") from exc

    def list(
        self,
        *,
        owner_identity_ref: str,
        mission_id: str,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> list[EventRecord]:
        owner = _identity(owner_identity_ref, "owner identity")
        mission = _identity(mission_id, "mission id", optional=True)
        if isinstance(after_sequence, bool) or not isinstance(after_sequence, int) or after_sequence < 0:
            raise EventError("after_sequence must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= self.MAX_PAGE_SIZE:
            raise EventError(f"limit must be between 1 and {self.MAX_PAGE_SIZE}")
        with self._connect() as connection:
            if after_sequence:
                previous = connection.execute(
                    "SELECT sequence, event_hash FROM mission_events WHERE owner_identity_ref = ? AND mission_id = ? AND sequence = ?",
                    (owner, mission, after_sequence),
                ).fetchone()
                if previous is None:
                    raise EventError("after_sequence must identify an existing event")
                previous_hash = str(previous["event_hash"])
            else:
                previous_hash = ""
            rows = connection.execute(
                "SELECT * FROM mission_events WHERE owner_identity_ref = ? AND mission_id = ? AND sequence > ? "
                "ORDER BY sequence LIMIT ?", (owner, mission, after_sequence, limit),
            ).fetchall()
        events: list[EventRecord] = []
        expected_sequence = after_sequence + 1
        for row in rows:
            event = self._decode(row)
            if event.sequence != expected_sequence or not hmac.compare_digest(event.previous_hash, previous_hash):
                raise EventIntegrityError("event sequence or hash-chain continuity is broken")
            events.append(event)
            expected_sequence += 1
            previous_hash = event.event_hash
        return events

    def verify_mission(self, *, owner_identity_ref: str, mission_id: str) -> bool:
        owner = _identity(owner_identity_ref, "owner identity")
        mission = _identity(mission_id, "mission id", optional=True)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM mission_events WHERE owner_identity_ref = ? AND mission_id = ? ORDER BY sequence",
                (owner, mission),
            )
            previous_hash = ""
            for expected_sequence, row in enumerate(rows, start=1):
                event = self._decode(row)
                if event.sequence != expected_sequence or not hmac.compare_digest(event.previous_hash, previous_hash):
                    raise EventIntegrityError("event sequence or hash-chain continuity is broken")
                previous_hash = event.event_hash
        return True


@dataclass(frozen=True)
class EventDelivery:
    event: EventRecord
    subscriber_failures: tuple[str, ...] = ()


class EventBus:
    """Persists events before notifying in-process observers."""

    def __init__(self, store: EventStore):
        self.store = store
        self._subscribers: dict[IntelligenceEventType, dict[str, Callable[[EventRecord], None]]] = {}
        self._lock = RLock()

    def subscribe(self, event_type: IntelligenceEventType, handler: Callable[[EventRecord], None]) -> str:
        if not isinstance(event_type, IntelligenceEventType) or not callable(handler):
            raise EventError("subscription requires an event type and callable observer")
        token = f"subscription_{uuid.uuid4().hex}"
        with self._lock:
            self._subscribers.setdefault(event_type, {})[token] = handler
        return token

    def unsubscribe(self, token: str) -> bool:
        if not isinstance(token, str):
            raise EventError("subscription token must be text")
        with self._lock:
            for subscriptions in self._subscribers.values():
                if token in subscriptions:
                    del subscriptions[token]
                    return True
        return False

    def publish(self, **event_fields: Any) -> EventDelivery:
        record = self.store.append(**event_fields)
        with self._lock:
            handlers = tuple(self._subscribers.get(record.event_type, {}).items())
        failures: list[str] = []
        for token, handler in handlers:
            try:
                handler(record)
            except Exception as exc:
                failures.append(f"{token}:{type(exc).__name__}")
        return EventDelivery(record, tuple(failures))


@dataclass(frozen=True)
class HookDecision:
    allow: bool = True
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.allow, bool):
            raise EventError("hook decision allow must be boolean")
        if not isinstance(self.reason, str) or len(self.reason) > 512:
            raise EventError("hook decision reason must be bounded text")


@dataclass(frozen=True)
class HookInvocation:
    hook_id: str
    phase: HookPhase
    owner_identity_ref: str
    mission_id: str
    correlation_id: str
    data: Mapping[str, Any]


@dataclass(frozen=True)
class HookResult:
    allowed: bool
    executed_hook_ids: tuple[str, ...]
    failures: tuple[str, ...]
    denied_reason: str = ""


@dataclass(frozen=True)
class _RegisteredHook:
    hook_id: str
    owner_identity_ref: str
    mission_id: str
    phase: HookPhase
    handler: Callable[[HookInvocation], HookDecision | None]
    authorization_check: Callable[[str, str, HookPhase], bool]


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


class HookRegistry:
    """Per-process trusted-code hooks that can veto, but never grant or mutate authority."""

    def __init__(self, event_store: EventStore | None = None):
        if event_store is not None and not isinstance(event_store, EventStore):
            raise EventError("event_store must be an EventStore")
        self.event_store = event_store
        self._hooks: dict[tuple[str, str, HookPhase, str], _RegisteredHook] = {}
        self._lock = RLock()

    def register(
        self,
        *,
        hook_id: str,
        owner_identity_ref: str,
        mission_id: str,
        phase: HookPhase,
        handler: Callable[[HookInvocation], HookDecision | None],
        authorization_check: Callable[[str, str, HookPhase], bool],
    ) -> None:
        hook = _RegisteredHook(
            _identity(hook_id, "hook id"),
            _identity(owner_identity_ref, "owner identity"),
            _identity(mission_id, "mission id"),
            phase,
            handler,
            authorization_check,
        )
        if not isinstance(phase, HookPhase) or not callable(handler) or not callable(authorization_check):
            raise EventError("hook registration requires a typed phase, handler and authorization check")
        try:
            authorized = authorization_check(hook.owner_identity_ref, hook.mission_id, phase)
        except Exception as exc:
            raise HookAuthorizationError("hook registration authority check failed") from exc
        if authorized is not True:
            raise HookAuthorizationError("current authority does not permit this hook registration")
        key = (hook.owner_identity_ref, hook.mission_id, hook.phase, hook.hook_id)
        with self._lock:
            if key in self._hooks:
                raise EventError("hook id is already registered for this owner, mission and phase")
            self._hooks[key] = hook

    def unregister(
        self,
        *,
        hook_id: str,
        owner_identity_ref: str,
        mission_id: str,
        phase: HookPhase,
        authorization_check: Callable[[str, str, HookPhase], bool],
    ) -> bool:
        owner = _identity(owner_identity_ref, "owner identity")
        mission = _identity(mission_id, "mission id")
        hook_name = _identity(hook_id, "hook id")
        if not isinstance(phase, HookPhase) or not callable(authorization_check):
            raise EventError("hook removal requires a typed phase and authorization check")
        try:
            authorized = authorization_check(owner, mission, phase)
        except Exception as exc:
            raise HookAuthorizationError("hook removal authority check failed") from exc
        if authorized is not True:
            raise HookAuthorizationError("current authority does not permit this hook removal")
        with self._lock:
            return self._hooks.pop((owner, mission, phase, hook_name), None) is not None

    def run(
        self,
        *,
        owner_identity_ref: str,
        mission_id: str,
        phase: HookPhase,
        correlation_id: str,
        data: Mapping[str, Any] | None = None,
    ) -> HookResult:
        owner = _identity(owner_identity_ref, "owner identity")
        mission = _identity(mission_id, "mission id")
        correlation = _identity(correlation_id, "correlation id")
        if not isinstance(phase, HookPhase):
            raise EventError("phase must be a HookPhase")
        safe_data = _sanitize(data or {})
        _canonical(safe_data, "hook context", 16_384)
        with self._lock:
            hooks = tuple(sorted(
                (hook for key, hook in self._hooks.items() if key[:3] == (owner, mission, phase)),
                key=lambda item: item.hook_id,
            ))
        before = phase in _PRE_EFFECT_PHASES
        executed: list[str] = []
        failures: list[str] = []
        denied_reason = ""
        allowed = True
        hook_run_id = uuid.uuid4().hex
        for hook in hooks:
            hook_event_type = IntelligenceEventType.HOOK_INVOKED
            try:
                if hook.authorization_check(owner, mission, phase) is not True:
                    raise HookAuthorizationError("current authority no longer permits this hook")
                invocation = HookInvocation(hook.hook_id, phase, owner, mission, correlation, _freeze(safe_data))
                response = hook.handler(invocation)
                executed.append(hook.hook_id)
                if before:
                    if not isinstance(response, HookDecision):
                        raise EventError("before-hook must return a typed HookDecision")
                    if not response.allow:
                        allowed = False
                        hook_event_type = IntelligenceEventType.HOOK_BLOCKED
                        denied_reason = response.reason or f"blocked by hook {hook.hook_id}"
                elif response is not None:
                    raise EventError("observer hooks cannot return a decision")
            except Exception as exc:
                hook_event_type = IntelligenceEventType.HOOK_FAILED
                failures.append(f"{hook.hook_id}:{type(exc).__name__}")
                if before:
                    allowed = False
                    denied_reason = f"before-hook {hook.hook_id} failed closed"
            if self.event_store is not None:
                try:
                    self.event_store.append(
                        owner_identity_ref=owner,
                        mission_id=mission,
                        event_type=hook_event_type,
                        idempotency_key=f"hook_run:{hook_run_id}:{hook.hook_id}",
                        request_id=correlation,
                        payload={
                            "hook_id": hook.hook_id,
                            "phase": phase.value,
                            "result": "allowed" if allowed else "blocked",
                            "failure": failures[-1] if failures and failures[-1].startswith(hook.hook_id + ":") else "",
                        },
                    )
                except Exception as exc:
                    failures.append(f"{hook.hook_id}:audit:{type(exc).__name__}")
                    if before:
                        allowed = False
                        denied_reason = f"before-hook {hook.hook_id} audit failed closed"
            if not allowed:
                break
        return HookResult(allowed, tuple(executed), tuple(failures), denied_reason)


__all__ = [
    "EventBus", "EventConflict", "EventDelivery", "EventError", "EventIntegrityError",
    "EventRecord", "EventStore", "HookAuthorizationError", "HookDecision",
    "HookInvocation", "HookPhase", "HookRegistry", "HookResult", "IntelligenceEventType",
]
