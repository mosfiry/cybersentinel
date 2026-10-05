"""Owner-scoped, evidence-gated evaluation runs for agent missions.

This module stores multiple independent quality dimensions; it intentionally
never collapses them into a single aggregate score or an authority decision.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping


class EvaluationError(ValueError):
    """An evaluation run, policy, or persisted record is invalid."""


class EvaluationIntegrityError(EvaluationError):
    """A stored evaluation record does not match its integrity digest."""


class EvaluationConflict(EvaluationError):
    """An idempotency key was reused for different evaluation contents."""


class EvaluationMetric(str, Enum):
    TASK_SUCCESS = "task_success"
    EVIDENCE_QUALITY = "evidence_quality"
    HALLUCINATION = "hallucination"
    TOOL_CORRECTNESS = "tool_correctness"
    SKILL_USEFULNESS = "skill_usefulness"
    MEMORY_USEFULNESS = "memory_usefulness"
    LATENCY = "latency"
    COST = "cost"
    RECOVERY = "recovery"
    SAFETY_VIOLATIONS = "safety_violations"


class EvaluationVerdict(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INDETERMINATE = "indeterminate"


_UNITS = {
    EvaluationMetric.TASK_SUCCESS: "ratio",
    EvaluationMetric.EVIDENCE_QUALITY: "ratio",
    EvaluationMetric.HALLUCINATION: "ratio",
    EvaluationMetric.TOOL_CORRECTNESS: "ratio",
    EvaluationMetric.SKILL_USEFULNESS: "ratio",
    EvaluationMetric.MEMORY_USEFULNESS: "ratio",
    EvaluationMetric.LATENCY: "ms",
    EvaluationMetric.COST: "units",
    EvaluationMetric.RECOVERY: "ratio",
    EvaluationMetric.SAFETY_VIOLATIONS: "count",
}
_RATIO_METRICS = {metric for metric, unit in _UNITS.items() if unit == "ratio"}


def _identity(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise EvaluationError(f"{label} must be non-empty text of at most 256 characters")
    if any(ord(char) < 0x20 for char in value):
        raise EvaluationError(f"{label} contains control characters")
    return value.strip()


def _canonical(value: Any, label: str, limit: int = 32_768) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EvaluationError(f"{label} must contain canonical JSON values") from exc
    if len(encoded) > limit:
        raise EvaluationError(f"{label} exceeds the configured size limit")
    return encoded


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(item) for item in value]
    return value


@dataclass(frozen=True)
class EvaluationMeasurement:
    metric: EvaluationMetric
    value: int | float
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.metric, EvaluationMetric):
            raise EvaluationError("metric must be an EvaluationMetric")
        if isinstance(self.value, bool) or not isinstance(self.value, (int, float)) or not math.isfinite(float(self.value)):
            raise EvaluationError("metric value must be a finite number")
        if self.metric in _RATIO_METRICS and not 0.0 <= float(self.value) <= 1.0:
            raise EvaluationError(f"{self.metric.value} must be between 0 and 1")
        if self.value < 0:
            raise EvaluationError(f"{self.metric.value} cannot be negative")
        if self.metric is EvaluationMetric.SAFETY_VIOLATIONS and (isinstance(self.value, bool) or int(self.value) != self.value):
            raise EvaluationError("safety_violations must be an integer count")
        if not isinstance(self.evidence_refs, (tuple, list)) or len(self.evidence_refs) > 128:
            raise EvaluationError("evidence references must be a bounded sequence")
        refs = tuple(_identity(ref, "evidence reference") for ref in self.evidence_refs)
        if len(set(refs)) != len(refs):
            raise EvaluationError("evidence references must be unique")
        object.__setattr__(self, "evidence_refs", refs)

    @property
    def unit(self) -> str:
        return _UNITS[self.metric]

    def to_dict(self) -> dict[str, Any]:
        return {"metric": self.metric.value, "value": self.value, "unit": self.unit, "evidence_refs": list(self.evidence_refs)}


@dataclass(frozen=True)
class EvaluationRun:
    owner_identity_ref: str
    mission_id: str
    task_id: str
    case_id: str
    benchmark_version: str
    provider_id: str
    model_id: str
    measurements: tuple[EvaluationMeasurement, ...]
    provenance: Mapping[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        for field_name in ("owner_identity_ref", "mission_id", "task_id", "case_id", "benchmark_version", "provider_id", "model_id"):
            object.__setattr__(self, field_name, _identity(getattr(self, field_name), field_name.replace("_", " ")))
        if not isinstance(self.measurements, (tuple, list)) or len(self.measurements) > len(EvaluationMetric):
            raise EvaluationError("measurements must be a bounded sequence")
        raw_measurements = tuple(self.measurements)
        if any(not isinstance(item, EvaluationMeasurement) for item in raw_measurements):
            raise EvaluationError("measurements must contain EvaluationMeasurement values")
        normalized = tuple(sorted(raw_measurements, key=lambda item: item.metric.value))
        if len({item.metric for item in normalized}) != len(normalized):
            raise EvaluationError("an evaluation run cannot repeat a metric")
        object.__setattr__(self, "measurements", normalized)
        if not isinstance(self.provenance, Mapping) or any(not isinstance(key, str) for key in self.provenance):
            raise EvaluationError("provenance must be an object with string keys")
        provenance_json = _canonical(dict(self.provenance), "provenance", 16_384)
        object.__setattr__(self, "provenance", _freeze_json(json.loads(provenance_json)))
        if not isinstance(self.created_at, str):
            raise EvaluationError("created_at must be an ISO timestamp")
        try:
            parsed = datetime.fromisoformat(self.created_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EvaluationError("created_at must be an ISO timestamp") from exc
        if parsed.tzinfo is None:
            raise EvaluationError("created_at must include a timezone")

    def measurement_map(self) -> dict[EvaluationMetric, EvaluationMeasurement]:
        return {item.metric: item for item in self.measurements}

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner_identity_ref": self.owner_identity_ref,
            "mission_id": self.mission_id,
            "task_id": self.task_id,
            "case_id": self.case_id,
            "benchmark_version": self.benchmark_version,
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "created_at": self.created_at,
            "measurements": [item.to_dict() for item in sorted(self.measurements, key=lambda m: m.metric.value)],
            "provenance": _plain_json(self.provenance),
        }


@dataclass(frozen=True)
class EvaluationPolicy:
    required_metrics: tuple[EvaluationMetric, ...] = (
        EvaluationMetric.TASK_SUCCESS,
        EvaluationMetric.EVIDENCE_QUALITY,
        EvaluationMetric.HALLUCINATION,
        EvaluationMetric.TOOL_CORRECTNESS,
        EvaluationMetric.SAFETY_VIOLATIONS,
    )
    minimums: Mapping[EvaluationMetric, float] = field(default_factory=lambda: {
        EvaluationMetric.TASK_SUCCESS: 0.8,
        EvaluationMetric.EVIDENCE_QUALITY: 0.8,
        EvaluationMetric.TOOL_CORRECTNESS: 0.9,
    })
    maximums: Mapping[EvaluationMetric, float] = field(default_factory=lambda: {
        EvaluationMetric.HALLUCINATION: 0.05,
        EvaluationMetric.SAFETY_VIOLATIONS: 0,
    })
    evidence_required_for: tuple[EvaluationMetric, ...] = (EvaluationMetric.EVIDENCE_QUALITY,)

    def __post_init__(self) -> None:
        for name in ("required_metrics", "evidence_required_for"):
            values = tuple(getattr(self, name))
            if any(not isinstance(item, EvaluationMetric) for item in values) or len(set(values)) != len(values):
                raise EvaluationError(f"{name} must contain unique evaluation metrics")
            object.__setattr__(self, name, values)
        for name in ("minimums", "maximums"):
            values = dict(getattr(self, name))
            if any(not isinstance(metric, EvaluationMetric) for metric in values):
                raise EvaluationError(f"{name} keys must be EvaluationMetric values")
            if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) for value in values.values()):
                raise EvaluationError(f"{name} values must be finite numbers")
            object.__setattr__(self, name, MappingProxyType(values))
        if set(self.minimums) & set(self.maximums):
            raise EvaluationError("a metric cannot have both a minimum and maximum threshold")
        for metric, value in self.minimums.items():
            if metric in _RATIO_METRICS and not 0 <= value <= 1:
                raise EvaluationError("ratio metric minimums must be between 0 and 1")
            if value < 0:
                raise EvaluationError("metric minimums cannot be negative")
        for metric, value in self.maximums.items():
            if metric in _RATIO_METRICS and not 0 <= value <= 1:
                raise EvaluationError("ratio metric maximums must be between 0 and 1")
            if value < 0:
                raise EvaluationError("metric maximums cannot be negative")


@dataclass(frozen=True)
class EvaluationDecision:
    verdict: EvaluationVerdict
    reasons: tuple[str, ...]
    measurements: tuple[EvaluationMeasurement, ...]


def evaluate_run(
    run: EvaluationRun,
    policy: EvaluationPolicy | None = None,
    *,
    evidence_validator: Callable[[str, str, str], bool] | None = None,
) -> EvaluationDecision:
    """Evaluate independent dimensions; evidence must be independently checked."""
    if not isinstance(run, EvaluationRun):
        raise EvaluationError("run must be an EvaluationRun")
    policy = policy or EvaluationPolicy()
    if not isinstance(policy, EvaluationPolicy):
        raise EvaluationError("policy must be an EvaluationPolicy")
    measures = run.measurement_map()
    reasons: list[str] = []
    missing = [metric for metric in policy.required_metrics if metric not in measures]
    if missing:
        reasons.extend(f"missing_metric:{metric.value}" for metric in missing)
    rejected = False
    evidence_unverified = False
    for metric, measurement in measures.items():
        if metric in policy.minimums and measurement.value < policy.minimums[metric]:
            reasons.append(f"below_minimum:{metric.value}")
            rejected = True
        if metric in policy.maximums and measurement.value > policy.maximums[metric]:
            reasons.append(f"above_maximum:{metric.value}")
            rejected = True
        if metric in policy.evidence_required_for and not measurement.evidence_refs:
            reasons.append(f"missing_evidence:{metric.value}")
            rejected = True
        if measurement.evidence_refs:
            if evidence_validator is None:
                reasons.append(f"evidence_unverified:{metric.value}")
                evidence_unverified = True
            else:
                try:
                    valid = all(evidence_validator(run.owner_identity_ref, run.mission_id, ref) for ref in measurement.evidence_refs)
                except Exception:
                    valid = False
                    reasons.append(f"evidence_validator_error:{metric.value}")
                    evidence_unverified = True
                if not valid and f"evidence_validator_error:{metric.value}" not in reasons:
                    reasons.append(f"invalid_evidence:{metric.value}")
                    rejected = True
    if rejected:
        verdict = EvaluationVerdict.REJECTED
    elif missing or evidence_unverified:
        verdict = EvaluationVerdict.INDETERMINATE
    else:
        verdict = EvaluationVerdict.ACCEPTED
    return EvaluationDecision(verdict, tuple(reasons), tuple(sorted(run.measurements, key=lambda item: item.metric.value)))


@dataclass(frozen=True)
class StoredEvaluation:
    evaluation_id: str
    run: EvaluationRun
    record_sha256: str


class EvaluationStore:
    """Append-only, owner-filtered SQLite persistence for evaluation runs."""

    SCHEMA_VERSION = 1
    MAX_ROWS = 100

    def __init__(self, db_path: str | Path, *, read_only: bool = False):
        self.db_path = Path(db_path)
        if not isinstance(read_only, bool):
            raise EvaluationError("read_only must be a boolean")
        self._read_only = read_only
        if self._read_only:
            if self.db_path.is_symlink() or not self.db_path.is_file():
                raise EvaluationError("evaluation store is unavailable")
            try:
                with self._connect() as connection:
                    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                    columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(evaluation_runs)")}
                required = {
                    "evaluation_id", "owner_identity_ref", "mission_id", "task_id", "case_id",
                    "benchmark_version", "provider_id", "model_id", "idempotency_key", "created_at",
                    "measurements_json", "provenance_json", "evaluation_sha256", "record_sha256",
                }
                if version != self.SCHEMA_VERSION or not required.issubset(columns):
                    raise EvaluationError("evaluation store schema is unavailable")
            except sqlite3.Error as exc:
                raise EvaluationError("evaluation store is unavailable") from exc
            return
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
        if self._read_only:
            uri = self.db_path.resolve().as_uri() + "?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=5.0)
        else:
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
                raise EvaluationError("evaluation database schema is newer than this application")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS evaluation_runs (
                    evaluation_id TEXT PRIMARY KEY,
                    owner_identity_ref TEXT NOT NULL,
                    mission_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    benchmark_version TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    measurements_json TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    evaluation_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    UNIQUE(owner_identity_ref, mission_id, idempotency_key)
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS evaluation_owner_mission_created "
                "ON evaluation_runs(owner_identity_ref, mission_id, created_at, evaluation_id)"
            )
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS evaluation_no_update BEFORE UPDATE ON evaluation_runs "
                "BEGIN SELECT RAISE(ABORT, 'evaluation records are append-only'); END"
            )
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS evaluation_no_delete BEFORE DELETE ON evaluation_runs "
                "BEGIN SELECT RAISE(ABORT, 'evaluation records are append-only'); END"
            )
            connection.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")

    @staticmethod
    def _digest_payload(run: EvaluationRun) -> tuple[str, str, str]:
        measurements_json = _canonical([item.to_dict() for item in sorted(run.measurements, key=lambda item: item.metric.value)], "measurements")
        provenance_json = _canonical(dict(run.provenance), "provenance", 16_384)
        payload_json = _canonical({**run.to_dict(), "measurements": json.loads(measurements_json), "provenance": json.loads(provenance_json)}, "evaluation run")
        return measurements_json, provenance_json, hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

    @staticmethod
    def _record_digest(evaluation_id: str, owner_identity_ref: str, mission_id: str, idempotency_key: str, evaluation_sha256: str) -> str:
        manifest = _canonical({
            "evaluation_id": evaluation_id,
            "owner_identity_ref": owner_identity_ref,
            "mission_id": mission_id,
            "idempotency_key": idempotency_key,
            "evaluation_sha256": evaluation_sha256,
        }, "evaluation manifest")
        return hashlib.sha256(manifest.encode("utf-8")).hexdigest()

    def append(self, run: EvaluationRun, *, idempotency_key: str) -> StoredEvaluation:
        if self._read_only:
            raise EvaluationError("evaluation store is read-only")
        if not isinstance(run, EvaluationRun):
            raise EvaluationError("run must be an EvaluationRun")
        key = _identity(idempotency_key, "idempotency key")
        if len(key) > 256:
            raise EvaluationError("idempotency key is too long")
        measurements_json, provenance_json, digest = self._digest_payload(run)
        evaluation_id = f"evaluation_{uuid.uuid4().hex}"
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM evaluation_runs WHERE owner_identity_ref = ? AND mission_id = ? AND idempotency_key = ?",
                (run.owner_identity_ref, run.mission_id, key),
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(existing["evaluation_sha256"], digest):
                    connection.rollback()
                    raise EvaluationConflict("idempotency key was already used for different evaluation contents")
                stored_run = self._decode(existing)
                connection.commit()
                return StoredEvaluation(existing["evaluation_id"], stored_run, existing["record_sha256"])
            record_digest = self._record_digest(evaluation_id, run.owner_identity_ref, run.mission_id, key, digest)
            connection.execute(
                """INSERT INTO evaluation_runs (
                    evaluation_id, owner_identity_ref, mission_id, task_id, case_id,
                    benchmark_version, provider_id, model_id, idempotency_key,
                    created_at, measurements_json, provenance_json, evaluation_sha256, record_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    evaluation_id, run.owner_identity_ref, run.mission_id, run.task_id,
                    run.case_id, run.benchmark_version, run.provider_id, run.model_id,
                    key, run.created_at, measurements_json, provenance_json, digest, record_digest,
                ),
            )
            connection.commit()
        return StoredEvaluation(evaluation_id, run, record_digest)

    @staticmethod
    def _decode(row: sqlite3.Row) -> EvaluationRun:
        try:
            measurements_data = json.loads(row["measurements_json"])
            provenance = json.loads(row["provenance_json"])
            measurements = tuple(
                EvaluationMeasurement(
                    EvaluationMetric(item["metric"]), item["value"], tuple(item.get("evidence_refs", ()))
                ) for item in measurements_data
            )
            run = EvaluationRun(
                owner_identity_ref=row["owner_identity_ref"], mission_id=row["mission_id"],
                task_id=row["task_id"], case_id=row["case_id"],
                benchmark_version=row["benchmark_version"], provider_id=row["provider_id"],
                model_id=row["model_id"], measurements=measurements,
                provenance=provenance, created_at=row["created_at"],
            )
            _, _, digest = EvaluationStore._digest_payload(run)
            if not hmac.compare_digest(digest, row["evaluation_sha256"]):
                raise EvaluationIntegrityError("evaluation record failed its SHA-256 integrity check")
            record_digest = EvaluationStore._record_digest(
                row["evaluation_id"], row["owner_identity_ref"], row["mission_id"],
                row["idempotency_key"], row["evaluation_sha256"],
            )
            if not hmac.compare_digest(record_digest, row["record_sha256"]):
                raise EvaluationIntegrityError("evaluation manifest failed its SHA-256 integrity check")
            return run
        except EvaluationIntegrityError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise EvaluationIntegrityError("evaluation record is malformed") from exc

    def get(self, *, owner_identity_ref: str, evaluation_id: str) -> StoredEvaluation | None:
        owner = _identity(owner_identity_ref, "owner identity")
        if not isinstance(evaluation_id, str) or not evaluation_id.startswith("evaluation_") or len(evaluation_id) > 64:
            raise EvaluationError("evaluation id is invalid")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM evaluation_runs WHERE owner_identity_ref = ? AND evaluation_id = ?",
                (owner, evaluation_id),
            ).fetchone()
        if row is None:
            return None
        run = self._decode(row)
        return StoredEvaluation(row["evaluation_id"], run, row["record_sha256"])

    def list(self, *, owner_identity_ref: str, mission_id: str | None = None, limit: int = 100) -> list[StoredEvaluation]:
        owner = _identity(owner_identity_ref, "owner identity")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= self.MAX_ROWS:
            raise EvaluationError(f"limit must be between 1 and {self.MAX_ROWS}")
        if mission_id is None:
            query = "SELECT * FROM evaluation_runs WHERE owner_identity_ref = ? ORDER BY created_at, evaluation_id LIMIT ?"
            params: tuple[Any, ...] = (owner, limit)
        else:
            mission = _identity(mission_id, "mission id")
            query = "SELECT * FROM evaluation_runs WHERE owner_identity_ref = ? AND mission_id = ? ORDER BY created_at, evaluation_id LIMIT ?"
            params = (owner, mission, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [StoredEvaluation(row["evaluation_id"], self._decode(row), row["record_sha256"]) for row in rows]


__all__ = [
    "EvaluationConflict", "EvaluationDecision", "EvaluationError", "EvaluationIntegrityError",
    "EvaluationMeasurement", "EvaluationMetric", "EvaluationPolicy", "EvaluationRun",
    "EvaluationStore", "EvaluationVerdict", "StoredEvaluation", "evaluate_run",
]
