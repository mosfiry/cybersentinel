"""Owner-scoped, append-only artifacts for evidence and mission outputs.

Payloads are stored as opaque bounded bytes. The store does not execute, parse,
render, or automatically promote artifact content into model context.
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
from typing import Any, Iterator, Mapping


class ArtifactStoreError(ValueError):
    """An artifact request or persisted record is invalid."""


class ArtifactIntegrityError(ArtifactStoreError):
    """Stored payload bytes no longer match their recorded content digest."""


class ArtifactKind(str, Enum):
    REPORT = "report"
    SCREENSHOT = "screenshot"
    SOURCE = "source"
    EXTRACTED_DATA = "extracted_data"
    EVIDENCE = "evidence"
    CODE = "code"
    FINDING = "finding"
    OTHER = "other"


class ArtifactSensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


class ArtifactValidation(str, Enum):
    UNVALIDATED = "unvalidated"
    VALIDATED = "validated"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_id: str
    owner_identity_ref: str
    mission_id: str
    task_id: str
    kind: ArtifactKind
    filename: str
    media_type: str
    created_at: str
    content_sha256: str
    manifest_sha256: str
    size_bytes: int
    sensitivity: ArtifactSensitivity
    validation: ArtifactValidation
    confidence: float
    scope: tuple[str, ...]
    provenance: dict[str, Any]
    metadata: dict[str, Any]
    content: bytes


class ArtifactStore:
    """SQLite-backed append-only artifact store with owner-bound reads."""

    SCHEMA_VERSION = 1
    MAX_CONTENT_BYTES = 4 * 1024 * 1024
    MAX_METADATA_CHARS = 16_384
    MAX_SCOPE_ITEMS = 64

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
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > self.SCHEMA_VERSION:
                raise ArtifactStoreError("artifact database schema is newer than this application")
            with connection:
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS artifacts (
                        artifact_id TEXT PRIMARY KEY,
                        owner_identity_ref TEXT NOT NULL,
                        mission_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        media_type TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        content_sha256 TEXT NOT NULL,
                        manifest_sha256 TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL,
                        sensitivity TEXT NOT NULL,
                        validation TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        scope_json TEXT NOT NULL,
                        provenance_json TEXT NOT NULL,
                        metadata_json TEXT NOT NULL,
                        content BLOB NOT NULL
                    )"""
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS artifacts_owner_mission_task_created "
                    "ON artifacts(owner_identity_ref, mission_id, task_id, created_at, artifact_id)"
                )
                connection.execute(
                    "CREATE TRIGGER IF NOT EXISTS artifacts_no_update "
                    "BEFORE UPDATE ON artifacts BEGIN SELECT RAISE(ABORT, 'artifacts are append-only'); END"
                )
                connection.execute(
                    "CREATE TRIGGER IF NOT EXISTS artifacts_no_delete "
                    "BEFORE DELETE ON artifacts BEGIN SELECT RAISE(ABORT, 'artifacts are append-only'); END"
                )
                connection.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")

    @staticmethod
    def _identity(value: str, label: str) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ArtifactStoreError(f"{label} must be non-empty text of at most 256 characters")
        if any(ord(char) < 0x20 for char in value):
            raise ArtifactStoreError(f"{label} contains control characters")
        return value.strip()

    @staticmethod
    def _json(value: Mapping[str, Any], label: str, max_chars: int) -> str:
        if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
            raise ArtifactStoreError(f"{label} must be an object with string keys")
        try:
            encoded = json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ArtifactStoreError(f"{label} must contain bounded JSON values") from exc
        if len(encoded) > max_chars:
            raise ArtifactStoreError(f"{label} exceeds the configured size limit")
        return encoded

    @staticmethod
    def _manifest_json(
        *, artifact_id: str, owner_identity_ref: str, mission_id: str, task_id: str,
        kind: str, filename: str, media_type: str, created_at: str,
        content_sha256: str, size_bytes: int, sensitivity: str, validation: str,
        confidence: float, scope: tuple[str, ...], provenance: Mapping[str, Any],
        metadata: Mapping[str, Any],
    ) -> str:
        return json.dumps({
            "artifact_id": artifact_id,
            "owner_identity_ref": owner_identity_ref,
            "mission_id": mission_id,
            "task_id": task_id,
            "kind": kind,
            "filename": filename,
            "media_type": media_type,
            "created_at": created_at,
            "content_sha256": content_sha256,
            "size_bytes": size_bytes,
            "sensitivity": sensitivity,
            "validation": validation,
            "confidence": confidence,
            "scope": scope,
            "provenance": provenance,
            "metadata": metadata,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)

    @staticmethod
    def _filename(value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 256 or any(ord(char) < 0x20 for char in value):
            raise ArtifactStoreError("filename must be non-empty safe text of at most 256 characters")
        normalized = value.replace("\\", "/").rsplit("/", 1)[-1].strip()
        if normalized in {"", ".", ".."}:
            raise ArtifactStoreError("filename must identify a file name, not a path")
        return normalized

    def put(
        self,
        *,
        owner_identity_ref: str,
        mission_id: str,
        task_id: str,
        kind: ArtifactKind,
        content: bytes | bytearray | memoryview | str,
        filename: str,
        media_type: str = "application/octet-stream",
        sensitivity: ArtifactSensitivity = ArtifactSensitivity.SENSITIVE,
        validation: ArtifactValidation = ArtifactValidation.UNVALIDATED,
        confidence: float = 0.0,
        scope: tuple[str, ...] | list[str] = (),
        provenance: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ArtifactRecord:
        owner = self._identity(owner_identity_ref, "owner identity")
        mission = self._identity(mission_id, "mission id")
        task = self._identity(task_id, "task id")
        if not isinstance(kind, ArtifactKind):
            raise ArtifactStoreError("kind must be an ArtifactKind")
        if not isinstance(sensitivity, ArtifactSensitivity) or not isinstance(validation, ArtifactValidation):
            raise ArtifactStoreError("sensitivity and validation must use their typed classifications")
        if isinstance(content, str):
            payload = content.encode("utf-8")
        elif isinstance(content, (bytes, bytearray, memoryview)):
            payload = bytes(content)
        else:
            raise ArtifactStoreError("artifact content must be text or bytes")
        if len(payload) > self.MAX_CONTENT_BYTES:
            raise ArtifactStoreError("artifact exceeds the configured content size limit")
        if not isinstance(media_type, str) or not re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+", media_type):
            raise ArtifactStoreError("media_type must be a syntactically valid MIME type")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0.0 <= float(confidence) <= 1.0:
            raise ArtifactStoreError("confidence must be a finite value between 0 and 1")
        if not isinstance(scope, (tuple, list)) or len(scope) > self.MAX_SCOPE_ITEMS:
            raise ArtifactStoreError("scope must be a bounded list of text references")
        normalized_scope = tuple(sorted({self._identity(item, "scope reference") for item in scope}))
        filename_value = self._filename(filename)
        provenance_json = self._json(provenance or {}, "provenance", self.MAX_METADATA_CHARS)
        metadata_json = self._json(metadata or {}, "metadata", self.MAX_METADATA_CHARS)
        scope_json = json.dumps(normalized_scope, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(payload).hexdigest()
        artifact_id = f"artifact_{uuid.uuid4().hex}"
        created_at = datetime.now(timezone.utc).isoformat()
        manifest = self._manifest_json(
            artifact_id=artifact_id, owner_identity_ref=owner, mission_id=mission, task_id=task,
            kind=kind.value, filename=filename_value, media_type=media_type, created_at=created_at,
            content_sha256=digest, size_bytes=len(payload), sensitivity=sensitivity.value,
            validation=validation.value, confidence=float(confidence), scope=normalized_scope,
            provenance=json.loads(provenance_json), metadata=json.loads(metadata_json),
        )
        manifest_digest = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
        record = ArtifactRecord(
            artifact_id=artifact_id,
            owner_identity_ref=owner,
            mission_id=mission,
            task_id=task,
            kind=kind,
            filename=filename_value,
            media_type=media_type,
            created_at=created_at,
            content_sha256=digest,
            manifest_sha256=manifest_digest,
            size_bytes=len(payload),
            sensitivity=sensitivity,
            validation=validation,
            confidence=float(confidence),
            scope=normalized_scope,
            provenance=json.loads(provenance_json),
            metadata=json.loads(metadata_json),
            content=payload,
        )
        with self._connect() as connection, connection:
            connection.execute(
                """INSERT INTO artifacts (
                    artifact_id, owner_identity_ref, mission_id, task_id, kind,
                    filename, media_type, created_at, content_sha256, manifest_sha256, size_bytes,
                    sensitivity, validation, confidence, scope_json,
                    provenance_json, metadata_json, content
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.artifact_id, record.owner_identity_ref, record.mission_id,
                    record.task_id, record.kind.value, record.filename, record.media_type,
                    record.created_at, record.content_sha256, record.manifest_sha256, record.size_bytes,
                    record.sensitivity.value, record.validation.value, record.confidence,
                    scope_json, provenance_json, metadata_json, sqlite3.Binary(payload),
                ),
            )
        return record

    def get(self, *, owner_identity_ref: str, artifact_id: str) -> ArtifactRecord | None:
        owner = self._identity(owner_identity_ref, "owner identity")
        if not isinstance(artifact_id, str) or not artifact_id.startswith("artifact_") or len(artifact_id) > 64:
            raise ArtifactStoreError("artifact id is invalid")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE owner_identity_ref = ? AND artifact_id = ?",
                (owner, artifact_id),
            ).fetchone()
        if row is None:
            return None
        payload = bytes(row["content"])
        digest = hashlib.sha256(payload).hexdigest()
        if len(payload) != row["size_bytes"] or not hmac.compare_digest(digest, row["content_sha256"]):
            raise ArtifactIntegrityError("artifact content failed its SHA-256 integrity check")
        try:
            scope = tuple(json.loads(row["scope_json"]))
            provenance = json.loads(row["provenance_json"])
            metadata = json.loads(row["metadata_json"])
            manifest = self._manifest_json(
                artifact_id=row["artifact_id"],
                owner_identity_ref=row["owner_identity_ref"],
                mission_id=row["mission_id"],
                task_id=row["task_id"],
                kind=row["kind"],
                filename=row["filename"],
                media_type=row["media_type"],
                created_at=row["created_at"],
                content_sha256=row["content_sha256"],
                size_bytes=row["size_bytes"],
                sensitivity=row["sensitivity"],
                validation=row["validation"],
                confidence=float(row["confidence"]),
                scope=scope,
                provenance=provenance,
                metadata=metadata,
            )
            manifest_digest = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(manifest_digest, row["manifest_sha256"]):
                raise ArtifactIntegrityError("artifact manifest failed its SHA-256 integrity check")
            return ArtifactRecord(
                artifact_id=row["artifact_id"],
                owner_identity_ref=row["owner_identity_ref"],
                mission_id=row["mission_id"],
                task_id=row["task_id"],
                kind=ArtifactKind(row["kind"]),
                filename=row["filename"],
                media_type=row["media_type"],
                created_at=row["created_at"],
                content_sha256=row["content_sha256"],
                manifest_sha256=row["manifest_sha256"],
                size_bytes=row["size_bytes"],
                sensitivity=ArtifactSensitivity(row["sensitivity"]),
                validation=ArtifactValidation(row["validation"]),
                confidence=float(row["confidence"]),
                scope=scope,
                provenance=provenance,
                metadata=metadata,
                content=payload,
            )
        except ArtifactIntegrityError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ArtifactIntegrityError("artifact metadata is malformed") from exc

    def list(
        self,
        *,
        owner_identity_ref: str,
        mission_id: str | None = None,
        task_id: str | None = None,
        kind: ArtifactKind | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        owner = self._identity(owner_identity_ref, "owner identity")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ArtifactStoreError("limit must be between 1 and 100")
        clauses = ["owner_identity_ref = ?"]
        params: list[Any] = [owner]
        if mission_id is not None:
            clauses.append("mission_id = ?")
            params.append(self._identity(mission_id, "mission id"))
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(self._identity(task_id, "task id"))
        if kind is not None:
            if not isinstance(kind, ArtifactKind):
                raise ArtifactStoreError("kind must be an ArtifactKind")
            clauses.append("kind = ?")
            params.append(kind.value)
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT artifact_id, mission_id, task_id, kind, filename, media_type, created_at, "
                "content_sha256, manifest_sha256, size_bytes, sensitivity, validation, confidence, scope_json, provenance_json, metadata_json "
                f"FROM artifacts WHERE {' AND '.join(clauses)} ORDER BY created_at, artifact_id LIMIT ?",
                params,
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            output.append({
                "artifact_id": row["artifact_id"],
                "mission_id": row["mission_id"],
                "task_id": row["task_id"],
                "kind": row["kind"],
                "filename": row["filename"],
                "media_type": row["media_type"],
                "created_at": row["created_at"],
                "content_sha256": row["content_sha256"],
                "manifest_sha256": row["manifest_sha256"],
                "size_bytes": row["size_bytes"],
                "sensitivity": row["sensitivity"],
                "validation": row["validation"],
                "confidence": row["confidence"],
                "scope": json.loads(row["scope_json"]),
                "provenance": json.loads(row["provenance_json"]),
                "metadata": json.loads(row["metadata_json"]),
            })
        return output


__all__ = [
    "ArtifactIntegrityError",
    "ArtifactKind",
    "ArtifactRecord",
    "ArtifactSensitivity",
    "ArtifactStore",
    "ArtifactStoreError",
    "ArtifactValidation",
]
