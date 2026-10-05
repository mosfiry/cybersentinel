"""Owner-scoped, versioned persistence for agent task graphs."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from .graph import TaskGraph, TaskGraphError, TaskGraphConflict


class TaskGraphIntegrityError(ValueError):
    pass


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


class TaskGraphStore:
    """Persist graph state without granting execution authority.

    A caller must revalidate the current MissionAuthorizationSnapshot before
    claiming work. Reads are always scoped by both Owner reference and mission.
    """

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path, timeout=30) as db:
            db.execute("PRAGMA busy_timeout=30000")
            db.execute(
                "CREATE TABLE IF NOT EXISTS agent_task_graphs ("
                "owner_identity_ref TEXT NOT NULL, mission_id TEXT NOT NULL, "
                "schema_version INTEGER NOT NULL, revision INTEGER NOT NULL, "
                "payload TEXT NOT NULL, payload_sha256 TEXT NOT NULL, updated_at TEXT NOT NULL, "
                "PRIMARY KEY(owner_identity_ref, mission_id))"
            )
            db.execute("CREATE INDEX IF NOT EXISTS idx_agent_graph_owner ON agent_task_graphs(owner_identity_ref, updated_at)")

    def save(self, graph: TaskGraph, *, expected_revision: int | None = None) -> TaskGraph:
        if not isinstance(graph, TaskGraph):
            raise TypeError("TaskGraph required")
        graph.validate()
        expected = graph.revision if expected_revision is None else int(expected_revision)
        if expected < 0:
            raise ValueError("expected_revision must be non-negative")
        with sqlite3.connect(self.db_path, timeout=30, isolation_level=None) as db:
            db.execute("PRAGMA busy_timeout=30000")
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT revision FROM agent_task_graphs WHERE owner_identity_ref=? AND mission_id=?",
                (graph.owner_identity_ref, graph.mission_id),
            ).fetchone()
            current = int(row[0]) if row else 0
            if current != expected:
                db.rollback()
                raise TaskGraphConflict(f"stale task graph revision: expected {expected}, current {current}")
            next_revision = current + 1
            payload = graph.to_dict()
            payload["revision"] = next_revision
            encoded = _canonical(payload)
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            db.execute(
                "INSERT INTO agent_task_graphs(owner_identity_ref, mission_id, schema_version, revision, payload, payload_sha256, updated_at) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(owner_identity_ref, mission_id) DO UPDATE SET "
                "schema_version=excluded.schema_version, revision=excluded.revision, payload=excluded.payload, "
                "payload_sha256=excluded.payload_sha256, updated_at=excluded.updated_at",
                (graph.owner_identity_ref, graph.mission_id, TaskGraph.SCHEMA_VERSION, next_revision, encoded, digest, datetime.now(timezone.utc).isoformat()),
            )
            db.commit()
        graph.revision = next_revision
        return graph

    def load(self, owner_identity_ref: str, mission_id: str) -> TaskGraph | None:
        if not str(owner_identity_ref).strip() or not str(mission_id).strip():
            return None
        with sqlite3.connect(self.db_path, timeout=30) as db:
            db.row_factory = sqlite3.Row
            row = db.execute(
                "SELECT schema_version, revision, payload, payload_sha256 FROM agent_task_graphs "
                "WHERE owner_identity_ref=? AND mission_id=?",
                (str(owner_identity_ref), str(mission_id)),
            ).fetchone()
        if row is None:
            return None
        version = int(row["schema_version"])
        if version != self.SCHEMA_VERSION:
            raise TaskGraphIntegrityError(f"unsupported persisted graph schema version: {version}")
        encoded = str(row["payload"])
        actual = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        if actual != str(row["payload_sha256"]):
            raise TaskGraphIntegrityError("task graph payload digest mismatch")
        try:
            payload = json.loads(encoded)
            graph = TaskGraph.from_dict(payload)
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise TaskGraphIntegrityError("persisted task graph is invalid") from exc
        if graph.owner_identity_ref != owner_identity_ref or graph.mission_id != mission_id:
            raise TaskGraphIntegrityError("persisted graph owner/mission binding mismatch")
        if graph.revision != int(row["revision"]):
            raise TaskGraphIntegrityError("persisted graph revision mismatch")
        return graph

    def list_for_owner(self, owner_identity_ref: str, *, limit: int = 100) -> list[dict[str, Any]]:
        if not str(owner_identity_ref).strip():
            return []
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with sqlite3.connect(self.db_path, timeout=30) as db:
            rows = db.execute(
                "SELECT mission_id, revision, updated_at FROM agent_task_graphs "
                "WHERE owner_identity_ref=? ORDER BY updated_at DESC, mission_id LIMIT ?",
                (str(owner_identity_ref), limit),
            ).fetchall()
        return [{"mission_id": str(row[0]), "revision": int(row[1]), "updated_at": str(row[2])} for row in rows]


__all__ = ["TaskGraphIntegrityError", "TaskGraphStore"]
