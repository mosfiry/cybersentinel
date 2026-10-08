from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json
import sqlite3
import threading
import uuid

from .execution_fence import ExecutionFence, ExecutionFenceError


@dataclass
class Evidence:
    claim: str
    source: str
    evidence: Any
    verification: str = "observed"
    confidence: int = 0
    timestamp: str = ""
    evidence_id: str = ""
    request_id: str = ""
    chain: tuple[str, ...] = ()
    sequence: int = 0
    previous_hash: str = ""
    current_hash: str = ""
    mission_id: str = ""
    task_id: str = ""
    execution_id: str = ""
    worker_id: str = ""
    worker_instance_id: str = ""
    runtime_generation: int = 0
    lease_epoch: int = 0
    task_version: int = 0
    authorization_hash: str = ""
    fence_id: str = ""

    def __post_init__(self):
        if type(self.confidence) is not int or not 0 <= self.confidence <= 10:
            raise ValueError("evidence confidence must be an integer from 0 to 10")
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.evidence_id:
            self.evidence_id = uuid.uuid4().hex
        if not self.current_hash:
            self.current_hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        payload = {"claim": self.claim, "source": self.source, "evidence": self.evidence, "verification": self.verification, "confidence": self.confidence, "timestamp": self.timestamp, "evidence_id": self.evidence_id, "request_id": self.request_id, "chain": list(self.chain), "sequence": self.sequence, "previous_hash": self.previous_hash}
        fence_fields = {"mission_id": self.mission_id, "task_id": self.task_id, "execution_id": self.execution_id, "worker_id": self.worker_id, "worker_instance_id": self.worker_instance_id, "runtime_generation": self.runtime_generation, "lease_epoch": self.lease_epoch, "task_version": self.task_version, "authorization_hash": self.authorization_hash, "fence_id": self.fence_id}
        if any(value not in ("", 0, None) for value in fence_fields.values()):
            payload.update(fence_fields)
        return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def verify(self) -> bool:
        return self.current_hash == self._calculate_hash()

    def to_dict(self):
        return asdict(self)


def observed(claim: str, source: str, evidence: Any, confidence: int = 10, *, request_id: str = "", chain: tuple[str, ...] = (), sequence: int = 0, previous_hash: str = "") -> dict:
    return Evidence(claim, source, evidence, "observed", max(0, min(10, confidence)), request_id=request_id, chain=chain, sequence=sequence, previous_hash=previous_hash).to_dict()


def verify_chain(records: list[dict]) -> bool:
    previous = ""
    seen_evidence_ids: set[str] = set()
    for expected_sequence, record in enumerate(records, start=1):
        if (
            not isinstance(record, dict)
            or not record.get("evidence_id")
            or not record.get("current_hash")
            or "previous_hash" not in record
        ):
            return False
        try:
            item = Evidence(**record)
        except (TypeError, ValueError, OverflowError):
            return False
        if (
            item.evidence_id in seen_evidence_ids
            or item.sequence != expected_sequence
            or item.previous_hash != previous
            or not item.verify()
        ):
            return False
        seen_evidence_ids.add(item.evidence_id)
        previous = item.current_hash
    return True


class EvidenceChainStore:
    """Durable hash chain; strict appends atomically bind evidence to mission and lease state."""

    _mission_append_lock = threading.RLock()

    @contextmanager
    def _connection(self, *, timeout: float = 5.0):
        connection = sqlite3.connect(self.db_path, timeout=timeout)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def __init__(
        self,
        db_path: str | Path,
        *,
        execution_fence: ExecutionFence | None = None,
        mission_store: Any | None = None,
        mission: Any | None = None,
        require_execution_fence: bool = False,
    ):
        self.db_path = str(db_path)
        self.execution_fence = execution_fence
        self.mission_store = mission_store
        self.mission = mission
        self.require_execution_fence = bool(require_execution_fence)
        if self.require_execution_fence and (self.mission_store is None or self.mission is None):
            raise ExecutionFenceError("strict evidence store requires its MissionStore and live mission")
        with self._connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS evidence_chain (sequence INTEGER PRIMARY KEY AUTOINCREMENT, current_hash TEXT UNIQUE NOT NULL, payload TEXT NOT NULL)")

    @staticmethod
    def _schema_name(schema: str) -> str:
        return '"' + schema.replace('"', '""') + '"'

    def _attach_atomic_stores(self, db: sqlite3.Connection, fence: ExecutionFence) -> str:
        if self.db_path == ":memory:":
            raise ExecutionFenceError("strict evidence requires a durable rollback-journal database")
        paths: dict[str, str] = {"main": str(Path(self.db_path).resolve())}
        schemas_by_path = {paths["main"]: "main"}
        for alias, path in (
            ("mission_store_db", self.mission_store.db_path),
            ("execution_queue_db", fence.queue.db_path),
        ):
            resolved = str(Path(path).resolve())
            schema = schemas_by_path.get(resolved)
            if schema is None:
                db.execute(f"ATTACH DATABASE ? AS {alias}", (resolved,))
                schema = alias
                paths[schema] = resolved
                schemas_by_path[resolved] = schema
            schemas_by_path[resolved] = schema
        for schema in dict.fromkeys(schemas_by_path.values()):
            mode = str(db.execute(f"PRAGMA {self._schema_name(schema)}.journal_mode").fetchone()[0]).lower()
            if mode not in {"delete", "truncate", "persist"}:
                raise ExecutionFenceError("evidence, mission, and queue writes require SQLite rollback-journal mode")
        return self._schema_name(schemas_by_path[str(Path(self.mission_store.db_path).resolve())])

    @staticmethod
    def _fence_marker_matches(mission: Any, fence: ExecutionFence) -> bool:
        marker = mission.progress.get("active_execution_claim")
        if not isinstance(marker, dict) or marker.get("lease_binding_id") != fence.lease_binding_id:
            return False
        expected = fence.metadata()
        # The lease identity is stable while a mission can have several sequential
        # task executions (or a declared parallel batch) under the same claim.
        for name in (
            "mission_id",
            "request_id",
            "worker_id",
            "worker_instance_id",
            "runtime_generation",
            "lease_epoch",
            "task_version",
            "authorization_hash",
        ):
            if marker.get(name) != expected.get(name):
                return False
        return True

    @staticmethod
    def _receipt(record: dict[str, Any]) -> dict[str, Any]:
        names = (
            "mission_id",
            "task_id",
            "execution_id",
            "request_id",
            "worker_id",
            "worker_instance_id",
            "runtime_generation",
            "lease_epoch",
            "task_version",
            "authorization_hash",
            "fence_id",
        )
        return {
            "evidence_id": record["evidence_id"],
            "sequence": int(record["sequence"]),
            "current_hash": str(record["current_hash"]),
            **{name: record[name] for name in names},
        }

    def _append_fenced(self, payload: dict[str, Any], fence: ExecutionFence) -> dict[str, Any]:
        from .mission import Mission

        if self.mission_store is None or self.mission is None:
            raise ExecutionFenceError("fenced evidence append requires its MissionStore and live mission")
        if not fence.queue.require_execution_fence or fence.queue.mission_store is not self.mission_store:
            raise ExecutionFenceError("fenced evidence append requires the queue's authoritative MissionStore")
        if str(getattr(self.mission, "mission_id", "")) != str(fence.mission_id):
            raise ExecutionFenceError("evidence live mission does not match execution fence")

        with self._connection(timeout=30) as db:
            mission_schema = self._attach_atomic_stores(db, fence)
            db.execute("BEGIN IMMEDIATE")
            # This single transaction holds the evidence chain, mission payload,
            # and current queue lease stable through both writes.
            stamped = fence.assert_evidence(payload)
            row = db.execute(
                f"SELECT payload FROM {mission_schema}.missions WHERE mission_id=?",
                (fence.mission_id,),
            ).fetchone()
            if row is None:
                raise ExecutionFenceError("evidence mission is not durably persisted")
            stored_mission = Mission.from_dict(json.loads(row[0]))
            fence.assert_active_execution(stored_mission, db=db)
            if not self._fence_marker_matches(stored_mission, fence):
                raise ExecutionFenceError("evidence execution does not match the durable mission claim")
            if str(getattr(self.mission, "integrity_hash", "")) != stored_mission.integrity_hash:
                raise ExecutionFenceError("evidence append mission state is stale")

            last = db.execute("SELECT sequence,current_hash FROM evidence_chain ORDER BY sequence DESC LIMIT 1").fetchone()
            sequence = int(last[0] if last else 0) + 1
            previous = str(last[1] if last else "")
            stamped["sequence"] = sequence
            stamped["previous_hash"] = previous
            # Factories may precompute a hash before the chain position is known.
            stamped.pop("current_hash", None)
            record = Evidence(**stamped)
            encoded_evidence = json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True)
            refs = stored_mission.progress.get("execution_evidence_refs", [])
            if not isinstance(refs, list):
                raise ExecutionFenceError("mission execution evidence references are invalid")
            receipt = self._receipt(record.to_dict())
            if any(isinstance(existing, dict) and existing.get("evidence_id") == receipt["evidence_id"] for existing in refs):
                raise ExecutionFenceError("duplicate evidence identity")
            duplicate = db.execute(
                "SELECT 1 FROM evidence_chain WHERE json_extract(payload,'$.evidence_id')=? LIMIT 1",
                (record.evidence_id,),
            ).fetchone()
            if duplicate:
                raise ExecutionFenceError("duplicate evidence identity")
            updated_refs = [*refs, receipt]
            stored_mission.progress["execution_evidence_refs"] = updated_refs
            encoded_mission_payload = stored_mission.to_dict()
            encoded_mission = json.dumps(encoded_mission_payload, ensure_ascii=False)

            db.execute(
                "INSERT INTO evidence_chain(sequence,current_hash,payload) VALUES(?,?,?)",
                (sequence, record.current_hash, encoded_evidence),
            )
            updated = db.execute(
                f"UPDATE {mission_schema}.missions SET payload=? WHERE mission_id=? AND payload=?",
                (encoded_mission, fence.mission_id, row[0]),
            )
            if updated.rowcount != 1:
                raise ExecutionFenceError("mission changed during evidence append")
            new_integrity_hash = str(encoded_mission_payload["integrity_hash"])

        # Keep the in-flight runtime object synchronized with the transaction so
        # its subsequent fenced mission save continues from the new CAS version.
        with self._mission_append_lock:
            self.mission.progress["execution_evidence_refs"] = updated_refs
            self.mission.integrity_hash = new_integrity_hash
        return record.to_dict()

    def _append_legacy(self, payload: dict[str, Any], fence: ExecutionFence | None) -> dict[str, Any]:
        with self._connection(timeout=30) as db:
            db.execute("BEGIN IMMEDIATE")
            if fence is not None:
                payload = fence.assert_evidence(payload)
            last = db.execute("SELECT sequence,current_hash FROM evidence_chain ORDER BY sequence DESC LIMIT 1").fetchone()
            sequence = int(last[0] if last else 0) + 1
            previous = str(last[1] if last else "")
            payload["sequence"] = sequence
            payload["previous_hash"] = previous
            # Evidence factories may precompute a hash before the chain position is known.
            payload.pop("current_hash", None)
            record = Evidence(**payload)
            duplicate = db.execute(
                "SELECT 1 FROM evidence_chain WHERE json_extract(payload,'$.evidence_id')=? LIMIT 1",
                (record.evidence_id,),
            ).fetchone()
            if duplicate:
                raise ValueError("duplicate evidence identity")
            db.execute(
                "INSERT INTO evidence_chain(sequence,current_hash,payload) VALUES(?,?,?)",
                (sequence, record.current_hash, json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True)),
            )
        return record.to_dict()

    def append(self, item: dict[str, Any], *, execution_fence: ExecutionFence | None = None) -> dict[str, Any]:
        fence = execution_fence or self.execution_fence
        if self.require_execution_fence and fence is None:
            raise ExecutionFenceError("evidence append requires an execution fence")
        payload = dict(item)
        if fence is not None:
            payload = fence.assert_evidence(payload)
        if self.require_execution_fence or (fence is not None and self.mission_store is not None and self.mission is not None):
            if fence is None:
                raise ExecutionFenceError("evidence append requires an execution fence")
            with self._mission_append_lock:
                return self._append_fenced(payload, fence)
        return self._append_legacy(payload, fence)

    def append_workspace_event(self, event: Any) -> dict[str, Any]:
        payload = asdict(event) if hasattr(event, "__dataclass_fields__") else dict(event)
        claim = f"workspace operation {payload.get('operation')} completed"
        return self.append(
            {
                "claim": claim,
                "source": f"workspace:{payload.get('tool_id') or 'unknown'}",
                "evidence": payload,
                "verification": "observed",
                "confidence": 10 if payload.get("result") == "success" else 0,
                "timestamp": datetime.fromtimestamp(float(payload.get("timestamp", 0) or 0), timezone.utc).isoformat(),
                "request_id": str(payload.get("request_id", "")),
                "mission_id": str(payload.get("mission_id", "")),
                "chain": (f"mission:{payload.get('mission_id', '')}", f"operation:{payload.get('operation', '')}"),
            },
            execution_fence=self.execution_fence,
        )

    def list(self, *, request_id: str | None = None) -> list[dict[str, Any]]:
        with self._connection() as db:
            if request_id:
                rows = db.execute("SELECT payload FROM evidence_chain WHERE json_extract(payload,'$.request_id')=? ORDER BY sequence", (request_id,)).fetchall()
            else:
                rows = db.execute("SELECT payload FROM evidence_chain ORDER BY sequence").fetchall()
        return [json.loads(row[0]) for row in rows]

    def verify(self) -> bool:
        try:
            records = self.list()
            return self.verify_records(
                records,
                mission_store=self.mission_store,
                require_execution_fence=self.require_execution_fence,
            )
        except (sqlite3.Error, KeyError, TypeError, ValueError, AttributeError, OverflowError):
            return False

    @classmethod
    def verify_records(
        cls,
        records: list[dict[str, Any]],
        *,
        mission_store: Any | None = None,
        require_execution_fence: bool = False,
    ) -> bool:
        try:
            if not verify_chain(records):
                return False
            if mission_store is None:
                return not require_execution_fence or all(
                    isinstance(record, dict) and bool(record.get("fence_id"))
                    for record in records
                )
            for record in records:
                if not isinstance(record, dict):
                    return False
                if not record.get("fence_id"):
                    if require_execution_fence:
                        return False
                    continue
                mission_id = str(record.get("mission_id", ""))
                if not mission_id:
                    return False
                mission = mission_store.load(mission_id)
                if mission is None:
                    return False
                refs = mission.progress.get("execution_evidence_refs", [])
                if not isinstance(refs, list):
                    return False
                expected = cls._receipt(record)
                if not any(
                    isinstance(receipt, dict)
                    and all(receipt.get(name) == value for name, value in expected.items())
                    for receipt in refs
                ):
                    return False
            return True
        except (sqlite3.Error, KeyError, TypeError, ValueError, AttributeError, OverflowError):
            return False


__all__ = ["Evidence", "EvidenceChainStore", "observed", "verify_chain"]
