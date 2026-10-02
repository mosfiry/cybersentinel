from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json
import sqlite3
import uuid


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

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.evidence_id:
            self.evidence_id = uuid.uuid4().hex
        if not self.current_hash:
            self.current_hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        payload = {"claim": self.claim, "source": self.source, "evidence": self.evidence, "verification": self.verification, "confidence": self.confidence, "timestamp": self.timestamp, "evidence_id": self.evidence_id, "request_id": self.request_id, "chain": list(self.chain), "sequence": self.sequence, "previous_hash": self.previous_hash}
        return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def verify(self) -> bool:
        return self.current_hash == self._calculate_hash()

    def to_dict(self):
        return asdict(self)


def observed(claim: str, source: str, evidence: Any, confidence: int = 10, *, request_id: str = "", chain: tuple[str, ...] = (), sequence: int = 0, previous_hash: str = "") -> dict:
    return Evidence(claim, source, evidence, "observed", max(0, min(10, confidence)), request_id=request_id, chain=chain, sequence=sequence, previous_hash=previous_hash).to_dict()


def verify_chain(records: list[dict]) -> bool:
    previous = ""
    for expected_sequence, record in enumerate(records, start=1):
        item = Evidence(**record)
        if item.sequence != expected_sequence or item.previous_hash != previous or not item.verify():
            return False
        previous = item.current_hash
    return True


def _mission_event_hash(payload: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "current_hash"}
    return hashlib.sha256(json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class MissionEvidenceChain:
    """Claim-scoped evidence events stored transactionally with their mission."""

    @staticmethod
    def initialize(db: sqlite3.Connection) -> None:
        db.execute(
            "CREATE TABLE IF NOT EXISTS mission_evidence_events ("
            "mission_id TEXT NOT NULL, sequence INTEGER NOT NULL, current_hash TEXT NOT NULL, payload TEXT NOT NULL, "
            "PRIMARY KEY(mission_id,sequence), UNIQUE(mission_id,current_hash))"
        )

    @classmethod
    def append_in_transaction(cls, db: sqlite3.Connection, mission_id: str, records: list[dict[str, Any]], claim: Any) -> list[dict[str, Any]]:
        if not records:
            return []
        rows = db.execute(
            "SELECT payload FROM mission_evidence_events WHERE mission_id=? ORDER BY sequence",
            (mission_id,),
        ).fetchall()
        existing = [json.loads(row[0]) for row in rows]
        if not cls.verify(existing):
            raise ValueError("mission evidence hash chain integrity mismatch")
        sequence = len(existing)
        previous_hash = str(existing[-1]["current_hash"]) if existing else ""
        appended: list[dict[str, Any]] = []
        for record in records:
            sequence += 1
            event = {
                "mission_id": mission_id,
                "sequence": sequence,
                "previous_hash": previous_hash,
                "evidence": dict(record),
                "worker_id": str(claim.worker_id),
                "lease_id": str(claim.lease_id),
                "generation": int(claim.generation),
                "acquired_at": str(claim.acquired_at),
                "expires_at": str(claim.expires_at),
            }
            event["current_hash"] = _mission_event_hash(event)
            db.execute(
                "INSERT INTO mission_evidence_events(mission_id,sequence,current_hash,payload) VALUES(?,?,?,?)",
                (mission_id, sequence, event["current_hash"], json.dumps(event, ensure_ascii=False, sort_keys=True)),
            )
            appended.append(event)
            previous_hash = event["current_hash"]
        return appended

    @staticmethod
    def list(db_path: str | Path, mission_id: str) -> list[dict[str, Any]]:
        with sqlite3.connect(str(db_path)) as db:
            rows = db.execute(
                "SELECT payload FROM mission_evidence_events WHERE mission_id=? ORDER BY sequence",
                (mission_id,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    @staticmethod
    def verify(records: list[dict[str, Any]]) -> bool:
        previous_hash = ""
        mission_id: str | None = None
        for sequence, event in enumerate(records, start=1):
            if mission_id is None:
                mission_id = str(event.get("mission_id", ""))
            if (
                str(event.get("mission_id", "")) != mission_id
                or int(event.get("sequence", 0)) != sequence
                or str(event.get("previous_hash", "")) != previous_hash
                or str(event.get("current_hash", "")) != _mission_event_hash(event)
            ):
                return False
            previous_hash = str(event["current_hash"])
        return True


class EvidenceChainStore:
    """Durable adapter for the existing hash-linked Evidence schema."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS evidence_chain (sequence INTEGER PRIMARY KEY AUTOINCREMENT, current_hash TEXT UNIQUE NOT NULL, payload TEXT NOT NULL)")

    def append(self, item: dict[str, Any]) -> dict[str, Any]:
        with sqlite3.connect(self.db_path) as db:
            last = db.execute("SELECT sequence,current_hash FROM evidence_chain ORDER BY sequence DESC LIMIT 1").fetchone()
            sequence = int(last[0] if last else 0) + 1
            previous = str(last[1] if last else "")
            payload = dict(item)
            payload["sequence"] = sequence
            payload["previous_hash"] = previous
            record = Evidence(**payload)
            db.execute("INSERT INTO evidence_chain(sequence,current_hash,payload) VALUES(?,?,?)", (sequence, record.current_hash, json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True)))
        return record.to_dict()

    def append_workspace_event(self, event: Any) -> dict[str, Any]:
        payload = asdict(event) if hasattr(event, "__dataclass_fields__") else dict(event)
        claim = f"workspace operation {payload.get('operation')} completed"
        return self.append({"claim": claim, "source": f"workspace:{payload.get('tool_id') or 'unknown'}", "evidence": payload, "verification": "observed", "confidence": 10 if payload.get("result") == "success" else 0, "timestamp": datetime.fromtimestamp(float(payload.get("timestamp", 0) or 0), timezone.utc).isoformat(), "request_id": str(payload.get("request_id", "")), "chain": (f"mission:{payload.get('mission_id', '')}", f"operation:{payload.get('operation', '')}")})

    def list(self, *, request_id: str | None = None) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as db:
            if request_id:
                rows = db.execute("SELECT payload FROM evidence_chain WHERE json_extract(payload,'$.request_id')=? ORDER BY sequence", (request_id,)).fetchall()
            else:
                rows = db.execute("SELECT payload FROM evidence_chain ORDER BY sequence").fetchall()
        return [json.loads(row[0]) for row in rows]

    def verify(self) -> bool:
        return verify_chain(self.list())


__all__ = ["Evidence", "EvidenceChainStore", "MissionEvidenceChain", "observed", "verify_chain"]
