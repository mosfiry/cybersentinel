from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
import hashlib
import json
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
        payload = {
            "claim": self.claim,
            "source": self.source,
            "evidence": self.evidence,
            "verification": self.verification,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "evidence_id": self.evidence_id,
            "request_id": self.request_id,
            "chain": list(self.chain),
            "sequence": self.sequence,
            "previous_hash": self.previous_hash,
        }
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
