from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import uuid

@dataclass
class Evidence:
    claim: str
    source: str
    evidence: object
    verification: str = 'observed'
    confidence: int = 0
    timestamp: str = ''
    evidence_id: str = ''

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp=datetime.now(timezone.utc).isoformat()
        if not self.evidence_id:
            self.evidence_id=uuid.uuid4().hex

    def to_dict(self):
        return asdict(self)


def observed(claim: str, source: str, evidence: object, confidence: int=10) -> dict:
    return Evidence(claim, source, evidence, 'observed', max(0,min(10,confidence))).to_dict()
