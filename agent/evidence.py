from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
import uuid

@dataclass
class Evidence:
    claim: str
    source: str
    evidence: Any
    verification: str = 'observed'
    confidence: int = 0
    timestamp: str = ''
    evidence_id: str = ''
    request_id: str = ''
    chain: tuple[str, ...] = ()

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp=datetime.now(timezone.utc).isoformat()
        if not self.evidence_id:
            self.evidence_id=uuid.uuid4().hex

    def to_dict(self):
        return asdict(self)


def observed(claim: str, source: str, evidence: Any, confidence: int=10, *, request_id: str = '', chain: tuple[str, ...] = ()) -> dict:
    return Evidence(claim, source, evidence, 'observed', max(0,min(10,confidence)), request_id=request_id, chain=chain).to_dict()
