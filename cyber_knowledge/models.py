from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date
from hashlib import sha256
import json
from typing import Any


@dataclass(frozen=True)
class KnowledgeObject:
    observation: str
    technique: str = ""
    hypothesis: str = ""
    evidence: tuple[str, ...] = ()
    reasoning: tuple[str, ...] = ()
    alternative_explanations: tuple[str, ...] = ()
    confidence: float = 0.0
    source: str = ""
    source_type: str = "local"
    date: str = ""
    mitre: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    object_id: str = ""
    content_hash: str = ""

    def __post_init__(self):
        if not self.observation.strip():
            raise ValueError("observation is required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.source_type not in {"github", "huggingface", "official", "local"}:
            raise ValueError("unsupported source_type")
        if self.date and self.date > date.today().isoformat():
            raise ValueError("knowledge date cannot be in the future")
        payload = {k: v for k, v in asdict(self).items() if k not in {"object_id", "content_hash"}}
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        digest = sha256(canonical.encode()).hexdigest()
        if self.content_hash and self.content_hash != digest:
            raise ValueError("knowledge content hash mismatch")
        object.__setattr__(self, "content_hash", digest)
        if not self.object_id:
            object.__setattr__(self, "object_id", f"ko-{digest[:16]}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize(raw: dict[str, Any], *, source: str, source_type: str) -> KnowledgeObject:
    if not isinstance(raw, dict):
        raise ValueError("knowledge record must be an object")
    allowed = {"observation", "technique", "hypothesis", "evidence", "reasoning", "alternative_explanations", "confidence", "date", "mitre", "cwe"}
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(f"unknown knowledge fields: {sorted(unknown)}")
    as_tuple = lambda key: tuple(str(value).strip() for value in raw.get(key, []) if str(value).strip())
    return KnowledgeObject(
        observation=str(raw.get("observation", "")).strip(),
        technique=str(raw.get("technique", "")).strip(),
        hypothesis=str(raw.get("hypothesis", "")).strip(),
        evidence=as_tuple("evidence"),
        reasoning=as_tuple("reasoning"),
        alternative_explanations=as_tuple("alternative_explanations"),
        confidence=float(raw.get("confidence", 0.0)),
        source=source,
        source_type=source_type,
        date=str(raw.get("date", "")),
        mitre=as_tuple("mitre"),
        cwe=as_tuple("cwe"),
    )
