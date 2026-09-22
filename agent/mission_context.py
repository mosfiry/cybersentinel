from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import hashlib
import json


@dataclass(frozen=True)
class ContextRecord:
    record_id: str
    content: dict[str, Any]
    source: str
    provenance: dict[str, Any] = field(default_factory=dict)
    content_hash: str = ""

    def __post_init__(self) -> None:
        expected = hashlib.sha256(json.dumps(self.content, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()
        if self.content_hash and self.content_hash != expected:
            raise ValueError("context record hash mismatch")
        if not self.content_hash:
            object.__setattr__(self, "content_hash", expected)

    def to_dict(self) -> dict[str, Any]:
        return {"record_id": self.record_id, "content": self.content, "source": self.source, "provenance": self.provenance, "content_hash": self.content_hash}


@dataclass
class MissionContext:
    mission_id: str
    working: list[ContextRecord] = field(default_factory=list)
    mission_memory: list[ContextRecord] = field(default_factory=list)
    workspace_memory: list[ContextRecord] = field(default_factory=list)
    evidence_memory: list[ContextRecord] = field(default_factory=list)
    knowledge: list[ContextRecord] = field(default_factory=list)

    def add(self, domain: str, record: ContextRecord) -> None:
        if domain in {"authorization", "owner_policy", "owner_instruction"}:
            raise ValueError("authority is not memory and must remain in AuthorizationContext")
        collection = {
            "working": self.working,
            "mission": self.mission_memory,
            "workspace": self.workspace_memory,
            "evidence": self.evidence_memory,
            "knowledge": self.knowledge,
        }.get(domain)
        if collection is None:
            raise ValueError("unknown context domain")
        collection.append(record)

    def snapshot(self) -> dict[str, Any]:
        return {"mission_id": self.mission_id, "working": [item.to_dict() for item in self.working], "mission_memory": [item.to_dict() for item in self.mission_memory], "workspace_memory": [item.to_dict() for item in self.workspace_memory], "evidence_memory": [item.to_dict() for item in self.evidence_memory], "knowledge": [item.to_dict() for item in self.knowledge]}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "MissionContext":
        value = cls(str(payload["mission_id"]))
        for domain, key in (("working", "working"), ("mission", "mission_memory"), ("workspace", "workspace_memory"), ("evidence", "evidence_memory"), ("knowledge", "knowledge")):
            for item in payload.get(key, ()):
                value.add(domain, ContextRecord(**item))
        return value


__all__ = ["ContextRecord", "MissionContext"]
