from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable

from .observation_intelligence import ConfidenceChange, ObservationInterpretationProposal


class HypothesisStatus(str, Enum):
    ACTIVE = "ACTIVE"
    WEAKENED = "WEAKENED"
    STRENGTHENED = "STRENGTHENED"
    DISPROVEN = "DISPROVEN"
    UNRESOLVED = "UNRESOLVED"
    CONFIRMED = "CONFIRMED"
    ABANDONED = "ABANDONED"


@dataclass
class HypothesisState:
    hypothesis_id: str
    statement: str
    status: HypothesisStatus = HypothesisStatus.UNRESOLVED
    confidence: float = 0.0
    supporting_evidence_ids: list[str] = field(default_factory=list)
    counter_evidence_ids: list[str] = field(default_factory=list)
    required_evidence_ids: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.hypothesis_id or not self.statement:
            raise ValueError("hypothesis identity and statement are required")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("hypothesis confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "statement": self.statement,
            "status": self.status.value,
            "confidence": round(float(self.confidence), 6),
            "supporting_evidence_ids": list(dict.fromkeys(self.supporting_evidence_ids)),
            "counter_evidence_ids": list(dict.fromkeys(self.counter_evidence_ids)),
            "required_evidence_ids": list(dict.fromkeys(self.required_evidence_ids)),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "provenance": dict(self.provenance),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HypothesisState":
        return cls(
            hypothesis_id=str(data["hypothesis_id"]),
            statement=str(data["statement"]),
            status=HypothesisStatus(data.get("status", HypothesisStatus.UNRESOLVED.value)),
            confidence=float(data.get("confidence", 0.0)),
            supporting_evidence_ids=list(data.get("supporting_evidence_ids", ())),
            counter_evidence_ids=list(data.get("counter_evidence_ids", ())),
            required_evidence_ids=list(data.get("required_evidence_ids", ())),
            created_at=str(data.get("created_at") or datetime.now(timezone.utc).isoformat()),
            updated_at=str(data.get("updated_at") or datetime.now(timezone.utc).isoformat()),
            provenance=dict(data.get("provenance", {})),
        )


class HypothesisEngine:
    def __init__(self, hypotheses: Iterable[HypothesisState] = ()):
        self.hypotheses = {item.hypothesis_id: item for item in hypotheses}

    def snapshot(self) -> list[dict[str, Any]]:
        return [self.hypotheses[key].to_dict() for key in sorted(self.hypotheses)]

    def apply(self, proposal: ObservationInterpretationProposal, *, goal_verified: bool = False, deterministic_validation: bool = False) -> list[dict[str, Any]]:
        updates: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc).isoformat()
        for item in proposal.hypothesis_updates:
            hid = str(item.get("hypothesis_id", "")).strip()
            statement = str(item.get("statement", "")).strip()
            if not hid:
                continue
            current = self.hypotheses.get(hid) or HypothesisState(hid, statement or hid, provenance={"source": "proposal"})
            if statement:
                current.statement = statement
            if item.get("status") == HypothesisStatus.CONFIRMED.value and not (goal_verified and deterministic_validation):
                raise ValueError("model cannot confirm a hypothesis without GoalVerification and deterministic validation")
            if item.get("status"):
                current.status = HypothesisStatus(item["status"])
            self.hypotheses[hid] = current
        for change in proposal.confidence_changes:
            current = self.hypotheses.get(change.hypothesis_id)
            if current is None:
                continue
            if not change.reason or (not change.supporting_evidence_ids and not change.counter_evidence_ids):
                raise ValueError("confidence changes require reason and evidence provenance")
            current.confidence = max(0.0, min(1.0, current.confidence + float(change.delta)))
            current.supporting_evidence_ids.extend(change.supporting_evidence_ids)
            current.counter_evidence_ids.extend(change.counter_evidence_ids)
            if current.status is not HypothesisStatus.CONFIRMED:
                if change.delta < 0:
                    current.status = HypothesisStatus.DISPROVEN if current.confidence == 0 else HypothesisStatus.WEAKENED
                elif change.delta > 0:
                    current.status = HypothesisStatus.STRENGTHENED
            current.updated_at = now
            current.provenance["last_confidence_change"] = change.to_dict()
            updates.append({"hypothesis_id": current.hypothesis_id, "status": current.status.value, "confidence": current.confidence, "reason": change.reason})
        return updates

    def add_required_evidence(self, hypothesis_id: str, evidence_ids: Iterable[str]) -> None:
        if hypothesis_id in self.hypotheses:
            self.hypotheses[hypothesis_id].required_evidence_ids.extend(str(item) for item in evidence_ids)
            self.hypotheses[hypothesis_id].updated_at = datetime.now(timezone.utc).isoformat()


__all__ = ["HypothesisEngine", "HypothesisState", "HypothesisStatus"]
