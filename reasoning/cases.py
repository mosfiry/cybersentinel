from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any


@dataclass(frozen=True)
class ReasoningCase:
    case_id: str
    observations: tuple[str, ...]
    candidate_hypotheses: tuple[dict[str, Any], ...]
    supporting_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]
    alternative_explanations: tuple[str, ...]
    required_next_evidence: tuple[str, ...]
    technique_mappings: tuple[str, ...]
    confidence: float
    confidence_rationale: str
    limitations: tuple[str, ...]
    provenance: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_case(*, observation: str, hypotheses: tuple[dict[str, Any], ...], supporting: tuple[str, ...], contradicting: tuple[str, ...], alternatives: tuple[str, ...], required: tuple[str, ...], techniques: tuple[str, ...], confidence: float, confidence_rationale: str, limitations: tuple[str, ...], provenance: dict[str, Any]) -> ReasoningCase:
    normalized = {
        "observations": [observation.strip()],
        "candidate_hypotheses": hypotheses,
        "supporting_evidence": supporting,
        "contradicting_evidence": contradicting,
        "alternative_explanations": alternatives,
        "required_next_evidence": required,
        "technique_mappings": techniques,
        "confidence": confidence,
        "confidence_rationale": confidence_rationale,
    }
    case_id = "case-" + sha256(json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    return ReasoningCase(case_id, (observation.strip(),), hypotheses, supporting, contradicting, alternatives, required, techniques, confidence, confidence_rationale, limitations, provenance)
