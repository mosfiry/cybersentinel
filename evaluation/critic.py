from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class CriticReport:
    findings: tuple[dict[str, str], ...]
    unsupported_claims: int
    missing_evidence: int
    ignored_counter_evidence: int
    poor_confidence: int
    mapping_errors: int
    passed: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def critique(assessment: dict[str, Any]) -> CriticReport:
    findings: list[dict[str, str]] = []
    if not assessment.get("required_next_evidence") and not assessment.get("required_evidence"):
        findings.append({"category": "missing_evidence", "detail": "no next evidence was requested"})
    if float(assessment.get("confidence", 0.0)) >= 0.8 and not assessment.get("supporting_evidence"):
        findings.append({"category": "poor_confidence", "detail": "high confidence without supporting evidence"})
    if assessment.get("candidate_hypotheses") and not assessment.get("alternative_explanations"):
        findings.append({"category": "bad_alternative", "detail": "no alternative explanation was recorded"})
    if assessment.get("technique_mappings") and not assessment.get("supporting_evidence"):
        findings.append({"category": "mapping_error", "detail": "mapping requires evidence review"})
    if assessment.get("contradicting_evidence") and not assessment.get("confidence_rationale"):
        findings.append({"category": "ignored_counter_evidence", "detail": "counter-evidence lacks a confidence rationale"})
    counts = {category: sum(1 for item in findings if item["category"] == category) for category in {item["category"] for item in findings}}
    return CriticReport(tuple(findings), counts.get("unsupported_claim", 0), counts.get("missing_evidence", 0), counts.get("ignored_counter_evidence", 0), counts.get("poor_confidence", 0), counts.get("mapping_error", 0), not findings)
