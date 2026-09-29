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
    invalid_evidence_references: int = 0
    contradictory_evidence: int = 0
    confidence_inflation: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "authority": "diagnostic_only",
            "semantic_truth_claimed": False,
            "confidence_changed": False,
            "validation_changed": False,
            "authorization_changed": False,
            "scope_changed": False,
            "completion_evidence_created": False,
            "passed_means": "no_structural_diagnostics_only_not_semantic_validation",
        }


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list, set, frozenset)):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def _confidence(value: Any) -> float | None:
    if isinstance(value, dict):
        value = value.get("claimed_value")
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if 0.0 <= parsed <= 1.0 else None


def critique(assessment: dict[str, Any]) -> CriticReport:
    """Return structural diagnostics and evidence requests; never validate truth.

    Evidence IDs are only checked for membership in a caller-supplied set that
    the canonical runtime builds from verified system evidence. The critic does
    not inspect evidence semantics, change a score/status, or affect mission
    authorization or completion.
    """
    findings: list[dict[str, str]] = []

    def add(category: str, detail: str) -> None:
        findings.append({"category": category, "detail": detail})

    required = _strings(assessment.get("required_next_evidence", assessment.get("required_evidence", ())))
    supporting = _strings(assessment.get("supporting_evidence", ()))
    counter = _strings(assessment.get("contradicting_evidence", ()))
    verified_provided = "verified_evidence_ids" in assessment
    verified = set(_strings(assessment.get("verified_evidence_ids", ())))
    rejected = set(_strings(assessment.get("unverified_evidence_ids", ())))
    if verified_provided:
        rejected.update((set(supporting) | set(counter)) - verified)
    if rejected:
        add("invalid_evidence_reference", "one or more cited evidence IDs are absent from verified system evidence; they are not treated as evidence")

    claims_present = bool(
        _strings(assessment.get("observations", ()))
        or assessment.get("candidate_hypotheses")
        or assessment.get("claims")
        or assessment.get("untrusted_claims")
    )
    if claims_present and not supporting:
        add("unsupported_claim", "observation or hypothesis claims have no verified system-evidence reference; semantic support was not assessed")
        add("missing_evidence", "no verified supporting evidence is linked to the unresolved claims; obtain independent system evidence")
    elif claims_present and not required:
        add("missing_evidence", "no specific next evidence was requested for the unresolved claims")
    elif not required and not supporting:
        add("missing_evidence", "no next evidence was requested")

    candidate_hypotheses = assessment.get("candidate_hypotheses", ())
    if isinstance(candidate_hypotheses, (tuple, list)):
        if any(isinstance(item, dict) and not str(item.get("rationale", "")).strip() for item in candidate_hypotheses):
            add("reasoning_gap", "one or more candidate hypotheses lack a recorded rationale; no inference was validated")
        if any(isinstance(item, dict) and _strings(item.get("assumptions", ())) for item in candidate_hypotheses) and not supporting:
            add("invalid_assumption", "hypothesis assumptions remain untrusted and lack verified system-evidence references")
        elif not candidate_hypotheses and claims_present and not str(assessment.get("reasoning_rationale", "")).strip():
            add("reasoning_gap", "no rationale was recorded for the untrusted observation interpretation")

    tool_claims = _strings(assessment.get("tool_interpretation_claims", ()))
    if assessment.get("tool_result_present") and tool_claims:
        add("tool_result_interpretation", "raw/model interpretation of tool output remains untrusted; reference provenance was checked, semantic match was not")

    if supporting and counter:
        add("contradictory_evidence", "supporting and counter-evidence references coexist; request resolution without inferring which is true")
    if counter and not assessment.get("confidence_rationale"):
        add("ignored_counter_evidence", "counter-evidence is recorded without a rationale or resolution request")

    alternatives = _strings(assessment.get("alternative_explanations", ()))
    if assessment.get("candidate_hypotheses") and not alternatives:
        add("bad_alternative", "no alternative explanation was recorded for the candidate hypotheses")

    techniques = _strings(assessment.get("technique_mappings", ()))
    if techniques and not supporting:
        add("mapping_error", "mapping requires verified evidence references; semantic relevance was not assessed")

    claimed_model_confidence = assessment.get("model_confidence") if "model_confidence" in assessment else assessment.get("confidence")
    model_confidence = _confidence(claimed_model_confidence)
    if model_confidence is not None and model_confidence >= 0.8:
        add("confidence_inflation", "high model/raw confidence is an untrusted claim, not an evidence-derived confidence score")
        if not supporting:
            add("poor_confidence", "high confidence claim has no verified supporting evidence reference")

    confidence_changes = assessment.get("model_confidence_changes", ())
    if isinstance(confidence_changes, (tuple, list)):
        for change in confidence_changes:
            if not isinstance(change, dict):
                continue
            try:
                delta = float(change.get("delta", 0.0))
            except (TypeError, ValueError, OverflowError):
                continue
            if delta >= 0.5 and not (
                _strings(change.get("supporting_evidence_ids", ()))
                or _strings(change.get("verified_supporting_evidence_ids", ()))
            ):
                add("confidence_inflation", "large proposed confidence increase has no evidence reference; no confidence change was applied")
                break

    counts = {category: sum(1 for item in findings if item["category"] == category) for category in {item["category"] for item in findings}}
    return CriticReport(
        findings=tuple(findings),
        unsupported_claims=counts.get("unsupported_claim", 0),
        missing_evidence=counts.get("missing_evidence", 0),
        ignored_counter_evidence=counts.get("ignored_counter_evidence", 0),
        poor_confidence=counts.get("poor_confidence", 0),
        mapping_errors=counts.get("mapping_error", 0),
        passed=not findings,
        invalid_evidence_references=counts.get("invalid_evidence_reference", 0),
        contradictory_evidence=counts.get("contradictory_evidence", 0),
        confidence_inflation=counts.get("confidence_inflation", 0),
    )
