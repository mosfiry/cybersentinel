from __future__ import annotations

from cyber_knowledge.models import KnowledgeObject
from .cases import ReasoningCase, make_case


def from_knowledge(obj: KnowledgeObject) -> ReasoningCase:
    alternatives = obj.alternative_explanations or ("benign operational activity", "data is insufficient for a determination")
    required = obj.evidence or ("independent telemetry", "timeline", "asset and user context")
    return make_case(
        observation=obj.observation,
        hypotheses=({"hypothesis": obj.hypothesis or "the observation is consistent with the mapped technique", "status": "requires_evidence"},),
        supporting=(),
        contradicting=(),
        alternatives=tuple(alternatives),
        required=tuple(required),
        techniques=tuple(obj.mitre),
        confidence=min(obj.confidence, 0.5),
        confidence_rationale="Knowledge source metadata creates a testable case; it does not establish that the observation is malicious.",
        limitations=("Generated from reference data; no attack procedure or executable instruction is retained.", "Human review and independent evidence are required."),
        provenance={"source": obj.source, "source_type": obj.source_type, "content_hash": obj.content_hash, "knowledge_object_id": obj.object_id},
    )
