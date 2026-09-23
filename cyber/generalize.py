"""Generalization: mapping UNSEEN behaviors onto known techniques.

This is cybersentinel's adaptation capability - the analog of what a language
model does when it meets a case it has not seen. The honesty contract is
strict because this is exactly where hallucination would live:

* An unseen behavior is mapped to known techniques by STRUCTURAL similarity
  (tactic overlap, behavioral-keyword overlap) - never by invented ids.
* The output is always a ranked list of TENTATIVE hypotheses with scores.
  It can NEVER be SUPPORTED by similarity alone: promotion requires evidence
  (promote_with_evidence), otherwise it stays TENTATIVE or UNKNOWN.
* Below the similarity threshold the honest answer is UNKNOWN with the reason
  recorded - the engine refuses to force a match.
* Structured authority fields are not accepted as authority. Free-text
  vocabulary is preserved for analysis and traceability; explicit source and
  authority metadata keep it from acquiring Owner authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from cyber.case_engine import EXTERNAL_UNTRUSTED, NO_AUTHORITY
from cyber.intel_ingest import _sanitize
from cyber.knowledge_model import CyberKnowledgeGraph

_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")

# similarity threshold below which we refuse to map (honest UNKNOWN)
SIMILARITY_THRESHOLD = 0.35


@dataclass
class BehaviorFeatures:
    tactic: str = ""
    keywords: list[str] = field(default_factory=list)


@dataclass
class MappedHypothesis:
    technique_id: str
    technique_name: str
    similarity: float
    status: str = "TENTATIVE"
    reasons: list[str] = field(default_factory=list)
    source: str = EXTERNAL_UNTRUSTED
    authority: str = NO_AUTHORITY

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "similarity": round(self.similarity, 3),
            "status": self.status,
            "reasons": list(self.reasons),
            "source": self.source,
            "authority": self.authority,
        }


class UnseenTechniqueMatcher:
    """Ranks known techniques against an unseen behavior by structural similarity."""

    def __init__(self, graph: CyberKnowledgeGraph) -> None:
        self.graph = graph
        self._index = self._build_index(graph)

    @staticmethod
    def _build_index(graph: CyberKnowledgeGraph) -> list[dict[str, Any]]:
        index: list[dict[str, Any]] = []
        for entity_id, entity in graph.entities().items():
            if entity.entity_type not in ("TECHNIQUE", "SUBTECHNIQUE"):
                continue
            attrs = entity.attributes
            keywords = [str(k).lower() for k in (attrs.get("keywords") or [])]
            index.append({
                "id": entity_id,
                "name": entity.name,
                "tactic": str(attrs.get("phase", "")).lower(),
                "keywords": keywords,
            })
        return index

    def extract_features(self, description: str, *, tactic: str = "") -> BehaviorFeatures:
        safe = _sanitize({"text": description})
        # _sanitize removes untrusted structured keys; free-text cyber
        # terminology remains available to analysis and feature extraction.
        text = str(safe.get("text", "")).lower()
        known_tactics = ("initial-access", "execution", "persistence", "privilege-escalation",
                         "defense-evasion", "credential-access", "discovery", "lateral-movement",
                         "collection", "command-and-control", "exfiltration", "impact")
        found_tactic = tactic.lower()
        if not found_tactic:
            for t in known_tactics:
                if t in text:
                    found_tactic = t
                    break
        stop = {"the", "a", "an", "of", "to", "in", "on", "with", "and", "or", "was", "is", "by", "for", "from", "at", "this", "that", "it", "built"}
        words = [w for w in re.findall(r"[a-z\-]{3,}", text) if w not in stop]
        return BehaviorFeatures(tactic=found_tactic, keywords=words)

    def rank(self, features: BehaviorFeatures, *, top_k: int = 5) -> list[MappedHypothesis]:
        scored: list[MappedHypothesis] = []
        kw = {k.lower() for k in features.keywords}
        for entry in self._index:
            reasons: list[str] = []
            sim = 0.0
            if features.tactic and entry["tactic"] == features.tactic:
                sim += 0.30
                reasons.append("tactic match: {}".format(entry["tactic"]))
            if entry["keywords"]:
                overlap = kw & set(entry["keywords"])
                if overlap:
                    cov = len(overlap) / len(entry["keywords"])
                    sim += 0.70 * min(1.0, cov * 2)
                    reasons.append("behavioral keywords: {}".format(sorted(overlap)[:6]))
            if sim > 0:
                scored.append(MappedHypothesis(
                    technique_id=entry["id"],
                    technique_name=entry["name"],
                    similarity=min(sim, 1.0),
                    reasons=reasons,
                ))
        scored.sort(key=lambda m: m.similarity, reverse=True)
        return [m for m in scored if m.similarity >= SIMILARITY_THRESHOLD][:top_k]

    def map_behavior(self, description: str, *, tactic: str = "") -> dict[str, Any]:
        features = self.extract_features(description, tactic=tactic)
        ranked = self.rank(features)
        if not ranked:
            return {
                "status": "UNKNOWN",
                "hypotheses": [],
                "unknowns": [
                    "no known technique reaches the similarity threshold ({:.2f}); refusing to force a match".format(SIMILARITY_THRESHOLD)
                ],
                "features": {"tactic": features.tactic, "keywords": features.keywords},
            }
        return {
            "status": "TENTATIVE",
            "hypotheses": [m.to_dict() for m in ranked],
            "unknowns": [
                "similarity mapping is TENTATIVE by construction; promotion to SUPPORTED requires evidence"
            ],
            "features": {"tactic": features.tactic, "keywords": features.keywords},
        }

    def promote_with_evidence(self, technique_id: str, *, evidence_statement: str) -> MappedHypothesis:
        if not _TECHNIQUE_ID.match(technique_id or ""):
            raise ValueError(
                "refusing to promote an invented technique id: " + str(technique_id))
        entity = self.graph.entity(technique_id)
        if entity is None:
            raise ValueError("refusing to promote a technique absent from the graph: " + str(technique_id))
        statement = str(evidence_statement).strip()
        if not statement:
            raise ValueError("promotion requires a non-empty evidence statement")
        return MappedHypothesis(
            technique_id=technique_id,
            technique_name=entity.name,
            similarity=1.0,
            status="SUPPORTED",
            reasons=["independent evidence recorded: {}".format(statement[:120])],
            source=EXTERNAL_UNTRUSTED,
            authority=NO_AUTHORITY,
        )
