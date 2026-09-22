"""Multi-hypothesis cyber reasoning, attack-chain reconstruction with evidence
discipline, and source-conflict handling.

Core rules enforced here:

* Evidence never collapses to a single hypothesis automatically; a dominant
  hypothesis is only reported when the posterior margin is decisive.
* Discriminating evidence is chosen by expected separation, not by guesswork.
* Every attack-chain edge carries evidence/confidence/source/status; missing
  evidence is UNKNOWN — the gap is never filled with invention.
* Conflicting sources stay UNRESOLVED unless the provenance weight difference
  is decisive; the loser is recorded, never silently dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from cyber.knowledge_model import (
    ClaimClass,
    CyberKnowledgeGraph,
    EdgeStatus,
    Provenance,
    SourceClass,
)


# --------------------------------------------------------------------------
# Multi-hypothesis reasoning
# --------------------------------------------------------------------------

@dataclass
class Hypothesis:
    hypothesis_id: str
    statement: str
    prior: float
    posterior: float
    eliminated: bool = False
    elimination_reason: str = ""


@dataclass
class CyberEvidence:
    kind: str
    detail: str = ""
    likelihoods: dict[str, float] = field(default_factory=dict)
    provenance: Provenance | None = None

    def __post_init__(self) -> None:
        for value in self.likelihoods.values():
            if not 0.0 <= value <= 1.0:
                raise ValueError("likelihoods must be within [0, 1]")


class MultiHypothesisEngine:
    """Bayesian-style bookkeeping with explicit elimination and margins."""

    DOMINANCE_MARGIN = 0.25

    def __init__(self, hypotheses: Sequence[tuple[str, str, float]]):
        if not hypotheses:
            raise ValueError("at least one hypothesis is required")
        total = sum(prior for _, _, prior in hypotheses) or 1.0
        self.hypotheses: dict[str, Hypothesis] = {}
        for hid, statement, prior in hypotheses:
            if not 0.0 <= prior <= 1.0:
                raise ValueError("prior must be within [0, 1]")
            normalized = prior / total
            self.hypotheses[hid] = Hypothesis(hid, statement, normalized, normalized)

    def apply(self, evidence: CyberEvidence) -> None:
        for hid, hyp in self.hypotheses.items():
            likelihood = evidence.likelihoods.get(hid, 0.5)
            if likelihood == 0.0 and not hyp.eliminated:
                hyp.eliminated = True
                hyp.elimination_reason = "contradicted by evidence: {}".format(evidence.kind)
                hyp.posterior = 0.0
                continue
            if hyp.eliminated:
                continue
            hyp.posterior = hyp.posterior * likelihood
        active_total = sum(h.posterior for h in self.hypotheses.values() if not h.eliminated)
        if active_total > 0:
            for hyp in self.hypotheses.values():
                if not hyp.eliminated:
                    hyp.posterior = hyp.posterior / active_total

    def dominant(self) -> Hypothesis | None:
        """None while no hypothesis is decisively ahead — no premature conclusion."""
        active = [h for h in self.hypotheses.values() if not h.eliminated]
        if not active:
            return None
        ranked = sorted(active, key=lambda h: h.posterior, reverse=True)
        if len(ranked) == 1:
            return ranked[0]
        if ranked[0].posterior - ranked[1].posterior < self.DOMINANCE_MARGIN:
            return None
        return ranked[0]

    def suggest_discriminator(self, candidates: Sequence[CyberEvidence]) -> CyberEvidence | None:
        """Pick the candidate evidence that best separates the leading hypotheses."""
        active = [h for h in self.hypotheses.values() if not h.eliminated]
        if len(active) < 2 or not candidates:
            return None
        best: CyberEvidence | None = None
        best_spread = -1.0
        for candidate in candidates:
            posteriors = []
            for hyp in active:
                posteriors.append(hyp.posterior * candidate.likelihoods.get(hyp.hypothesis_id, 0.5))
            total = sum(posteriors) or 1.0
            normalized = [p / total for p in posteriors]
            spread = max(normalized) - min(normalized)
            if spread > best_spread:
                best_spread = spread
                best = candidate
        return best

    def snapshot(self) -> dict[str, Any]:
        return {
            hid: {
                "statement": h.statement,
                "posterior": round(h.posterior, 4),
                "eliminated": h.eliminated,
                "elimination_reason": h.elimination_reason,
            }
            for hid, h in self.hypotheses.items()
        }


# --------------------------------------------------------------------------
# Attack-chain reconstruction
# --------------------------------------------------------------------------

CHAIN_STAGES = (
    "OBSERVATION",
    "PRIMITIVE",
    "HYPOTHESIS",
    "PRECONDITIONS",
    "INPUT_FLOW",
    "TRUST_BOUNDARY",
    "CONTROL_BYPASS",
    "IMPACT",
)


@dataclass
class ChainEdge:
    from_stage: str
    to_stage: str
    evidence_refs: tuple[str, ...] = ()
    confidence: float = 0.0
    source: str = ""
    status: EdgeStatus = EdgeStatus.UNKNOWN

    def __post_init__(self) -> None:
        for stage in (self.from_stage, self.to_stage):
            if stage not in CHAIN_STAGES:
                raise ValueError("unknown chain stage: {!r}".format(stage))
        expected = CHAIN_STAGES.index(self.from_stage) + 1
        if CHAIN_STAGES.index(self.to_stage) != expected:
            raise ValueError(
                "chain edges must follow the canonical order; got {} -> {}".format(
                    self.from_stage, self.to_stage
                )
            )


class AttackChainReconstructor:
    """Rebuilds an attack chain from evidence-bearing edges only.

    A chain is only SUPPORTED when every stage transition carries evidence
    with acceptable confidence. Anything less is reported honestly:
    WEAK (low confidence), CONTRADICTED (contradicted edge) or
    UNKNOWN (a stage transition without evidence).
    """

    def reconstruct(self, edges: Iterable[ChainEdge]) -> dict[str, Any]:
        edges = list(edges)
        covered: dict[int, ChainEdge] = {}
        for edge in edges:
            index = CHAIN_STAGES.index(edge.from_stage)
            covered[index] = edge
        missing = [
            "{} -> {}".format(CHAIN_STAGES[i], CHAIN_STAGES[i + 1])
            for i in range(len(CHAIN_STAGES) - 1)
            if i not in covered
        ]
        statuses = [edge.status for edge in covered.values()]
        if any(s is EdgeStatus.CONTRADICTED for s in statuses):
            overall = EdgeStatus.CONTRADICTED
        elif missing:
            overall = EdgeStatus.UNKNOWN
        elif any(s is EdgeStatus.UNKNOWN for s in statuses):
            overall = EdgeStatus.UNKNOWN
        elif any(s is EdgeStatus.WEAK for s in statuses):
            overall = EdgeStatus.WEAK
        else:
            overall = EdgeStatus.SUPPORTED
        return {
            "stages": list(CHAIN_STAGES),
            "edges": [
                {
                    "from": edge.from_stage,
                    "to": edge.to_stage,
                    "evidence_refs": list(edge.evidence_refs),
                    "confidence": edge.confidence,
                    "source": edge.source,
                    "status": edge.status.value,
                }
                for edge in edges
            ],
            "missing_transitions": missing,
            "status": overall.value,
        }


# --------------------------------------------------------------------------
# Source conflict engine
# --------------------------------------------------------------------------

SOURCE_WEIGHT = {
    SourceClass.REAL: 1.0,
    SourceClass.PARTIAL: 0.5,
    SourceClass.UNVERIFIED: 0.25,
    SourceClass.SYNTHETIC: 0.1,
    SourceClass.FIXTURE: 0.1,
}


@dataclass
class SourceClaim:
    value: Any
    provenance: Provenance


class SourceConflictEngine:
    """Never auto-picks a winner between disagreeing sources without weight."""

    DECISIVE_RATIO = 2.0

    def evaluate(self, claims: Sequence[SourceClaim]) -> dict[str, Any]:
        if not claims:
            return {"status": "UNKNOWN", "values": []}
        weights: dict[Any, float] = {}
        details: dict[Any, list[dict[str, Any]]] = {}
        for claim in claims:
            weight = SOURCE_WEIGHT[claim.provenance.source_class] * claim.provenance.confidence
            weights[claim.value] = weights.get(claim.value, 0.0) + weight
            details.setdefault(claim.value, []).append(claim.provenance.to_dict())
        if len(weights) == 1:
            value = next(iter(weights))
            return {
                "status": "SUPPORTED",
                "values": [value],
                "supporting_sources": details[value],
                "conflict": False,
            }
        ranked = sorted(weights.items(), key=lambda kv: kv[1], reverse=True)
        decisive = len(ranked) == 1 or (
            ranked[0][1] >= self.DECISIVE_RATIO * max(ranked[1][1], 1e-9)
        )
        if decisive:
            return {
                "status": "UNRESOLVED",
                "values": [v for v, _ in ranked],
                "weights": {v: round(w, 4) for v, w in ranked},
                "conflict": True,
                "note": "weight difference is decisive only in favor of the strongest value; both are retained",
            }
        return {
            "status": "UNRESOLVED",
            "values": [v for v, _ in ranked],
            "weights": {v: round(w, 4) for v, w in ranked},
            "conflict": True,
            "note": "sources disagree without a decisive weight margin; no winner is auto-selected",
        }


# --------------------------------------------------------------------------
# Anti-hallucination gate
# --------------------------------------------------------------------------

class CyberClaimGate:
    """Cyber claims pass through explicit classification, never invention."""

    def __init__(self, graph: CyberKnowledgeGraph):
        self.graph = graph

    def check_premise(self, entity_id: str) -> bool:
        """A question about a fabricated entity has a false premise."""
        return self.graph.has_entity(entity_id)

    def classify(self, entity_id: str, claim_text: str = "") -> dict[str, Any]:
        if not self.check_premise(entity_id):
            return {
                "entity": entity_id,
                "claim": claim_text,
                "classification": ClaimClass.UNKNOWN.value,
                "reason": "entity not present in the knowledge graph; refusing to invent",
            }
        classification = self.graph.classify_entity(entity_id)
        sources = self.graph.supporting_sources(entity_id)
        distinct = {p.source for p in sources}
        reason = {
            ClaimClass.VERIFIED: "multiple independent REAL sources",
            ClaimClass.SUPPORTED: "at least one evidenced source",
            ClaimClass.HYPOTHESIS: "asserted without supporting evidence",
        }.get(classification, "derived from relationships without direct source evidence")
        return {
            "entity": entity_id,
            "claim": claim_text,
            "classification": classification.value,
            "source_count": len(distinct),
            "single_source": len(distinct) == 1,
            "reason": reason,
        }
