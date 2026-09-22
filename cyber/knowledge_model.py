"""Cyber knowledge model — typed entities, provenance-carrying claims, and a
relationship graph that supports traversal-based reasoning (not keyword match).

Knowledge is DATA, never authority: nothing in this module can grant
authorization, scope, or Owner permissions. Classification discipline is
enforced by construction:

    VERIFIED   - multiple independent REAL sources support the claim
    SUPPORTED  - one REAL source supports the claim
    INFERRED   - derived from relationships, no direct source evidence
    HYPOTHESIS - asserted without evidence
    UNKNOWN    - no evidence, or entity/claim not in the graph

Fabricated identifiers (fake CVE, fake IOC, fake technique) are UNKNOWN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable


class ClaimClass(str, Enum):
    VERIFIED = "VERIFIED"
    SUPPORTED = "SUPPORTED"
    INFERRED = "INFERRED"
    HYPOTHESIS = "HYPOTHESIS"
    UNKNOWN = "UNKNOWN"


class SourceClass(str, Enum):
    REAL = "REAL"
    PARTIAL = "PARTIAL"
    SYNTHETIC = "SYNTHETIC"
    FIXTURE = "FIXTURE"
    UNVERIFIED = "UNVERIFIED"


class EdgeStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    WEAK = "WEAK"
    CONTRADICTED = "CONTRADICTED"
    UNKNOWN = "UNKNOWN"


ENTITY_TYPES = frozenset({
    "ACTOR", "CAMPAIGN", "MALWARE", "TOOL", "TECHNIQUE", "SUBTECHNIQUE",
    "VULNERABILITY", "PRODUCT", "VERSION", "ORGANIZATION", "TARGET", "IOC",
    "TTP", "CVE", "CWE", "ADVISORY", "PATCH", "COMMIT", "EXPLOIT_PRIMITIVE",
    "ATTACK_CHAIN", "EVIDENCE", "DETECTION", "MITIGATION",
})

RELATION_TYPES = frozenset({
    "USES", "TARGETS", "EXPLOITS", "AFFECTS", "PATCHES", "PRECEDES", "ENABLES",
    "REQUIRES", "DEPENDS_ON", "OBSERVED_IN", "ATTRIBUTED_TO", "DETECTED_BY",
    "MITIGATED_BY", "CONTRADICTS", "SUPPORTS",
})


@dataclass
class Provenance:
    """Where a piece of knowledge came from. Required on every claim."""

    source: str
    uri: str = ""
    retrieved_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source_class: SourceClass = SourceClass.UNVERIFIED
    confidence: float = 0.0

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("provenance requires a source")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0, 1]")
        if self.source_class not in SourceClass:
            raise ValueError("unknown source class")

    def is_independent_of(self, other: "Provenance") -> bool:
        return self.source != other.source

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "uri": self.uri,
            "retrieved_at": self.retrieved_at,
            "source_class": self.source_class.value,
            "confidence": self.confidence,
        }


@dataclass
class Entity:
    entity_id: str
    entity_type: str
    name: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.entity_id:
            raise ValueError("entity requires an id")
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError("unknown entity type: {!r}".format(self.entity_type))

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "name": self.name,
            "attributes": dict(self.attributes),
        }


@dataclass
class ClaimEdge:
    """A typed relationship, asserted by evidence, with provenance."""

    relation: str
    source_id: str
    target_id: str
    provenance: Provenance
    evidence_refs: tuple[str, ...] = ()
    confidence: float = 0.0
    status: EdgeStatus = EdgeStatus.UNKNOWN

    def __post_init__(self) -> None:
        if self.relation not in RELATION_TYPES:
            raise ValueError("unknown relation: {!r}".format(self.relation))
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0, 1]")
        if self.status is EdgeStatus.SUPPORTED and not self.evidence_refs:
            raise ValueError("a SUPPORTED edge requires evidence references")


class CyberKnowledgeGraph:
    """Typed cyber knowledge graph with provenance-enforced claims.

    All queries traverse typed relations. Identifiers are never matched by
    keyword or by name substring, so a decoy name cannot fool a query.
    """

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._edges: list[ClaimEdge] = []

    # -- construction -----------------------------------------------------

    def add_entity(self, entity: Entity) -> Entity:
        if entity.entity_id in self._entities:
            existing = self._entities[entity.entity_id]
            if existing.entity_type != entity.entity_type:
                raise ValueError("entity id collision with different type")
            return existing
        self._entities[entity.entity_id] = entity
        return entity

    def add_claim(self, edge: ClaimEdge) -> None:
        if edge.source_id not in self._entities:
            raise ValueError("claim references unknown source entity")
        if edge.target_id not in self._entities:
            raise ValueError("claim references unknown target entity")
        self._edges.append(edge)

    # -- primitive queries -------------------------------------------------

    def entities(self) -> dict[str, Entity]:
        # Read-only view of all entities (for index building).
        return dict(self._entities)

    def has_entity(self, entity_id: str) -> bool:
        return entity_id in self._entities

    def entity(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def edges_from(self, entity_id: str, relation: str | None = None) -> list[ClaimEdge]:
        return [
            edge for edge in self._edges
            if edge.source_id == entity_id
            and (relation is None or edge.relation == relation)
        ]

    def edges_to(self, entity_id: str, relation: str | None = None) -> list[ClaimEdge]:
        return [
            edge for edge in self._edges
            if edge.target_id == entity_id
            and (relation is None or edge.relation == relation)
        ]

    @staticmethod
    def _evidenced(edges: Iterable[ClaimEdge]) -> list[ClaimEdge]:
        return [
            edge for edge in edges
            if edge.status in (EdgeStatus.SUPPORTED, EdgeStatus.WEAK)
            and edge.provenance.source_class in (SourceClass.REAL, SourceClass.PARTIAL)
        ]

    # -- reasoning queries (traversal, not keyword matching) --------------

    def products_affected_by(self, cve_id: str) -> list[str]:
        """CVE -AFFECTS-> VERSION -DEPENDS_ON-> parent PRODUCT (traversal only)."""
        affected: list[str] = []
        seen: set[str] = set()
        frontier = [cve_id]
        while frontier:
            current = frontier.pop()
            for edge in self._evidenced(self.edges_from(current, "AFFECTS")):
                target = self._entities[edge.target_id]
                if target.entity_type in ("VERSION", "PRODUCT") and target.entity_id not in seen:
                    seen.add(target.entity_id)
                    affected.append(target.entity_id)
                if target.entity_type == "VERSION":
                    frontier.append(target.entity_id)
            # a VERSION's parent PRODUCT is reachable via DEPENDS_ON traversal
            for edge in self._evidenced(self.edges_from(current, "DEPENDS_ON")):
                target = self._entities[edge.target_id]
                if target.entity_type == "PRODUCT" and target.entity_id not in seen:
                    seen.add(target.entity_id)
                    affected.append(target.entity_id)
        return affected

    def techniques_of_actor(self, actor_id: str) -> list[str]:
        """Actor -(ATTRIBUTED_TO)-> CAMPAIGN -(USES)-> TOOL -(USES)-> TECHNIQUE,
        plus direct Actor -USES-> TECHNIQUE edges."""
        techniques: list[str] = []
        seen: set[str] = set()

        def visit(node: str, depth: int) -> None:
            if depth > 4:
                return
            for edge in self._evidenced(self.edges_from(node, "USES")):
                target = self._entities[edge.target_id]
                if target.entity_type == "TECHNIQUE" and target.entity_id not in seen:
                    seen.add(target.entity_id)
                    techniques.append(target.entity_id)
                elif target.entity_type in ("TOOL", "MALWARE", "CAMPAIGN"):
                    visit(target.entity_id, depth + 1)

        visit(actor_id, 0)
        for edge in self._evidenced(self.edges_from(actor_id, "ATTRIBUTED_TO")):
            visit(edge.target_id, 0)
        return techniques

    def evidence_for(self, chain_id: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for edge in self._edges:
            if edge.source_id == chain_id and edge.status in (EdgeStatus.SUPPORTED, EdgeStatus.WEAK):
                out.append({
                    "relation": edge.relation,
                    "target": edge.target_id,
                    "evidence_refs": list(edge.evidence_refs),
                    "confidence": edge.confidence,
                    "provenance": edge.provenance.to_dict(),
                })
        return out

    def detections_for(self, entity_id: str) -> list[str]:
        """entity -DETECTED_BY-> DETECTION, transitively through ATTACK_CHAIN."""
        found: list[str] = []
        seen: set[str] = set()
        frontier = [entity_id]
        while frontier:
            current = frontier.pop()
            for edge in self._evidenced(self.edges_from(current, "DETECTED_BY")):
                if edge.target_id not in seen:
                    seen.add(edge.target_id)
                    found.append(edge.target_id)
            for edge in self._evidenced(self.edges_from(current, "ENABLES")):
                if edge.target_id not in seen:
                    frontier.append(edge.target_id)
        return found

    def preconditions_for(self, entity_id: str) -> list[str]:
        """Direct REQUIRES / DEPENDS_ON targets of a hypothesis or primitive."""
        out: list[str] = []
        for relation in ("REQUIRES", "DEPENDS_ON"):
            for edge in self._evidenced(self.edges_from(entity_id, relation)):
                if edge.target_id not in out:
                    out.append(edge.target_id)
        return out

    # -- claim classification ----------------------------------------------

    def supporting_sources(self, entity_id: str) -> list[Provenance]:
        return [
            edge.provenance
            for edge in self._evidenced(self.edges_from(entity_id))
        ]

    def classify_entity(self, entity_id: str) -> ClaimClass:
        if not self.has_entity(entity_id):
            return ClaimClass.UNKNOWN
        provs = self.supporting_sources(entity_id)
        real = [p for p in provs if p.source_class is SourceClass.REAL]
        if len(real) >= 2 and len({p.source for p in real}) >= 2:
            return ClaimClass.VERIFIED
        if real:
            return ClaimClass.SUPPORTED
        if provs:
            return ClaimClass.SUPPORTED
        return ClaimClass.HYPOTHESIS

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities": {k: v.to_dict() for k, v in self._entities.items()},
            "edges": [
                {
                    "relation": edge.relation,
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "status": edge.status.value,
                    "confidence": edge.confidence,
                    "provenance": edge.provenance.to_dict(),
                    "evidence_refs": list(edge.evidence_refs),
                }
                for edge in self._edges
            ],
        }


def classify_cyber_claim(graph: CyberKnowledgeGraph, entity_id: str) -> ClaimClass:
    """Anti-hallucination entrypoint: a fabricated identifier is UNKNOWN."""
    return graph.classify_entity(entity_id)
