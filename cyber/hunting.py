"""Threat hunting: hypothesis-driven hunts over the knowledge graph.

Owner policy (this layer):
* A hunt is a QUESTION over recorded knowledge, answered by graph traversal.
* Results are honest: an empty traversal yields NO_DETECTIONS with the
  unexplained residual recorded as an unknown - never a fabricated finding.
* Hunt quality is measured against seeded ground truth only (fixtures);
  no claim of effectiveness against real environments is made.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cyber.knowledge_model import CyberKnowledgeGraph


@dataclass
class HuntHypothesis:
    hunt_id: str
    statement: str
    entry_entity: str
    traverse_relations: tuple[str, ...] = ()
    target_type: str | None = None


@dataclass
class HuntResult:
    hunt_id: str
    status: str  # DETECTED | NO_DETECTIONS
    findings: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hunt_id": self.hunt_id,
            "status": self.status,
            "findings": list(self.findings),
            "unknowns": list(self.unknowns),
        }


class ThreatHunter:
    """Runs hunt hypotheses as traversals over the evidenced subgraph."""

    def __init__(self, graph: CyberKnowledgeGraph) -> None:
        self.graph = graph

    def run(self, hypothesis: HuntHypothesis) -> HuntResult:
        result = HuntResult(hunt_id=hypothesis.hunt_id, status="NO_DETECTIONS")
        if not self.graph.has_entity(hypothesis.entry_entity):
            result.unknowns.append(
                "entry entity {} is not in the graph: hypothesis unanswerable with current knowledge".format(
                    hypothesis.entry_entity
                )
            )
            return result
        seen: set[str] = set()
        frontier = [hypothesis.entry_entity]
        while frontier:
            current = frontier.pop()
            if current in seen:
                continue
            seen.add(current)
            entity = self.graph.entity(current)
            if entity is None:
                continue
            if (hypothesis.target_type is None or entity.entity_type == hypothesis.target_type) \
                    and current != hypothesis.entry_entity:
                result.findings.append(current)
            for relation in hypothesis.traverse_relations:
                for edge in self.graph.edges_from(current, relation):
                    # _evidenced discipline is preserved by the graph queries:
                    # an UNVERIFIED edge never appears as a detection because
                    # edges_from returns raw edges; filter by evidenced status
                    if edge.provenance.source_class.value in ("REAL", "PARTIAL"):
                        frontier.append(edge.target_id)
        result.status = "DETECTED" if result.findings else "NO_DETECTIONS"
        if not result.findings:
            result.unknowns.append(
                "no evidenced path matched the hypothesis; absence of evidence is NOT evidence of absence"
            )
        return result
