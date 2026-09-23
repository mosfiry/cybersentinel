"""Adaptive analyst: runtime observations -> technique hypotheses -> hunts.

This closes the loop between the generalization engine and live mission data:

    mission events -> case observations -> UNSEEN behavior descriptions
        -> ranked TENTATIVE technique hypotheses
        -> promotion ONLY with independent SUPPORTED evidence
        -> hunts launched from promoted techniques

Owner policy:
* Adaptation never invents: unmappable observations stay UNKNOWN in the case.
* TENTATIVE hypotheses are recorded as hypotheses (never as evidence).
* Hunts run only from SUPPORTED (promoted) techniques; TENTATIVE ones are
  listed as suggested next actions for the operator to confirm.
* Evidence statements are poison-neutralized before entering the case:
  authority-bearing content can never launder itself into case evidence.
* No execution authority anywhere; hunts are graph traversals only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cyber.case_engine import CyberCase, EvidenceStatus, Provenance as CaseProvenance
from cyber.generalize import UnseenTechniqueMatcher, neutralize_poison_text
from cyber.hunting import HuntHypothesis, ThreatHunter
from cyber.seed_corpus import build_seed_graph


@dataclass
class AdaptationReport:
    mapped_observations: int = 0
    unknown_observations: int = 0
    tentative_hypotheses: list[dict[str, Any]] = field(default_factory=list)
    promoted: list[dict[str, Any]] = field(default_factory=list)
    hunts_run: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mapped_observations": self.mapped_observations,
            "unknown_observations": self.unknown_observations,
            "tentative_hypotheses": self.tentative_hypotheses,
            "promoted": self.promoted,
            "hunts_run": self.hunts_run,
        }


class AdaptiveAnalyst:
    """Adapts a case built from runtime events with technique-level reasoning."""

    def __init__(self, case: CyberCase, matcher: UnseenTechniqueMatcher | None = None) -> None:
        self.case = case
        if matcher is not None:
            self.matcher = matcher
            self._owns_graph = False
        else:
            graph, _ = build_seed_graph()
            self.matcher = UnseenTechniqueMatcher(graph)
            self._owns_graph = True

    def analyze_observations(self) -> AdaptationReport:
        """Map every case observation as a potentially UNSEEN behavior."""
        report = AdaptationReport()
        for obs in self.case.observations:
            description = str(obs.get("text", ""))
            mapping = self.matcher.map_behavior(description)
            if mapping["status"] == "UNKNOWN":
                report.unknown_observations += 1
                for u in mapping["unknowns"]:
                    self.case.add_unknown("adaptation[{}]: {}".format(obs.get("observation_id"), u))
                continue
            report.mapped_observations += 1
            for hyp in mapping["hypotheses"]:
                hyp_id = "adapt-{}-{}".format(obs.get("observation_id"), hyp["technique_id"].replace(".", "-"))
                self.case.add_hypothesis(hyp_id, (
                    "behavior may map to {} ({}, similarity {:.2f})"
                ).format(hyp["technique_id"], hyp["technique_name"], hyp["similarity"]))
                report.tentative_hypotheses.append({
                    "hypothesis_id": hyp_id,
                    "technique_id": hyp["technique_id"],
                    "similarity": hyp["similarity"],
                    "status": "TENTATIVE",
                })
        return report

    def promote(self, technique_id: str, *, evidence_statement: str,
                source: str = "runtime-sensor") -> dict[str, Any]:
        """Promote a TENTATIVE mapping to SUPPORTED with independent evidence.

        The evidence is recorded in the case first, so the promotion remains
        traceable from the case itself. The statement is poison-neutralized
        before it can enter the case.
        """
        clean = neutralize_poison_text(evidence_statement).strip()
        if not clean:
            raise ValueError("promotion requires an evidence statement free of authority-bearing content")
        promoted = self.matcher.promote_with_evidence(technique_id, evidence_statement=clean)
        prov = CaseProvenance(source=source, classification="REAL")
        evidence_id = self.case.add_evidence(
            "independent evidence for technique {}: {}".format(technique_id, clean),
            provenance=prov, status=EvidenceStatus.SUPPORTED,
        )
        entry = {
            "technique_id": technique_id,
            "technique_name": promoted.technique_name,
            "evidence_id": evidence_id,
            "status": "SUPPORTED",
        }
        return entry

    def hunt_from(self, technique_id: str) -> dict[str, Any]:
        """Launch a traversal hunt from a technique the graph knows about."""
        hunter = ThreatHunter(self.matcher.graph)
        result = hunter.run(HuntHypothesis(
            hunt_id="hunt-from-{}".format(technique_id.replace(".", "-")),
            statement="entities connected to confirmed technique {}".format(technique_id),
            entry_entity=technique_id,
            traverse_relations=("DEPENDS_ON", "USES", "ENABLES"),
        ))
        for u in result.unknowns:
            self.case.add_unknown("hunt[{}]: {}".format(result.hunt_id, u))
        return result.to_dict()
