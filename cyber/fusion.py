"""Cross-layer fusion: one audited pipeline across every cyber layer.

    intel ingestion -> malware triage -> knowledge graph -> threat hunting
    -> case building -> IR recommendations

Owner policy (this layer):
* Every stage's honesty gates compose: poison stripped at ingestion, evidence
  required at case building, SUPPORTED evidence required for IR actions.
* The whole pipeline is auditable: each stage's report is preserved in the
  output, including every refusal and every unknown.
* Nothing here executes anything; the terminal artifact is a recommendation
  set whose authority field is explicitly NONE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cyber.case_engine import CyberCase, EvidenceStatus, Provenance as CaseProvenance
from cyber.hunting import HuntHypothesis, HuntResult, ThreatHunter
from cyber.incident_response import IRAction, IRPlaybook
from cyber.intel_ingest import IntelIngest, IngestReport
from cyber.knowledge_model import CyberKnowledgeGraph, SourceClass
from cyber.malware import MalwareTriage, record_triage_in_graph, triage_sample


@dataclass
class FusionInput:
    intel_items: list[dict[str, Any]] = field(default_factory=list)
    malware_samples: list[dict[str, Any]] = field(default_factory=list)
    expected_families: dict[str, list[str]] | None = None
    hunts: list[HuntHypothesis] = field(default_factory=list)
    objective: str = "cross-layer simulation on synthetic fixtures"
    scope: str = "synthetic-lab"


class FusionPipeline:
    """Runs the full pipeline and returns an auditable report."""

    def __init__(self, source: str = "fusion-simulation") -> None:
        if not source or not str(source).strip():
            raise ValueError("fusion requires a provenance source label")
        self.source = source

    def run(self, data: FusionInput) -> dict[str, Any]:
        graph = CyberKnowledgeGraph()
        ingest = IntelIngest(graph)

        # -- stage 1: intel ingestion -----------------------------------
        intel_reports: list[dict[str, Any]] = []
        for item in data.intel_items:
            report = ingest.ingest_nvd_item(
                item, source="nvd-fixture", source_class=SourceClass.REAL
            )
            intel_reports.append(report.to_dict())

        # -- stage 2: malware triage --------------------------------------
        triages: list[MalwareTriage] = []
        for sample in data.malware_samples:
            triage = triage_sample(sample, expected_families=data.expected_families)
            record_triage_in_graph(
                graph, triage,
                source="static-triage", source_class=SourceClass.REAL,
            )
            triages.append(triage)

        # -- stage 3: threat hunting ----------------------------------------
        hunter = ThreatHunter(graph)
        hunt_results: list[HuntResult] = [hunter.run(h) for h in data.hunts]

        # -- stage 4: case building ------------------------------------------
        case = CyberCase(objective=data.objective, scope=data.scope)
        case_prov = CaseProvenance(source=self.source, classification="REAL")
        for triage in triages:
            case.add_observation(
                "triage of {}: verdict={}, family={} ({})".format(
                    triage.sample_id, triage.verdict,
                    triage.family or "none", triage.family_confidence,
                ),
                provenance=case_prov,
            )
            for u in triage.unknowns:
                case.add_unknown("triage[{}]: {}".format(triage.sample_id, u))

        supported_evidence: list[str] = []
        for res in hunt_results:
            for finding in res.findings:
                case.add_observation(
                    "hunt {} detected {}".format(res.hunt_id, finding),
                    provenance=case_prov,
                )
                supported_evidence.append(case.add_evidence(
                    "hunt {} traversal reached {}".format(res.hunt_id, finding),
                    provenance=case_prov, status=EvidenceStatus.SUPPORTED,
                ))
            for u in res.unknowns:
                case.add_unknown("hunt[{}]: {}".format(res.hunt_id, u))

        # -- stage 5: IR recommendations (SUPPORTED evidence only) ------------
        playbook = IRPlaybook(case)
        recommendations: list[IRAction] = []
        if supported_evidence:
            for triage in triages:
                for ioc in triage.iocs:
                    try:
                        recommendations.append(playbook.recommend_block_ioc(
                            ioc["value"], evidence_ids=supported_evidence,
                        ))
                    except ValueError:
                        # no SUPPORTED evidence applicable: honestly skipped
                        case.add_unknown(
                            "IOC {} recorded but no SUPPORTED evidence ties it to activity".format(ioc["value"])
                        )

        # -- audit assembly -------------------------------------------------------
        return {
            "objective": data.objective,
            "scope": data.scope,
            "intel_reports": intel_reports,
            "triages": [t.to_dict() for t in triages],
            "hunts": [h.to_dict() for h in hunt_results],
            "case": case.as_dict(),
            "recommendations": [r.to_dict() for r in recommendations],
            "graph": graph.to_dict(),
            "audit": {
                "refusals": {
                    "intel": [r for rep in intel_reports for r in rep["refused"]],
                    "count": sum(rep["refused"].__len__() for rep in intel_reports),
                },
                "unknowns_total": len(case.unknowns),
                "all_recommendations_authority_none": all(
                    "security.authorization" in r.authority for r in recommendations
                ),
            },
        }
