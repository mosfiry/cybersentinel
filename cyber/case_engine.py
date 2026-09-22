"""Cyber case engine: structured representation of a cyber investigation case.

Owner policy (this layer):
* A case conclusion must be traceable to concrete evidence recorded in the case.
* Evidence marked CONTRADICTED cannot support a conclusion.
* Anything unexplained is recorded as UNKNOWN - never filled by guessing.
* ATT&CK technique ids and CVE ids are structurally validated; the engine
  refuses to record invented identifiers.
* This module is DATA + REASONING only. It grants no execution authority:
  authorization lives in security.authorization (Expert 2 scope).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import re


class EvidenceStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    WEAK = "WEAK"
    CONTRADICTED = "CONTRADICTED"
    UNKNOWN = "UNKNOWN"


class HypothesisStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    STRENGTHENED = "STRENGTHENED"
    WEAKENED = "WEAKENED"
    DISPROVEN = "DISPROVEN"


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    CLOSED_CONCLUDED = "CLOSED_CONCLUDED"
    CLOSED_INSUFFICIENT_EVIDENCE = "CLOSED_INSUFFICIENT_EVIDENCE"


_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass
class Provenance:
    source: str
    classification: str = "UNVERIFIED"  # REAL | PARTIAL | SYNTHETIC | FIXTURE | UNVERIFIED
    timestamp: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "classification": self.classification,
            "timestamp": self.timestamp,
        }


@dataclass
class Evidence:
    evidence_id: str
    statement: str
    status: EvidenceStatus = EvidenceStatus.UNKNOWN
    provenance: Provenance | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "statement": self.statement,
            "status": self.status.value,
            "provenance": self.provenance.as_dict() if self.provenance else None,
        }


@dataclass
class Hypothesis:
    hypothesis_id: str
    statement: str
    status: HypothesisStatus = HypothesisStatus.CANDIDATE
    supporting: list[str] = field(default_factory=list)
    opposing: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "statement": self.statement,
            "status": self.status.value,
            "supporting": list(self.supporting),
            "opposing": list(self.opposing),
        }


class CyberCase:
    """Investigation case: observations, evidence, hypotheses, conclusion.

    A conclusion is only accepted when every referenced evidence item exists
    and none of them is CONTRADICTED. Unexplained material is stored as
    unknowns instead of being silently resolved.
    """

    def __init__(self, *, objective: str, scope: str | None = None) -> None:
        if not objective or not objective.strip():
            raise ValueError("case objective is required")
        self.objective = objective
        self.scope = scope
        self.status = CaseStatus.OPEN
        self.observations: list[dict[str, Any]] = []
        self.evidence: dict[str, Evidence] = {}
        self.hypotheses: dict[str, Hypothesis] = {}
        self.contradictions: list[dict[str, Any]] = []
        self.entities: list[str] = []
        self.techniques: list[str] = []
        self.vulnerabilities: list[str] = []
        self.detections: list[str] = []
        self.mitigations: list[str] = []
        self.unknowns: list[str] = []
        self.next_actions: list[str] = []
        self.conclusion: str | None = None
        self.conclusion_evidence: list[str] = []

    # -- observations -------------------------------------------------

    def add_observation(self, text: str, *, provenance: Provenance | None = None) -> str:
        if not text or not str(text).strip():
            raise ValueError("observation text is required")
        obs_id = "obs-{}".format(len(self.observations) + 1)
        self.observations.append(
            {"observation_id": obs_id, "text": str(text), "provenance": provenance.as_dict() if provenance else None}
        )
        return obs_id

    # -- evidence ------------------------------------------------------

    def add_evidence(self, statement: str, *, provenance: Provenance | None = None,
                     status: EvidenceStatus = EvidenceStatus.WEAK) -> str:
        if not statement or not str(statement).strip():
            raise ValueError("evidence statement is required")
        evidence_id = "ev-{}".format(len(self.evidence) + 1)
        self.evidence[evidence_id] = Evidence(
            evidence_id=evidence_id, statement=str(statement), status=status, provenance=provenance
        )
        return evidence_id

    def register_contradiction(self, evidence_id_a: str, evidence_id_b: str, *, note: str = "") -> None:
        if evidence_id_a not in self.evidence or evidence_id_b not in self.evidence:
            raise ValueError("contradiction must reference recorded evidence")
        self.evidence[evidence_id_a].status = EvidenceStatus.CONTRADICTED
        self.evidence[evidence_id_b].status = EvidenceStatus.CONTRADICTED
        self.contradictions.append(
            {"a": evidence_id_a, "b": evidence_id_b, "note": note, "resolution": "UNRESOLVED"}
        )

    # -- hypotheses -----------------------------------------------------

    def add_hypothesis(self, hypothesis_id: str, statement: str) -> None:
        if hypothesis_id in self.hypotheses:
            raise ValueError("duplicate hypothesis id: " + hypothesis_id)
        self.hypotheses[hypothesis_id] = Hypothesis(hypothesis_id=hypothesis_id, statement=str(statement))

    def apply_evidence(self, hypothesis_id: str, evidence_id: str, *, supports: bool) -> None:
        if hypothesis_id not in self.hypotheses:
            raise ValueError("unknown hypothesis: " + hypothesis_id)
        if evidence_id not in self.evidence:
            raise ValueError("unknown evidence: " + evidence_id)
        ev = self.evidence[evidence_id]
        if ev.status == EvidenceStatus.CONTRADICTED:
            raise ValueError("contradicted evidence cannot update a hypothesis")
        hyp = self.hypotheses[hypothesis_id]
        if supports:
            hyp.supporting.append(evidence_id)
            if hyp.status != HypothesisStatus.DISPROVEN:
                hyp.status = HypothesisStatus.STRENGTHENED
        else:
            hyp.opposing.append(evidence_id)
            if ev.status == EvidenceStatus.SUPPORTED:
                hyp.status = HypothesisStatus.DISPROVEN
            else:
                hyp.status = HypothesisStatus.WEAKENED

    # -- structured identifiers (anti-hallucination) ---------------------

    def add_technique(self, technique_id: str) -> None:
        if not _TECHNIQUE_PATTERN.match(technique_id):
            raise ValueError("refusing to record invented ATT&CK technique id: " + str(technique_id))
        self.techniques.append(technique_id)

    def add_vulnerability(self, cve_id: str) -> None:
        if not _CVE_PATTERN.match(cve_id):
            raise ValueError("refusing to record invented CVE id: " + str(cve_id))
        self.vulnerabilities.append(cve_id)

    # -- unknowns / actions ----------------------------------------------

    def add_unknown(self, text: str) -> None:
        self.unknowns.append(str(text))

    def add_next_action(self, text: str) -> None:
        self.next_actions.append(str(text))

    # -- conclusion --------------------------------------------------------

    def add_conclusion(self, statement: str, *, evidence_ids: list[str]) -> None:
        if not evidence_ids:
            raise ValueError("refusing untraceable conclusion: no evidence referenced")
        for eid in evidence_ids:
            if eid not in self.evidence:
                raise ValueError("refusing untraceable conclusion: unknown evidence " + str(eid))
            if self.evidence[eid].status == EvidenceStatus.CONTRADICTED:
                raise ValueError("refusing conclusion supported by contradicted evidence " + str(eid))
        self.conclusion = str(statement)
        self.conclusion_evidence = list(evidence_ids)

    def close(self) -> CaseStatus:
        if self.conclusion is None:
            if self.unknowns:
                self.unknowns.append("case closed without conclusion: insufficient evidence")
            else:
                self.unknowns.append("case closed without conclusion and without recorded unknowns")
            self.status = CaseStatus.CLOSED_INSUFFICIENT_EVIDENCE
        else:
            self.status = CaseStatus.CLOSED_CONCLUDED
        return self.status

    # -- serialization -------------------------------------------------------

    def as_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "scope": self.scope,
            "status": self.status.value,
            "observations": list(self.observations),
            "evidence": [e.as_dict() for e in self.evidence.values()],
            "hypotheses": [h.as_dict() for h in self.hypotheses.values()],
            "contradictions": list(self.contradictions),
            "entities": list(self.entities),
            "techniques": list(self.techniques),
            "vulnerabilities": list(self.vulnerabilities),
            "detections": list(self.detections),
            "mitigations": list(self.mitigations),
            "unknowns": list(self.unknowns),
            "next_actions": list(self.next_actions),
            "conclusion": self.conclusion,
            "conclusion_evidence": list(self.conclusion_evidence),
        }
