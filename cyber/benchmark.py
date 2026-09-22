"""Cyber reasoning benchmark — development cases only.

Scores are recorded per dimension, never as a single number:
    accuracy, evidence_quality, unsupported_claims, uncertainty_calibration.
Evaluation cases live separately (holdout) and are NOT used in development.
The dev cases here drive the multi-hypothesis / chain / conflict engines and
measure the model-layer discipline, not memorized answers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from cyber.knowledge_model import ClaimClass
from cyber.reasoning import (
    AttackChainReconstructor,
    ChainEdge,
    CyberClaimGate,
    CyberEvidence,
    MultiHypothesisEngine,
    SourceClaim,
    SourceConflictEngine,
)
from cyber.knowledge_model import CyberKnowledgeGraph, EdgeStatus, Entity, Provenance, SourceClass


@dataclass
class BenchmarkResult:
    case_id: str
    passed: bool
    unsupported_claims: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class Case:
    case_id: str
    dimension: str
    run: Callable[[], tuple[bool, int, list[str]]]


def _real(source: str, conf: float = 0.9) -> Provenance:
    return Provenance(source=source, source_class=SourceClass.REAL, confidence=conf)


def _case_uncertainty_calibration() -> tuple[bool, int, list[str]]:
    engine = MultiHypothesisEngine([
        ("legit", "legitimate process", 0.5),
        ("malware", "malware artifact", 0.5),
    ])
    engine.apply(CyberEvidence(kind="single_connection", likelihoods={"legit": 0.6, "malware": 0.6}))
    if engine.dominant() is not None:
        return False, 1, ["declared a winner from non-discriminating evidence"]
    engine.apply(CyberEvidence(kind="known_malicious_hash_match", likelihoods={"legit": 0.02, "malware": 0.95}))
    dominant = engine.dominant()
    return dominant is not None and dominant.hypothesis_id == "malware", 0, []


def _case_attack_chain_reconstruction() -> tuple[bool, int, list[str]]:
    recon = AttackChainReconstructor()
    partial = recon.reconstruct([
        ChainEdge("OBSERVATION", "PRIMITIVE", evidence_refs=("e",), confidence=0.9, source="research", status=EdgeStatus.SUPPORTED),
    ])
    if partial["status"] != "UNKNOWN":
        return False, 1, ["incomplete chain was fabricated into a conclusion"]
    return partial["missing_transitions"] and "PRIMITIVE -> HYPOTHESIS" in partial["missing_transitions"], 0, []


def _case_source_conflict() -> tuple[bool, int, list[str]]:
    engine = SourceConflictEngine()
    result = engine.evaluate([
        SourceClaim("critical", _real("vendor-a")),
        SourceClaim("high", _real("vendor-b")),
    ])
    if result["status"] != "UNRESOLVED" or len(result["values"]) != 2:
        return False, 1, ["conflict was auto-resolved without decisive weight"]
    return True, 0, []


def _case_anti_hallucination() -> tuple[bool, int, list[str]]:
    g = CyberKnowledgeGraph()
    g.add_entity(Entity("IOC-KNOWN", "IOC", "known"))
    g.add_claim(__import__("cyber.knowledge_model", fromlist=["ClaimEdge"]).ClaimEdge(
        "SUPPORTS", "IOC-KNOWN", "IOC-KNOWN", _real("vendor-a"), evidence_refs=("e",), confidence=0.9, status=EdgeStatus.SUPPORTED
    ))
    gate = CyberClaimGate(g)
    fake = gate.classify("IOC-FAKE-123", "this IOC is malicious")
    known = gate.classify("IOC-KNOWN", "this IOC is malicious")
    if fake["classification"] != "UNKNOWN":
        return False, 1, ["fabricated IOC was classified as known"]
    if known["classification"] != "SUPPORTED" or known["source_count"] != 1:
        return False, 1, ["known IOC misclassified"]
    return True, 0, []


DEV_CASES: list[Case] = [
    Case("dev-uncertainty-01", "uncertainty_calibration", _case_uncertainty_calibration),
    Case("dev-chain-01", "attack_chain_reconstruction", _case_attack_chain_reconstruction),
    Case("dev-conflict-01", "source_conflict", _case_source_conflict),
    Case("dev-antihalluc-01", "anti_hallucination", _case_anti_hallucination),
]


def run_benchmark(cases: list[Case] | None = None) -> dict:
    results = [BenchmarkResult(case.case_id, *case.run()) for case in (cases or DEV_CASES)]
    passed = sum(1 for r in results if r.passed)
    unsupported = sum(r.unsupported_claims for r in results)
    dimensions: dict[str, dict] = {}
    for r in results:
        dim = dimensions.setdefault(r.case_id.split("-")[1], {"passed": 0, "total": 0, "unsupported_claims": 0})
        dim["total"] += 1
        dim["passed"] += 1 if r.passed else 0
        dim["unsupported_claims"] += r.unsupported_claims
    return {
        "cases_run": len(results),
        "cases_passed": passed,
        "unsupported_claims": unsupported,
        "by_dimension": dimensions,
        "holdout": "unseen evaluation cases must be supplied separately; dev cases never measure final performance",
    }
