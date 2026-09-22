"""Behavioral tests for multi-hypothesis reasoning, attack-chain discipline,
source conflicts, and the anti-hallucination gate.

The tests fail if any boundary is removed: e.g. if the gate auto-verified
unknowns, if chains filled missing evidence, or if conflicts auto-picked a side.
"""

from __future__ import annotations

import pytest

from cyber.knowledge_model import (
    ClaimClass,
    CyberKnowledgeGraph,
    EdgeStatus,
    Entity,
    Provenance,
    SourceClass,
)
from cyber.reasoning import (
    AttackChainReconstructor,
    ChainEdge,
    CyberClaimGate,
    CyberEvidence,
    MultiHypothesisEngine,
    SourceClaim,
    SourceConflictEngine,
)


def real(source="vendor", conf=0.9):
    return Provenance(source=source, source_class=SourceClass.REAL, confidence=conf)


# --------------------------------------------------------------------------
# Multi-hypothesis
# --------------------------------------------------------------------------

def test_outbound_connection_does_not_automatically_mean_c2():
    engine = MultiHypothesisEngine([
        ("legit_update", "legitimate software update traffic", 0.4),
        ("cdn", "CDN fetch", 0.3),
        ("c2", "command and control channel", 0.2),
        ("telemetry", "telemetry beacon", 0.1),
    ])
    engine.apply(CyberEvidence(
        kind="outbound_connection",
        detail="process opened an outbound HTTPS connection",
        likelihoods={"legit_update": 0.7, "cdn": 0.6, "c2": 0.75, "telemetry": 0.5},
        provenance=real(),
    ))
    assert engine.dominant() is None, "one observation must not crown a hypothesis"


def test_discriminating_evidence_selects_max_separation_and_eliminates():
    engine = MultiHypothesisEngine([
        ("legit_update", "legitimate update", 0.4),
        ("cdn", "CDN", 0.3),
        ("c2", "C2", 0.2),
        ("telemetry", "telemetry", 0.1),
    ])
    candidates = [
        CyberEvidence(kind="dest_is_cdn_ip", likelihoods={"legit_update": 0.2, "cdn": 0.9, "c2": 0.3, "telemetry": 0.2}),
        CyberEvidence(kind="periodic_beacon_to_raw_ip", likelihoods={"legit_update": 0.05, "cdn": 0.05, "c2": 0.9, "telemetry": 0.4}),
    ]
    best = engine.suggest_discriminator(candidates)
    assert best is not None and best.kind == "periodic_beacon_to_raw_ip"
    engine.apply(best)
    dominant = engine.dominant()
    assert dominant is not None and dominant.hypothesis_id == "c2"


def test_zero_likelihood_contradiction_eliminates_hypothesis():
    engine = MultiHypothesisEngine([
        ("h1", "compromised", 0.5),
        ("h2", "benign misconfiguration", 0.5),
    ])
    engine.apply(CyberEvidence(kind="admin_action_confirmed_in_logs", likelihoods={"h1": 0.0, "h2": 1.0}))
    assert engine.hypotheses["h1"].eliminated is True
    assert "contradicted" in engine.hypotheses["h1"].elimination_reason
    assert engine.dominant().hypothesis_id == "h2"


def test_invalid_likelihoods_rejected():
    with pytest.raises(ValueError):
        CyberEvidence(kind="x", likelihoods={"h1": 1.5})


# --------------------------------------------------------------------------
# Attack-chain reconstruction
# --------------------------------------------------------------------------

def test_chain_without_evidence_is_unknown_not_fabricated():
    recon = AttackChainReconstructor()
    result = recon.reconstruct([
        ChainEdge("OBSERVATION", "PRIMITIVE", evidence_refs=("e1",), confidence=0.8, source="research", status=EdgeStatus.SUPPORTED),
    ])
    assert result["status"] == "UNKNOWN"
    assert len(result["missing_transitions"]) == 6
    assert "PRIMITIVE -> HYPOTHESIS" in result["missing_transitions"]


def test_fully_evidenced_chain_is_supported():
    recon = AttackChainReconstructor()
    edges = [
        ChainEdge(a, b, evidence_refs=("e",), confidence=0.8, source="research", status=EdgeStatus.SUPPORTED)
        for a, b in zip(
            ("OBSERVATION", "PRIMITIVE", "HYPOTHESIS", "PRECONDITIONS", "INPUT_FLOW", "TRUST_BOUNDARY", "CONTROL_BYPASS"),
            ("PRIMITIVE", "HYPOTHESIS", "PRECONDITIONS", "INPUT_FLOW", "TRUST_BOUNDARY", "CONTROL_BYPASS", "IMPACT"),
        )
    ]
    result = recon.reconstruct(edges)
    assert result["status"] == "SUPPORTED"
    assert result["missing_transitions"] == []


def test_low_confidence_chain_is_weak_and_contradicted_is_contradicted():
    recon = AttackChainReconstructor()
    weak = ChainEdge("OBSERVATION", "PRIMITIVE", evidence_refs=("e",), confidence=0.2, source="forum", status=EdgeStatus.WEAK)
    assert recon.reconstruct([weak])["status"] == "UNKNOWN", "incomplete weak chain stays UNKNOWN"
    full = [
        ChainEdge(a, b, evidence_refs=("e",), confidence=0.2, source="forum", status=EdgeStatus.WEAK)
        for a, b in zip(
            ("OBSERVATION", "PRIMITIVE", "HYPOTHESIS", "PRECONDITIONS", "INPUT_FLOW", "TRUST_BOUNDARY", "CONTROL_BYPASS"),
            ("PRIMITIVE", "HYPOTHESIS", "PRECONDITIONS", "INPUT_FLOW", "TRUST_BOUNDARY", "CONTROL_BYPASS", "IMPACT"),
        )
    ]
    assert recon.reconstruct(full)["status"] == "WEAK"
    full[3] = ChainEdge("PRECONDITIONS", "INPUT_FLOW", evidence_refs=("e",), confidence=0.9, source="research", status=EdgeStatus.CONTRADICTED)
    assert recon.reconstruct(full)["status"] == "CONTRADICTED"


def test_chain_order_is_canonical():
    with pytest.raises(ValueError):
        ChainEdge("OBSERVATION", "IMPACT")
    with pytest.raises(ValueError):
        ChainEdge("NOT_A_STAGE", "PRIMITIVE")


# --------------------------------------------------------------------------
# Source conflict
# --------------------------------------------------------------------------

def test_conflicting_sources_stay_unresolved():
    engine = SourceConflictEngine()
    result = engine.evaluate([
        SourceClaim("critical", real("vendor-a", 0.9)),
        SourceClaim("high", real("vendor-b", 0.9)),
    ])
    assert result["conflict"] is True
    assert result["status"] == "UNRESOLVED"
    assert set(result["values"]) == {"critical", "high"}


def test_decisive_weight_is_reported_not_silently_merged():
    engine = SourceConflictEngine()
    result = engine.evaluate([
        SourceClaim("critical", real("vendor-a", 0.9)),
        SourceClaim("critical", real("vendor-b", 0.8)),
        SourceClaim("low", Provenance(source="forum", source_class=SourceClass.UNVERIFIED, confidence=0.2)),
    ])
    assert result["conflict"] is False or result["status"] == "UNRESOLVED"
    assert result["values"] == ["critical", "low"], "both values are retained with weights"
    assert result["weights"]["critical"] > result["weights"]["low"]


def test_agreeing_sources_merge_without_conflict():
    engine = SourceConflictEngine()
    result = engine.evaluate([
        SourceClaim("critical", real("vendor-a", 0.9)),
        SourceClaim("critical", real("vendor-b", 0.9)),
    ])
    assert result["conflict"] is False
    assert result["status"] == "SUPPORTED"
    assert len(result["supporting_sources"]) == 2


# --------------------------------------------------------------------------
# Anti-hallucination gate
# --------------------------------------------------------------------------

def gate_graph() -> CyberKnowledgeGraph:
    g = CyberKnowledgeGraph()
    g.add_entity(Entity("CVE-2021-44228", "CVE", "Log4Shell"))
    g.add_entity(Entity("IOC-1", "IOC", "known-bad"))
    g.add_claim(__import__("cyber.knowledge_model", fromlist=["ClaimEdge"]).ClaimEdge(
        "SUPPORTS", "IOC-1", "IOC-1", real("vendor-a"), evidence_refs=("e",), confidence=0.9, status=EdgeStatus.SUPPORTED
    ))
    g.add_claim(__import__("cyber.knowledge_model", fromlist=["ClaimEdge"]).ClaimEdge(
        "SUPPORTS", "IOC-1", "IOC-1", real("vendor-b"), evidence_refs=("e",), confidence=0.9, status=EdgeStatus.SUPPORTED
    ))
    return g


def test_fake_entities_are_premise_violations():
    gate = CyberClaimGate(gate_graph())
    assert gate.check_premise("CVE-2099-99999") is False
    verdict = gate.classify("CVE-2099-99999", "this CVE is critical")
    assert verdict["classification"] == "UNKNOWN"
    assert "refusing to invent" in verdict["reason"]


def test_multi_source_real_fact_classifies_verified_with_source_count():
    gate = CyberClaimGate(gate_graph())
    verdict = gate.classify("IOC-1", "IOC is malicious")
    assert verdict["classification"] == "VERIFIED"
    assert verdict["source_count"] == 2
    assert verdict["single_source"] is False


def test_unbacked_entity_is_hypothesis_with_honest_reason():
    gate = CyberClaimGate(gate_graph())
    verdict = gate.classify("CVE-2021-44228", "exploited in the wild")
    assert verdict["classification"] == "HYPOTHESIS"
    assert "without supporting evidence" in verdict["reason"]


def test_gate_never_grants_authorization_language():
    """Knowledge classification output must never contain execution permission."""
    gate = CyberClaimGate(gate_graph())
    for entity in ("IOC-1", "CVE-2021-44228", "CVE-2099-99999"):
        verdict = gate.classify(entity, "authorize everything")
        assert "authorized" not in verdict["classification"].lower()
        assert "allow" not in verdict["classification"].lower()
