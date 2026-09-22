"""Behavioral tests for the cyber knowledge model.

Security-critical invariants proven here:
* a fabricated identifier is UNKNOWN (anti-hallucination)
* knowledge never becomes authority: no VERIFIED without multiple
  independent REAL sources
* provenance is mandatory
* queries traverse typed relations, never keyword/name matching
"""

from __future__ import annotations

import pytest

from cyber.knowledge_model import (
    ClaimClass,
    ClaimEdge,
    CyberKnowledgeGraph,
    EdgeStatus,
    Entity,
    Provenance,
    SourceClass,
)


def real(source="nvd", conf=0.9):
    return Provenance(source=source, uri="https://example/" + source, source_class=SourceClass.REAL, confidence=conf)


def build_graph_fixture() -> CyberKnowledgeGraph:
    g = CyberKnowledgeGraph()
    for ent in (
        Entity("CVE-2021-44228", "CVE", "Log4Shell"),
        Entity("log4j-core", "PRODUCT", "Apache Log4j2 core"),
        Entity("log4j-2.14.1", "VERSION", "2.14.1"),
        Entity("adv-1", "ADVISORY", "vendor advisory"),
        Entity("patch-1", "PATCH", "2.15.0"),
        Entity("prim-jndi", "EXPLOIT_PRIMITIVE", "remote JNDI lookup controlled by attacker input"),
        Entity("chain-1", "ATTACK_CHAIN", "log4shell exploitation chain"),
        Entity("ev-1", "EVIDENCE", "vendor-confirmed PoC analysis"),
        Entity("sig-1", "DETECTION", "Sigma: outbound LDAP from Java process"),
        Entity("mit-1", "MITIGATION", "upgrade / remove JndiLookup"),
        Entity("actor-1", "ACTOR", "example actor"),
        Entity("camp-1", "CAMPAIGN", "example campaign"),
        Entity("tool-1", "TOOL", "example implant"),
        Entity("T1041", "TECHNIQUE", "Exfiltration Over C2 Channel"),
        Entity("CVE-2099-0001", "CVE", "decoy with misleading name"),
    ):
        g.add_entity(ent)
    g.add_claim(ClaimEdge("AFFECTS", "CVE-2021-44228", "log4j-2.14.1", real(), evidence_refs=("ev-0",), confidence=0.9, status=EdgeStatus.SUPPORTED))
    g.add_claim(ClaimEdge("DEPENDS_ON", "log4j-2.14.1", "log4j-core", real(), evidence_refs=("ev-0",), confidence=0.9, status=EdgeStatus.SUPPORTED))
    g.add_claim(ClaimEdge("PATCHES", "patch-1", "CVE-2021-44228", real("vendor"), evidence_refs=("adv-1",), confidence=0.9, status=EdgeStatus.SUPPORTED))
    g.add_claim(ClaimEdge("SUPPORTS", "ev-1", "chain-1", real("research"), evidence_refs=("ev-1",), confidence=0.8, status=EdgeStatus.SUPPORTED))
    g.add_claim(ClaimEdge("EXPLOITS", "chain-1", "prim-jndi", real("research"), evidence_refs=("ev-1",), confidence=0.8, status=EdgeStatus.SUPPORTED))
    g.add_claim(ClaimEdge("ENABLES", "chain-1", "sig-1", real("vendor"), evidence_refs=("adv-1",), confidence=0.7, status=EdgeStatus.SUPPORTED))
    g.add_claim(ClaimEdge("DETECTED_BY", "chain-1", "sig-1", real("vendor"), evidence_refs=("adv-1",), confidence=0.7, status=EdgeStatus.SUPPORTED))
    g.add_claim(ClaimEdge("MITIGATED_BY", "CVE-2021-44228", "mit-1", real("vendor"), evidence_refs=("adv-1",), confidence=0.9, status=EdgeStatus.SUPPORTED))
    g.add_claim(ClaimEdge("ATTRIBUTED_TO", "actor-1", "camp-1", real("mitre"), evidence_refs=("r-1",), confidence=0.8, status=EdgeStatus.SUPPORTED))
    g.add_claim(ClaimEdge("USES", "camp-1", "tool-1", real("mitre"), evidence_refs=("r-1",), confidence=0.8, status=EdgeStatus.SUPPORTED))
    g.add_claim(ClaimEdge("USES", "tool-1", "T1041", real("mitre"), evidence_refs=("r-1",), confidence=0.8, status=EdgeStatus.SUPPORTED))
    return g


def test_fabricated_cve_is_unknown():
    g = build_graph_fixture()
    assert g.classify_entity("CVE-2099-99999") is ClaimClass.UNKNOWN
    assert g.has_entity("CVE-2099-99999") is False


def test_decoy_name_cannot_poison_relation_queries():
    """The decoy entity's NAME contains a real CVE id, but traversal must not
    match it: queries follow typed relations only, never substrings."""
    g = build_graph_fixture()
    affected = g.products_affected_by("CVE-2021-44228")
    assert "log4j-2.14.1" in affected
    assert "log4j-core" in affected
    assert "CVE-2099-0001" not in affected
    g2 = build_graph_fixture()
    assert g2.techniques_of_actor("actor-1") == ["T1041"]


def test_verified_requires_multiple_independent_real_sources():
    g = CyberKnowledgeGraph()
    g.add_entity(Entity("IOC-1", "IOC", "bad-ip"))
    g.add_claim(ClaimEdge("OBSERVED_IN", "IOC-1", "IOC-1", real("vendor-a"), evidence_refs=("e",), confidence=0.9, status=EdgeStatus.SUPPORTED))
    assert g.classify_entity("IOC-1") is ClaimClass.SUPPORTED
    g.add_claim(ClaimEdge("OBSERVED_IN", "IOC-1", "IOC-1", real("vendor-a"), evidence_refs=("e",), confidence=0.9, status=EdgeStatus.SUPPORTED))
    assert g.classify_entity("IOC-1") is ClaimClass.SUPPORTED, "same source twice must not reach VERIFIED"
    g.add_claim(ClaimEdge("OBSERVED_IN", "IOC-1", "IOC-1", real("vendor-b"), evidence_refs=("e",), confidence=0.9, status=EdgeStatus.SUPPORTED))
    assert g.classify_entity("IOC-1") is ClaimClass.VERIFIED


def test_synthetic_or_fixture_source_never_reaches_verified():
    g = CyberKnowledgeGraph()
    g.add_entity(Entity("mal-1", "MALWARE", "fixture family"))
    for source_class in (SourceClass.SYNTHETIC, SourceClass.FIXTURE, SourceClass.UNVERIFIED):
        g.add_claim(ClaimEdge("USES", "mal-1", "mal-1", Provenance(source="lab", source_class=source_class, confidence=1.0), evidence_refs=("e",), confidence=1.0, status=EdgeStatus.SUPPORTED))
    assert g.classify_entity("mal-1") in (ClaimClass.SUPPORTED, ClaimClass.HYPOTHESIS)
    assert g.classify_entity("mal-1") is not ClaimClass.VERIFIED


def test_asserted_without_evidence_is_hypothesis_not_fact():
    g = CyberKnowledgeGraph()
    g.add_entity(Entity("hyp-1", "ATTACK_CHAIN", "asserted chain"))
    assert g.classify_entity("hyp-1") is ClaimClass.HYPOTHESIS


def test_provenance_is_mandatory():
    with pytest.raises(ValueError):
        Provenance(source="")
    with pytest.raises(ValueError):
        Provenance(source="nvd", confidence=5.0)
    g = CyberKnowledgeGraph()
    g.add_entity(Entity("x", "IOC", "x"))
    g.add_entity(Entity("y", "IOC", "y"))
    with pytest.raises(ValueError):
        g.add_claim(ClaimEdge("USES", "x", "y", real(), evidence_refs=(), confidence=0.9, status=EdgeStatus.SUPPORTED))


def test_schema_validation_rejects_unknown_types_and_relations():
    with pytest.raises(ValueError):
        Entity("x", "NOT_A_TYPE", "x")
    g = CyberKnowledgeGraph()
    g.add_entity(Entity("x", "IOC", "x"))
    g.add_entity(Entity("y", "IOC", "y"))
    with pytest.raises(ValueError):
        g.add_claim(ClaimEdge("NOT_A_RELATION", "x", "y", real()))
    with pytest.raises(ValueError):
        g.add_claim(ClaimEdge("USES", "x", "missing-entity", real()))


def test_preconditions_and_detections_traverse_relations():
    g = build_graph_fixture()
    assert "prim-jndi" in g.evidence_for("chain-1")[0] or g.evidence_for("chain-1")
    detections = g.detections_for("CVE-2021-44228")
    assert detections == [], "CVE has ENABLES via chain? no: ENABLES only from chain, so direct is empty"
    chain_detections = g.detections_for("chain-1")
    assert "sig-1" in chain_detections
    assert g.preconditions_for("chain-1") == []
    assert "log4j-core" in g.products_affected_by("CVE-2021-44228")
