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


def provenance(source="source-a", source_class=SourceClass.REAL, confidence=0.9):
    return Provenance(source=source, source_class=source_class, confidence=confidence)


def test_provenance_and_entity_validation_is_fail_closed():
    with pytest.raises(ValueError, match="requires a source"):
        Provenance(source="")
    with pytest.raises(ValueError, match=r"within \[0, 1\]"):
        Provenance(source="fixture", confidence=1.1)
    with pytest.raises(ValueError, match="unknown source class"):
        Provenance(source="fixture", source_class=object())
    with pytest.raises(ValueError, match="requires an id"):
        Entity("", "CVE")
    with pytest.raises(ValueError, match="unknown entity type"):
        Entity("x", "NOT_AN_ENTITY")

    first = provenance("vendor-a")
    assert first.is_independent_of(provenance("vendor-b")) is True
    assert first.is_independent_of(provenance("vendor-a")) is False


def test_claim_edge_validation_and_graph_reference_boundaries():
    source = Entity("source", "IOC")
    target = Entity("target", "MALWARE")
    with pytest.raises(ValueError, match="unknown relation"):
        ClaimEdge("NOT_A_RELATION", "source", "target", provenance())
    with pytest.raises(ValueError, match=r"within \[0, 1\]"):
        ClaimEdge("USES", "source", "target", provenance(), confidence=-0.1)
    with pytest.raises(ValueError, match="requires evidence references"):
        ClaimEdge("USES", "source", "target", provenance(), status=EdgeStatus.SUPPORTED)

    graph = CyberKnowledgeGraph()
    graph.add_entity(source)
    graph.add_entity(target)
    assert graph.add_entity(Entity("source", "IOC")) is source
    with pytest.raises(ValueError, match="different type"):
        graph.add_entity(Entity("source", "MALWARE"))
    with pytest.raises(ValueError, match="unknown source entity"):
        graph.add_claim(ClaimEdge("USES", "missing", "target", provenance()))
    with pytest.raises(ValueError, match="unknown target entity"):
        graph.add_claim(ClaimEdge("USES", "source", "missing", provenance()))


def test_graph_traversal_filters_untrusted_edges_and_deduplicates_results():
    graph = CyberKnowledgeGraph()
    for entity_id, entity_type in (
        ("cve", "CVE"),
        ("version", "VERSION"),
        ("product", "PRODUCT"),
        ("attack", "ATTACK_CHAIN"),
        ("detection", "DETECTION"),
        ("prerequisite", "PRODUCT"),
    ):
        graph.add_entity(Entity(entity_id, entity_type))

    graph.add_claim(ClaimEdge("AFFECTS", "cve", "version", provenance(), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    graph.add_claim(ClaimEdge("DEPENDS_ON", "version", "product", provenance(), evidence_refs=("e",), status=EdgeStatus.WEAK))
    graph.add_claim(ClaimEdge("DEPENDS_ON", "version", "product", provenance(), evidence_refs=("e",), status=EdgeStatus.WEAK))
    graph.add_claim(ClaimEdge("DETECTED_BY", "attack", "detection", provenance(), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    graph.add_claim(ClaimEdge("ENABLES", "cve", "attack", provenance(), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    graph.add_claim(ClaimEdge("REQUIRES", "attack", "prerequisite", provenance(), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    graph.add_claim(ClaimEdge("DEPENDS_ON", "attack", "prerequisite", provenance(), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    graph.add_claim(ClaimEdge("USES", "cve", "product", provenance(source_class=SourceClass.FIXTURE), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))

    assert [edge.source_id for edge in graph.edges_to("product")] == ["version", "version", "cve"]
    assert graph.products_affected_by("cve") == ["version", "product"]
    assert graph.detections_for("cve") == ["detection"]
    assert graph.preconditions_for("attack") == ["prerequisite"]
    assert graph.evidence_for("attack")[0]["evidence_refs"] == ["e"]
    assert [item["relation"] for item in graph.evidence_for("cve")] == ["AFFECTS", "ENABLES", "USES"]
    assert graph.to_dict()["entities"]["cve"]["entity_type"] == "CVE"


def test_technique_traversal_has_depth_guard_and_direct_attribution():
    graph = CyberKnowledgeGraph()
    graph.add_entity(Entity("actor", "ACTOR"))
    graph.add_entity(Entity("campaign", "CAMPAIGN"))
    graph.add_entity(Entity("technique", "TECHNIQUE"))
    graph.add_claim(ClaimEdge("ATTRIBUTED_TO", "actor", "campaign", provenance(), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    graph.add_claim(ClaimEdge("USES", "campaign", "technique", provenance(), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    graph.add_claim(ClaimEdge("USES", "actor", "technique", provenance(), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))

    assert graph.techniques_of_actor("actor") == ["technique"]
    assert graph.techniques_of_actor("missing") == []

    for index in range(5):
        graph.add_entity(Entity(f"tool-{index}", "TOOL"))
    graph.add_entity(Entity("deep-technique", "TECHNIQUE"))
    graph.add_claim(ClaimEdge("USES", "actor", "tool-0", provenance(), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    for index in range(4):
        graph.add_claim(ClaimEdge("USES", f"tool-{index}", f"tool-{index + 1}", provenance(), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    graph.add_claim(ClaimEdge("USES", "tool-4", "deep-technique", provenance(), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    assert "deep-technique" not in graph.techniques_of_actor("actor")


def test_classification_distinguishes_unknown_hypothesis_supported_and_verified():
    graph = CyberKnowledgeGraph()
    graph.add_entity(Entity("hypothesis", "IOC"))
    graph.add_entity(Entity("partial", "IOC"))
    graph.add_entity(Entity("single-real", "IOC"))
    graph.add_entity(Entity("verified", "IOC"))
    graph.add_claim(ClaimEdge("SUPPORTS", "partial", "partial", provenance(source_class=SourceClass.PARTIAL), evidence_refs=("e",), status=EdgeStatus.WEAK))
    graph.add_claim(ClaimEdge("SUPPORTS", "single-real", "single-real", provenance("vendor-single"), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    graph.add_claim(ClaimEdge("SUPPORTS", "verified", "verified", provenance("vendor-a"), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))
    graph.add_claim(ClaimEdge("SUPPORTS", "verified", "verified", provenance("vendor-b"), evidence_refs=("e",), status=EdgeStatus.SUPPORTED))

    assert graph.classify_entity("missing") is ClaimClass.UNKNOWN
    assert graph.classify_entity("hypothesis") is ClaimClass.HYPOTHESIS
    assert graph.classify_entity("partial") is ClaimClass.SUPPORTED
    assert graph.classify_entity("single-real") is ClaimClass.SUPPORTED
    assert graph.classify_entity("verified") is ClaimClass.VERIFIED
    assert graph.entities()["hypothesis"].entity_id == "hypothesis"
    assert graph.entity("missing") is None
    assert graph.has_entity("verified") is True


def test_public_claim_classification_entrypoint_matches_graph():
    graph = CyberKnowledgeGraph()
    graph.add_entity(Entity("ioc", "IOC"))

    from cyber.knowledge_model import classify_cyber_claim

    assert classify_cyber_claim(graph, "ioc") is ClaimClass.HYPOTHESIS
