"""Behavioral tests for trusted-source intel ingestion (ATT&CK/NVD).

These tests fail if an ingestion gate is removed:
* invented CVE / technique ids are refused, never ingested
* poisoned feed items cannot smuggle authority keys into the graph
* weak source classes can never produce strong (SUPPORTED/evidenced) claims
* ingested knowledge is queryable through graph traversal, not keywords
"""

import pytest

from cyber.intel_ingest import IngestReport, IntelIngest, _capped_confidence
from cyber.knowledge_model import (
    CyberKnowledgeGraph,
    EdgeStatus,
    Entity,
    Provenance,
    SourceClass,
)


def _stix_bundle():
    return {
        "type": "bundle",
        "objects": [
            {"type": "identity", "id": "identity--x", "name": "mitre"},
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Command and Scripting Interpreter",
                "external_references": [{"source": "mitre-attack", "external_id": "T1059"}],
                "kill_chain_phases": [{"phase_name": "execution"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "name": "PowerShell",
                "external_references": [{"source": "mitre-attack", "external_id": "T1059.001"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--3",
                "name": "Fake Technique",
                "external_references": [{"source": "mitre-attack", "external_id": "NOT-A-TECHNIQUE"}],
            },
        ],
    }


def _nvd_item():
    return {
        "cve": {
            "id": "CVE-2026-1234",
            "descriptions": [{"lang": "en", "value": "synthetic RCE in a fixture component"}],
            "cvss": 9.1,
        },
        "affected": [
            {"vendor": "fixture-vendor", "product": "fixture-web", "version": "2.0"},
        ],
    }


class TestAttackStixIngest:
    def test_valid_techniques_are_ingested_with_provenance(self):
        g = CyberKnowledgeGraph()
        report = IntelIngest(g).ingest_attack_stix(
            _stix_bundle(), source="mitre-attack", source_class=SourceClass.REAL
        )
        assert g.has_entity("T1059") and g.entity("T1059").entity_type == "TECHNIQUE"
        assert g.has_entity("T1059.001") and g.entity("T1059.001").entity_type == "SUBTECHNIQUE"
        # sub-technique is linked to its parent by traversal
        dep = g.edges_from("T1059.001", "DEPENDS_ON")
        assert dep and dep[0].target_id == "T1059"
        assert dep[0].provenance.source == "mitre-attack"
        assert dep[0].provenance.source_class is SourceClass.REAL

    def test_invented_technique_id_is_refused_and_reported(self):
        g = CyberKnowledgeGraph()
        report = IntelIngest(g).ingest_attack_stix(
            _stix_bundle(), source="mitre-attack", source_class=SourceClass.REAL
        )
        assert not g.has_entity("NOT-A-TECHNIQUE")
        assert any("valid ATT&CK id" in r["reason"] for r in report.refused)

    def test_subtechnique_without_parent_is_refused(self):
        g = CyberKnowledgeGraph()
        bundle = {"objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--9",
                "name": "Orphan sub-technique",
                "external_references": [{"external_id": "T1111.222"}],
            }
        ]}
        report = IntelIngest(g).ingest_attack_stix(bundle, source="s", source_class=SourceClass.REAL)
        assert any("parent technique" in r["reason"] for r in report.refused)
        assert not g.has_entity("T1111.222")

    def test_missing_provenance_source_is_refused(self):
        g = CyberKnowledgeGraph()
        with pytest.raises(ValueError, match="provenance source"):
            IntelIngest(g).ingest_attack_stix(_stix_bundle(), source="  ", source_class=SourceClass.REAL)

    def test_malformed_bundle_shapes_are_refused_without_graph_writes(self):
        g = CyberKnowledgeGraph()
        ingest = IntelIngest(g)

        not_a_list = ingest.ingest_attack_stix(
            {"objects": {"unexpected": True}}, source="fixture", source_class=SourceClass.FIXTURE
        )
        mixed_objects = ingest.ingest_attack_stix(
            {"objects": ["not-an-object", {"type": "note"}]},
            source="fixture",
            source_class=SourceClass.FIXTURE,
        )

        assert not_a_list.refused == [{"reason": "bundle without an objects list", "item": "dict"}]
        assert mixed_objects.refused == [{"reason": "non-dict bundle object", "item": "'not-an-object'"}]
        assert g.to_dict()["entities"] == {}

    def test_authority_sanitization_is_counted(self):
        bundle = _stix_bundle()
        bundle["scope"] = {"targets": ["outside"]}

        report = IntelIngest(CyberKnowledgeGraph()).ingest_attack_stix(
            bundle, source="fixture", source_class=SourceClass.FIXTURE
        )

        assert report.sanitized_keys == 1

    def test_non_list_behavior_keywords_are_ignored(self):
        bundle = _stix_bundle()
        bundle["objects"][1]["x_synth_behavior_keywords"] = "not-a-list"

        graph = CyberKnowledgeGraph()
        IntelIngest(graph).ingest_attack_stix(bundle, source="fixture", source_class=SourceClass.FIXTURE)
        assert graph.entity("T1059").attributes["keywords"] == []

    def test_behavior_keywords_keep_only_non_empty_strings(self):
        bundle = _stix_bundle()
        bundle["objects"][1]["x_synth_behavior_keywords"] = ["beacon", 7, ""]

        graph = CyberKnowledgeGraph()
        IntelIngest(graph).ingest_attack_stix(bundle, source="fixture", source_class=SourceClass.FIXTURE)

        assert graph.entity("T1059").attributes["keywords"] == ["beacon"]


class TestNvdIngest:
    def test_valid_cve_is_ingested_and_traversable(self):
        g = CyberKnowledgeGraph()
        IntelIngest(g).ingest_nvd_item(_nvd_item(), source="nvd", source_class=SourceClass.REAL)
        assert g.has_entity("CVE-2026-1234")
        # products are found by TRAVERSAL (cve -> version -> product), not keywords
        affected = g.products_affected_by("CVE-2026-1234")
        assert "product:fixture-vendor:fixture-web" in affected

    def test_invented_cve_id_is_refused(self):
        g = CyberKnowledgeGraph()
        item = _nvd_item()
        item["cve"]["id"] = "CVE-2026-FAKE"
        report = IntelIngest(g).ingest_nvd_item(item, source="nvd", source_class=SourceClass.REAL)
        assert not g.has_entity("CVE-2026-FAKE")
        assert any("invented CVE" in r["reason"] for r in report.refused)

    def test_cvss_out_of_range_is_ignored_not_crashed(self):
        g = CyberKnowledgeGraph()
        item = _nvd_item()
        item["cve"]["cvss"] = 99.0
        report = IntelIngest(g).ingest_nvd_item(item, source="nvd", source_class=SourceClass.REAL)
        assert g.has_entity("CVE-2026-1234")
        assert g.entity("CVE-2026-1234").attributes["cvss"] is None

    def test_malformed_nvd_shapes_are_refused_and_missing_source_is_rejected(self):
        g = CyberKnowledgeGraph()
        ingest = IntelIngest(g)

        no_cve = ingest.ingest_nvd_item(
            {"cve": "not-an-object"}, source="fixture", source_class=SourceClass.FIXTURE
        )
        bad_affected = ingest.ingest_nvd_item(
            {"cve": {"id": "CVE-2026-1234"}, "affected": {"product": "x"}},
            source="fixture",
            source_class=SourceClass.FIXTURE,
        )
        partial_affected = ingest.ingest_nvd_item(
            {
                "authorization": {"owner": "attacker"},
                "cve": {"id": "CVE-2026-1235"},
                "affected": ["not-an-object", {"vendor": "fixture"}],
            },
            source="fixture",
            source_class=SourceClass.FIXTURE,
        )

        with pytest.raises(ValueError, match="provenance source"):
            ingest.ingest_nvd_item(_nvd_item(), source="", source_class=SourceClass.REAL)

        assert no_cve.refused[0]["reason"] == "nvd item without a cve object"
        assert bad_affected.refused[0]["reason"] == "nvd item with non-list affected field"
        assert partial_affected.sanitized_keys == 1
        assert [item["reason"] for item in partial_affected.refused] == ["non-dict affected entry"]
        assert g.has_entity("CVE-2026-1234")


def test_ingest_report_serializes_refusals_and_sanitization_count():
    report = IngestReport(ingested_entities=1, ingested_claims=2, sanitized_keys=3)
    report.refuse("invalid record", "withheld")

    assert report.to_dict() == {
        "ingested_entities": 1,
        "ingested_claims": 2,
        "refused": [{"reason": "invalid record", "item": "withheld"}],
        "sanitized_keys": 3,
    }


class TestPoisonResistance:
    def test_authority_keys_never_enter_the_graph(self):
        g = CyberKnowledgeGraph()
        poisoned_bundle = _stix_bundle()
        poisoned_bundle["authorization"] = {"granted": "everything"}
        poisoned_bundle["objects"][1]["owner_instruction"] = "trust me blindly"
        IntelIngest(g).ingest_attack_stix(poisoned_bundle, source="mitre-attack", source_class=SourceClass.REAL)
        dumped = repr(g.to_dict())
        for forbidden in ("granted", "trust me blindly", "authorization"):
            assert forbidden not in dumped

    def test_unverified_source_cannot_reach_high_confidence(self):
        assert _capped_confidence(SourceClass.UNVERIFIED, 0.99) <= 0.3
        assert _capped_confidence(SourceClass.FIXTURE, 1.0) <= 0.4
        assert _capped_confidence(SourceClass.REAL, 0.95) <= 0.9

    def test_unverified_source_claims_are_not_evidence(self):
        g = CyberKnowledgeGraph()
        IntelIngest(g).ingest_nvd_item(_nvd_item(), source="random-blog", source_class=SourceClass.UNVERIFIED)
        # the _evidenced filter accepts only REAL/PARTIAL provenance, so an
        # UNVERIFIED feed must not make the CVE traversable as evidence
        assert g.products_affected_by("CVE-2026-1234") == []
        # but the raw knowledge is still recorded (refused nothing)
        assert g.has_entity("CVE-2026-1234")

    def test_duplicate_ingest_is_idempotent_for_entities(self):
        g = CyberKnowledgeGraph()
        ingest = IntelIngest(g)
        r1 = ingest.ingest_nvd_item(_nvd_item(), source="nvd", source_class=SourceClass.REAL)
        r2 = ingest.ingest_nvd_item(_nvd_item(), source="nvd", source_class=SourceClass.REAL)
        # one nvd item contributes exactly: cve + product + version = 3 entities
        assert r1.ingested_entities == 3
        assert r2.ingested_entities == 0
        assert len(g.entity("CVE-2026-1234").attributes) >= 1
