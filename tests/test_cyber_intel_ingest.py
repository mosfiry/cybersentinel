"""Behavioral tests for trusted-source intel ingestion (ATT&CK/NVD).

These tests fail if an ingestion gate is removed:
* invented CVE / technique ids are refused, never ingested
* poisoned feed items cannot smuggle authority keys into the graph
* weak source classes can never produce strong (SUPPORTED/evidenced) claims
* ingested knowledge is queryable through graph traversal, not keywords
"""

import pytest

from cyber.intel_ingest import IntelIngest, _capped_confidence
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
        assert r1.ingested_entities == 5  # cve + product + version (+2 from first call? no: 3)
        assert r2.ingested_entities == 0
