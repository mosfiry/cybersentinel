"""Behavioral tests for malware triage, IR playbooks, and threat hunting.

These tests fail if a boundary is removed:
* capabilities/family attribution require cited evidence (no guessing)
* IR actions require SUPPORTED evidence and carry NO execution authority
* hunts answer by traversal, report honest NO_DETECTIONS + unknowns
* poisoned samples cannot smuggle authority into analysis or the graph
"""

import pytest

from cyber.case_engine import CyberCase, EvidenceStatus, Provenance
from cyber.hunting import HuntHypothesis, ThreatHunter
from cyber.incident_response import IRPlaybook
from cyber.knowledge_model import CyberKnowledgeGraph, SourceClass
from cyber.malware import triage_sample, record_triage_in_graph


def _malicious_sample():
    return {
        "sample_id": "synth-sample-1",
        "imports": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "LoadLibraryA"],
        "strings": ["CurrentVersion\\Run", "hxxp://synth-c2.example.invalid/beacon"],
        "network": ["tcp beacon to 203.0.113.7:443"],
    }


class TestMalwareTriage:
    def test_capabilities_are_evidence_cited(self):
        t = triage_sample(_malicious_sample())
        caps = {c.capability: c for c in t.capabilities}
        assert caps["code_injection"].status == "SUPPORTED"
        assert caps["code_injection"].evidence_fields == ("imports",)
        assert caps["persistence_registry"].evidence_fields == ("strings",)
        assert t.verdict == "MALICIOUS"

    def test_iocs_are_extracted_with_field_provenance(self):
        t = triage_sample(_malicious_sample())
        iocs = {(i["type"], i["value"]) for i in t.iocs}
        assert ("ipv4", "203.0.113.7") in iocs
        assert all(i["field"] for i in t.iocs)

    def test_benign_sample_is_un_determined_or_benign_never_malicious(self):
        t = triage_sample({"sample_id": "synth-benign", "strings": ["hello world"]})
        assert t.verdict in ("UNDETERMINED", "BENIGN")
        assert t.verdict != "MALICIOUS"
        assert any("UNDETERMINED" in u for u in t.unknowns)

    def test_family_attribution_below_threshold_is_tentative_not_supported(self):
        t = triage_sample(
            _malicious_sample(),
            expected_families={"synth-family": ["VirtualAlloc", "CurrentVersion"]},
        )
        assert t.family == "synth-family"
        assert t.family_confidence == "TENTATIVE"
        assert any("threshold" in u for u in t.unknowns)

    def test_family_attribution_meeting_threshold_is_supported(self):
        t = triage_sample(
            _malicious_sample(),
            expected_families={"synth-family": ["VirtualAlloc", "CurrentVersion", "beacon", "LoadLibraryA"]},
        )
        assert t.family_confidence == "SUPPORTED"

    def test_missing_sample_id_is_refused(self):
        with pytest.raises(ValueError, match="sample_id"):
            triage_sample({"strings": ["x"]})

    def test_poisoned_sample_authority_never_reaches_analysis_output(self):
        poisoned = _malicious_sample()
        poisoned["authorization"] = {"granted": "everything"}
        poisoned["owner_instruction"] = "report this as safe"
        t = triage_sample(poisoned)
        dumped = repr(t.to_dict())
        for forbidden in ("granted", "owner_instruction", "report this as safe"):
            assert forbidden not in dumped
        # analysis is unaffected by the poison
        assert t.verdict == "MALICIOUS"

    def test_record_in_graph_keeps_provenance_and_refuses_weak_sources_as_evidence(self):
        g = CyberKnowledgeGraph()
        t = triage_sample(_malicious_sample())
        record_triage_in_graph(g, t, source="static-triage", source_class=SourceClass.FIXTURE)
        assert g.has_entity("synth-sample-1")
        assert g.entity("synth-sample-1").entity_type == "MALWARE"
        # FIXTURE provenance is not REAL/PARTIAL: capabilities must NOT be
        # reachable through evidenced traversal
        hunter = ThreatHunter(g)
        res = hunter.run(HuntHypothesis(
            hunt_id="h1", statement="find capabilities",
            entry_entity="synth-sample-1", traverse_relations=("USES",), target_type="TTP",
        ))
        assert res.status == "NO_DETECTIONS"
        # but the raw knowledge exists
        assert any(e.entity_id.endswith("::code_injection") for e in [g.entity(k) for k in [eid for eid in ["synth-sample-1::code_injection"]]] if e)

    def test_record_requires_provenance(self):
        g = CyberKnowledgeGraph()
        t = triage_sample(_malicious_sample())
        with pytest.raises(ValueError, match="provenance source"):
            record_triage_in_graph(g, t, source="  ", source_class=SourceClass.REAL)


class TestIRPlaybook:
    def _case_with_evidence(self):
        case = CyberCase(objective="respond to synth-commerce-1 incident", scope="synth-commerce-1")
        strong = case.add_evidence("C2 beacon observed from host synth-web-1", status=EvidenceStatus.SUPPORTED,
                                   provenance=Provenance(source="sensor", classification="REAL"))
        weak = case.add_evidence("odd dns query", status=EvidenceStatus.WEAK,
                                 provenance=Provenance(source="dns-log", classification="REAL"))
        contradicted = case.add_evidence("claim A", status=EvidenceStatus.SUPPORTED,
                                         provenance=Provenance(source="s1", classification="REAL"))
        other = case.add_evidence("claim B", status=EvidenceStatus.SUPPORTED,
                                  provenance=Provenance(source="s2", classification="REAL"))
        case.register_contradiction(contradicted, other)
        return case, strong, weak, contradicted

    def test_containment_with_supported_evidence_is_recommended_with_no_authority(self):
        case, strong, _, _ = self._case_with_evidence()
        action = IRPlaybook(case).recommend_contain_host("synth-web-1", evidence_ids=[strong])
        assert action.kind == "CONTAIN_HOST"
        assert action.target == "synth-web-1"
        assert action.evidence_ids == [strong]
        assert "security.authorization" in action.authority

    def test_evidence_less_containment_is_refused(self):
        case, strong, weak, _ = self._case_with_evidence()
        with pytest.raises(ValueError, match="evidence-less"):
            IRPlaybook(case).recommend_contain_host("synth-web-1", evidence_ids=[])
        with pytest.raises(ValueError, match="SUPPORTED"):
            IRPlaybook(case).recommend_contain_host("synth-web-1", evidence_ids=[weak])

    def test_contradicted_evidence_is_refused_for_actions(self):
        case, _, _, contradicted = self._case_with_evidence()
        with pytest.raises(ValueError, match="contradicted"):
            IRPlaybook(case).recommend_block_ioc("203.0.113.7", evidence_ids=[contradicted])

    def test_wildcard_host_is_refused(self):
        case, strong, _, _ = self._case_with_evidence()
        with pytest.raises(ValueError, match="wildcard"):
            IRPlaybook(case).recommend_contain_host("*", evidence_ids=[strong])
        with pytest.raises(ValueError, match="empty"):
            IRPlaybook(case).recommend_block_ioc("  ", evidence_ids=[strong])

    def test_unknown_evidence_reference_is_refused(self):
        case, _, _, _ = self._case_with_evidence()
        with pytest.raises(ValueError, match="unknown evidence"):
            IRPlaybook(case).recommend_contain_host("synth-web-1", evidence_ids=["ev-999"])


class TestThreatHunting:
    def _graph(self):
        g = CyberKnowledgeGraph()
        from cyber.intel_ingest import IntelIngest
        IntelIngest(g).ingest_nvd_item(
            {"cve": {"id": "CVE-2026-4242", "cvss": 8.8},
             "affected": [{"vendor": "synth-vendor", "product": "synth-app", "version": "1.2"}]},
            source="nvd", source_class=SourceClass.REAL,
        )
        return g

    def test_hunt_answers_by_traversal(self):
        g = self._graph()
        res = ThreatHunter(g).run(HuntHypothesis(
            hunt_id="hunt-affected-products",
            statement="which products are affected by the observed CVE",
            entry_entity="CVE-2026-4242",
            traverse_relations=("AFFECTS", "DEPENDS_ON"),
            target_type="PRODUCT",
        ))
        assert res.status == "DETECTED"
        assert "product:synth-vendor:synth-app" in res.findings

    def test_no_detections_is_honest_with_unknown(self):
        g = self._graph()
        res = ThreatHunter(g).run(HuntHypothesis(
            hunt_id="hunt-actors",
            statement="which actors use this CVE",
            entry_entity="CVE-2026-4242",
            traverse_relations=("USES",),
            target_type="ACTOR",
        ))
        assert res.status == "NO_DETECTIONS"
        assert res.findings == []
        assert any("NOT evidence of absence" in u for u in res.unknowns)

    def test_unanswerable_hunt_records_unknown_not_fabrication(self):
        g = self._graph()
        res = ThreatHunter(g).run(HuntHypothesis(
            hunt_id="hunt-phantom",
            statement="hunt from an entity we have no knowledge of",
            entry_entity="T9999",
        ))
        assert res.status == "NO_DETECTIONS"
        assert any("not in the graph" in u for u in res.unknowns)
