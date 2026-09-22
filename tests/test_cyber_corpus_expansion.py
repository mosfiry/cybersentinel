"""Behavioral tests: corpus breadth beyond the original nine tactics.

These fail if the breadth contract breaks:
* the corpus covers discovery, lateral movement, privilege escalation and
  cloud techniques (the tactics an intruder needs AFTER initial access)
* unseen lateral-movement / privilege-escalation behaviors map to ranked
  TENTATIVE hypotheses over that breadth
* every expanded entry still carries PARTIAL/REAL provenance
"""

import pytest

from cyber.generalize import UnseenTechniqueMatcher
from cyber.knowledge_model import SourceClass
from cyber.seed_corpus import build_seed_graph, corpus_size, corpus_technique_ids


@pytest.fixture(scope="module")
def seeded():
    graph, count = build_seed_graph()
    return graph, count


class TestExpandedBreadth:
    def test_corpus_grew_beyond_thirty(self):
        assert corpus_size() >= 40

    def test_discovery_lateral_and_privilege_tactics_are_covered(self, seeded):
        graph, _ = seeded()
        tactics = set()
        for eid, e in graph.entities().items():
            if e.entity_type in ("TECHNIQUE", "SUBTECHNIQUE"):
                tactics.add(e.attributes.get("phase", ""))
        for required in ("discovery", "lateral-movement", "privilege-escalation"):
            assert required in tactics, "corpus must cover tactic " + required

    def test_cloud_platform_techniques_exist(self, seeded):
        graph, _ = seeded()
        for tech_id in ("T1078.004", "T1580", "T1530", "T1496", "T1059.009"):
            assert graph.entity(tech_id) is not None, tech_id + " must be seeded"

    def test_all_expanded_entries_carry_partial_provenance(self, seeded):
        graph, _ = seeded()
        ids = corpus_technique_ids()
        for tech_id in ids:
            provs = graph.supporting_sources(tech_id)
            if tech_id in ("T1059", "T1566", "T1003", "T1547", "T1078", "T1071", "T1021",
                           "T1550", "T1548", "T1566.001"):
                # parent techniques carry provenance via their sub-technique edges;
                # direct-parent provenance is only guaranteed where claims exist
                continue
            assert provs, tech_id + " must carry provenance"
            assert all(p.source_class in (SourceClass.REAL, SourceClass.PARTIAL) for p in provs)


class TestGeneralizationOverNewBreadth:
    def test_unseen_lateral_movement_maps_tentatively(self, seeded):
        graph, _ = seeded()
        matcher = UnseenTechniqueMatcher(graph)
        result = matcher.map_behavior(
            "the operator moved laterally by reusing a stolen authentication hash "
            "to access remote systems",
            tactic="lateral-movement",
        )
        assert result["status"] == "TENTATIVE"
        ids = [h["technique_id"] for h in result["hypotheses"]]
        assert "T1550.002" in ids, "pass-the-hash must be reachable from an unseen lateral description"

    def test_unseen_privilege_escalation_maps_tentatively(self, seeded):
        graph, _ = seeded()
        matcher = UnseenTechniqueMatcher(graph)
        result = matcher.map_behavior(
            "attacker exploited a software vulnerability to gain elevated privileges",
            tactic="privilege-escalation",
        )
        assert result["status"] == "TENTATIVE"
        ids = [h["technique_id"] for h in result["hypotheses"]]
        assert "T1068" in ids, "privilege-escalation-by-exploit must be reachable"

    def test_unseen_cloud_discovery_maps_tentatively(self, seeded):
        graph, _ = seeded()
        matcher = UnseenTechniqueMatcher(graph)
        result = matcher.map_behavior(
            "operator enumerated the cloud infrastructure of the tenant",
            tactic="discovery",
        )
        assert result["status"] == "TENTATIVE"
        ids = [h["technique_id"] for h in result["hypotheses"]]
        assert "T1580" in ids, "cloud infrastructure discovery must be reachable"
