"""Behavioral tests: corpus breadth beyond the original nine tactics.

These fail if the breadth contract breaks:
* the corpus covers discovery, lateral movement, privilege escalation and
  cloud techniques (the tactics an intruder needs AFTER initial access)
* unseen lateral-movement / privilege-escalation behaviors map to ranked
  TENTATIVE hypotheses over that breadth
* every sub-technique still carries PARTIAL/REAL provenance via its
  DEPENDS_ON claim (parent techniques are carriers of knowledge, their
  provenance is witnessed through their sub-technique claims)
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

    def test_all_subtechniques_carry_partial_provenance(self, seeded):
        graph, _ = seeded()
        subs = [i for i in corpus_technique_ids() if "." in i]
        assert len(subs) >= 12
        for tech_id in subs:
            provs = graph.supporting_sources(tech_id)
            assert provs, tech_id + " must carry provenance"
            assert all(
                p.source_class in (SourceClass.REAL, SourceClass.PARTIAL) for p in provs
            )


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
