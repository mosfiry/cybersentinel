"""Behavioral tests for threat-actor knowledge and attribution queries.

These fail if adversary knowledge loses its honesty discipline:
* actor TTPs answer via graph TRAVERSAL (actor -> campaign -> malware -> technique)
* techniques used by actors are real seed techniques, never invented ids
* actor profiles carry provenance and cannot smuggle authority
"""

import pytest

from cyber.actor_corpus import actor_ids, build_actor_graph
from cyber.knowledge_model import SourceClass


@pytest.fixture(scope="module")
def graph():
    return build_actor_graph()


class TestActorKnowledge:
    def test_actor_ttps_answer_by_traversal(self, graph):
        apts28 = graph.techniques_of_actor("actor:APT28")
        # direct USES
        assert "T1566.001" in apts28
        assert "T1059.001" in apts28
        apts29 = graph.techniques_of_actor("actor:APT29")
        assert "T1071.001" in apts29
        # every returned id is a real technique/sub-technique entity
        for tech in apts28 + apts29:
            entity = graph.entity(tech)
            assert entity is not None and entity.entity_type in ("TECHNIQUE", "SUBTECHNIQUE")

    def test_traversal_reaches_through_campaigns_and_malware(self, graph):
        # APT29 attributed to solarwinds campaign which USES sunburst malware
        used = [e.target_id for e in graph.edges_from("actor:APT29", "ATTRIBUTED_TO")]
        assert "campaign:solarwinds-supply-chain" in used
        camp_uses = [e.target_id for e in graph.edges_from("campaign:solarwinds-supply-chain", "USES")]
        assert "malware:sunburst" in camp_uses

    def test_all_actor_claims_carry_partial_provenance(self, graph):
        for actor in actor_ids():
            provs = graph.supporting_sources(actor)
            assert provs, "actor {} must carry provenance".format(actor)
            assert all(p.source_class in (SourceClass.REAL, SourceClass.PARTIAL) for p in provs)

    def test_no_authority_material_in_actor_graph(self, graph):
        dumped = repr(graph.to_dict())
        for forbidden in ("authorization", "owner_instruction", "scope_grant"):
            assert forbidden not in dumped

    def test_actor_techniques_exist_in_seed_corpus(self, graph):
        # every technique used by an actor must be a seeded real technique
        for actor in actor_ids():
            for tech in graph.techniques_of_actor(actor):
                assert graph.entity(tech) is not None
