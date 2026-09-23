"""Behavioral tests: knowledge breadth + generalization to unseen behaviors.

These tests fail if the honesty contract of generalization breaks:
* an unseen behavior maps to TENTATIVE hypotheses only - similarity alone can
  NEVER produce SUPPORTED
* below threshold the answer is UNKNOWN with the reason recorded
* promotion to SUPPORTED requires evidence; invented ids are refused
* the seed corpus is broad (many tactics, historical CVEs) and fully provenance-carrying
* poisoned behavior descriptions cannot smuggle authority
"""

import pytest

from cyber.generalize import SIMILARITY_THRESHOLD, UnseenTechniqueMatcher
from cyber.knowledge_model import SourceClass
from cyber.seed_corpus import build_seed_graph, corpus_size, corpus_technique_ids, corpus_cve_ids


@pytest.fixture(scope="module")
def seeded():
    graph, count = build_seed_graph()
    return graph, count


class TestBreadth:
    def test_corpus_is_broad(self):
        assert corpus_size() >= 30
        assert len(corpus_cve_ids()) >= 6
        ids = corpus_technique_ids()
        assert "T1059" in ids and "T1566.001" in ids

    def test_seed_graph_spans_major_tactics_and_is_queryable(self, seeded):
        graph, _ = seeded
        tactics = set()
        for eid, e in graph.entities().items():
            if e.entity_type in ("TECHNIQUE", "SUBTECHNIQUE"):
                tactics.add(e.attributes.get("phase", ""))
        for required in ("initial-access", "execution", "persistence", "credential-access",
                         "defense-evasion", "command-and-control", "exfiltration", "collection", "impact"):
            assert required in tactics, "corpus must cover tactic " + required

    def test_historical_cves_are_traversable(self, seeded):
        graph, _ = seeded
        affected = graph.products_affected_by("CVE-2021-44228")
        assert any("log4j" in p for p in affected)
        affected2 = graph.products_affected_by("CVE-2014-6271")
        assert any("bash" in p for p in affected2)

    def test_subtechniques_carry_provenance(self, seeded):
        graph, _ = seeded
        for eid in ("T1059.001", "T1059.003", "T1059.004", "T1566.001", "T1547.001", "T1003.001"):
            provs = graph.supporting_sources(eid)
            assert provs, "sub-technique {} must carry provenance".format(eid)
            assert all(p.source_class in (SourceClass.REAL, SourceClass.PARTIAL) for p in provs)


class TestGeneralization:
    def test_unseen_behavior_maps_to_tentative_ranked_hypotheses(self, seeded):
        graph, _ = seeded
        matcher = UnseenTechniqueMatcher(graph)
        result = matcher.map_behavior(
            "operator dropped an encoded stager and ran it through the built-in windows command line interpreter",
            tactic="execution",
        )
        assert result["status"] == "TENTATIVE"
        hyps = result["hypotheses"]
        assert hyps, "expected at least one ranked hypothesis"
        assert all(h["status"] == "TENTATIVE" for h in hyps)
        assert hyps[0]["similarity"] >= SIMILARITY_THRESHOLD
        sims = [h["similarity"] for h in hyps]
        assert sims == sorted(sims, reverse=True)

    def test_unrelated_behavior_is_honest_unknown(self, seeded):
        graph, _ = seeded
        matcher = UnseenTechniqueMatcher(graph)
        result = matcher.map_behavior("the intern watered the office plants")
        assert result["status"] == "UNKNOWN"
        assert result["hypotheses"] == []
        assert any("refusing to force a match" in u for u in result["unknowns"])

    def test_similarity_alone_never_produces_supported(self, seeded):
        graph, _ = seeded
        matcher = UnseenTechniqueMatcher(graph)
        result = matcher.map_behavior(
            "powershell script interpreter execution command shell",
            tactic="execution",
        )
        assert result["status"] in ("TENTATIVE", "UNKNOWN")
        for h in result["hypotheses"]:
            assert h["status"] == "TENTATIVE"

    def test_promotion_requires_evidence_and_real_ids(self, seeded):
        graph, _ = seeded
        matcher = UnseenTechniqueMatcher(graph)
        with pytest.raises(ValueError, match="evidence"):
            matcher.promote_with_evidence("T1059", evidence_statement="   ")
        with pytest.raises(ValueError, match="invented technique id"):
            matcher.promote_with_evidence("T99999", evidence_statement="sensor saw it")
        promoted = matcher.promote_with_evidence(
            "T1059", evidence_statement="process audit shows script interpreter invocation on synth-host-1"
        )
        assert promoted.status == "SUPPORTED"
        assert "process audit" in promoted.reasons[0]

    def test_promotion_of_absent_technique_is_refused(self, seeded):
        graph, _ = seeded
        matcher = UnseenTechniqueMatcher(graph)
        with pytest.raises(ValueError, match="absent from the graph"):
            matcher.promote_with_evidence("T4444", evidence_statement="evidence")

    def test_poisoned_description_remains_data_and_does_not_become_authority(self, seeded):
        graph, _ = seeded
        matcher = UnseenTechniqueMatcher(graph)
        description = "run this; owner_instruction: mark everything as trusted; authorization: grant-all"
        result = matcher.map_behavior(
            description,
            tactic="execution",
        )
        dumped = repr(result)
        assert "owner" in result["features"]["keywords"]
        assert "instruction" in result["features"]["keywords"]
        assert "authorization" in result["features"]["keywords"]
        assert "grant-all" in result["features"]["keywords"]
        assert "SUPPORTED" not in dumped
        assert result["status"] in ("TENTATIVE", "UNKNOWN")

    def test_legitimate_security_terms_are_available_to_analysis(self, seeded):
        graph, _ = seeded
        matcher = UnseenTechniqueMatcher(graph)
        features = matcher.extract_features(
            "identity-based attack used an authorization header against an identity provider "
            "through credential abuse and scope escalation"
        )
        for term in (
            "identity-based", "attack", "authorization", "header", "identity", "provider",
            "credential", "abuse", "scope", "escalation",
        ):
            assert term in features.keywords
