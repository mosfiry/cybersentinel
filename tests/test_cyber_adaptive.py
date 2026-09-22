"""Behavioral tests for the adaptive analyst loop.

These tests fail if adaptation honesty breaks:
* unmappable runtime observations stay UNKNOWN (never forced into techniques)
* TENTATIVE hypotheses enter the case as hypotheses, never as evidence
* promotion requires independent evidence and is traceable from the case
* hunts run from the evidenced graph only
"""

import pytest

from cyber.adaptive import AdaptiveAnalyst
from cyber.case_engine import CaseStatus, CyberCase, EvidenceStatus, Provenance
from cyber.generalize import UnseenTechniqueMatcher
from cyber.seed_corpus import build_seed_graph


def _case_from_runtime_like_events():
    """A case shaped like mission_adapter output: observation texts only."""
    case = CyberCase(objective="adapt to synth-commerce-1 intrusion", scope="synth-commerce-1")
    prov = Provenance(source="mission-runtime", classification="REAL")
    case.add_observation(
        "operator dropped an encoded stager and ran it through the built-in windows command line interpreter",
        provenance=prov,
    )
    case.add_observation("the intern watered the office plants", provenance=prov)
    case.add_observation(
        "process audit shows script interpreter invocation on synth-host-1",
        provenance=prov,
    )
    return case


class TestAdaptiveAnalyst:
    def test_unseen_observations_map_tentatively_and_unknowns_stay_honest(self):
        case = _case_from_runtime_like_events()
        analyst = AdaptiveAnalyst(case)
        report = analyst.analyze_observations()
        # the plants observation must be UNKNOWN, never forced
        assert report.unknown_observations >= 1
        # the encoded stager observation must map to ranked TENTATIVE hypotheses
        assert report.mapped_observations >= 1
        assert report.tentative_hypotheses
        assert all(h["status"] == "TENTATIVE" for h in report.tentative_hypotheses)
        # hypotheses entered the case as HYPOTHESES, never as evidence
        assert report.tentative_hypotheses[0]["hypothesis_id"] in case.hypotheses
        for e in case.evidence.values():
            assert "may map to" not in e.statement
        # the refusal reason is preserved as an unknown
        assert any("refusing to force a match" in u for u in case.unknowns)

    def test_promotion_records_traceable_evidence_and_enables_hunts(self):
        case = _case_from_runtime_like_events()
        analyst = AdaptiveAnalyst(case)
        analyst.analyze_observations()
        promoted = analyst.promote(
            "T1059",
            evidence_statement="process audit shows script interpreter invocation on synth-host-1",
        )
        assert promoted["status"] == "SUPPORTED"
        evidence = case.evidence[promoted["evidence_id"]]
        assert evidence.status is EvidenceStatus.SUPPORTED
        # the case conclusion can now cite that evidence
        case.add_conclusion(
            "execution via script interpreter confirmed on synth-host-1",
            evidence_ids=[promoted["evidence_id"]],
        )
        assert case.close() == CaseStatus.CLOSED_CONCLUDED
        # a hunt from the promoted technique answers over the graph
        hunt = analyst.hunt_from("T1059")
        assert hunt["hunt_id"] == "hunt-from-T1059"
        assert hunt["status"] in ("DETECTED", "NO_DETECTIONS")

    def test_promotion_of_invented_technique_is_refused(self):
        case = _case_from_runtime_like_events()
        analyst = AdaptiveAnalyst(case)
        with pytest.raises(ValueError, match="invented technique id"):
            analyst.promote("T99999", evidence_statement="x")

    def test_hunt_from_unknown_entity_is_honest(self):
        case = _case_from_runtime_like_events()
        analyst = AdaptiveAnalyst(case)
        hunt = analyst.hunt_from("T8888")
        assert hunt["status"] == "NO_DETECTIONS"
        assert any("not in the graph" in u for u in hunt["unknowns"])

    def test_external_matcher_is_reused_not_rebuilt(self):
        graph, _ = build_seed_graph()
        matcher = UnseenTechniqueMatcher(graph)
        case = _case_from_runtime_like_events()
        analyst = AdaptiveAnalyst(case, matcher)
        assert analyst.matcher is matcher
