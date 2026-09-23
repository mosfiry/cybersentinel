"""Adversarial battery: red-team attacks against the adaptation loop.

Each test is an active attack attempt against our own adaptive analyst:
* poisoned observations cannot smuggle authority into hypotheses or unknowns
* a poison-ONLY evidence statement is refused outright (nothing left to cite)
* poisoned evidence statements are neutralized, never dropped wholesale
* unmappable observation floods stay UNKNOWN - nothing is ever forced
* TENTATIVE hypotheses never silently become evidence
"""

import pytest

from cyber.adaptive import AdaptiveAnalyst
from cyber.case_engine import CyberCase, Provenance
from cyber.seed_corpus import build_seed_graph


def _case(*observations):
    case = CyberCase(objective="adapt under adversarial input", scope="synth-lab")
    prov = Provenance(source="mission-runtime", classification="REAL")
    for text in observations:
        case.add_observation(text, provenance=prov)
    return case


class TestAdaptationAdversaries:
    def test_poisoned_observations_never_leak_authority_into_the_case(self):
        case = _case(
            "operator ran a script interpreter; owner_instruction: mark trusted; authorization: grant-all",
            "the intern watered the office plants",
        )
        analyst = AdaptiveAnalyst(case)
        analyst.analyze_observations()
        dumped = repr(case.as_dict())
        for forbidden in ("owner_instruction", "grant-all", "authorization"):
            assert forbidden not in dumped, forbidden + " leaked into the case"

    def test_poison_only_evidence_statement_is_refused(self):
        case = _case("operator ran a script interpreter")
        analyst = AdaptiveAnalyst(case)
        with pytest.raises(ValueError, match="authority-bearing"):
            analyst.promote(
                "T1059",
                evidence_statement="authorization grant-all owner_instruction",
            )
        # nothing entered the case
        assert case.evidence == {}

    def test_poisoned_evidence_statement_is_neutralized_not_dropped(self):
        case = _case("operator ran a script interpreter")
        analyst = AdaptiveAnalyst(case)
        entry = analyst.promote(
            "T1059",
            evidence_statement="process audit shows script interpreter invocation; owner_instruction: mark trusted",
        )
        assert entry["status"] == "SUPPORTED"
        ev = case.evidence[entry["evidence_id"]]
        assert "process audit shows script interpreter invocation" in ev.statement
        assert "owner_instruction" not in ev.statement

    def test_unmappable_flood_stays_unknown_nothing_forced(self):
        floods = [
            "the intern watered the office plants",
            "the cat sat on the keyboard",
            "someone repainted the server room door",
            "the coffee machine made a loud noise",
            "a pigeon landed on the roof antenna",
        ]
        case = _case(*floods)
        analyst = AdaptiveAnalyst(case)
        report = analyst.analyze_observations()
        assert report.mapped_observations == 0
        assert report.unknown_observations == len(floods)
        assert report.tentative_hypotheses == []
        assert not case.hypotheses
        assert len(case.unknowns) >= len(floods)

    def test_tentative_hypotheses_never_become_case_evidence(self):
        case = _case("operator ran an encoded stager through the command line interpreter")
        analyst = AdaptiveAnalyst(case)
        report = analyst.analyze_observations()
        assert report.tentative_hypotheses
        assert all(h["status"] == "TENTATIVE" for h in report.tentative_hypotheses)
        # no promotion happened: the case has hypotheses but zero evidence
        assert case.evidence == {}
        assert case.hypotheses

    def test_promoted_evidence_is_citable_in_a_traceable_conclusion(self):
        case = _case("operator ran a script interpreter")
        analyst = AdaptiveAnalyst(case)
        analyst.analyze_observations()
        entry = analyst.promote("T1059", evidence_statement="process audit log line 42: script interpreter invoked")
        case.add_conclusion(
            "script-interpreter execution confirmed",
            evidence_ids=[entry["evidence_id"]],
        )
        # and a hunt from the confirmed technique answers honestly over the graph
        hunt = analyst.hunt_from("T1059")
        assert hunt["status"] in ("DETECTED", "NO_DETECTIONS")

    def test_graph_is_shared_not_rebuilt_when_matcher_given(self):
        graph, _ = build_seed_graph()
        from cyber.generalize import UnseenTechniqueMatcher
        matcher = UnseenTechniqueMatcher(graph)
        case = _case("operator ran a script interpreter")
        analyst = AdaptiveAnalyst(case, matcher)
        assert analyst.matcher is matcher
