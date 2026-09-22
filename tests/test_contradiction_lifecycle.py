"""Round 2 P1 - contradiction evidence drives hypothesis and strategy updates.

Evidence A strengthens a hypothesis; contradicting evidence B weakens or
disproves it, and the deterministic strategy engine orders a replan. The model
alone can never mark a hypothesis CONFIRMED.
"""

from __future__ import annotations

import pytest

from agent.hypotheses import HypothesisEngine, HypothesisState, HypothesisStatus
from agent.observation_intelligence import (
    ConfidenceChange,
    InformationGain,
    ObservationInterpreter,
    ObservationInterpretationProposal,
    ReplanTrigger,
)
from agent.strategy import StrategyDecisionType, decide


def _proposal(**kwargs):
    base = dict(
        observation_id="obs-1",
        summary="interpretation",
        information_gain=InformationGain.NO_CHANGE,
    )
    base.update(kwargs)
    return ObservationInterpretationProposal(**base)


def test_supporting_evidence_strengthens_hypothesis():
    engine = HypothesisEngine([HypothesisState("h1", "asset A is compromised", HypothesisStatus.UNRESOLVED, 0.3)])
    proposal = _proposal(
        confidence_changes=(
            ConfidenceChange("h1", 0.4, "suspicious outbound log supports compromise", supporting_evidence_ids=("e1",)),
        ),
        information_gain=InformationGain.MEDIUM,
    )
    updates = engine.apply(proposal)
    assert updates and updates[0]["status"] == HypothesisStatus.STRENGTHENED.value
    assert engine.hypotheses["h1"].confidence == pytest.approx(0.7)
    decision = decide(proposal, action_success=True)
    assert decision.decision is StrategyDecisionType.CHANGE_HYPOTHESIS


def test_contradicting_evidence_disproves_and_forces_replan():
    engine = HypothesisEngine([HypothesisState("h1", "asset A is compromised", HypothesisStatus.ACTIVE, 0.8)])
    proposal = _proposal(
        contradictions=({"evidence_id": "c1", "summary": "asset A runs the patched version"},),
        confidence_changes=(
            ConfidenceChange("h1", -0.9, "patched version contradicts compromise", counter_evidence_ids=("c1",)),
        ),
        replan_reason="patched-version evidence contradicted the compromise hypothesis",
        information_gain=InformationGain.HIGH,
        triggers=(ReplanTrigger.CONTRADICTORY_EVIDENCE, ReplanTrigger.HYPOTHESIS_REJECTED),
    )
    engine.apply(proposal)
    hypothesis = engine.hypotheses["h1"]
    assert hypothesis.status is HypothesisStatus.DISPROVEN
    assert hypothesis.confidence == 0.0
    assert "c1" in hypothesis.counter_evidence_ids
    decision = decide(proposal, action_success=True)
    assert decision.decision is StrategyDecisionType.REPLAN
    assert "contradicted" in decision.reason


def test_partial_contradiction_weakens_instead_of_disproving():
    engine = HypothesisEngine([HypothesisState("h1", "asset A is compromised", HypothesisStatus.ACTIVE, 0.8)])
    proposal = _proposal(
        confidence_changes=(
            ConfidenceChange("h1", -0.3, "partial counter evidence", counter_evidence_ids=("c1",)),
        ),
    )
    engine.apply(proposal)
    assert engine.hypotheses["h1"].status is HypothesisStatus.WEAKENED


def test_deterministic_interpreter_extracts_contradictions_from_observation():
    interpreter = ObservationInterpreter()
    proposal = interpreter.interpret(
        mission={"mission_id": "m1"},
        plan={},
        current_step=None,
        action="status",
        observation={
            "success": True,
            "counter_evidence": [{"evidence_id": "c1", "summary": "asset is patched"}],
        },
        evidence=[],
        hypothesis_state={},
    )
    assert proposal.contradictions and proposal.contradictions[0]["evidence_id"] == "c1"
    assert proposal.information_gain is InformationGain.HIGH
    assert ReplanTrigger.CONTRADICTORY_EVIDENCE in proposal.triggers
    assert proposal.replan_reason, "material information gain must carry a replan reason"
    decision = decide(proposal, action_success=True)
    assert decision.decision is StrategyDecisionType.REPLAN


def test_model_cannot_confirm_a_hypothesis():
    engine = HypothesisEngine([HypothesisState("h1", "asset A is compromised")])
    poisoned = _proposal(
        hypothesis_updates=({"hypothesis_id": "h1", "status": "CONFIRMED"},),
    )
    with pytest.raises(ValueError):
        engine.apply(poisoned)

    confirmed = _proposal(
        hypothesis_updates=({"hypothesis_id": "h1", "status": "CONFIRMED"},),
    )
    engine.apply(confirmed, goal_verified=True, deterministic_validation=True)
    assert engine.hypotheses["h1"].status is HypothesisStatus.CONFIRMED
