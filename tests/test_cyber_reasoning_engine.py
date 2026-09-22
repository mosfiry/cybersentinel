"""Behavioral tests for the advanced offensive reasoning engine.

These prove the reasoning discipline itself:
* fanout scales with effort, and every hypothesis is falsifiable
* self-critique attacks unfalsifiable/unsupported/unknown-technique steps
* voting cannot crown an evidence-free path
* progressive deepening stops at diminishing returns, honestly
* verification requirements are explicit for the winning path
"""

from __future__ import annotations

import pytest

from cyber.reasoning_engine import (
    AttackPath,
    Critique,
    OffensiveReasoningEngine,
    ReasoningEffort,
    ReasoningStep,
)


def step(sid, desc, evidence="probe evidence", falsifiable=True, technique=""):
    return ReasoningStep(sid, desc, technique=technique, evidence_required=evidence if falsifiable else "", falsifiable=falsifiable)


def path(pid, support=0.5, discrim=0.4, hypothesis="h1", steps=None):
    return AttackPath(
        path_id=pid,
        objective="assess target.example",
        steps=tuple(steps or [step("s1", "enumerate surface"), step("s2", "test entry point")]),
        hypothesis=hypothesis,
        evidence_support=support,
        discriminating_power=discrim,
    )


def builders(*paths):
    return [(lambda p=p: p) for p in paths]


def test_fanout_scales_with_reasoning_effort():
    engine = OffensiveReasoningEngine()
    seeds = ["entry-{}".format(i) for i in range(30)]
    fast = engine.generate_hypotheses("obj", seeds, ReasoningEffort.FAST)
    exhaustive = engine.generate_hypotheses("obj", seeds, ReasoningEffort.EXHAUSTIVE)
    assert len(fast) == 2
    assert len(exhaustive) == 16
    for hypothesis in exhaustive:
        assert hypothesis.discriminating_question
        assert hypothesis.verification_requirement


def test_every_hypothesis_is_falsifiable_by_design():
    engine = OffensiveReasoningEngine()
    hypotheses = engine.generate_hypotheses("obj", ["web", "api"], ReasoningEffort.STANDARD)
    assert all(h.discriminating_question for h in hypotheses)


def test_self_critique_attacks_unfalsifiable_and_evidence_free_steps():
    engine = OffensiveReasoningEngine()
    weak = path(
        "p-weak",
        support=0.0,
        steps=[step("s1", "blindly trust the model", falsifiable=False)],
    )
    critiques = engine.critique_path(weak)
    kinds = {c.kind for c in critiques}
    assert "unfalsifiable_step" in kinds
    assert "missing_evidence" in kinds
    assert "unsupported_path" in kinds


def test_critique_flags_unknown_techniques_via_knowledge_lookup():
    engine = OffensiveReasoningEngine(
        knowledge_lookup=lambda technique: {"classification": "UNKNOWN"}
        if technique == "T9999" else {"classification": "SUPPORTED"}
    )
    suspicious = path("p-sus", steps=[step("s1", "use technique", technique="T9999")])
    good = path("p-good", steps=[step("s1", "use technique", technique="T1041")])
    assert any(c.kind == "unverified_technique" for c in engine.critique_path(suspicious))
    assert all(c.kind != "unverified_technique" for c in engine.critique_path(good))


def test_voting_ranks_evidence_support_over_step_count():
    engine = OffensiveReasoningEngine()
    supported_short = path("p-supported", support=0.8, discrim=0.2, hypothesis="ha")
    speculative_long = path(
        "p-spec",
        support=0.0,
        discrim=0.9,
        hypothesis="hb",
        steps=[step("s{}".format(i), "step {}".format(i)) for i in range(10)],
    )
    ranked = engine.explore_paths("obj", builders(speculative_long, supported_short), ReasoningEffort.STANDARD)
    assert ranked[0].path_id == "p-supported", "evidence-free speculation must never outrank support"


def test_self_consistency_votes_reinforce_same_hypothesis():
    engine = OffensiveReasoningEngine()
    a1 = path("p1", support=0.6, hypothesis="ha")
    a2 = path("p2", support=0.6, hypothesis="ha")
    b1 = path("p3", support=0.6, hypothesis="hb")
    ranked = engine.explore_paths("obj", builders(a1, a2, b1), ReasoningEffort.DEEP)
    assert ranked[0].hypothesis == "ha"
    assert ranked[0].votes >= 1


def test_progressive_deepening_stops_at_diminishing_returns():
    engine = OffensiveReasoningEngine()
    run = engine.run(
        "obj",
        seeds=["web", "api", "identity"],
        path_builders=builders(path("p1")),
        effort=ReasoningEffort.DEEP,
    )
    assert run.passes >= 1
    assert run.stopped_for in ("diminishing_returns", "completed", "no_supported_path")
    assert run.reflections, "deep effort must reflect between passes"


def test_no_supported_path_is_never_crowned():
    engine = OffensiveReasoningEngine()
    run = engine.run(
        "obj",
        seeds=["web"],
        path_builders=builders(path("p-spec", support=0.0)),
        effort=ReasoningEffort.STANDARD,
    )
    assert run.stopped_for == "no_supported_path"


def test_verification_plan_is_explicit_for_the_winning_path():
    engine = OffensiveReasoningEngine()
    run = engine.run(
        "obj",
        seeds=["web"],
        path_builders=builders(path("p1", support=0.7)),
        effort=ReasoningEffort.STANDARD,
    )
    plan = engine.verification_plan(run)
    assert plan
    assert all(item["evidence_required"] for item in plan)


def test_effort_config_is_monotonic():
    from cyber.reasoning_engine import _EFFORT_CONFIG
    order = [ReasoningEffort.FAST, ReasoningEffort.STANDARD, ReasoningEffort.DEEP, ReasoningEffort.EXHAUSTIVE]
    for lighter, heavier in zip(order, order[1:]):
        assert _EFFORT_CONFIG[heavier]["paths"] >= _EFFORT_CONFIG[lighter]["paths"]
        assert _EFFORT_CONFIG[heavier]["hypotheses"] >= _EFFORT_CONFIG[lighter]["hypotheses"]
        assert _EFFORT_CONFIG[heavier]["passes"] >= _EFFORT_CONFIG[lighter]["passes"]


def test_step_must_be_falsifiable_with_evidence_or_explicitly_not():
    with pytest.raises(ValueError):
        ReasoningStep("s1", "unfalsifiable", falsifiable=True, evidence_required="")
    ok = ReasoningStep("s1", "unfalsifiable", falsifiable=False)
    assert ok.falsifiable is False
