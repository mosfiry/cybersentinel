from __future__ import annotations

import pytest

from agent.offensive_mind import (
    Campaign,
    Engagement,
    EngagementError,
    KillChainPhase,
    OffensiveMind,
    StepStatus,
)


def _engagement(**overrides):
    kwargs = {
        "engagement_id": "eng-001",
        "authorized_scope": ("target.example",),
        "rules_of_engagement_accepted": True,
    }
    kwargs.update(overrides)
    return Engagement(**kwargs)


def test_planning_requires_accepted_rules_of_engagement():
    with pytest.raises(EngagementError):
        Engagement(engagement_id="eng-002", authorized_scope=("target.example",), rules_of_engagement_accepted=False)


def test_planning_requires_scope():
    with pytest.raises(ValueError):
        Engagement(engagement_id="eng-003", authorized_scope=(), rules_of_engagement_accepted=True)


def test_plan_is_deterministic():
    mind = OffensiveMind(_engagement())
    features = ("web-exposed-surface", "api-gateway", "identity-provider", "cloud-workload")
    first = mind.plan("assess the perimeter of target.example", features)
    second = OffensiveMind(_engagement()).plan("assess the perimeter of target.example", features)
    assert first.fingerprint() == second.fingerprint()


def test_plan_produces_evidence_gated_steps_across_phases():
    campaign = OffensiveMind(_engagement()).plan("assess target.example", ("web-exposed-surface", "identity-provider", "cloud-workload"))
    assert campaign.steps, "expected generated steps"
    phases = {step.phase for step in campaign.steps}
    assert KillChainPhase.RECON in phases
    for step in campaign.steps:
        assert step.evidence_required, "every step must demand evidence"
        assert 0.0 <= step.priority <= 1.0
        assert step.mitre_technique.startswith("T")


def test_generated_steps_stay_in_scope_and_actionable():
    engagement = _engagement()
    mind = OffensiveMind(engagement)
    campaign = mind.plan("assess target.example", ("web-exposed-surface",))
    assert campaign.steps
    for step in campaign.steps:
        assert engagement.covers(step.target_asset)
        assert step.status is not StepStatus.OUT_OF_SCOPE


def test_scope_covers_subdomains_only():
    engagement = _engagement()
    assert engagement.covers("target.example")
    assert engagement.covers("api.target.example")
    assert not engagement.covers("other.example")
    assert not engagement.covers("evilexample")


def test_failed_step_activates_fallback_ladder():
    mind = OffensiveMind(_engagement())
    campaign = mind.plan("assess target.example", ("web-exposed-surface",))
    target = campaign.steps[0]
    before = len(campaign.steps)
    mind.adapt(campaign, {"type": "STEP_RESULT", "step_id": target.step_id, "outcome": "FAILED"})
    assert target.status is StepStatus.FAILED
    fallbacks = [s for s in campaign.steps if s.fallback_of == target.step_id]
    assert fallbacks, "a failed step must spawn fallbacks"
    assert len(campaign.steps) > before
    nxt = campaign.next_step()
    assert nxt is not None
    assert nxt.step_id != target.step_id


def test_detected_step_quarantines_dependents():
    mind = OffensiveMind(_engagement())
    campaign = mind.plan("assess target.example", ("web-exposed-surface",))
    recon = campaign.steps[0]
    mind.adapt(campaign, {"type": "STEP_RESULT", "step_id": recon.step_id, "outcome": "COMPLETED"})
    assert recon.status is StepStatus.COMPLETED
    dependent = next((s for s in campaign.steps if s.step_id != recon.step_id and "surface inventory complete" in s.preconditions), None)
    if dependent is not None:
        mind.adapt(campaign, {"type": "STEP_RESULT", "step_id": dependent.step_id, "outcome": "DETECTED"})
        assert dependent.status is StepStatus.DETECTED


def test_deception_cues_freeze_active_steps():
    mind = OffensiveMind(_engagement())
    campaign = mind.plan("assess target.example", ("web-exposed-surface", "identity-provider"))
    campaign.steps[0].status = StepStatus.ACTIVE
    mind.adapt(campaign, {"type": "OBSERVATION", "note": "responses show uniform latency across all endpoints"})
    assert campaign.deception_flags, "deception cue must raise a flag"
    assert all(s.status is not StepStatus.ACTIVE for s in campaign.steps)


def test_honeytoken_is_flagged_as_bait():
    mind = OffensiveMind(_engagement())
    campaign = mind.plan("assess target.example", ("web-exposed-surface",))
    mind.adapt(campaign, {"type": "OBSERVATION", "note": "found a honeytoken secret immediately"})
    assert any("too-easily-found secret" in flag for flag in campaign.deception_flags), (
        "the honeytoken deception cue must be flagged as bait"
    )


def test_creativity_level_one_limits_fallback_width():
    mind = OffensiveMind(Engagement(engagement_id="eng-005", authorized_scope=("target.example",), rules_of_engagement_accepted=True, creativity_level=1))
    campaign = mind.plan("assess target.example", ("web-exposed-surface",))
    before = len(campaign.steps)
    mind.adapt(campaign, {"type": "STEP_RESULT", "step_id": campaign.steps[0].step_id, "outcome": "FAILED"})
    fallbacks = [s for s in campaign.steps if s.fallback_of == campaign.steps[0].step_id]
    assert len(fallbacks) == 1
    assert len(campaign.steps) == before + 1


def test_unknown_event_or_step_rejected():
    mind = OffensiveMind(_engagement())
    campaign = mind.plan("assess target.example", ("web-exposed-surface",))
    with pytest.raises(ValueError):
        mind.adapt(campaign, {"type": "NONSENSE"})
    with pytest.raises(ValueError):
        mind.adapt(campaign, {"type": "STEP_RESULT", "step_id": "s-99", "outcome": "FAILED"})
    with pytest.raises(ValueError):
        mind.adapt(campaign, {"type": "STEP_RESULT", "step_id": campaign.steps[0].step_id, "outcome": "MAYBE"})


def test_campaign_round_trips_through_dict():
    mind = OffensiveMind(_engagement())
    campaign = mind.plan("assess target.example", ("web-exposed-surface", "cloud-workload"))
    restored = Campaign.from_dict(campaign.to_dict())
    assert restored.fingerprint() == campaign.fingerprint()
    assert restored.to_dict()["limitations"], "limitations must survive serialization"


def test_fanout_scales_with_creativity():
    features = ("web-exposed-surface", "identity-provider", "cloud-workload")
    narrow = OffensiveMind(_engagement()).plan("x", features).hypothesis_fanout
    wide = OffensiveMind(Engagement(engagement_id="eng-006", authorized_scope=("target.example",), rules_of_engagement_accepted=True, creativity_level=3)).plan("x", features).hypothesis_fanout
    assert 0 < len(narrow) < len(wide)
