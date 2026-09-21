from __future__ import annotations

import pytest

from agent.planning import (
    FailureClass,
    GoalVerification,
    Plan,
    PlanStep,
    ReasoningMode,
    RecoveryAction,
    RecoveryPolicy,
    VerificationCriterion,
    evidence_for,
    select_reasoning_profile,
)


def test_reasoning_mode_is_bounded_and_has_no_authority_effect():
    assert select_reasoning_profile("ما معنى CVE؟").mode is ReasoningMode.FAST
    profile = select_reasoning_profile("حلل هذه الحادثة وابنِ خطة ثم اختبرها")
    assert profile.mode is ReasoningMode.DEEP
    assert profile.long_horizon is True
    assert 0 <= profile.temperature <= 1


def test_plan_is_versioned_and_replanning_preserves_history_value():
    first = Plan.initial("تحليل حادثة", created_from="conversation")
    second = first.replan(
        steps=(PlanStep("s1", "جمع الأدلة", action="search", verification=("evidence",)),),
        assumptions=("المصدر متاح",),
        reason="observation: source available",
    )
    assert first.version == 1
    assert second.version == 2
    assert first.steps == ()
    assert second.steps[0].step_id == "s1"
    assert first.fingerprint != second.fingerprint
    assert second.to_dict()["steps"][0]["verification"] == ["evidence"]


def test_goal_verification_rejects_model_claim_without_evidence():
    criteria = (VerificationCriterion("tests", "tests pass", "pytest"), VerificationCriterion("artifact", "artifact exists", "filesystem"))
    verification = GoalVerification.evaluate("deliver", criteria, (evidence_for("tests", True, "pytest", {"passed": 3}),))
    assert verification.verified is False
    assert verification.missing_criteria == ("artifact",)
    with pytest.raises(ValueError, match="artifact"):
        verification.require_verified()


def test_goal_verification_accepts_only_required_verified_criteria():
    criteria = (VerificationCriterion("tests", "tests pass", "pytest"), VerificationCriterion("note", "optional note", "docs", required=False))
    verification = GoalVerification.evaluate("deliver", criteria, (evidence_for("tests", True, "pytest", {"passed": 243}),))
    verification.require_verified()
    assert verification.verified is True


def test_failure_recovery_never_bypasses_authorization_or_scope():
    policy = RecoveryPolicy(max_retries=2)
    assert policy.action_for(FailureClass.AUTHORIZATION, 0) is RecoveryAction.OWNER_INPUT_REQUIRED
    assert policy.action_for(FailureClass.SCOPE, 0) is RecoveryAction.SCOPE_BLOCKED
    assert policy.action_for(FailureClass.NETWORK, 0) is RecoveryAction.RETRY
    assert policy.action_for(FailureClass.NETWORK, 2) is RecoveryAction.FAIL
