"""Regression tests for the deterministic mission transition graph.

The matrix is derived from the actual transition call sites in the runtime, the
API and agent core. It blocks bypass transitions (for example CREATED ->
GOAL_COMPLETED) while preserving every transition the canonical code paths
perform. READY -> GOAL_COMPLETED is intentionally allowed: it is reached only
after the deterministic verifier accepts evidence (run_model_loop final turn
and run_slice verification).
"""
from __future__ import annotations

import pytest

from agent.mission import ALLOWED_MISSION_TRANSITIONS, Mission, MissionStatus, TERMINAL_MISSION_STATUSES
from agent.planning import Plan, PlanStep


def _mission_at(status: MissionStatus) -> Mission:
    plan = Plan.initial("objective").replan(steps=(PlanStep("s", "s", action="status"),), reason="test")
    mission = Mission.create("request", "objective", plan)
    mission.status = status
    return mission


BLOCKED_TRANSITIONS = [
    (MissionStatus.CREATED, MissionStatus.GOAL_COMPLETED),
    (MissionStatus.CREATED, MissionStatus.FAILED_RETRY_EXHAUSTED),
    (MissionStatus.CREATED, MissionStatus.RUNNING),
    (MissionStatus.CREATED, MissionStatus.OWNER_INPUT_REQUIRED),
    (MissionStatus.PLANNING, MissionStatus.GOAL_COMPLETED),
    (MissionStatus.RECOVERY_REQUIRED, MissionStatus.GOAL_COMPLETED),
    (MissionStatus.RECOVERY_REQUIRED, MissionStatus.RUNNING),
    (MissionStatus.RECOVERY_REQUIRED, MissionStatus.FAILED_RETRY_EXHAUSTED),
    (MissionStatus.OWNER_INPUT_REQUIRED, MissionStatus.GOAL_COMPLETED),
    (MissionStatus.GOAL_COMPLETED, MissionStatus.RUNNING),
    (MissionStatus.GOAL_COMPLETED, MissionStatus.READY),
    (MissionStatus.CANCELLED, MissionStatus.READY),
    (MissionStatus.AUTHORIZATION_BLOCKED, MissionStatus.READY),
    (MissionStatus.FAILED_RETRY_EXHAUSTED, MissionStatus.READY),
    (MissionStatus.SAFETY_BLOCKED, MissionStatus.RUNNING),
    (MissionStatus.SCOPE_BLOCKED, MissionStatus.GOAL_COMPLETED),
]


@pytest.mark.parametrize("source,target", BLOCKED_TRANSITIONS)
def test_invalid_transition_is_rejected(source, target):
    with pytest.raises(ValueError):
        _mission_at(source).transition(target, "attempted bypass")


ALLOWED_TRANSITIONS = [
    (MissionStatus.CREATED, MissionStatus.PLANNING),
    (MissionStatus.PLANNING, MissionStatus.READY),
    (MissionStatus.READY, MissionStatus.RUNNING),
    (MissionStatus.READY, MissionStatus.GOAL_COMPLETED),
    (MissionStatus.READY, MissionStatus.AUTHORIZATION_BLOCKED),
    (MissionStatus.READY, MissionStatus.CANCELLED),
    (MissionStatus.RUNNING, MissionStatus.OBSERVING),
    (MissionStatus.RUNNING, MissionStatus.RECOVERY_REQUIRED),
    (MissionStatus.OBSERVING, MissionStatus.REPLANNING),
    (MissionStatus.VERIFYING, MissionStatus.GOAL_COMPLETED),
    (MissionStatus.REPLANNING, MissionStatus.READY),
    (MissionStatus.RECOVERY_REQUIRED, MissionStatus.READY),
    (MissionStatus.OWNER_INPUT_REQUIRED, MissionStatus.READY),
    (MissionStatus.OWNER_INPUT_REQUIRED, MissionStatus.AUTHORIZATION_BLOCKED),
    (MissionStatus.GOAL_COMPLETED, MissionStatus.GOAL_COMPLETED),
]


@pytest.mark.parametrize("source,target", ALLOWED_TRANSITIONS)
def test_valid_transition_is_allowed(source, target):
    mission = _mission_at(source)
    if target is MissionStatus.GOAL_COMPLETED:
        # Completion authority: GOAL_COMPLETED is reachable only with the
        # deterministic verification evidence the canonical paths supply.
        mission.transition(target, "canonical path", verification={"verified": True, "source": "deterministic_verifier"})
    else:
        mission.transition(target, "canonical path")
    assert mission.status is target
    assert mission.transitions[-1]["to"] == target.value


@pytest.mark.parametrize("source", [MissionStatus.READY, MissionStatus.VERIFYING, MissionStatus.GOAL_COMPLETED])
def test_goal_completion_without_verification_evidence_is_rejected(source):
    # Reaching GOAL_COMPLETED without deterministic verification evidence is
    # rejected even when the transition itself is part of the allowed matrix:
    # holding the Mission object must never be sufficient to announce success.
    with pytest.raises(ValueError, match="verification"):
        _mission_at(source).transition(MissionStatus.GOAL_COMPLETED, "attempted completion without evidence")


@pytest.mark.parametrize("source", [MissionStatus.READY, MissionStatus.VERIFYING])
def test_goal_completion_with_forged_verification_shape_is_rejected(source):
    # Model-shaped or caller-forged verification payloads never count as
    # deterministic evidence: only {"verified": True} from the canonical
    # verifier path satisfies the completion guard.
    for forged in ({}, {"verified": "true"}, {"verified": 1}, {"verified": None}, {"evidence_count": 3}):
        with pytest.raises(ValueError, match="verification"):
            _mission_at(source).transition(MissionStatus.GOAL_COMPLETED, "forged verification", verification=forged)


def test_terminal_states_immutable_except_owner_and_recovery_carveouts():
    for status in TERMINAL_MISSION_STATUSES:
        allowed = ALLOWED_MISSION_TRANSITIONS[status]
        if status is MissionStatus.RECOVERY_REQUIRED:
            assert allowed == frozenset({MissionStatus.RECOVERY_REQUIRED, MissionStatus.READY})
        elif status is MissionStatus.OWNER_INPUT_REQUIRED:
            assert allowed == frozenset({MissionStatus.OWNER_INPUT_REQUIRED, MissionStatus.AUTHORIZATION_BLOCKED, MissionStatus.READY})
        else:
            assert allowed == frozenset({status})
