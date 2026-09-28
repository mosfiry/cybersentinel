from __future__ import annotations

"""Adversarial battery: GOAL_COMPLETED is a deterministic system invariant.

No caller (model, API, worker, library) can complete a mission by
assertion. GOAL_COMPLETED requires the deterministic goal-verification
state written by MissionRuntime. Recovery reconciliation keeps precedence
over the guard (a RECOVERY_REQUIRED mission must reconcile first).
"""

import pytest

from agent.mission import Mission, MissionStatus
from agent.planning import Plan


def make_mission() -> Mission:
    return Mission.create("owner", "objective", Plan.initial("objective"), request_id="req-gc")


def test_goal_completed_by_assertion_is_rejected():
    mission = make_mission()
    mission.transition(MissionStatus.READY, "prepared")
    with pytest.raises(ValueError, match="system invariant"):
        mission.transition(MissionStatus.GOAL_COMPLETED, "model asserts success")
    assert mission.status is MissionStatus.READY


def test_goal_completed_with_forged_string_verification_is_rejected():
    mission = make_mission()
    mission.transition(MissionStatus.READY, "prepared")
    mission.verification_state = {"verified": "true"}
    with pytest.raises(ValueError, match="system invariant"):
        mission.transition(MissionStatus.GOAL_COMPLETED, "string is not truth")


def test_goal_completed_with_empty_verification_state_is_rejected():
    mission = make_mission()
    mission.transition(MissionStatus.READY, "prepared")
    mission.verification_state = {}
    with pytest.raises(ValueError, match="system invariant"):
        mission.transition(MissionStatus.GOAL_COMPLETED, "empty state")


def test_goal_completed_with_deterministic_verification_is_accepted():
    mission = make_mission()
    mission.transition(MissionStatus.READY, "prepared")
    mission.verification_state = {"verified": True}
    mission.transition(MissionStatus.GOAL_COMPLETED, "verified")
    assert mission.status is MissionStatus.GOAL_COMPLETED


def test_recovery_reconciliation_keeps_precedence_over_guard():
    mission = make_mission()
    mission.transition(MissionStatus.READY, "prepared")
    mission.transition(MissionStatus.RECOVERY_REQUIRED, "ambiguous")
    with pytest.raises(ValueError, match="reconciliation"):
        mission.transition(MissionStatus.GOAL_COMPLETED, "forged completion")
    mission.transition(MissionStatus.READY, "reconciled")
    with pytest.raises(ValueError, match="system invariant"):
        mission.transition(MissionStatus.GOAL_COMPLETED, "no verification state")
    mission.verification_state = {"verified": True}
    mission.transition(MissionStatus.GOAL_COMPLETED, "verified")


def test_persisted_mission_without_verification_cannot_complete():
    mission = make_mission()
    mission.transition(MissionStatus.READY, "prepared")
    restored = Mission.from_dict(mission.to_dict())
    with pytest.raises(ValueError, match="system invariant"):
        restored.transition(MissionStatus.GOAL_COMPLETED, "restart forgery")


def test_persisted_mission_with_verification_can_complete():
    mission = make_mission()
    mission.transition(MissionStatus.READY, "prepared")
    mission.verification_state = {"verified": True}
    restored = Mission.from_dict(mission.to_dict())
    restored.transition(MissionStatus.GOAL_COMPLETED, "verified")
    assert restored.status is MissionStatus.GOAL_COMPLETED
