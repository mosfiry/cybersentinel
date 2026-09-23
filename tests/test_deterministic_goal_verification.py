from __future__ import annotations
from runtime_authorization import make_test_snapshot
"""Round 2 P1 - deterministic goal verification.

A MODEL CLAIM alone can never complete a mission. Completion requires
observable evidence for every required criterion evaluated by the deterministic
GoalVerification, or the mission returns to READY instead of completing.
"""


from pathlib import Path

import pytest

from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import (
    GoalVerification,
    Plan,
    PlanStep,
    VerificationCriterion,
    evidence_for,
)


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime, criteria):
    plan = Plan.initial("prove the goal").replan(
        steps=(PlanStep("observe", "observe", action="status"),), reason="test"
    )
    return runtime.create("prove the goal", "prove the goal", plan, completion_criteria=criteria)


def test_goal_verification_requires_all_required_criteria():
    criteria = (
        VerificationCriterion("c1", "first", "check"),
        VerificationCriterion("c2", "second", "check"),
        VerificationCriterion("c3", "optional", "check", required=False),
    )
    partial = (evidence_for("c1", True, "test", {"v": 1}),)
    result = GoalVerification.evaluate("goal", criteria, partial)
    assert result.verified is False
    assert result.missing_criteria == ("c2",)
    with pytest.raises(ValueError):
        result.require_verified()

    complete = partial + (evidence_for("c2", True, "test", {"v": 2}),)
    verified = GoalVerification.evaluate("goal", criteria, complete)
    assert verified.verified is True
    assert verified.missing_criteria == ()
    verified.require_verified()


def test_failed_evidence_does_not_verify():
    criteria = (VerificationCriterion("c1", "first", "check"),)
    evidence = (evidence_for("c1", False, "test", {"v": 1}),)
    result = GoalVerification.evaluate("goal", criteria, evidence)
    assert result.verified is False
    assert result.missing_criteria == ("c1",)


def test_model_final_claim_without_evidence_does_not_complete(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, [{"criterion_id": "goal"}])

    class ConfidentModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, content="CONFIRMED: goal fully achieved and verified", finish_reason="stop")

    result = runtime.run_model_loop(mission.mission_id, ConfidentModel(), tools=[], max_turns=3)
    assert result.status is not MissionStatus.GOAL_COMPLETED
    assert result.status is MissionStatus.READY
    assert "lacked deterministic goal evidence" in result.error
    assert result.verification_state.get("verified") is False
    assert "goal" in result.verification_state.get("missing_criteria", [])


def test_completion_requires_passed_evidence_not_a_claim(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: {"ok": True, "criterion_id": "goal", "source": "fixture"})
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, [{"criterion_id": "goal"}])

    class EvidenceThenFinalModel:
        def __init__(self):
            self.count = 0

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            self.count += 1
            if self.count == 1:
                return ModelTurn(
                    turn_id,
                    tool_calls=(
                        ToolCallProposal.create(
                            "status",
                            {},
                            mission_id=mission_id,
                            run_id=run_id,
                            turn_id=turn_id,
                            plan_version=plan_version,
                            tool_call_id="call_001",
                        ),
                    ),
                )
            return ModelTurn(turn_id, content="goal achieved", finish_reason="stop")

    result = runtime.run_model_loop(mission.mission_id, EvidenceThenFinalModel(), tools=[{"name": "status"}], max_turns=4)
    assert result.status is MissionStatus.GOAL_COMPLETED
    assert result.verification_state.get("verified") is True
    events = [event["event"] for event in result.trajectory]
    assert "GoalVerified" in events
    assert "MissionCompleted" in events


def test_turn_budget_exhaustion_is_an_honest_failure(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: {"ok": True, "criterion_id": "goal", "source": "fixture"})

    runtime = _runtime(tmp_path)
    mission = _mission(runtime, [{"criterion_id": "goal"}])

    class NeverConcludesModel:
        """Proposes a tool call on every turn and never reaches a final answer."""

        def __init__(self):
            self.count = 0

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            self.count += 1
            return ModelTurn(
                turn_id,
                tool_calls=(
                    ToolCallProposal.create(
                        "status",
                        {},
                        mission_id=mission_id,
                        run_id=run_id,
                        turn_id=turn_id,
                        plan_version=plan_version,
                        tool_call_id="call_%03d" % self.count,
                    ),
                ),
            )

    result = runtime.run_model_loop(mission.mission_id, NeverConcludesModel(), tools=[{"name": "status"}], max_turns=3)
    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert "budget exhausted" in result.error
    assert result.is_terminal
