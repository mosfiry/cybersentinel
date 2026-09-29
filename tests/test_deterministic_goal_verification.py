from __future__ import annotations
from runtime_authorization import make_test_snapshot, signed_test_owner_kwargs
"""Round 2 P1 - deterministic goal verification.

A MODEL CLAIM or generic tool observation alone can never complete a mission.
Completion requires supported system-issued evidence for every required
criterion; otherwise the mission stops for Owner input instead of looping.
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


def _mission(runtime, criteria, **kwargs):
    plan = Plan.initial("prove the goal").replan(
        steps=(PlanStep("observe", "observe", action="status"),), reason="test"
    )
    return runtime.create("prove the goal", "prove the goal", plan, completion_criteria=criteria, **kwargs)


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


def test_empty_required_criteria_and_conflicting_evidence_never_verify():
    assert GoalVerification.evaluate("goal", (), ()).verified is False
    criteria = (VerificationCriterion("c1", "first", "check"),)
    contradictory = (evidence_for("c1", True, "system", {}), evidence_for("c1", False, "system", {}))
    result = GoalVerification.evaluate("goal", criteria, contradictory)
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


def test_tool_success_flag_and_model_claim_do_not_complete(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: {"ok": True, "criterion_id": "goal", "source": "fixture"})
    runtime = _runtime(tmp_path)
    owner_kwargs = signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="request-fake-tool")
    mission = _mission(runtime, [{"criterion_id": "goal"}], **owner_kwargs)

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
    assert result.status is MissionStatus.READY
    assert result.verification_state.get("verified") is False
    assert not result.completion_proof
    assert not any(item.get("system_evidence") for item in result.evidence)


def test_signed_completion_requires_independent_status_check_and_survives_restart(tmp_path, monkeypatch):
    import core.engine
    import security.truthfulness as truthfulness

    monkeypatch.setattr(truthfulness, "PROVENANCE_KEY_PATH", Path(tmp_path) / "completion.key")
    monkeypatch.setattr(truthfulness, "_ISSUER", None)
    monkeypatch.setattr(core.engine, "status", lambda: {"service": "CyberSentinel X", "version": "test", "online": True})
    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    runtime = MissionRuntime(
        store,
        executor=lambda *_: {"success": True, "source": "status", "result": {"online": False}},
        authorizer=lambda *_: (True, "test owner authorization"),
        authorization_snapshot_factory=make_test_snapshot,
    )
    mission = _mission(runtime, [{"criterion_id": "service-online", "check": "system_online"}])
    completed = runtime.run_to_completion(mission.mission_id, max_slices=4)

    assert completed.status is MissionStatus.GOAL_COMPLETED
    assert completed.completion_proof and completed.completion_proof["provenance_token"]
    assert completed.verification_state == {"verified": True, "missing_criteria": [], "evidence_count": 1}
    assert completed.evidence[0]["result"]["online"] is True
    assert completed.evidence[0]["system_evidence"]["payload"]["action_id"] == completed.action_history[0]["action_id"]
    reloaded = MissionStore(Path(tmp_path) / "missions.sqlite3").load(completed.mission_id)
    assert reloaded is not None and reloaded.status is MissionStatus.GOAL_COMPLETED
    assert reloaded.completion_proof_is_valid()


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


def test_generic_tool_observation_does_not_mint_completion_evidence(tmp_path):
    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, [{"criterion_id": "mission-goal", "check": "tool observation"}])
    mission.record_action("action-observation", "observe", "completed", {"source": "status", "success": True, "result": {"online": True}}, plan_fingerprint=mission.plan.fingerprint)

    assert store.issue_criterion_evidence(mission, "mission-goal", "action-observation") is None


@pytest.mark.parametrize(
    "tool,result",
    [
        ("status", {"error": "provider unavailable", "error_type": "provider_unavailable"}),
        ("run_project_tests", {"ok": False, "returncode": 1, "output": "failed"}),
        ("scoped_http_probe", {"ok": True, "note": "legacy placeholder"}),
        ("status", {}),
        ("status", []),
    ],
)
def test_tool_observation_evidence_rejects_errors_empty_and_unavailable_tools(tmp_path, tool, result):
    store = MissionStore(Path(tmp_path) / f"missions-{tool}-{len(str(result))}.sqlite3")
    runtime = MissionRuntime(store, executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("prove the goal").replan(steps=(PlanStep("observe", "observe", action=tool),), reason="test")
    mission = runtime.create(
        "prove the goal",
        "prove the goal",
        plan,
        completion_criteria=[{"criterion_id": "mission-goal", "check": "tool observation"}],
    )
    action_id = "action-observation"
    mission.record_action(action_id, "observe", "completed", {"source": tool, "success": True, "result": result}, plan_fingerprint=plan.fingerprint)

    assert store.issue_criterion_evidence(mission, "mission-goal", action_id) is None


def test_unverifiable_criterion_stops_for_owner_without_repeating_verification(tmp_path):
    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    runtime = MissionRuntime(
        store,
        executor=lambda *_: {"success": True, "source": "status", "result": {"service": "CyberSentinel X", "version": "test", "online": True}},
        authorizer=lambda *_: (True, "test owner authorization"),
        authorization_snapshot_factory=make_test_snapshot,
    )
    mission = _mission(runtime, [{"criterion_id": "unknown", "check": "no deterministic validator"}])
    result = runtime.run_to_completion(mission.mission_id, max_slices=60)

    assert result.status is MissionStatus.OWNER_INPUT_REQUIRED
    assert result.iteration_count == 2
    assert "unknown" in result.error
