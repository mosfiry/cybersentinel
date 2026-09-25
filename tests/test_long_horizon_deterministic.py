from __future__ import annotations
from runtime_authorization import make_test_authorization_context, make_test_snapshot
"""Round 2 P0-3 - long-horizon trajectory (MOCK-VERIFIED, 23 model turns).

HONESTY LABEL: MOCK-VERIFIED. This harness drives the REAL MissionRuntime
model/tool/observation loop for 23 real model turns (22 tool turns + final),
with a deterministic scripted NativeModel instead of a live provider, because
no provider credentials exist in this environment. The live-provider variant
lives in tests/test_real_provider_long_horizon.py and stays UNVERIFIED until
credentials are provided.

The trajectory must show, in order: model turns, tool proposals, authorization
checks, tool executions, observations (including one real deterministic tool
failure), interpretation, hypothesis updates, replan decisions, evidence, and
final deterministic goal verification.
"""


from pathlib import Path

from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep

TOOL_TURNS = 22


class LongHorizonModel:
    """Deterministic native model: one tool call per turn, then a final."""

    def __init__(self):
        self.turn_count = 0

    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        self.turn_count += 1
        if self.turn_count <= TOOL_TURNS:
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
                        step_id="observe",
                        action_id="a%d" % self.turn_count,
                        tool_call_id="call_%03d" % self.turn_count,
                    ),
                ),
            )
        return ModelTurn(turn_id, content="mission objective verified with evidence", finish_reason="stop")


def _executor_script(execution_index):
    if execution_index == 4:
        return {"ok": False, "error": "deterministic tool failure", "error_type": "provider_unavailable"}
    if execution_index == 5:
        return {
            "ok": True,
            "hypothesis_updates": [{"hypothesis_id": "h1", "statement": "asset A is compromised by the reported CVE"}],
            "evidence": [{"evidence_id": "e1", "summary": "suspicious outbound log entry"}],
        }
    if execution_index == 12:
        return {
            "ok": True,
            "counter_evidence": [{"evidence_id": "c1", "summary": "asset A runs the patched version"}],
            "confidence_changes": [
                {"hypothesis_id": "h1", "delta": -0.9, "reason": "patched version contradicts compromise", "counter_evidence_ids": ["c1"]}
            ],
        }
    return {"ok": True, "criterion_id": "goal", "source": "long-horizon-fixture"}


def test_long_horizon_trajectory_records_full_reasoning_lifecycle(tmp_path, monkeypatch):
    import tools.registry

    executions = []

    def fixture(name, argument, **kwargs):
        executions.append(name)
        return _executor_script(len(executions))

    monkeypatch.setattr(tools.registry, "execute", fixture)

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("audit asset A across a long horizon").replan(
        steps=(PlanStep("observe", "observe", action="status"),), reason="test"
    )
    mission = runtime.create(
        "audit asset A across a long horizon",
        "audit asset A across a long horizon",
        plan,
        completion_criteria=[{"criterion_id": "goal"}],
        request_id="req-long",
        authorization_context=make_test_authorization_context("req-long", tmp_path).to_dict(),
    )
    model = LongHorizonModel()

    result = runtime.run_model_loop(mission.mission_id, model, tools=[{"name": "status"}], max_turns=TOOL_TURNS + 5)

    # the loop really ran 20+ model turns
    assert model.turn_count == TOOL_TURNS + 1
    assert len(result.progress["model_loop"]["turns"]) == TOOL_TURNS + 1

    events = [event["event"] for event in result.trajectory]
    assert events.count("ModelTurn") == TOOL_TURNS + 1
    assert events.count("ToolProposed") == TOOL_TURNS
    assert events.count("AuthorizationChecked") == TOOL_TURNS
    assert events.count("ObservationReceived") == TOOL_TURNS
    assert events.count("ObservationInterpreted") == TOOL_TURNS
    assert events.count("StrategyDecided") == TOOL_TURNS
    assert "HypothesisUpdated" in events
    assert "GoalVerified" in events
    assert "MissionCompleted" in events

    # a real deterministic tool failure was observed and never became evidence
    assert any(observation.get("ok") is False for observation in result.observations)
    assert any(decision["decision"] == "REPLAN" for decision in result.strategy_decisions)

    # the contradicted hypothesis was rejected by the deterministic engine
    disproven = [item for item in result.hypotheses if item["hypothesis_id"] == "h1"]
    assert disproven and disproven[0]["status"] == "DISPROVEN"

    # every tool call executed exactly once - no infinite retry, no replay
    assert len(executions) == TOOL_TURNS
    assert len(result.progress["model_loop"]["seen_call_ids"]) == TOOL_TURNS
    assert len(set(result.progress["model_loop"]["seen_call_ids"])) == TOOL_TURNS

    # completion came from deterministic verification, not the model claim
    assert result.status is MissionStatus.GOAL_COMPLETED
    assert result.verification_state.get("verified") is True
    assert any(item.get("criterion_id") == "goal" and item.get("passed") for item in result.evidence)
