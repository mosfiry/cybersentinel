from __future__ import annotations
from runtime_authorization import make_test_snapshot

from pathlib import Path

from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep


class ScriptedModel:
    def __init__(self, mission_id: str):
        self.mission_id = mission_id
        self.turns = []

    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        self.turns.append(list(messages))
        if len(self.turns) == 1:
            return ModelTurn(
                turn_id,
                tool_calls=(ToolCallProposal.create("status", {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, request_id="r1", plan_version=plan_version, step_id="observe", action_id="a1", tool_call_id="call_001"),),
            )
        assert any(message.role == "tool" and "fixture-result" in message.content for message in self.turns[-1])
        return ModelTurn(turn_id, content="goal verified", finish_reason="stop")


def test_native_loop_executes_tool_then_models_again(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: {"ok": True, "criterion_id": "goal", "source": "fixture-result"})
    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("investigate").replan(steps=(PlanStep("observe", "observe", action="status"),), reason="test")
    mission = runtime.create("investigate", "investigate", plan, completion_criteria=[{"criterion_id": "goal"}])
    model = ScriptedModel(mission.mission_id)

    result = runtime.run_model_loop(mission.mission_id, model, tools=[{"name": "status"}], max_turns=3)

    assert result.status is MissionStatus.GOAL_COMPLETED
    assert len(model.turns) == 2
    assert len(result.progress["model_loop"]["turns"]) == 2
    assert result.progress["model_loop"]["seen_call_ids"] == ["call_001"]
    assert any(event["event"] == "ModelTurn" for event in result.trajectory)


def test_native_loop_rejects_cross_mission_call_without_execution(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})

    class MaliciousModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, tool_calls=(ToolCallProposal.create("status", {}, mission_id="other-mission", run_id=run_id, turn_id=turn_id, plan_version=plan_version, tool_call_id="call-old"),))

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    mission = runtime.create("check", "check", Plan.initial("check").replan(steps=(PlanStep("s", "s", action="status"),), reason="test"))
    result = runtime.run_model_loop(mission.mission_id, MaliciousModel(), tools=[], max_turns=1)

    assert calls == []
    assert result.progress["model_loop"]["tool_results"][0]["error"] == "tool call belongs to another mission"
    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED
