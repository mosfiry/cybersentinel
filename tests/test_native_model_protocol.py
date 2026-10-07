from __future__ import annotations
from runtime_authorization import make_test_snapshot, mission_model_tools, valid_status_snapshot

from pathlib import Path

from agent.model_protocol import ModelTurn, ToolCallProposal, derive_action_id
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
                tool_calls=(ToolCallProposal.create("status", {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, plan_version=plan_version, step_id="observe", tool_call_id="call_001"),),
            )
        assert any(message.role == "tool" and "fixture-result" in message.content for message in self.turns[-1])
        return ModelTurn(turn_id, content="goal verified", finish_reason="stop")


def test_native_loop_executes_tool_then_models_again(tmp_path, monkeypatch):
    import tools.registry

    executions = []

    def fixture(name, arguments, **kwargs):
        executions.append((name, arguments))
        return {**valid_status_snapshot(), "source": "fixture-result"}

    monkeypatch.setattr(tools.registry, "execute", fixture)
    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("check system status").replan(steps=(PlanStep("observe", "observe", action="status"),), reason="test")
    mission = runtime.create("check system status", "check system status", plan, completion_criteria=[{"criterion_id": "status", "check": "status_snapshot"}])
    model = ScriptedModel(mission.mission_id)

    result = runtime.run_model_loop(mission.mission_id, model, tools=mission_model_tools("status"), max_turns=3)

    assert result.status is MissionStatus.GOAL_COMPLETED
    assert len(model.turns) == 2
    assert len(result.progress["model_loop"]["turns"]) == 2
    assert result.progress["model_loop"]["seen_call_ids"] == ["call_001"]
    assert executions == [("status", {})]
    accepted_call = result.progress["model_loop"]["turns"][0]["tool_calls"][0]
    assert accepted_call["mission_id"] == mission.mission_id
    assert accepted_call["run_id"] == result.progress["model_run_id"]
    assert accepted_call["request_id"] == mission.request_id
    assert accepted_call["plan_version"] == mission.plan.version
    assert accepted_call["step_id"] == "observe"
    accepted_turn_id = result.progress["model_loop"]["turns"][0]["turn_id"]
    assert accepted_call["action_id"] == derive_action_id(mission.mission_id, accepted_turn_id, "call_001")
    assert any(event["event"] == "ModelTurn" for event in result.trajectory)


def test_native_loop_preserves_list_valued_tool_results(tmp_path, monkeypatch):
    import tools.registry

    items = [{"source": "fixture-list-result", "trust_classification": "UNTRUSTED_DATA"}]
    monkeypatch.setattr(tools.registry, "execute", lambda *_args, **_kwargs: items)

    class ListResultModel:
        def __init__(self):
            self.turn_count = 0

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            self.turn_count += 1
            if self.turn_count == 1:
                return ModelTurn(
                    turn_id,
                    tool_calls=(ToolCallProposal.create(
                        "status", {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id,
                        plan_version=plan_version, step_id="observe", tool_call_id="call_list_result",
                    ),),
                )
            assert any(
                message.role == "tool" and "fixture-list-result" in message.content
                for message in messages
            )
            return ModelTurn(turn_id, content="list result observed")

    class Verified:
        verified = True
        missing_criteria = ()
        evidence = ()

    runtime = MissionRuntime(
        MissionStore(Path(tmp_path) / "missions.sqlite3"),
        executor=lambda *_: {},
        verifier=lambda _mission: Verified(),
        authorization_snapshot_factory=make_test_snapshot,
    )
    plan = Plan.initial("check system status").replan(
        steps=(PlanStep("observe", "observe", action="status"),),
        reason="list result regression",
    )
    mission = runtime.create("check system status", "check system status", plan)
    model = ListResultModel()

    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=mission_model_tools("status"),
        max_turns=2,
    )

    assert result.status is MissionStatus.GOAL_COMPLETED
    assert model.turn_count == 2
    assert result.progress["model_loop"]["tool_results"][0]["result"]["items"] == items
    assert result.failures == []


def test_native_loop_rejects_cross_mission_call_without_execution(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})

    class MaliciousModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, tool_calls=(ToolCallProposal.create("status", {}, mission_id="other-mission", run_id=run_id, turn_id=turn_id, plan_version=plan_version, tool_call_id="call-old"),))

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    mission = runtime.create("check", "check", Plan.initial("check").replan(steps=(PlanStep("s", "s", action="status"),), reason="test"))
    result = runtime.run_model_loop(mission.mission_id, MaliciousModel(), tools=mission_model_tools("status"), max_turns=1)

    assert calls == []
    assert result.progress["model_loop"]["turns"] == []
    assert result.progress["model_loop"]["tool_results"] == []
    assert result.progress["model_failures"][-1]["kind"] == "INVALID_MODEL_RESPONSE"
    assert not any(event["event"] in {"ModelTurn", "ToolProposed", "AuthorizationChecked"} for event in result.trajectory)
    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED
