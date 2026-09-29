from __future__ import annotations
from runtime_authorization import make_test_snapshot, signed_test_owner_kwargs

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
        assert any(message.role == "tool" and "tool_observation" in message.content for message in self.turns[-1])
        return ModelTurn(turn_id, content="goal verified", finish_reason="stop")


def test_native_loop_executes_tool_then_models_again(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: {"ok": True, "criterion_id": "goal", "source": "fixture-result"})
    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("investigate").replan(steps=(PlanStep("observe", "observe", action="status"),), reason="test")
    mission = runtime.create("investigate", "investigate", plan, completion_criteria=[{"criterion_id": "goal", "check": "system_online"}], **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="native-protocol-test"))
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


def test_native_loop_rejects_dependent_step_before_prerequisite(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args[0]) or {"success": True})

    class DependentFirstModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            proposal = ToolCallProposal.create(
                "status",
                {},
                mission_id=mission_id,
                run_id=run_id,
                turn_id=turn_id,
                plan_version=plan_version,
                step_id="dependent",
                action_id="dependent-action",
                tool_call_id="dependent-call",
            )
            return ModelTurn(turn_id, tool_calls=(proposal,))

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("dependency order").replan(
        steps=(
            PlanStep("dependent", "dependent", action="status", prerequisites=("prerequisite",)),
            PlanStep("prerequisite", "prerequisite", action="status"),
        ),
        reason="reverse topological order regression",
    )
    mission = runtime.create(
        "dependency order",
        "dependency order",
        plan,
        **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="native-dag-test"),
    )

    result = runtime.run_model_loop(mission.mission_id, DependentFirstModel(), tools=[{"name": "status"}], max_turns=1)

    assert calls == []
    assert "prerequisite" in result.progress["model_loop"]["tool_results"][0]["error"]


def test_parallel_native_loop_rejects_dependent_call_in_same_batch(tmp_path, monkeypatch):
    import tools.registry

    executions = []
    monkeypatch.setattr(tools.registry, "execute", lambda name, *args, **kwargs: executions.append(name) or {"success": True})

    class ParallelDependentModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            proposals = (
                ToolCallProposal.create("status", {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, plan_version=plan_version, step_id="prerequisite", action_id="prerequisite-action", tool_call_id="prerequisite-call"),
                ToolCallProposal.create("status", {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, plan_version=plan_version, step_id="dependent", action_id="dependent-action", tool_call_id="dependent-call"),
            )
            return ModelTurn(turn_id, tool_calls=proposals)

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("parallel dependency").replan(
        steps=(
            PlanStep("dependent", "dependent", action="status", prerequisites=("prerequisite",)),
            PlanStep("prerequisite", "prerequisite", action="status"),
        ),
        reason="parallel prerequisite gate regression",
    )
    mission = runtime.create("parallel dependency", "parallel dependency", plan, **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="parallel-dag-test"))

    result = runtime.run_model_loop(mission.mission_id, ParallelDependentModel(), tools=[{"name": "status"}], max_turns=1)

    assert executions == ["status"]
    tool_results = result.progress["model_loop"]["tool_results"]
    assert tool_results[0]["tool_call_id"] == "prerequisite-call"
    assert tool_results[1]["tool_call_id"] == "dependent-call"
    assert "prerequisite" in tool_results[1]["error"]


def test_completed_write_step_cannot_be_reopened_as_auxiliary(tmp_path):
    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("write once").replan(steps=(PlanStep("watch-step", "add watch", action="watch"),), reason="write replay regression")
    mission = runtime.create("write once", "write once", plan)
    mission.record_action("watch-action", "watch-step", "completed", {"ok": True}, plan_fingerprint=plan.fingerprint)
    proposal = ToolCallProposal.create(
        "watch",
        {"query": "critical"},
        mission_id=mission.mission_id,
        run_id="run-1",
        turn_id="turn-1",
        plan_version=plan.version,
        step_id="watch-step",
        tool_call_id="watch-replay",
    )

    _bound, planned_step, error = runtime._bind_proposal_to_ready_step(mission, proposal)

    assert planned_step is None
    assert error == "plan step is already completed"


def test_false_native_tool_result_is_not_recorded_as_completed(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: {"success": False, "error": "service is unavailable"})

    class FailingStatusModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            proposal = ToolCallProposal.create(
                "status", {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id,
                plan_version=plan_version, step_id="observe", action_id="observe-action", tool_call_id="observe-call",
            )
            return ModelTurn(turn_id, tool_calls=(proposal,))

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("verify status").replan(steps=(PlanStep("observe", "observe", action="status"),), reason="false result regression")
    mission = runtime.create("verify status", "verify status", plan, **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="false-result-test"))

    result = runtime.run_model_loop(mission.mission_id, FailingStatusModel(), tools=[{"name": "status"}], max_turns=1)

    assert result.action_history[0]["status"] == "failed"
    assert result.progress["model_loop"]["tool_results"][0]["ok"] is False
    assert result.status.name != "GOAL_COMPLETED"
