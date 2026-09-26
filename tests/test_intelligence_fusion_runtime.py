from __future__ import annotations
from runtime_authorization import make_test_snapshot, make_test_owner_kwargs

from pathlib import Path

from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.planning import Plan, PlanStep


class ParallelModel:
    def __init__(self):
        self.turn_count = 0

    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        self.turn_count += 1
        if self.turn_count == 1:
            calls = tuple(ToolCallProposal.create(name, {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, action_id=f"a-{name}", tool_call_id=f"call-{name}", plan_version=plan_version) for name in ("status", "latest_intel"))
            return ModelTurn(turn_id, tool_calls=calls)
        assert sum(message.role == "tool" for message in messages) == 2
        return ModelTurn(turn_id, content="verified")


def test_native_runtime_parallel_calls_have_independent_results(tmp_path, monkeypatch):
    import tools.registry

    def execute(name, *args, **kwargs):
        return {"ok": True, "criterion_id": "goal", "source": name}

    monkeypatch.setattr(tools.registry, "execute", execute)
    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("collect").replan(steps=(PlanStep("s", "collect", action="status"),), reason="test")
    mission = runtime.create("collect", "collect", plan, completion_criteria=[{"criterion_id": "goal"}], **make_test_owner_kwargs("collect", "fusion-test"))
    result = runtime.run_model_loop(mission.mission_id, ParallelModel(), tools=[{"name": "status"}, {"name": "latest_intel"}], max_turns=3)

    assert result.status is MissionStatus.GOAL_COMPLETED
    assert len(result.progress["model_loop"]["tool_results"]) == 2
    assert result.checkpoint["status"] == "completed"
