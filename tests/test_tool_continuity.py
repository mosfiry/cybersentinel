"""Round 2 P1 - tool result continuity on the canonical model loop.

Every tool result is bound to mission_id / run_id / turn_id / tool_call_id.
Duplicates, replays, stale runs, and cross-mission calls are rejected without
execution; parallel results fold deterministically.
"""

from __future__ import annotations

from pathlib import Path

from agent.model_intelligence.tool_calls import validate_proposals
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {})


def _mission(runtime):
    plan = Plan.initial("maintain continuity").replan(
        steps=(PlanStep("observe", "observe", action="status"),), reason="test"
    )
    return runtime.create("maintain continuity", "maintain continuity", plan)


def _call(mission_id, run_id, turn_id, plan_version, n, tool_call_id=None):
    return ToolCallProposal.create(
        "status",
        {},
        mission_id=mission_id,
        run_id=run_id,
        turn_id=turn_id,
        plan_version=plan_version,
        step_id="observe",
        action_id="a%d" % n,
        tool_call_id=tool_call_id or ("call_%03d" % n),
    )


def _proposal(mission_id="m1", run_id="r1", tool_call_id="call_1"):
    return ToolCallProposal.create("status", {}, mission_id=mission_id, run_id=run_id, tool_call_id=tool_call_id)


def test_validate_proposals_rejects_cross_mission():
    errors = validate_proposals([_proposal(mission_id="other")], mission_id="m1", run_id="r1")
    assert errors == ["call_1:cross_mission"]


def test_validate_proposals_rejects_stale_run():
    errors = validate_proposals([_proposal(run_id="old-run")], mission_id="m1", run_id="r1")
    assert errors == ["call_1:stale_run"]


def test_validate_proposals_rejects_duplicate_and_missing_identity():
    errors = validate_proposals([_proposal(), _proposal()], mission_id="m1", run_id="r1")
    assert errors == ["call_1:duplicate"]
    missing = ToolCallProposal.create("status", {}, mission_id="m1", run_id="r1", tool_call_id="")
    assert "missing_tool_call_id" in validate_proposals([missing], mission_id="m1", run_id="r1")


def test_duplicate_tool_call_id_is_rejected_prior_result_is_authoritative(tmp_path, monkeypatch):
    import tools.registry

    executions = []

    def fixture(name, argument, **kwargs):
        executions.append(name)
        return {"ok": True, "criterion_id": "goal", "source": "first-execution"}

    monkeypatch.setattr(tools.registry, "execute", fixture)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)

    class ReplayModel:
        """Turn 1 executes call_001; turn 2 replays the same id."""

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            if not executions:
                return ModelTurn(turn_id, tool_calls=(_call(mission_id, run_id, turn_id, plan_version, 1, "call_001"),))
            return ModelTurn(turn_id, tool_calls=(_call(mission_id, run_id, turn_id, plan_version, 2, "call_001"),))

    result = runtime.run_model_loop(mission.mission_id, ReplayModel(), tools=[{"name": "status"}], max_turns=4)
    assert len(executions) == 1, "a replayed tool_call_id must never execute twice"
    tool_results = result.progress["model_loop"]["tool_results"]
    assert tool_results[1]["ok"] is False
    assert tool_results[1]["error"] == "duplicate tool call rejected; prior result is authoritative"
    assert result.progress["model_loop"]["seen_call_ids"] == ["call_001"]


def test_wrong_run_id_is_rejected_without_execution(tmp_path, monkeypatch):
    import tools.registry

    executions = []
    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: executions.append(a) or {"ok": True})
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)

    class StaleRunModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(
                turn_id,
                tool_calls=(
                    ToolCallProposal.create(
                        "status",
                        {},
                        mission_id=mission_id,
                        run_id="run-from-an-older-restart",
                        turn_id=turn_id,
                        plan_version=plan_version,
                        tool_call_id="call_001",
                    ),
                ),
            )

    result = runtime.run_model_loop(mission.mission_id, StaleRunModel(), tools=[], max_turns=1)
    assert executions == []
    assert result.progress["model_loop"]["tool_results"][0]["error"] == "tool call belongs to another run"


def test_parallel_results_fold_deterministically(tmp_path, monkeypatch):
    import tools.registry

    def fixture(name, argument, **kwargs):
        return {"ok": True, "source": "parallel-fixture"}

    monkeypatch.setattr(tools.registry, "execute", fixture)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)

    class ParallelModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            done = mission.progress.get("model_loop", {}).get("tool_results")
            if done:
                return ModelTurn(turn_id, content="parallel observations complete", finish_reason="stop")
            return ModelTurn(
                turn_id,
                tool_calls=(
                    _call(mission_id, run_id, turn_id, plan_version, 1, "call_001"),
                    _call(mission_id, run_id, turn_id, plan_version, 2, "call_002"),
                ),
            )

    result = runtime.run_model_loop(mission.mission_id, ParallelModel(), tools=[{"name": "status"}], max_turns=4)
    tool_results = result.progress["model_loop"]["tool_results"]
    assert [item["tool_call_id"] for item in tool_results] == ["call_001", "call_002"], "parallel results must fold in proposal order"
    assert all(item["ok"] for item in tool_results)
    assert len(result.observations) == 2
    assert result.checkpoint.get("status") == "completed"
    assert result.progress["model_loop"]["seen_call_ids"] == ["call_001", "call_002"]
