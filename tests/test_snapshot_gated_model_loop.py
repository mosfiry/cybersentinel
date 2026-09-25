"""Regression tests: MissionAuthorizationSnapshot is the deterministic gate for
every model-originated tool call in MissionRuntime.run_model_loop, including the
parallel path. Model output can never create or widen authorization.

Hermetic: scripted model, monkeypatched tool registry, local snapshot factory.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from runtime_authorization import make_test_authorization_context, make_test_snapshot


class ScriptedProposer:
    """Proposes a fixed list of tool calls on the first turn, then stops."""

    def __init__(self, mission_id: str, proposals: list[tuple[str, str]]):
        self.mission_id = mission_id
        self.proposals = proposals
        self.turns = 0

    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        self.turns += 1
        if self.turns == 1:
            return ModelTurn(turn_id, tool_calls=tuple(
                ToolCallProposal.create(name, {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, request_id="r1", plan_version=plan_version, step_id="observe", action_id="a1", tool_call_id=call_id)
                for name, call_id in self.proposals
            ))
        return ModelTurn(turn_id, content="goal verified", finish_reason="stop")


def _runtime(tmp_path, factory) -> MissionRuntime:
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=factory)


def _mission(runtime: MissionRuntime, action: str = "status", **kwargs):
    plan = Plan.initial("investigate").replan(steps=(PlanStep("observe", "observe", action=action),), reason="test")
    return runtime.create("investigate", "investigate", plan, completion_criteria=[{"criterion_id": "goal"}], **kwargs)


def _restricted(mission, **overrides):
    snapshot = make_test_snapshot(mission)
    fields = {"allowed_tools": ("status",), "allowed_actions": ("status",), "forbidden_actions": (), "authorization_hash": ""}
    fields.update(overrides)
    return replace(snapshot, **fields)


def test_model_loop_executes_owner_authorized_tool(tmp_path, monkeypatch):
    """Happy-path regression: a snapshot-authorized tool still executes."""
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: {"ok": True, "criterion_id": "goal", "source": "fixture-result"})
    runtime = _runtime(tmp_path, make_test_snapshot)
    mission = _mission(runtime, request_id="req-test", authorization_context=make_test_authorization_context("req-test", tmp_path).to_dict())

    result = runtime.run_model_loop(mission.mission_id, ScriptedProposer(mission.mission_id, [("status", "call_001")]), tools=[{"name": "status"}], max_turns=3)

    assert result.status is MissionStatus.GOAL_COMPLETED
    assert result.progress["model_loop"]["tool_results"][0]["ok"] is True


def test_model_loop_blocks_tool_outside_snapshot_allowlist(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})
    runtime = _runtime(tmp_path, _restricted)
    mission = _mission(runtime)

    result = runtime.run_model_loop(mission.mission_id, ScriptedProposer(mission.mission_id, [("search", "call_001")]), tools=[], max_turns=1)

    assert calls == []
    tool_result = result.progress["model_loop"]["tool_results"][0]
    assert tool_result["ok"] is False
    assert "outside authorization snapshot allowlist" in tool_result["error"]


def test_model_loop_blocks_forbidden_tool_proposal(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})

    def forbidden(mission):
        return _restricted(mission, allowed_tools=("status", "search"), allowed_actions=("status", "search"), forbidden_actions=("search",))

    runtime = _runtime(tmp_path, forbidden)
    mission = _mission(runtime)

    result = runtime.run_model_loop(mission.mission_id, ScriptedProposer(mission.mission_id, [("search", "call_001")]), tools=[], max_turns=1)

    assert calls == []
    assert "forbidden by authorization snapshot" in result.progress["model_loop"]["tool_results"][0]["error"]


def test_model_loop_blocks_expired_snapshot_at_entry(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})
    now = datetime.now(timezone.utc)

    def expired(mission):
        return replace(make_test_snapshot(mission), created_at=(now - timedelta(hours=2)).isoformat(), expires_at=(now - timedelta(hours=1)).isoformat(), authorization_hash="")

    runtime = _runtime(tmp_path, expired)
    mission = _mission(runtime)

    result = runtime.run_model_loop(mission.mission_id, ScriptedProposer(mission.mission_id, [("status", "call_001")]), tools=[], max_turns=1)

    assert calls == []
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert "authorization snapshot expired or not active" in result.error


def test_model_loop_blocks_forged_snapshot(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})
    runtime = _runtime(tmp_path, make_test_snapshot)
    mission = _mission(runtime)

    forged = dict(mission.authorization_snapshot)
    forged["allowed_tools"] = list(forged["allowed_tools"]) + ["search"]
    mission.authorization_snapshot = forged
    runtime.store.save(mission)

    result = runtime.run_model_loop(mission.mission_id, ScriptedProposer(mission.mission_id, [("search", "call_001")]), tools=[], max_turns=1)

    assert calls == []
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert "authorization snapshot invalid" in result.error


def test_model_loop_blocks_plan_action_outside_snapshot(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})
    runtime = _runtime(tmp_path, _restricted)
    mission = _mission(runtime, action="search")

    result = runtime.run_model_loop(mission.mission_id, ScriptedProposer(mission.mission_id, [("search", "call_001")]), tools=[], max_turns=1)

    assert calls == []
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert "mission actions or tools outside authorization snapshot" in result.error


def test_model_loop_blocks_workspace_boundary_mismatch(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})
    runtime = _runtime(tmp_path, make_test_snapshot)
    mission = _mission(runtime)
    mission.scope_snapshot = {"target_id": "test-target", "workspace_root": "/workspace/elsewhere"}
    runtime.store.save(mission)

    result = runtime.run_model_loop(mission.mission_id, ScriptedProposer(mission.mission_id, [("status", "call_001")]), tools=[], max_turns=1)

    assert calls == []
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert "workspace boundary mismatch" in result.error


def test_model_loop_blocks_target_outside_snapshot(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})
    runtime = _runtime(tmp_path, make_test_snapshot)
    mission = _mission(runtime)
    mission.scope_snapshot = {"target_id": "other-target"}
    runtime.store.save(mission)

    result = runtime.run_model_loop(mission.mission_id, ScriptedProposer(mission.mission_id, [("status", "call_001")]), tools=[], max_turns=1)

    assert calls == []
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert "authorization snapshot target mismatch" in result.error


def test_model_loop_blocks_network_boundary_mismatch(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})
    runtime = _runtime(tmp_path, make_test_snapshot)
    mission = _mission(runtime)
    mission.scope_snapshot = {"target_id": "test-target", "allowed_networks": ("10.0.0.0/8",)}
    runtime.store.save(mission)

    result = runtime.run_model_loop(mission.mission_id, ScriptedProposer(mission.mission_id, [("status", "call_001")]), tools=[], max_turns=1)

    assert calls == []
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert "network boundary mismatch" in result.error


def test_parallel_calls_gated_per_proposal(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True, "criterion_id": "goal", "source": "fixture-result"})
    runtime = _runtime(tmp_path, _restricted)
    mission = _mission(runtime, request_id="req-test", authorization_context=make_test_authorization_context("req-test", tmp_path).to_dict())

    result = runtime.run_model_loop(mission.mission_id, ScriptedProposer(mission.mission_id, [("status", "call_001"), ("search", "call_002")]), tools=[], max_turns=3)

    assert [args[0] for args in calls] == ["status"]
    blocked = [item for item in result.progress["model_loop"]["tool_results"] if item["tool_call_id"] == "call_002"]
    assert blocked and blocked[0]["ok"] is False
    assert "outside authorization snapshot allowlist" in blocked[0]["error"]


def test_parallel_calls_all_blocked_execute_nothing(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})
    runtime = _runtime(tmp_path, _restricted)
    mission = _mission(runtime)

    result = runtime.run_model_loop(mission.mission_id, ScriptedProposer(mission.mission_id, [("search", "call_001"), ("search", "call_002")]), tools=[], max_turns=1)

    assert calls == []
    errors = [item["error"] for item in result.progress["model_loop"]["tool_results"]]
    assert len(errors) == 2
    assert all("outside authorization snapshot allowlist" in error for error in errors)
