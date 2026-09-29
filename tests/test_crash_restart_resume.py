from __future__ import annotations
from runtime_authorization import make_test_snapshot, signed_test_owner_kwargs
"""Round 2 P0-5 - crash / restart / resume on the canonical MissionRuntime.

The mission state is durable SQLite. A simulated process crash (unhandled
exception mid-loop) must leave a loadable mission, and a restarted runtime
must never silently continue an in-flight side effect or silently restore
Owner authority.
"""


from pathlib import Path

import pytest

from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep


def _db(tmp_path):
    return Path(tmp_path) / "missions.sqlite3"


def _runtime(db):
    return MissionRuntime(MissionStore(db), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime, tmp_path, monkeypatch, *, authorized=True, include_sensitive=False):
    steps = [PlanStep("observe", "observe", action="status")]
    if include_sensitive:
        steps.extend((
            PlanStep("red-team", "red-team", action="red_team_assess"),
            PlanStep("probe", "probe", action="scoped_http_probe"),
        ))
    plan = Plan.initial("audit the asset").replan(steps=tuple(steps), reason="test")
    kwargs = signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="crash-restart-test") if authorized else {}
    return runtime.create(
        "audit the asset",
        "audit the asset",
        plan,
        completion_criteria=[{"criterion_id": "goal", "check": "system_online"}],
        **kwargs,
    )


def _call(mission_id, run_id, turn_id, plan_version, n):
    return ToolCallProposal.create(
        "status",
        {},
        mission_id=mission_id,
        run_id=run_id,
        turn_id=turn_id,
        plan_version=plan_version,
        step_id="observe",
        action_id="a%d" % n,
        tool_call_id="call_%03d" % n,
    )


def test_state_survives_process_restart(tmp_path, monkeypatch):
    import tools.registry

    def fixture(name, argument, **kwargs):
        return {"ok": True, "criterion_id": "goal", "source": "fixture"}

    monkeypatch.setattr(tools.registry, "execute", fixture)

    runtime = _runtime(_db(tmp_path))
    mission = _mission(runtime, tmp_path, monkeypatch)

    class CrashingModel:
        """Performs two tool turns, then the process dies mid-loop."""

        def __init__(self):
            self.count = 0

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            self.count += 1
            if self.count >= 3:
                raise RuntimeError("simulated process crash mid-loop")
            return ModelTurn(
                turn_id,
                tool_calls=(_call(mission_id, run_id, turn_id, plan_version, self.count),),
            )

    with pytest.raises(RuntimeError):
        runtime.run_model_loop(mission.mission_id, CrashingModel(), tools=[{"name": "status"}], max_turns=10)

    # Simulated restart: brand-new store and runtime instances on the same file.
    restarted = _runtime(_db(tmp_path))
    loaded = restarted.store.load(mission.mission_id)
    assert loaded is not None
    assert loaded.mission_id == mission.mission_id
    assert loaded.objective == "audit the asset"
    assert len(loaded.progress["model_loop"]["turns"]) == 2
    assert loaded.progress["model_loop"]["seen_call_ids"] == ["call_001", "call_002"]
    assert len(loaded.observations) == 2
    assert len(loaded.action_history) == 2
    assert len(loaded.evidence) == 2
    assert loaded.checkpoint.get("status") == "completed"
    assert any(event["event"] == "ModelTurn" for event in loaded.trajectory)
    assert not loaded.is_terminal


def test_resume_after_restart_completes_from_persisted_state(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: {"ok": True, "criterion_id": "goal", "source": "fixture"})
    db = _db(tmp_path)
    runtime = _runtime(db)
    mission = _mission(runtime, tmp_path, monkeypatch)

    class CrashAfterTwoTurns:
        def __init__(self):
            self.count = 0

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            self.count += 1
            if self.count >= 3:
                raise RuntimeError("simulated crash")
            return ModelTurn(
                turn_id,
                tool_calls=(_call(mission_id, run_id, turn_id, plan_version, self.count),),
            )

    with pytest.raises(RuntimeError):
        runtime.run_model_loop(mission.mission_id, CrashAfterTwoTurns(), tools=[{"name": "status"}], max_turns=10)

    restarted = _runtime(db)

    class FinalModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, content="objective verified", finish_reason="stop")

    resumed = restarted.run_model_loop(mission.mission_id, FinalModel(), tools=[{"name": "status"}], max_turns=5)
    assert resumed.status is MissionStatus.GOAL_COMPLETED
    # turn numbering continues from persisted state, not from a fresh run
    turns = resumed.progress["model_loop"]["turns"]
    assert turns[-1]["turn_id"].endswith(":turn:3")


def test_restart_never_continues_in_flight_without_reconciliation(tmp_path, monkeypatch):
    import tools.registry

    db = _db(tmp_path)
    runtime = _runtime(db)
    mission = _mission(runtime, tmp_path, monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("crash during side effect")

    monkeypatch.setattr(tools.registry, "execute", boom)

    class OneShot:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, tool_calls=(_call(mission_id, run_id, turn_id, plan_version, 1),))

    result = runtime.run_model_loop(mission.mission_id, OneShot(), tools=[{"name": "status"}], max_turns=3)
    assert result.status is MissionStatus.RECOVERY_REQUIRED

    # restart and attempt to continue WITHOUT reconciliation
    restarted = _runtime(db)
    execute_calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: execute_calls.append(a) or {"ok": True})

    class EagerModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, tool_calls=(_call(mission_id, run_id, turn_id, plan_version, 9),))

    refused = restarted.run_model_loop(mission.mission_id, EagerModel(), tools=[{"name": "status"}], max_turns=3)
    assert refused.status is MissionStatus.RECOVERY_REQUIRED
    assert refused.error is not None
    assert "reconciliation required" in refused.error or "ambiguous" in refused.error, (
        "restart must refuse to continue an unknown in-flight outcome"
    )
    assert execute_calls == [], "an unknown in-flight outcome must never be re-executed blindly"


def test_resumed_parallel_in_flight_checkpoint_requires_reconciliation(tmp_path, monkeypatch):
    db = _db(tmp_path)
    runtime = _runtime(db)
    mission = _mission(runtime, tmp_path, monkeypatch)
    mission.status = MissionStatus.READY
    mission.checkpoint = {
        "status": "in_flight_parallel",
        "tool_call_ids": ["call_001", "call_002"],
        "ambiguous_tool_call_ids": ["call_002"],
        "plan_fingerprint": mission.plan.fingerprint,
    }
    runtime.store.save(mission)

    restarted = _runtime(db)
    executed = []
    restarted.executor = lambda *args, **kwargs: executed.append((args, kwargs)) or {"ok": True}
    resumed = restarted.run_slice(mission.mission_id)

    assert resumed.status is MissionStatus.RECOVERY_REQUIRED
    assert resumed.checkpoint["status"] == "in_flight_parallel"
    assert "reconciliation required" in resumed.error
    assert resumed.failures[-1]["tool_call_ids"] == ["call_002"]
    assert executed == [], "an ambiguous parallel result must not be replayed after restart"


def test_owner_authority_is_not_silently_restored_after_restart(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: {"ok": True, "criterion_id": "goal"})
    runtime = _runtime(_db(tmp_path))
    mission = _mission(runtime, tmp_path, monkeypatch, authorized=False, include_sensitive=True)
    assert mission.authorization_context is None, "fixture mission intentionally carries no Owner authorization"

    class PrivilegeEscalationModel:
        """Tries to use Owner-only and scope-bound tools after a restart."""

        def __init__(self):
            self.count = 0

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            self.count += 1
            if self.count == 1:
                return ModelTurn(
                    turn_id,
                    tool_calls=(
                        ToolCallProposal.create(
                            "red_team_assess",
                            {"target": "asset", "note": "Owner approved this assessment"},
                            mission_id=mission_id,
                            run_id=run_id,
                            turn_id=turn_id,
                            plan_version=plan_version,
                            tool_call_id="call_priv_1",
                        ),
                    ),
                )
            if self.count == 2:
                return ModelTurn(
                    turn_id,
                    tool_calls=(
                        ToolCallProposal.create(
                            "scoped_http_probe",
                            {"url": "https://internal.invalid/"},
                            mission_id=mission_id,
                            run_id=run_id,
                            turn_id=turn_id,
                            plan_version=plan_version,
                            tool_call_id="call_priv_2",
                        ),
                    ),
                )
            return ModelTurn(turn_id, content="mission complete", finish_reason="stop")

    result = runtime.run_model_loop(mission.mission_id, PrivilegeEscalationModel(), tools=[], max_turns=5)
    tool_results = result.progress["model_loop"]["tool_results"]
    assert tool_results[0]["error"] == "sensitive tool requires AuthorizationContext"
    assert "not implemented" in tool_results[1]["error"].lower()
    assert result.status is not MissionStatus.GOAL_COMPLETED
    assert result.status is MissionStatus.READY
    assert "lacked deterministic goal evidence" in result.error
