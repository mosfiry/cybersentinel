from __future__ import annotations
from runtime_authorization import make_test_snapshot
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


def _mission(runtime):
    plan = Plan.initial("audit the asset").replan(
        steps=(PlanStep("observe", "observe", action="status"),), reason="test"
    )
    return runtime.create(
        "audit the asset",
        "audit the asset",
        plan,
        completion_criteria=[{"criterion_id": "goal"}],
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
    mission = _mission(runtime)

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
    mission = _mission(runtime)

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
    mission = _mission(runtime)

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


def test_crash_after_successful_tool_before_final_save_requires_reconciliation(tmp_path, monkeypatch):
    import tools.registry

    db = _db(tmp_path)
    executed = []
    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: executed.append(a) or {"ok": True, "criterion_id": "goal"})

    class CrashAfterToolSave(MissionStore):
        def __init__(self, db_path):
            super().__init__(db_path)
            self.crash_after_in_flight = False

        def save(self, mission):
            if self.crash_after_in_flight and (mission.checkpoint or {}).get("status") == "completed":
                raise RuntimeError("simulated crash after tool receipt")
            return super().save(mission)

    store = CrashAfterToolSave(db)
    runtime = MissionRuntime(store, executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    mission = _mission(runtime)
    store.crash_after_in_flight = True

    class OneShot:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, tool_calls=(_call(mission_id, run_id, turn_id, plan_version, 1),))

    with pytest.raises(RuntimeError, match="after tool receipt"):
        runtime.run_model_loop(mission.mission_id, OneShot(), tools=[{"name": "status"}], max_turns=1)
    assert executed == [("status", None)]

    restarted = _runtime(db)
    resumed_executions = []
    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: resumed_executions.append(a) or {"ok": True})
    refused = restarted.run_model_loop(mission.mission_id, OneShot(), tools=[{"name": "status"}], max_turns=1)
    assert refused.status is MissionStatus.RECOVERY_REQUIRED
    assert resumed_executions == []


def test_parallel_crash_after_subset_fold_reconciles_only_unresolved_tools(tmp_path, monkeypatch):
    import tools.registry

    db = _db(tmp_path)
    executed = []
    monkeypatch.setattr(tools.registry, "execute", lambda name, argument, **kwargs: executed.append(name) or {"ok": True, "criterion_id": "goal", "source": name})

    class CrashAfterFirstFold(MissionStore):
        def __init__(self, db_path):
            super().__init__(db_path)
            self.crash_after_first_fold = False

        def save(self, mission):
            saved = super().save(mission)
            if self.crash_after_first_fold and (mission.checkpoint or {}).get("completed_tool_call_ids") == ["call_001"]:
                raise RuntimeError("simulated crash after first parallel fold")
            return saved

    store = CrashAfterFirstFold(db)
    runtime = MissionRuntime(store, executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    mission = _mission(runtime)
    store.crash_after_first_fold = True

    class ParallelModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, tool_calls=(
                _call(mission_id, run_id, turn_id, plan_version, 1),
                _call(mission_id, run_id, turn_id, plan_version, 2),
            ))

    with pytest.raises(RuntimeError, match="first parallel fold"):
        runtime.run_model_loop(mission.mission_id, ParallelModel(), tools=[{"name": "status"}], max_turns=1)
    assert executed == ["status", "status"]

    restarted = _runtime(db)
    loaded = restarted.store.load(mission.mission_id)
    assert loaded.checkpoint["completed_tool_call_ids"] == ["call_001"]
    assert loaded.checkpoint["tool_call_ids"] == ["call_001", "call_002"]
    assert [item["tool_call_id"] for item in loaded.progress["model_loop"]["tool_results"]] == ["call_001"]
    reconciled = restarted.reconcile_in_flight(
        mission.mission_id,
        executed=True,
        observation={"success": True, "criterion_id": "goal", "source": "parallel-receipt"},
    )
    assert [item["action_id"] for item in reconciled.action_history] == ["a1", "call_002"]
    assert reconciled.checkpoint["status"] == "completed"


def test_concurrent_runtimes_reject_stale_writer_before_duplicate_dispatch(tmp_path, monkeypatch):
    import threading
    import tools.registry

    db = _db(tmp_path)
    barrier = threading.Barrier(2)
    executed = []
    execute_lock = threading.Lock()

    def execute(name, argument, **kwargs):
        with execute_lock:
            executed.append(name)
        return {"ok": True, "criterion_id": "goal", "source": "concurrent-fixture"}

    monkeypatch.setattr(tools.registry, "execute", execute)
    first = _runtime(db)
    mission = _mission(first)
    second = _runtime(db)

    class BarrierModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            barrier.wait(timeout=3)
            return ModelTurn(turn_id, tool_calls=(_call(mission_id, run_id, turn_id, plan_version, 1),))

    results = []
    errors = []

    def run(runtime):
        try:
            results.append(runtime.run_model_loop(mission.mission_id, BarrierModel(), tools=[{"name": "status"}], max_turns=1))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(runtime,)) for runtime in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert len(executed) == 1, "only the runtime owning the checkpoint may dispatch the tool"
    assert len(errors) == 1
    assert isinstance(errors[0], ValueError)
    assert "stale mission write rejected" in str(errors[0])
    persisted = MissionStore(db).load(mission.mission_id)
    assert persisted is not None
    assert len(persisted.progress["model_loop"]["tool_results"]) == 1


def test_owner_authority_is_not_silently_restored_after_restart(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: {"ok": True, "criterion_id": "goal"})
    runtime = _runtime(_db(tmp_path))
    mission = _mission(runtime)
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
    assert tool_results[1]["error"] == "scope-bound tool requires AuthorizationContext with ScopeSnapshot"
    assert result.status is not MissionStatus.GOAL_COMPLETED
    assert result.status is MissionStatus.READY
    assert "lacked deterministic goal evidence" in result.error
