from __future__ import annotations

import json
import sqlite3
import threading

import pytest

from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.planning import Plan, PlanStep
from runtime_authorization import make_test_snapshot
from tools import registry as tool_registry


BASE = "2026-01-01T00:00:00+00:00"
AFTER_EXPIRY = "2026-01-01T00:00:01+00:00"
TOOL = "m2d.synthetic_local"


def _register_local_tool(monkeypatch, handler):
    from security import authorization

    spec = tool_registry.ToolSpec(
        TOOL,
        "Deterministic local M2.d integration fixture",
        "analysis",
        False,
        str,
        handler,
        timeout=3,
    )
    monkeypatch.setitem(tool_registry.REGISTRY, TOOL, spec)
    monkeypatch.setattr(tool_registry, "KNOWN_TOOLS", tool_registry.KNOWN_TOOLS | {TOOL})
    monkeypatch.setattr(authorization, "KNOWN_TOOLS", authorization.KNOWN_TOOLS | {TOOL})


def _plan():
    return Plan.initial("perform a deterministic local effect").replan(
        steps=(PlanStep("local-effect", "invoke the deterministic local tool", action=TOOL),),
        reason="M2.d integration fixture",
    )


def _create_mission(authority, tmp_path, executor):
    store = MissionStore(authority)
    queue = MissionQueue(authority)
    runtime = MissionRuntime(
        store,
        executor=executor,
        authorization_snapshot_factory=lambda mission: make_test_snapshot(mission, root=str(tmp_path)),
    )
    mission = runtime.create("local test request", "perform a deterministic local effect", _plan())
    queue.enqueue(mission.mission_id, available_at=BASE)
    return store, queue, mission


def _registry_executor(mission, step, action_id):
    payload = json.dumps({"mission_id": mission.mission_id, "action_id": action_id})
    return tool_registry.execute(step.action, payload, request_id=mission.request_id or "local-request")


def _intent_row(authority, mission_id):
    with sqlite3.connect(authority) as db:
        return db.execute(
            "SELECT effect_id,idempotency_key,state,current_attempt FROM external_effect_intents "
            "WHERE mission_id=?",
            (mission_id,),
        ).fetchone()


def test_worker_runtime_confirms_only_after_dispatching_is_committed(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    handler_entries = []

    def local_handler(argument):
        payload = json.loads(argument)
        with sqlite3.connect(authority) as db:
            intent = db.execute(
                "SELECT i.state,i.effect_id,i.idempotency_key,a.claim_generation "
                "FROM external_effect_intents i JOIN external_effect_attempts a "
                "ON a.effect_id=i.effect_id AND a.attempt_number=i.current_attempt "
                "WHERE i.mission_id=?",
                (payload["mission_id"],),
            ).fetchone()
            mission_payload = db.execute(
                "SELECT payload FROM missions WHERE mission_id=?",
                (payload["mission_id"],),
            ).fetchone()[0]
        checkpoint = json.loads(mission_payload)["checkpoint"]
        assert intent is not None and intent[0] == "DISPATCHING"
        assert intent[1] and intent[2].startswith("cybersentinel-effect-v1:")
        assert intent[3] == 1
        assert checkpoint["effect_id"] == intent[1]
        assert checkpoint["claim_generation"] == intent[3]
        handler_entries.append(payload)
        return {"success": True, "criterion_id": "local-effect", "source": "synthetic-local", "receipt_id": "receipt-1"}

    _register_local_tool(monkeypatch, local_handler)
    store, queue, mission = _create_mission(authority, tmp_path, _registry_executor)
    worker = MissionWorker(
        queue,
        lambda: MissionRuntime(store, executor=_registry_executor),
        worker_id="worker-a",
        lease_seconds=30,
    )

    result = worker.run_once(now=BASE, max_slices=1)

    intent_row = _intent_row(authority, mission.mission_id)
    persisted = MissionStore(authority).load(mission.mission_id)
    assert len(handler_entries) == 1
    assert intent_row is not None and intent_row[2] == "CONFIRMED"
    assert intent_row[1].startswith("cybersentinel-effect-v1:")
    assert persisted is not None
    assert persisted.status is MissionStatus.READY
    effect_observations = [item for item in persisted.observations if item.get("effect_id") == intent_row[0]]
    effect_evidence = [item for item in persisted.evidence if item.get("provenance", {}).get("effect_id") == intent_row[0]]
    assert len(effect_observations) == 1
    assert len(effect_evidence) == 1 and effect_evidence[0]["passed"] is True
    assert result is not None and result.state is WorkerMissionState.PARTIAL_SUCCESS


def test_reclaim_during_real_handler_rejects_old_result_and_all_old_writes(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def local_handler(argument):
        calls.append(json.loads(argument))
        with sqlite3.connect(authority) as db:
            state = db.execute(
                "SELECT state FROM external_effect_intents WHERE mission_id=?",
                (calls[-1]["mission_id"],),
            ).fetchone()[0]
        assert state == "DISPATCHING"
        entered.set()
        assert release.wait(timeout=5), "test barrier was not released"
        return {"success": True, "criterion_id": "local-effect", "source": "synthetic-local", "receipt_id": "late-receipt"}

    _register_local_tool(monkeypatch, local_handler)
    store, queue, mission = _create_mission(authority, tmp_path, _registry_executor)
    worker_a = MissionWorker(queue, lambda: MissionRuntime(store, executor=_registry_executor), worker_id="worker-a", lease_seconds=1)
    result_a = {}
    errors_a = []

    def run_a():
        try:
            result_a["item"] = worker_a.run_once(now=BASE, max_slices=1)
        except BaseException as exc:  # captured for assertion in the controlling test thread
            errors_a.append(exc)

    thread = threading.Thread(target=run_a)
    thread.start()
    assert entered.wait(timeout=5), "local tool handler was not reached"

    queue.recover_expired(now=AFTER_EXPIRY)
    worker_b = MissionWorker(queue, lambda: MissionRuntime(store, executor=_registry_executor), worker_id="worker-b", lease_seconds=30)
    item_b = worker_b.run_once(now=AFTER_EXPIRY, max_slices=1)
    assert item_b is not None and item_b.lease_claim is not None
    assert item_b.lease_claim.generation == 2
    assert MissionStore(authority).load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    before_stale_return_mission = MissionStore(authority).load(mission.mission_id).to_dict()
    before_stale_return_intent = _intent_row(authority, mission.mission_id)
    before_stale_return_queue = queue.get(mission.mission_id)

    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive(), "old worker did not finish after barrier release"
    assert errors_a == []
    assert len(calls) == 1
    assert MissionStore(authority).load(mission.mission_id).to_dict() == before_stale_return_mission
    assert _intent_row(authority, mission.mission_id) == before_stale_return_intent
    after_queue = queue.get(mission.mission_id)
    assert after_queue == before_stale_return_queue
    assert before_stale_return_intent is not None and before_stale_return_intent[2] == "UNKNOWN"
    assert before_stale_return_queue.state is WorkerMissionState.WAITING_FOR_TOOL


def test_new_worker_recovers_dispatched_crash_as_unknown_without_second_call(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    calls = []

    class SimulatedProcessDeath(BaseException):
        pass

    def crashing_handler(argument):
        calls.append(json.loads(argument))
        with sqlite3.connect(authority) as db:
            state = db.execute(
                "SELECT state FROM external_effect_intents WHERE mission_id=?",
                (calls[-1]["mission_id"],),
            ).fetchone()[0]
        assert state == "DISPATCHING"
        raise SimulatedProcessDeath("worker process stopped after crossing dispatch boundary")

    _register_local_tool(monkeypatch, crashing_handler)
    store, queue, mission = _create_mission(authority, tmp_path, _registry_executor)
    worker_a = MissionWorker(queue, lambda: MissionRuntime(store, executor=_registry_executor), worker_id="worker-a", lease_seconds=1)
    with pytest.raises(SimulatedProcessDeath):
        worker_a.run_once(now=BASE, max_slices=1)

    assert _intent_row(authority, mission.mission_id)[2] == "DISPATCHING"
    queue.recover_expired(now=AFTER_EXPIRY)
    worker_b = MissionWorker(queue, lambda: MissionRuntime(store, executor=_registry_executor), worker_id="worker-b", lease_seconds=30)
    item_b = worker_b.run_once(now=AFTER_EXPIRY, max_slices=1)

    persisted = MissionStore(authority).load(mission.mission_id)
    assert item_b is not None
    assert persisted is not None and persisted.status is MissionStatus.RECOVERY_REQUIRED
    assert _intent_row(authority, mission.mission_id)[2] == "UNKNOWN"
    assert persisted.checkpoint["reconciliation_status"] == "OWNER_RECONCILIATION_REQUIRED"
    assert len(calls) == 1


def test_confirmation_persistence_failure_rolls_back_and_never_marks_queue_failed(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    handler_calls = []
    mission_row_at_call = []

    def local_handler(argument):
        mission_id = json.loads(argument)["mission_id"]
        handler_calls.append(mission_id)
        with sqlite3.connect(authority) as db:
            mission_row_at_call.append(db.execute(
                "SELECT payload,revision FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone())
            db.execute(
                "CREATE TRIGGER reject_m2d_confirmation BEFORE UPDATE ON missions "
                "BEGIN SELECT RAISE(ABORT,'injected M2.d persistence failure'); END"
            )
        return {"success": True, "criterion_id": "local-effect", "source": "synthetic-local", "receipt_id": "receipt-rollback"}

    _register_local_tool(monkeypatch, local_handler)
    store, queue, mission = _create_mission(authority, tmp_path, _registry_executor)
    worker = MissionWorker(queue, lambda: MissionRuntime(store, executor=_registry_executor), worker_id="worker-a", lease_seconds=30)

    item = worker.run_once(now=BASE, max_slices=1)

    assert item is not None and item.state is WorkerMissionState.EXECUTING
    assert handler_calls == [mission.mission_id]
    assert _intent_row(authority, mission.mission_id)[2] == "DISPATCHING"
    with sqlite3.connect(authority) as db:
        after_mission_row = db.execute(
            "SELECT payload,revision FROM missions WHERE mission_id=?", (mission.mission_id,)
        ).fetchone()
        ledger_count = db.execute(
            "SELECT COUNT(*) FROM mission_evidence_events WHERE mission_id=?", (mission.mission_id,)
        ).fetchone()[0]
        failed_queue = db.execute(
            "SELECT COUNT(*) FROM mission_queue WHERE mission_id=? AND state=?",
            (mission.mission_id, WorkerMissionState.FAILED.value),
        ).fetchone()[0]
    assert after_mission_row == mission_row_at_call[0]
    assert ledger_count == 0
    assert failed_queue == 0


def test_reclaimed_prepared_attempt_keeps_same_effect_key_and_calls_only_after_new_gate(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    handler_entries = []

    def local_handler(argument):
        payload = json.loads(argument)
        with sqlite3.connect(authority) as db:
            state = db.execute(
                "SELECT state FROM external_effect_intents WHERE mission_id=?",
                (payload["mission_id"],),
            ).fetchone()[0]
        assert state == "DISPATCHING"
        handler_entries.append(payload)
        return {"success": True, "criterion_id": "local-effect", "source": "synthetic-local", "receipt_id": "receipt-retry"}

    _register_local_tool(monkeypatch, local_handler)
    store, queue, mission = _create_mission(authority, tmp_path, _registry_executor)
    claim_a_item = queue.claim_next(now=BASE, worker_id="worker-a", lease_seconds=1)
    assert claim_a_item is not None and claim_a_item.lease_claim is not None
    bound_a = store.with_claim(claim_a_item.lease_claim, now=BASE)
    first_logical_action_id = f"{mission.mission_id}:{mission.plan.version}:local-effect:0"
    step = mission.plan.steps[0]
    first = bound_a.effect_intents.prepare(
        mission,
        logical_action_id=first_logical_action_id,
        tool_id=step.action,
        payload={"step": step.to_dict(), "plan_version": mission.plan.version},
    )
    assert first.state.value == "PREPARED"
    assert handler_entries == []

    queue.recover_expired(now=AFTER_EXPIRY)
    # Process restart occurred after PREPARED committed but before DISPATCHING.
    worker_b = MissionWorker(queue, lambda: MissionRuntime(store, executor=_registry_executor), worker_id="worker-b", lease_seconds=30)
    result_b = worker_b.run_once(now=AFTER_EXPIRY, max_slices=1)

    final = _intent_row(authority, mission.mission_id)
    assert final is not None
    assert final[0] == first.effect_id
    assert final[1] == first.idempotency_key
    assert final[2] == "CONFIRMED"
    assert final[3] == 2
    assert len(handler_entries) == 1
    persisted = MissionStore(authority).load(mission.mission_id)
    assert persisted is not None
    confirmed_evidence = [item for item in persisted.evidence if item.get("provenance", {}).get("effect_id") == first.effect_id]
    assert len(confirmed_evidence) == 1
    assert confirmed_evidence[0]["provenance"]["claim_generation"] == 2
    with sqlite3.connect(authority) as db:
        attempts = db.execute(
            "SELECT attempt_number,claim_generation,state FROM external_effect_attempts WHERE effect_id=? ORDER BY attempt_number",
            (first.effect_id,),
        ).fetchall()
    assert attempts == [(1, 1, "DEFINITE_NOT_SENT"), (2, 2, "CONFIRMED")]
    assert result_b is not None


def test_worker_bound_native_model_calls_also_enter_the_same_gate(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    handler_entries = []

    def local_handler(argument):
        payload = json.loads(argument)
        with sqlite3.connect(authority) as db:
            state = db.execute(
                "SELECT state FROM external_effect_intents WHERE mission_id=?",
                (payload["mission_id"],),
            ).fetchone()[0]
        assert state == "DISPATCHING"
        handler_entries.append(payload)
        return {"success": True, "criterion_id": "native-tool", "source": "synthetic-native", "receipt_id": "native-receipt"}

    _register_local_tool(monkeypatch, local_handler)
    store, queue, mission = _create_mission(authority, tmp_path, _registry_executor)

    class ScriptedModel:
        calls = 0

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            self.calls += 1
            if self.calls == 1:
                proposal = ToolCallProposal.create(
                    TOOL,
                    {"query": json.dumps({"mission_id": mission_id, "action_id": "native-action"})},
                    mission_id=mission_id,
                    run_id=run_id,
                    turn_id=turn_id,
                    action_id="native-action",
                    tool_call_id="native-call-1",
                    plan_version=plan_version,
                    step_id="local-effect",
                )
                return ModelTurn(turn_id=turn_id, tool_calls=(proposal,), provider="fixture", model="fixture")
            return ModelTurn(turn_id=turn_id, content="done", provider="fixture", model="fixture")

    class NativeLoopRuntime(MissionRuntime):
        def __init__(self, target_store):
            super().__init__(target_store, executor=_registry_executor)
            self.model = ScriptedModel()

        def run_to_completion(self, mission_id, *, max_slices=None, heartbeat=None):
            if heartbeat is not None:
                heartbeat()
            return self.run_model_loop(mission_id, self.model, tools=[], max_turns=2)

    worker = MissionWorker(queue, lambda: NativeLoopRuntime(store), worker_id="worker-native", lease_seconds=30)
    result = worker.run_once(now=BASE, max_slices=2)

    persisted = MissionStore(authority).load(mission.mission_id)
    intent_row = _intent_row(authority, mission.mission_id)
    assert len(handler_entries) == 1
    assert intent_row is not None and intent_row[2] == "CONFIRMED"
    assert persisted is not None
    assert len([item for item in persisted.observations if item.get("effect_id") == intent_row[0]]) == 1
    assert result is not None


def test_worker_bound_native_parallel_tools_are_serialized_through_intent_gate(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    handler_entries = []

    def local_handler(argument):
        payload = json.loads(argument)
        with sqlite3.connect(authority) as db:
            row = db.execute(
                "SELECT state FROM external_effect_intents WHERE mission_id=? AND logical_action_id=?",
                (payload["mission_id"], payload["action_id"]),
            ).fetchone()
        assert row is not None and row[0] == "DISPATCHING"
        handler_entries.append(payload)
        return {"success": True, "criterion_id": payload["action_id"], "source": "synthetic-parallel", "receipt_id": payload["action_id"]}

    _register_local_tool(monkeypatch, local_handler)
    store, queue, mission = _create_mission(authority, tmp_path, _registry_executor)

    class ScriptedModel:
        calls = 0

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            self.calls += 1
            if self.calls == 1:
                proposals = tuple(
                    ToolCallProposal.create(
                        TOOL,
                        {"query": json.dumps({"mission_id": mission_id, "action_id": f"parallel-action-{number}"})},
                        mission_id=mission_id,
                        run_id=run_id,
                        turn_id=turn_id,
                        action_id=f"parallel-action-{number}",
                        tool_call_id=f"parallel-call-{number}",
                        plan_version=plan_version,
                        step_id="local-effect",
                    )
                    for number in (1, 2)
                )
                return ModelTurn(turn_id=turn_id, tool_calls=proposals, provider="fixture", model="fixture")
            return ModelTurn(turn_id=turn_id, content="done", provider="fixture", model="fixture")

    class NativeLoopRuntime(MissionRuntime):
        def __init__(self, target_store):
            super().__init__(target_store, executor=_registry_executor)
            self.model = ScriptedModel()

        def run_to_completion(self, mission_id, *, max_slices=None, heartbeat=None):
            if heartbeat is not None:
                heartbeat()
            return self.run_model_loop(mission_id, self.model, tools=[], max_turns=2)

    worker = MissionWorker(queue, lambda: NativeLoopRuntime(store), worker_id="worker-native-parallel", lease_seconds=30)
    result = worker.run_once(now=BASE, max_slices=2)

    with sqlite3.connect(authority) as db:
        states = db.execute(
            "SELECT logical_action_id,state FROM external_effect_intents WHERE mission_id=? ORDER BY logical_action_id",
            (mission.mission_id,),
        ).fetchall()
    assert len(handler_entries) == 2
    assert states == [("parallel-action-1", "CONFIRMED"), ("parallel-action-2", "CONFIRMED")]
    persisted = MissionStore(authority).load(mission.mission_id)
    assert persisted is not None
    assert len([item for item in persisted.observations if item.get("effect_id")]) == 2
    assert result is not None
