from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import threading
import time

import pytest

from agent.execution_fence import ExecutionFence, ExecutionFenceError
from agent.external_effects import (
    EffectDispatchBlocked,
    EffectIdentityConflict,
    EffectLedgerError,
    EffectRecoveryRequired,
    EffectState,
    EffectTransitionError,
    ExternalEffectLedger,
)
from agent.mission import Mission, MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue
from agent.planning import Plan, PlanStep
from security.mission_authorization import MissionAuthorizationSnapshot
from tools import registry as registry_module
from tools.registry import ToolSpec


def _authorization(mission_id: str, tool_name: str) -> MissionAuthorizationSnapshot:
    created = datetime.now(timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity="owner-test",
        mission_id=mission_id,
        target_identity="target-test",
        scope=("workspace",),
        allowed_actions=(tool_name,),
        forbidden_actions=(),
        allowed_tools=(tool_name,),
        time_window={"timezone": "UTC"},
        max_duration=900,
        rate_limits={tool_name: 10},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("target-test",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": "/tmp"},
        policy_version="external-effect-test",
        owner_approval="owner-proof-test",
        created_at=created.isoformat(),
        expires_at=(created + timedelta(minutes=10)).isoformat(),
    )


def _leased_fence(
    tmp_path: Path,
    tool_name: str = "effect_probe",
    *,
    mission_id: str = "effect-mission",
    execution_id: str = "effect-execution",
    active_checkpoint: bool = True,
):
    store = MissionStore(tmp_path / "missions.sqlite3")
    snapshot = _authorization(mission_id, tool_name)
    mission = Mission.create(
        "test request",
        "verify a fenced side effect",
        Plan(version=1, objective="verify a fenced side effect", steps=(
            PlanStep("step-1", "perform the effect", action=tool_name),
        )),
        mission_id=mission_id,
        request_id="effect-request",
        owner_identity_ref="owner-test",
        scope_snapshot={"target_id": "target-test"},
        authorization_snapshot=snapshot.to_dict(),
    )
    mission.transition(MissionStatus.READY, "test mission ready")
    store.save(mission)
    queue = MissionQueue(
        tmp_path / "queue.sqlite3",
        require_execution_fence=True,
        mission_store=store,
    )
    queue.enqueue(mission_id)
    identity = queue.register_worker("effect-worker")
    identity_fence = ExecutionFence.for_worker(queue, identity)
    claim = queue.claim_next(
        now=datetime.now(timezone.utc).isoformat(),
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=600,
        execution_fence=identity_fence,
    )
    assert claim is not None
    fence = identity_fence.with_lease(claim).for_mission(
        mission, task_id="step-1", execution_id=execution_id
    )
    binding = store.bind_execution_claim(mission_id, fence)
    assert binding.terminal_status is None
    mission = store.load(mission_id)
    assert mission is not None
    if active_checkpoint:
        mission.checkpoint = {
            "status": "in_flight",
            "step_id": fence.task_id,
            "action_id": fence.execution_id,
            "plan_version": mission.plan.version,
        }
        store.save(mission, execution_fence=fence)
    return store, mission, snapshot, queue, identity, claim, fence


def _effect_spec(name: str, handler, *, idempotency_supported: bool = False) -> ToolSpec:
    return ToolSpec(
        name,
        "test-only fenced effect",
        "state-write",
        False,
        str,
        handler,
        effect_provider="fixture-provider",
        idempotency_supported=idempotency_supported,
    )


def _execute(monkeypatch, spec: ToolSpec, mission, snapshot, fence, argument: str = "payload", scope_context=None):
    monkeypatch.setattr(registry_module, "get_tool", lambda name: spec if name == spec.name else None)
    return registry_module.execute(
        spec.name,
        argument,
        request_id=mission.request_id,
        mission_authorization=snapshot,
        mission_id=mission.mission_id,
        target_identity=snapshot.target_identity,
        scope_context=scope_context,
        execution_fence=fence,
        execution_id=fence.execution_id,
    )


def test_ledger_records_fenced_state_transitions_and_reference_fields(tmp_path):
    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    ledger = ExternalEffectLedger(queue.db_path)

    effect = ledger.reserve(
        fence,
        operation="test.effect",
        operation_fingerprint="a" * 64,
        provider="fixture-provider",
        authorization_snapshot=snapshot,
    )

    assert effect.state == EffectState.RESERVED
    assert effect.mission_id == mission.mission_id
    assert effect.task_id == fence.task_id
    assert effect.execution_id == fence.execution_id
    assert effect.request_id == mission.request_id
    assert effect.operation_fingerprint == "a" * 64
    assert effect.provider == "fixture-provider"
    assert effect.idempotency_key is None
    assert effect.created_at
    assert effect.evidence_ref == f"mission-execution:{mission.mission_id}:{fence.execution_id}"
    assert effect.fence_ref == fence.fence_id

    ledger.mark_dispatched(
        effect.effect_id,
        fence,
        dispatch_id="dispatch-1",
        authorization_snapshot=snapshot,
    )
    ledger.mark_succeeded(
        effect.effect_id,
        fence,
        dispatch_id="dispatch-1",
        result={"ok": True},
        authorization_snapshot=snapshot,
    )

    completed = ledger.get(effect.effect_id)
    assert completed is not None
    assert completed.state == EffectState.SUCCEEDED
    assert len(completed.result_sha256) == 64
    assert completed.fence_ref == fence.fence_id
    assert [item["to_state"] for item in ledger.history(effect.effect_id)] == [
        "PLANNED", "RESERVED", "DISPATCHED", "SUCCEEDED"
    ]


def test_provider_idempotency_key_is_stable_and_only_created_when_supported(tmp_path):
    _store, _mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    ledger = ExternalEffectLedger(queue.db_path)

    first = ledger.reserve(
        fence,
        operation="test.effect",
        operation_fingerprint="b" * 64,
        provider="fixture-provider",
        idempotency_supported=True,
        authorization_snapshot=snapshot,
    )
    assert first.idempotency_key
    assert first.idempotency_key.startswith("csfx_")
    assert ledger.get(first.effect_id).idempotency_key == first.idempotency_key


def test_tool_registry_persists_effect_before_handler_and_never_replays_success(
    tmp_path, monkeypatch
):
    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    calls: list[str] = []
    spec = _effect_spec("effect_probe", lambda value: calls.append(value) or {"ok": True})

    result = _execute(monkeypatch, spec, mission, snapshot, fence, "private-payload")
    assert result == {"ok": True}
    assert calls == ["private-payload"]

    ledger = ExternalEffectLedger(queue.db_path)
    records = ledger.list_effects(mission_id=mission.mission_id)
    assert len(records) == 1
    assert records[0].state == EffectState.SUCCEEDED
    assert records[0].provider == "fixture-provider"
    assert [item["to_state"] for item in ledger.history(records[0].effect_id)] == [
        "PLANNED", "RESERVED", "DISPATCHED", "SUCCEEDED"
    ]

    with pytest.raises(EffectDispatchBlocked):
        _execute(monkeypatch, spec, mission, snapshot, fence, "private-payload")
    assert calls == ["private-payload"]


def test_same_execution_with_changed_payload_is_rejected_before_second_dispatch(
    tmp_path, monkeypatch
):
    _store, mission, snapshot, _queue, _identity, _claim, fence = _leased_fence(tmp_path)
    calls: list[str] = []
    spec = _effect_spec("effect_probe", lambda value: calls.append(value) or {"ok": True})

    _execute(monkeypatch, spec, mission, snapshot, fence, "first-payload")
    with pytest.raises(EffectIdentityConflict):
        _execute(monkeypatch, spec, mission, snapshot, fence, "changed-payload")
    assert calls == ["first-payload"]


def test_concurrent_duplicate_reservations_allow_only_one_handler(tmp_path, monkeypatch):
    _store, mission, snapshot, _queue, _identity, _claim, fence = _leased_fence(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def handler(value):
        calls.append(value)
        entered.set()
        assert release.wait(5)
        return {"ok": True}

    spec = _effect_spec("effect_probe", handler)
    monkeypatch.setattr(registry_module, "get_tool", lambda name: spec if name == spec.name else None)
    kwargs = dict(
        request_id=mission.request_id,
        mission_authorization=snapshot,
        mission_id=mission.mission_id,
        target_identity=snapshot.target_identity,
        execution_fence=fence,
        execution_id=fence.execution_id,
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(registry_module.execute, spec.name, "same-payload", **kwargs)
        assert entered.wait(5)
        second = pool.submit(registry_module.execute, spec.name, "same-payload", **kwargs)
        with pytest.raises(EffectDispatchBlocked):
            second.result(timeout=5)
        release.set()
        assert first.result(timeout=5) == {"ok": True}
    assert calls == ["same-payload"]


def test_unknown_status_is_preserved_and_blocks_replay(tmp_path, monkeypatch):
    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    calls: list[str] = []
    spec = _effect_spec("effect_probe", lambda value: calls.append(value) or {"ok": True})
    _execute(monkeypatch, spec, mission, snapshot, fence, "payload")

    ledger = ExternalEffectLedger(queue.db_path)
    effect = ledger.list_effects(mission_id=mission.mission_id)[0]
    with sqlite3.connect(queue.db_path) as db:
        db.execute("UPDATE external_effects SET state='UNKNOWN' WHERE effect_id=?", (effect.effect_id,))

    observed = ledger.get(effect.effect_id)
    assert observed is not None
    assert observed.state == EffectState.UNKNOWN
    assert observed.requires_reconciliation
    with pytest.raises(EffectDispatchBlocked):
        _execute(monkeypatch, spec, mission, snapshot, fence, "payload")
    assert calls == ["payload"]


def test_dispatch_exception_is_quarantined_and_not_retried(tmp_path, monkeypatch):
    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    calls: list[str] = []

    def handler(value):
        calls.append(value)
        raise RuntimeError("provider response contained a private detail")

    spec = _effect_spec("effect_probe", handler)
    with pytest.raises(EffectRecoveryRequired):
        _execute(monkeypatch, spec, mission, snapshot, fence, "payload")

    ledger = ExternalEffectLedger(queue.db_path)
    effect = ledger.list_effects(mission_id=mission.mission_id)[0]
    assert effect.state == EffectState.RECOVERY_REQUIRED
    assert effect.error_code == "RUNTIMEERROR"
    with pytest.raises(EffectDispatchBlocked):
        _execute(monkeypatch, spec, mission, snapshot, fence, "payload")
    assert calls == ["payload"]


def test_process_death_after_dispatch_leaves_durable_intent_and_forbids_replay(
    tmp_path, monkeypatch
):
    class SimulatedProcessDeath(BaseException):
        pass

    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    calls: list[str] = []

    def handler(value):
        calls.append(value)
        raise SimulatedProcessDeath()

    spec = _effect_spec("effect_probe", handler)
    with pytest.raises(SimulatedProcessDeath):
        _execute(monkeypatch, spec, mission, snapshot, fence, "payload")

    ledger = ExternalEffectLedger(queue.db_path)
    effect = ledger.list_effects(mission_id=mission.mission_id)[0]
    assert effect.state == EffectState.DISPATCHED
    with pytest.raises(EffectDispatchBlocked):
        _execute(monkeypatch, spec, mission, snapshot, fence, "payload")
    assert calls == ["payload"]


def test_fence_failures_create_no_intent_and_never_reach_handler(tmp_path, monkeypatch):
    _store, mission, snapshot, queue, identity, claim, fence = _leased_fence(tmp_path)
    calls: list[str] = []
    spec = _effect_spec("effect_probe", lambda value: calls.append(value) or {"ok": True})
    monkeypatch.setattr(registry_module, "get_tool", lambda name: spec if name == spec.name else None)

    with pytest.raises(ExecutionFenceError, match="requires an execution fence"):
        registry_module.execute(
            spec.name,
            "payload",
            request_id=mission.request_id,
            mission_authorization=snapshot,
            mission_id=mission.mission_id,
            execution_id=fence.execution_id,
        )

    stale_identity = queue.register_worker(identity.worker_id)
    stale_fence = ExecutionFence.for_worker(queue, stale_identity).with_lease(claim).for_mission(
        mission, task_id=fence.task_id, execution_id=fence.execution_id
    )
    with pytest.raises(ExecutionFenceError):
        _execute(monkeypatch, spec, mission, snapshot, stale_fence)
    with sqlite3.connect(queue.db_path) as db:
        table = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='external_effects'"
        ).fetchone()
        assert table is None
    assert calls == []


def test_raw_argument_result_and_exception_text_are_never_persisted(tmp_path, monkeypatch):
    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    argument_secret = "RAW_ARGUMENT_SECRET_4821"
    result_secret = "RAW_RESULT_SECRET_9152"
    spec = _effect_spec(
        "effect_probe",
        lambda _value: {"ok": True, "sensitive": result_secret},
    )
    _execute(monkeypatch, spec, mission, snapshot, fence, argument_secret)

    persisted = Path(queue.db_path).read_bytes()
    assert argument_secret.encode() not in persisted
    assert result_secret.encode() not in persisted


def test_unknown_provider_status_moves_to_recovery_with_truthful_event_history(tmp_path):
    _store, _mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    ledger = ExternalEffectLedger(queue.db_path)
    effect = ledger.reserve(
        fence,
        operation="test.effect",
        operation_fingerprint="c" * 64,
        provider="fixture-provider",
        authorization_snapshot=snapshot,
    )
    ledger.mark_dispatched(
        effect.effect_id,
        fence,
        dispatch_id="dispatch-unknown",
        authorization_snapshot=snapshot,
    )
    observed = ledger.mark_unknown(
        effect.effect_id,
        fence,
        dispatch_id="dispatch-unknown",
        authorization_snapshot=snapshot,
    )
    assert observed.state == EffectState.UNKNOWN
    assert observed.requires_reconciliation

    recovered = ledger.mark_recovery_required(
        effect.effect_id,
        fence,
        dispatch_id="dispatch-unknown",
        reason_code="STATUS_UNAVAILABLE",
        authorization_snapshot=snapshot,
    )
    assert recovered.state == EffectState.RECOVERY_REQUIRED
    history = ledger.history(effect.effect_id)
    assert [item["to_state"] for item in history] == [
        "PLANNED", "RESERVED", "DISPATCHED", "UNKNOWN", "RECOVERY_REQUIRED"
    ]
    assert history[-1]["from_state"] == "UNKNOWN"


def test_strict_mission_runtime_persists_effect_recovery_without_reexecution(tmp_path):
    mission_id = "runtime-effect-mission"
    expected_action_id = f"{mission_id}:1:step-1:0"
    store = MissionStore(tmp_path / "runtime-missions.sqlite3")
    snapshot = _authorization(mission_id, "effect_probe")
    mission = Mission.create(
        "test request",
        "quarantine ambiguous effect",
        Plan(version=1, objective="quarantine ambiguous effect", steps=(
            PlanStep("step-1", "perform effect", action="effect_probe"),
        )),
        mission_id=mission_id,
        request_id="runtime-effect-request",
        owner_identity_ref="owner-test",
        scope_snapshot={"target_id": "target-test"},
        authorization_snapshot=snapshot.to_dict(),
    )
    mission.transition(MissionStatus.READY, "test mission ready")
    store.save(mission)
    queue = MissionQueue(
        tmp_path / "runtime-queue.sqlite3",
        require_execution_fence=True,
        mission_store=store,
    )
    queue.enqueue(mission_id)
    identity = queue.register_worker("runtime-effect-worker")
    worker_fence = ExecutionFence.for_worker(queue, identity)
    claim = queue.claim_next(
        now=datetime.now(timezone.utc).isoformat(),
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=600,
        execution_fence=worker_fence,
    )
    assert claim is not None
    leased_worker_fence = worker_fence.with_lease(claim)
    calls: list[str] = []

    def executor(_mission, _step, action_id, *, execution_fence):
        calls.append(action_id)
        assert action_id == expected_action_id
        assert execution_fence.execution_id == expected_action_id
        return {
            "success": False,
            "failure_class": "UNKNOWN",
            "effect_id": "ef_unknown-test-effect",
            "effect_state": "UNKNOWN",
            "reason_code": "PROVIDER_STATUS_UNKNOWN",
        }

    runtime = MissionRuntime(
        store,
        executor=executor,
        require_authorization_snapshot=True,
        require_execution_fence=True,
    )
    runtime.bind_execution_claim(mission_id, leased_worker_fence)

    result = runtime.run_to_completion(mission_id, max_slices=3)

    assert result.status == MissionStatus.RECOVERY_REQUIRED
    assert result.checkpoint["status"] == "in_flight"
    assert result.checkpoint["effect_id"] == "ef_unknown-test-effect"
    assert result.checkpoint["effect_state"] == "UNKNOWN"
    assert result.current_step == 0
    assert len(calls) == 1


def test_timeout_quarantines_in_flight_call_and_records_late_result(tmp_path, monkeypatch):
    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    started = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def handler(value):
        calls.append(value)
        started.set()
        assert release.wait(5)
        return {"ok": True, "observed": "late"}

    spec = _effect_spec("effect_probe", handler)
    monkeypatch.setattr(registry_module, "get_tool", lambda name: spec if name == spec.name else None)

    def invoke():
        return registry_module.execute(
            spec.name,
            "payload",
            request_id=mission.request_id,
            mission_authorization=snapshot,
            mission_id=mission.mission_id,
            target_identity=snapshot.target_identity,
            execution_fence=fence,
            execution_id=fence.execution_id,
            timeout=0.15,
        )

    ledger = ExternalEffectLedger(queue.db_path)
    try:
        with ThreadPoolExecutor(max_workers=1) as caller:
            pending = caller.submit(invoke)
            assert started.wait(5)
            with pytest.raises(EffectRecoveryRequired):
                pending.result(timeout=5)
        record = ledger.list_effects(mission_id=mission.mission_id)[0]
        assert record.state == EffectState.RECOVERY_REQUIRED
        assert calls == ["payload"]
    finally:
        release.set()

    for _ in range(500):
        record = ledger.list_effects(mission_id=mission.mission_id)[0]
        if record.state == EffectState.SUCCEEDED:
            break
        time.sleep(0.01)
    assert record.state == EffectState.SUCCEEDED
    assert [item["to_state"] for item in ledger.history(record.effect_id)][-2:] == [
        "RECOVERY_REQUIRED", "SUCCEEDED"
    ]
    assert calls == ["payload"]


def test_process_death_after_planned_commit_leaves_recoverable_intent(tmp_path, monkeypatch):
    class SimulatedProcessDeath(BaseException):
        pass

    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    ledger = ExternalEffectLedger(queue.db_path)
    promote = ledger._promote_to_reserved

    def die_after_planning(*_args, **_kwargs):
        raise SimulatedProcessDeath()

    monkeypatch.setattr(ledger, "_promote_to_reserved", die_after_planning)
    with pytest.raises(SimulatedProcessDeath):
        ledger.reserve(
            fence,
            operation="test.effect",
            operation_fingerprint="d" * 64,
            provider="fixture-provider",
            authorization_snapshot=snapshot,
        )

    planned = ledger.list_effects(mission_id=mission.mission_id)
    assert len(planned) == 1
    assert planned[0].state == EffectState.PLANNED
    assert [item["to_state"] for item in ledger.history(planned[0].effect_id)] == ["PLANNED"]

    monkeypatch.setattr(ledger, "_promote_to_reserved", promote)
    reserved = ledger.reserve(
        fence,
        operation="test.effect",
        operation_fingerprint="d" * 64,
        provider="fixture-provider",
        authorization_snapshot=snapshot,
    )
    assert reserved.effect_id == planned[0].effect_id
    assert reserved.state == EffectState.RESERVED
    assert [item["to_state"] for item in ledger.history(reserved.effect_id)] == [
        "PLANNED", "RESERVED"
    ]


def test_effect_capable_tool_without_fence_is_rejected_before_handler(monkeypatch):
    calls: list[str] = []
    spec = _effect_spec("effect_probe", lambda value: calls.append(value) or {"ok": True})
    monkeypatch.setattr(registry_module, "get_tool", lambda name: spec if name == spec.name else None)

    with pytest.raises(ExecutionFenceError, match="effect-capable tool dispatch requires"):
        registry_module.execute(spec.name, "payload")

    assert calls == []


def test_registry_rejects_side_effect_capable_tool_without_ledger_metadata():
    for risk_class in ("network-read", "state-write", "bounded-exec"):
        spec = ToolSpec(
            f"probe_{risk_class.replace('-', '_')}",
            "unclassified effect test",
            risk_class,
            True,
            str,
            lambda _value: None,
        )
        with pytest.raises(ValueError, match="invalid registry metadata"):
            registry_module.build_registry([spec])


def test_post_dispatch_effect_cannot_be_marked_failed_by_boolean_claim(tmp_path):
    _store, _mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    ledger = ExternalEffectLedger(queue.db_path)
    effect = ledger.reserve(
        fence,
        operation="test.effect",
        operation_fingerprint="e" * 64,
        provider="fixture-provider",
        authorization_snapshot=snapshot,
    )
    ledger.mark_dispatched(
        effect.effect_id,
        fence,
        dispatch_id="dispatch-may-have-applied",
        authorization_snapshot=snapshot,
    )

    with pytest.raises(EffectTransitionError, match="provably cancelled before start"):
        ledger.mark_failed(
            effect.effect_id,
            fence,
            reason_code="PROVIDER_SAYS_FAILED",
            provider_confirmed_no_effect=True,
            dispatch_id="dispatch-may-have-applied",
            authorization_snapshot=snapshot,
        )
    assert ledger.get(effect.effect_id).state == EffectState.DISPATCHED


def test_arbitrary_evidence_reference_is_rejected_before_storage(tmp_path):
    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    ledger = ExternalEffectLedger(queue.db_path)
    with pytest.raises(ValueError, match="canonical mission-execution reference"):
        ledger.reserve(
            fence,
            operation="test.effect",
            operation_fingerprint="f" * 64,
            provider="fixture-provider",
            evidence_ref="RAW_SECRET_REFERENCE",
            authorization_snapshot=snapshot,
        )
    assert ledger.list_effects(mission_id=mission.mission_id) == []


def test_effect_history_is_append_only_at_sqlite_boundary(tmp_path):
    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    ledger = ExternalEffectLedger(queue.db_path)
    effect = ledger.reserve(
        fence,
        operation="test.effect",
        operation_fingerprint="9" * 64,
        provider="fixture-provider",
        authorization_snapshot=snapshot,
    )

    with sqlite3.connect(queue.db_path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute(
                "UPDATE external_effect_events SET to_state='FAILED' WHERE effect_id=?",
                (effect.effect_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute(
                "DELETE FROM external_effect_events WHERE effect_id=?",
                (effect.effect_id,),
            )

    assert [item["to_state"] for item in ledger.history(effect.effect_id)] == [
        "PLANNED", "RESERVED"
    ]
    assert ledger.get(effect.effect_id).mission_id == mission.mission_id


def test_ledger_fails_closed_when_shared_queue_database_uses_wal(tmp_path):
    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    with sqlite3.connect(queue.db_path) as db:
        mode = db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    assert str(mode).lower() == "wal"

    ledger = ExternalEffectLedger(queue.db_path)
    with pytest.raises(EffectLedgerError, match="rollback-journal"):
        ledger.reserve(
            fence,
            operation="test.effect",
            operation_fingerprint="8" * 64,
            provider="fixture-provider",
            authorization_snapshot=snapshot,
        )
    assert ledger.list_effects(mission_id=mission.mission_id) == []


def test_failed_is_available_only_for_a_reserved_effect_cancelled_before_dispatch(tmp_path):
    _store, _mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    ledger = ExternalEffectLedger(queue.db_path)
    effect = ledger.reserve(
        fence,
        operation="test.effect",
        operation_fingerprint="7" * 64,
        provider="fixture-provider",
        authorization_snapshot=snapshot,
    )

    failed = ledger.mark_failed(
        effect.effect_id,
        fence,
        reason_code="CANCELLED_BEFORE_DISPATCH",
        provider_confirmed_no_effect=True,
        authorization_snapshot=snapshot,
    )
    assert failed.state == EffectState.FAILED
    assert failed.dispatch_id == ""
    assert not failed.requires_reconciliation


def test_same_execution_with_changed_scope_context_is_rejected_before_dispatch(tmp_path, monkeypatch):
    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    calls: list[str] = []
    spec = _effect_spec("effect_probe", lambda value: calls.append(value) or {"ok": True})

    _execute(
        monkeypatch,
        spec,
        mission,
        snapshot,
        fence,
        "payload",
        scope_context={"target_id": "target-a", "workspace_root": "/tmp/a", "private": "SCOPE_CONTEXT_SECRET_SENTINEL"},
    )
    with pytest.raises(EffectIdentityConflict):
        _execute(
            monkeypatch,
            spec,
            mission,
            snapshot,
            fence,
            "payload",
            scope_context={"target_id": "target-b", "workspace_root": "/tmp/b", "private": "SCOPE_CONTEXT_SECRET_SENTINEL"},
        )

    assert calls == ["payload"]
    ledger = ExternalEffectLedger(queue.db_path)
    assert len(ledger.list_effects(mission_id=mission.mission_id)) == 1
    with sqlite3.connect(queue.db_path) as db:
        persisted = repr(db.execute("SELECT * FROM external_effects").fetchall())
        persisted += repr(db.execute("SELECT * FROM external_effect_events").fetchall())
    assert "SCOPE_CONTEXT_SECRET_SENTINEL" not in persisted


def test_effect_dispatch_with_fence_but_no_mission_authorization_is_denied(tmp_path, monkeypatch):
    _store, mission, snapshot, queue, _identity, _claim, fence = _leased_fence(tmp_path)
    calls: list[str] = []
    spec = _effect_spec("effect_probe", lambda value: calls.append(value) or {"ok": True})
    monkeypatch.setattr(registry_module, "get_tool", lambda name: spec if name == spec.name else None)

    with pytest.raises(ExecutionFenceError, match="mission authorization snapshot"):
        registry_module.execute(
            spec.name,
            "payload",
            request_id=mission.request_id,
            mission_id=mission.mission_id,
            target_identity=snapshot.target_identity,
            execution_fence=fence,
            execution_id=fence.execution_id,
        )

    assert calls == []
    assert ExternalEffectLedger(queue.db_path).list_effects(mission_id=mission.mission_id) == []
