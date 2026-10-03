from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent.agent_core import AgentCore
from agent.execution_fence import ExecutionFence
from agent.external_effects import EffectState, ExternalEffectLedger
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState
from agent.model_router import ModelRouter
from agent.planning import Plan, PlanStep
from api.missions import MissionService
from owner_session_testutils import allow_owner_sessions
from runtime_authorization import make_test_snapshot
from security.mission_authorization import MissionAuthorizationSnapshot


def _ready(tmp_path: Path, *, strict: bool = False, mission_id: str = "control-mission"):
    store = MissionStore(tmp_path / "missions.sqlite3")
    runtime = MissionRuntime(
        store,
        executor=lambda *_args, **_kwargs: pytest.fail("control-plane fixture must not dispatch"),
        authorization_snapshot_factory=make_test_snapshot,
        require_authorization_snapshot=True,
        require_execution_fence=strict,
    )
    plan = Plan.initial("Owner control objective").replan(
        steps=(PlanStep("step-1", "check status", action="status"),),
        reason="test",
    )
    mission = runtime.create(
        "Owner control objective",
        "Owner control objective",
        plan,
        mission_id=mission_id,
        request_id=f"request-{mission_id}",
        owner_identity_ref="owner:1",
    )
    queue = MissionQueue(
        tmp_path / "queue.sqlite3",
        require_execution_fence=strict,
        mission_store=store if strict else None,
    )
    core = AgentCore(ModelRouter([]), store=store)
    service = MissionService(runtime, queue, owner_revalidator=core.prepare_mission_for_queue)
    return store, runtime, queue, mission, core, service


def test_foreign_and_missing_sessions_cannot_read_or_mutate_a_mission(tmp_path, monkeypatch):
    import security.owner_password as owner_password

    sessions = {
        "owner-one": {"session_id": "owner-one", "owner_id": 1, "username": "one", "auth_method": "username_password"},
        "owner-two": {"session_id": "owner-two", "owner_id": 2, "username": "two", "auth_method": "username_password"},
    }
    monkeypatch.setattr(owner_password, "resolve_session", lambda token: sessions.get(token))
    store, _runtime, queue, mission, _core, service = _ready(tmp_path)

    assert service.status(mission.mission_id, owner_session_token="owner-one")["mission_id"] == mission.mission_id
    with pytest.raises(PermissionError, match="mission access denied"):
        service.status(mission.mission_id, owner_session_token="owner-two")
    with pytest.raises(PermissionError, match="mission access denied"):
        service.pause_mission(mission.mission_id, owner_session_token="owner-two")
    with pytest.raises(PermissionError, match="owner authentication required"):
        service.status(mission.mission_id, owner_session_token="revoked-session")

    assert store.load(mission.mission_id).progress.get("pause_requested") is None
    assert queue.list() == []


def test_legacy_unbound_mission_is_read_only_and_is_never_adopted(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "owner-session")
    store = MissionStore(tmp_path / "missions.sqlite3")
    runtime = MissionRuntime(store, executor=lambda *_args, **_kwargs: {})
    mission = runtime.create(
        "legacy objective",
        "legacy objective",
        Plan.initial("legacy objective"),
        request_id="legacy-request",
    )
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    core = AgentCore(ModelRouter([]), store=store)
    service = MissionService(runtime, queue, owner_revalidator=core.prepare_mission_for_queue)

    assert service.status(mission.mission_id, owner_session_token="owner-session")["mission_id"] == mission.mission_id
    with pytest.raises(PermissionError, match="mission access denied"):
        service.start_mission(mission.mission_id, owner_session_token="owner-session")
    with pytest.raises(PermissionError, match="durable Owner identity"):
        core.prepare_mission_for_queue(mission.mission_id, "owner-session")
    persisted = store.load(mission.mission_id)
    assert persisted.owner_identity_ref == ""
    assert persisted.authorization_snapshot is None
    assert queue.list() == []


def test_owner_reauthorization_moves_quarantined_mission_back_to_ready(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "owner-session")
    store, runtime, queue, mission, _core, service = _ready(tmp_path, strict=True)
    queue.enqueue(mission.mission_id)
    worker = MissionWorker(queue, lambda: object(), worker_id="control-recovery-worker")

    recovered = worker.recover_after_restart()
    assert recovered[0].state is WorkerMissionState.NEEDS_INPUT
    quarantined = store.load(mission.mission_id)
    assert quarantined.status is MissionStatus.OWNER_REAUTH_REQUIRED
    prior_version = quarantined.authorization_snapshot["version"]

    resumed = service.resume_mission(mission.mission_id, owner_session_token="owner-session")

    persisted = store.load(mission.mission_id)
    assert resumed["status"] == MissionStatus.READY.value
    assert persisted.status is MissionStatus.READY
    assert persisted.owner_identity_ref == "owner:1"
    assert persisted.authorization_snapshot["version"] == prior_version + 1
    assert persisted.authorization_snapshot["owner_approval"] == persisted.policy_snapshot["authentication"]["proof_fingerprint"]
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED


def test_foreign_owner_and_mismatched_snapshot_cannot_reauthorize_quarantine(tmp_path, monkeypatch):
    import security.owner_password as owner_password

    sessions = {
        "owner-one": {"session_id": "owner-one", "owner_id": 1, "username": "one", "auth_method": "username_password"},
        "owner-two": {"session_id": "owner-two", "owner_id": 2, "username": "two", "auth_method": "username_password"},
    }
    monkeypatch.setattr(owner_password, "resolve_session", lambda token: sessions.get(token))
    store, _runtime, queue, mission, core, service = _ready(tmp_path, strict=True)
    queue.enqueue(mission.mission_id)
    worker = MissionWorker(queue, lambda: object(), worker_id="foreign-owner-worker")
    worker.recover_after_restart()

    with pytest.raises(PermissionError, match="mission access denied"):
        service.resume_mission(mission.mission_id, owner_session_token="owner-two")
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT

    persisted = store.load(mission.mission_id)
    original = MissionAuthorizationSnapshot.from_dict(persisted.authorization_snapshot)
    mismatched = original.amend(
        owner_approval="owner-two-proof",
        changes={"owner_identity": "owner:2"},
    )
    persisted.authorization_snapshot = mismatched.to_dict()
    persisted.provenance["authorization_snapshot_version"] = mismatched.version
    store.save(persisted)

    with pytest.raises(PermissionError, match="authorization snapshot cannot be renewed"):
        core.prepare_mission_for_queue(mission.mission_id, "owner-one")
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT


def _effect_recovery_fixture(tmp_path: Path):
    store = MissionStore(tmp_path / "missions.sqlite3")

    def snapshot_factory(mission):
        now = datetime.now(timezone.utc)
        return MissionAuthorizationSnapshot.create(
            owner_identity=mission.owner_identity_ref,
            mission_id=mission.mission_id,
            target_identity="fixture-target",
            scope=("workspace",),
            allowed_actions=("effect_probe",),
            forbidden_actions=(),
            allowed_tools=("effect_probe",),
            time_window={"timezone": "UTC"},
            max_duration=3600,
            rate_limits={"effect_probe": 1},
            network_boundary={"allowed": ()},
            data_boundary={"allowed": ("fixture-target",)},
            credential_boundary={"allowed": ()},
            workspace_boundary={"root": str(tmp_path)},
            policy_version="control-plane-test",
            owner_approval="original-owner-approval",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
        )

    dispatches: list[str] = []

    def execute(_mission, _step, action_id, *, execution_fence):
        assert execution_fence is not None
        dispatches.append(action_id)
        return {"success": True, "criterion_id": "effect-probe", "source": "fixture"}

    runtime = MissionRuntime(
        store,
        executor=execute,
        authorization_snapshot_factory=snapshot_factory,
        require_authorization_snapshot=True,
        require_execution_fence=True,
    )
    plan = Plan(version=1, objective="external effect", steps=(PlanStep("step-1", "perform effect", action="effect_probe"),))
    mission = runtime.create(
        "external effect",
        "external effect",
        plan,
        mission_id="effect-control-mission",
        request_id="effect-control-request",
        owner_identity_ref="owner:1",
    )
    queue = MissionQueue(
        tmp_path / "queue.sqlite3",
        require_execution_fence=True,
        mission_store=store,
    )
    queue.enqueue(mission.mission_id)
    worker = MissionWorker(
        queue,
        lambda: MissionRuntime(
            store,
            executor=execute,
            authorization_snapshot_factory=snapshot_factory,
            require_authorization_snapshot=True,
            require_execution_fence=True,
        ),
        worker_id="effect-control-worker",
    )
    identity = worker.identity
    identity_fence = worker.identity_fence
    claim = queue.claim_next(
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=600,
        execution_fence=identity_fence,
    )
    assert claim is not None
    fence = identity_fence.with_lease(claim).for_mission(
        mission,
        task_id="step-1",
        execution_id="effect-execution-1",
    )
    store.bind_execution_claim(mission.mission_id, fence)
    mission = store.load(mission.mission_id)
    mission.checkpoint = {
        "status": "in_flight",
        "step_id": "step-1",
        "action_id": "effect-execution-1",
        "effect_id": "",
        "plan_version": mission.plan.version,
    }
    store.save(mission, execution_fence=fence)

    ledger = ExternalEffectLedger(queue.db_path)
    authorization_snapshot = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot)
    effect = ledger.reserve(
        fence,
        operation="fixture.effect",
        operation_fingerprint="a" * 64,
        argument_sha256="b" * 64,
        provider="fixture-provider",
        authorization_snapshot=authorization_snapshot,
    )
    mission = store.load(mission.mission_id)
    mission.checkpoint["effect_id"] = effect.effect_id
    store.save(mission, execution_fence=fence)
    ledger.mark_dispatched(
        effect.effect_id,
        fence,
        dispatch_id="fixture-dispatch-1",
        authorization_snapshot=authorization_snapshot,
    )
    mission = store.load(mission.mission_id)
    mission.transition(MissionStatus.RECOVERY_REQUIRED, "ambiguous external effect")
    mission.checkpoint["effect_state"] = "DISPATCHED"
    store.save(mission, execution_fence=fence)
    queue.release(
        mission.mission_id,
        WorkerMissionState.WAITING_FOR_TOOL,
        worker_id=identity.worker_id,
        lease_epoch=claim.lease_epoch,
        runtime_generation=identity.runtime_generation,
        worker_instance_id=identity.worker_instance_id,
        execution_fence=fence,
        error="reconciliation required",
    )
    worker.recover_after_restart()
    mission = store.load(mission.mission_id)
    core = AgentCore(ModelRouter([]), store=store)
    service = MissionService(runtime, queue, owner_revalidator=core.prepare_mission_for_queue)
    return store, runtime, queue, mission, effect, ledger, service, worker, dispatches


def test_effect_inspection_is_sanitized_and_owner_outcomes_are_exactly_bound(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "owner-session")
    store, _runtime, _queue, mission, effect, ledger, service, worker, dispatches = _effect_recovery_fixture(tmp_path)

    inspected = service.inspect_effect(
        mission.mission_id,
        effect.effect_id,
        owner_session_token="owner-session",
    )
    assert inspected["effect_id"] == effect.effect_id
    assert inspected["state"] == EffectState.DISPATCHED.value
    assert "argument_sha256" not in inspected
    assert "idempotency_key" not in inspected
    assert "provider_proof" not in inspected
    assert "secret-tool-argument" not in repr(inspected)
    listed = service.effects(mission.mission_id, owner_session_token="owner-session")
    assert listed == [inspected]

    with pytest.raises(ValueError, match="only explicit Owner outcomes"):
        service.reconcile_effect(
            mission.mission_id,
            effect.effect_id,
            owner_session_token="owner-session",
            outcome="PROVIDER_LOOKUP",
            evidence_reference="provider-proof",
        )
    with pytest.raises(PermissionError, match="evidence reference"):
        service.reconcile_effect(
            mission.mission_id,
            effect.effect_id,
            owner_session_token="owner-session",
            outcome="OWNER_CONFIRM_APPLIED",
            evidence_reference="",
        )
    assert ledger.get(effect.effect_id).state == EffectState.DISPATCHED

    result = service.reconcile_effect(
        mission.mission_id,
        effect.effect_id,
        owner_session_token="owner-session",
        outcome="OWNER_CONFIRM_APPLIED",
        evidence_reference="owner-reviewed-receipt-reference",
    )
    assert result["status"] == "OWNER_CONFIRMED_APPLIED"
    assert result["dispatch_authorized"] is False
    assert ledger.get(effect.effect_id).state == EffectState.SUCCEEDED
    assert "owner-reviewed-receipt-reference" not in repr(result)
    assert "owner-reviewed-receipt-reference" not in repr(ledger.history(effect.effect_id))
    assert store.load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    resumed = service.resume_mission(mission.mission_id, owner_session_token="owner-session")
    assert resumed["status"] == MissionStatus.READY.value
    assert store.load(mission.mission_id).checkpoint["status"] == "reconciled_applied"
    assert _queue.get(mission.mission_id).state is WorkerMissionState.QUEUED

    worker.run_once(max_slices=4)
    assert dispatches == []
    assert store.load(mission.mission_id).current_step == 1


def test_effect_inspection_and_reconciliation_reject_foreign_session_and_cross_mission_effect(tmp_path, monkeypatch):
    import security.owner_password as owner_password

    sessions = {
        "owner-one": {"session_id": "owner-one", "owner_id": 1, "username": "one", "auth_method": "username_password"},
        "owner-two": {"session_id": "owner-two", "owner_id": 2, "username": "two", "auth_method": "username_password"},
    }
    monkeypatch.setattr(owner_password, "resolve_session", lambda token: sessions.get(token))
    store, runtime, _queue, mission, effect, _ledger, service, _worker, _dispatches = _effect_recovery_fixture(tmp_path)

    with pytest.raises(PermissionError, match="mission access denied"):
        service.inspect_effect(mission.mission_id, effect.effect_id, owner_session_token="owner-two")

    other = runtime.create(
        "other mission",
        "other mission",
        Plan.initial("other mission"),
        mission_id="another-owner-mission",
        request_id="another-owner-request",
        owner_identity_ref="owner:1",
    )
    with pytest.raises(PermissionError, match="does not belong"):
        service.inspect_effect(other.mission_id, effect.effect_id, owner_session_token="owner-one")


def test_unresolved_effect_and_stale_checkpoint_cannot_resume_or_change_queue_state(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "owner-session")
    store, _runtime, queue, mission, effect, ledger, service, _worker, dispatches = _effect_recovery_fixture(tmp_path)

    with pytest.raises(ValueError, match="unresolved external effects"):
        service.resume_mission(mission.mission_id, owner_session_token="owner-session")
    assert store.load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert dispatches == []

    persisted = store.load(mission.mission_id)
    persisted.checkpoint["plan_version"] += 1
    store.save(persisted)
    with pytest.raises(ValueError, match="stale for the current plan"):
        service.resume_mission(mission.mission_id, owner_session_token="owner-session")
    assert store.load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert ledger.get(effect.effect_id).state == EffectState.DISPATCHED
    assert dispatches == []


def test_confirmed_no_effect_requires_fresh_owner_and_dispatches_only_new_plan_identity(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "owner-session")
    store, _runtime, queue, mission, effect, ledger, service, worker, dispatches = _effect_recovery_fixture(tmp_path)
    previous_plan_version = mission.plan.version
    previous_execution_id = effect.execution_id

    service.reconcile_effect(
        mission.mission_id,
        effect.effect_id,
        owner_session_token="owner-session",
        outcome="OWNER_CONFIRM_NO_EFFECT",
        evidence_reference="owner-verified-no-effect-reference",
    )
    assert ledger.get(effect.effect_id).state == EffectState.FAILED
    assert store.load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED

    resumed = service.resume_mission(mission.mission_id, owner_session_token="owner-session")
    ready = store.load(mission.mission_id)
    assert resumed["status"] == MissionStatus.READY.value
    assert ready.status is MissionStatus.READY
    assert ready.plan.version == previous_plan_version + 1
    assert ready.checkpoint["status"] == "reconciled_no_effect"
    assert ready.checkpoint["prior_execution_ids"] == [previous_execution_id]
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED

    worker.run_once(max_slices=4)
    assert dispatches == [f"{mission.mission_id}:{ready.plan.version}:step-1:0"]
    assert dispatches[0] != previous_execution_id


def _parallel_effect_recovery_fixture(tmp_path: Path):
    store = MissionStore(tmp_path / "parallel-missions.sqlite3")
    dispatches: list[str] = []

    def snapshot_factory(mission):
        now = datetime.now(timezone.utc)
        return MissionAuthorizationSnapshot.create(
            owner_identity=mission.owner_identity_ref,
            mission_id=mission.mission_id,
            target_identity="parallel-fixture-target",
            scope=("workspace",),
            allowed_actions=("effect_probe",),
            forbidden_actions=(),
            allowed_tools=("effect_probe",),
            time_window={"timezone": "UTC"},
            max_duration=3600,
            rate_limits={"effect_probe": 2},
            network_boundary={"allowed": ()},
            data_boundary={"allowed": ("parallel-fixture-target",)},
            credential_boundary={"allowed": ()},
            workspace_boundary={"root": str(tmp_path)},
            policy_version="parallel-control-plane-test",
            owner_approval="original-owner-approval",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
        )

    def execute(_mission, _step, action_id, *, execution_fence):
        assert execution_fence is not None
        dispatches.append(action_id)
        return {"success": True, "criterion_id": "parallel-effect-probe", "source": "fixture"}

    runtime = MissionRuntime(
        store,
        executor=execute,
        authorization_snapshot_factory=snapshot_factory,
        require_authorization_snapshot=True,
        require_execution_fence=True,
    )
    mission = runtime.create(
        "parallel external effect",
        "parallel external effect",
        Plan(version=1, objective="parallel external effect", steps=(PlanStep("step-1", "perform parallel effects", action="effect_probe"),)),
        mission_id="parallel-effect-control-mission",
        request_id="parallel-effect-control-request",
        owner_identity_ref="owner:1",
    )
    queue = MissionQueue(
        tmp_path / "parallel-queue.sqlite3",
        require_execution_fence=True,
        mission_store=store,
    )
    queue.enqueue(mission.mission_id)
    worker = MissionWorker(
        queue,
        lambda: MissionRuntime(
            store,
            executor=execute,
            authorization_snapshot_factory=snapshot_factory,
            require_authorization_snapshot=True,
            require_execution_fence=True,
        ),
        worker_id="parallel-effect-control-worker",
    )
    claim = queue.claim_next(
        worker_id=worker.identity.worker_id,
        worker_instance_id=worker.identity.worker_instance_id,
        runtime_generation=worker.identity.runtime_generation,
        lease_seconds=600,
        execution_fence=worker.identity_fence,
    )
    assert claim is not None
    base_fence = worker.identity_fence.with_lease(claim)
    call_ids = ["call-parallel-1", "call-parallel-2"]
    execution_ids = ["parallel-execution-1", "parallel-execution-2"]
    task_ids = ["step-1", "step-1"]
    checkpoint = {
        "status": "in_flight_parallel",
        "step_id": "step-1",
        "tool_call_ids": call_ids,
        "ambiguous_tool_call_ids": call_ids,
        "execution_ids": execution_ids,
        "task_ids": task_ids,
        "plan_version": mission.plan.version,
        "run_id": "parallel-run-1",
        "turn_id": "parallel-turn-1",
    }
    ledger = ExternalEffectLedger(queue.db_path)
    effects = []
    last_fence = None
    for index, (call_id, execution_id, task_id) in enumerate(zip(call_ids, execution_ids, task_ids), start=1):
        fence = base_fence.for_mission(mission, task_id=task_id, execution_id=execution_id)
        store.bind_execution_claim(mission.mission_id, fence)
        mission = store.load(mission.mission_id)
        mission.checkpoint = dict(checkpoint)
        store.save(mission, execution_fence=fence)
        authorization_snapshot = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot)
        effect = ledger.reserve(
            fence,
            operation="fixture.parallel_effect",
            operation_fingerprint=f"{index:064x}",
            argument_sha256=f"{index + 10:064x}",
            provider="fixture-provider",
            authorization_snapshot=authorization_snapshot,
        )
        ledger.mark_dispatched(
            effect.effect_id,
            fence,
            dispatch_id=f"parallel-dispatch-{index}",
            authorization_snapshot=authorization_snapshot,
        )
        effects.append(effect)
        last_fence = fence
    mission = store.load(mission.mission_id)
    mission.transition(MissionStatus.RECOVERY_REQUIRED, "ambiguous parallel external effects")
    store.save(mission, execution_fence=last_fence)
    queue.release(
        mission.mission_id,
        WorkerMissionState.WAITING_FOR_TOOL,
        worker_id=worker.identity.worker_id,
        lease_epoch=claim.lease_epoch,
        runtime_generation=worker.identity.runtime_generation,
        worker_instance_id=worker.identity.worker_instance_id,
        execution_fence=last_fence,
        error="parallel reconciliation required",
    )
    worker.recover_after_restart()
    mission = store.load(mission.mission_id)
    core = AgentCore(ModelRouter([]), store=store)
    service = MissionService(runtime, queue, owner_revalidator=core.prepare_mission_for_queue)
    return store, queue, mission, effects, ledger, service, worker, dispatches


def test_parallel_applied_effects_are_not_redispatched_after_owner_resume(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "owner-session")
    store, queue, mission, effects, ledger, service, worker, dispatches = _parallel_effect_recovery_fixture(tmp_path)

    for effect in effects:
        service.reconcile_effect(
            mission.mission_id,
            effect.effect_id,
            owner_session_token="owner-session",
            outcome="OWNER_CONFIRM_APPLIED",
            evidence_reference=f"owner-reviewed-{effect.effect_id}",
        )
        assert ledger.get(effect.effect_id).state == EffectState.SUCCEEDED

    service.resume_mission(mission.mission_id, owner_session_token="owner-session")
    assert store.load(mission.mission_id).checkpoint["status"] == "reconciled_applied"
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED
    worker.run_once(max_slices=4)
    assert dispatches == []
    assert store.load(mission.mission_id).current_step == 1


def test_parallel_confirmed_no_effect_creates_a_new_plan_identity(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "owner-session")
    store, _queue, mission, effects, ledger, service, worker, dispatches = _parallel_effect_recovery_fixture(tmp_path)
    old_version = mission.plan.version
    old_execution_ids = {effect.execution_id for effect in effects}

    for effect in effects:
        service.reconcile_effect(
            mission.mission_id,
            effect.effect_id,
            owner_session_token="owner-session",
            outcome="OWNER_CONFIRM_NO_EFFECT",
            evidence_reference=f"owner-verified-none-{effect.effect_id}",
        )
        assert ledger.get(effect.effect_id).state == EffectState.FAILED

    service.resume_mission(mission.mission_id, owner_session_token="owner-session")
    ready = store.load(mission.mission_id)
    assert ready.status is MissionStatus.READY
    assert ready.plan.version == old_version + 1
    assert ready.checkpoint["status"] == "reconciled_no_effect"
    assert set(ready.checkpoint["prior_execution_ids"]) == old_execution_ids
    worker.run_once(max_slices=4)
    assert len(dispatches) == 1
    assert dispatches[0] == f"{mission.mission_id}:{ready.plan.version}:step-1:0"
    assert dispatches[0] not in old_execution_ids


def test_parallel_resume_blocks_if_any_outcome_is_unresolved(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "owner-session")
    store, queue, mission, effects, ledger, service, _worker, dispatches = _parallel_effect_recovery_fixture(tmp_path)

    service.reconcile_effect(
        mission.mission_id,
        effects[0].effect_id,
        owner_session_token="owner-session",
        outcome="OWNER_CONFIRM_APPLIED",
        evidence_reference="owner-reviewed-first-parallel-effect",
    )
    assert ledger.get(effects[0].effect_id).state == EffectState.SUCCEEDED
    assert ledger.get(effects[1].effect_id).state == EffectState.DISPATCHED

    with pytest.raises(ValueError, match="unresolved external effects"):
        service.resume_mission(mission.mission_id, owner_session_token="owner-session")
    assert store.load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert dispatches == []
