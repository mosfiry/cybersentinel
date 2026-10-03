from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from pathlib import Path
import hashlib
import sqlite3
import threading

import pytest

from agent.effect_reconciliation import (
    EffectReconciliationAction,
    EffectReconciliationAuthorization,
    EffectReconciliationEngine,
    EffectReconciliationError,
    EffectProviderObservation,
    ProviderEffectStatus,
    ReconciliationStatus,
)
from agent.execution_fence import ExecutionFence, ExecutionFenceError
from agent.external_effects import (
    EffectState,
    EffectTransitionError,
    ExternalEffectLedger,
)
from agent.mission import Mission, MissionStatus
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, WorkerMissionState
from agent.planning import Plan, PlanStep
from security.authorization_context import AuthorizationContext
from security.mission_authorization import MissionAuthorizationSnapshot
from security.owner_policy import authenticate_owner, capture_policy_snapshot
from agent.mission import MissionStore


def _owner_context(monkeypatch, *, token: str = "valid-owner-session", request_id: str = "owner-control-request", owner_id: int = 1):
    from security import owner_password

    def resolve(session_token):
        if session_token != token:
            return None
        return {
            "session_id": token,
            "owner_id": owner_id,
            "username": "owner",
            "auth_method": "username_password",
            "expires_at": "2999-01-01T00:00:00+00:00",
        }

    monkeypatch.setattr(owner_password, "resolve_session", resolve)
    evidence = authenticate_owner(token, request_id)
    policy = capture_policy_snapshot(request_id, evidence)
    return AuthorizationContext(
        request_id=request_id,
        owner_evidence=evidence,
        policy_snapshot=policy,
        session_id=evidence.session_id,
    )


def _mission_auth(mission_id: str, tool_name: str = "effect_probe") -> MissionAuthorizationSnapshot:
    now = datetime.now(timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity="owner:1",
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
        policy_version="effect-reconciliation-test",
        owner_approval="owner-proof-test",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=10)).isoformat(),
    )


def _fixture(
    tmp_path: Path,
    *,
    state: EffectState = EffectState.RESERVED,
    release_worker: bool = True,
    idempotency_supported: bool = False,
):
    mission_id = "reconcile-mission"
    store = MissionStore(tmp_path / "missions.sqlite3")
    snapshot = _mission_auth(mission_id)
    mission = Mission.create(
        "owner request",
        "verify external effect",
        Plan(version=1, objective="verify external effect", steps=(
            PlanStep("step-1", "perform effect", action="effect_probe"),
        )),
        mission_id=mission_id,
        request_id="effect-request",
        owner_identity_ref="owner:1",
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
    identity = queue.register_worker("reconcile-worker")
    base_fence = ExecutionFence.for_worker(queue, identity)
    claim = queue.claim_next(
        now=datetime.now(timezone.utc).isoformat(),
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=600,
        execution_fence=base_fence,
    )
    assert claim is not None
    mission = store.load(mission_id)
    fence = base_fence.with_lease(claim).for_mission(
        mission,
        task_id="step-1",
        execution_id="effect-execution",
    )
    store.bind_execution_claim(mission_id, fence)
    mission = store.load(mission_id)
    mission.checkpoint = {
        "status": "in_flight",
        "step_id": fence.task_id,
        "action_id": fence.execution_id,
        "plan_version": mission.plan.version,
    }
    store.save(mission, execution_fence=fence)

    ledger = ExternalEffectLedger(queue.db_path)
    effect = ledger.reserve(
        fence,
        operation="test.effect",
        operation_fingerprint="a" * 64,
        argument_sha256="b" * 64,
        provider="fixture-provider",
        idempotency_supported=idempotency_supported,
        authorization_snapshot=snapshot,
    )
    dispatch_id = "dispatch-1"
    if state in {
        EffectState.DISPATCHED,
        EffectState.SUCCEEDED,
        EffectState.AMBIGUOUS,
        EffectState.UNKNOWN,
        EffectState.RECOVERY_REQUIRED,
    }:
        ledger.mark_dispatched(
            effect.effect_id,
            fence,
            dispatch_id=dispatch_id,
            authorization_snapshot=snapshot,
        )
    if state == EffectState.SUCCEEDED:
        ledger.mark_succeeded(
            effect.effect_id,
            fence,
            dispatch_id=dispatch_id,
            result={"ok": True},
            authorization_snapshot=snapshot,
        )
    elif state == EffectState.FAILED:
        ledger.mark_failed(
            effect.effect_id,
            fence,
            reason_code="TEST_CONFIRMED_NO_EFFECT",
            provider_confirmed_no_effect=True,
            authorization_snapshot=snapshot,
        )
    elif state == EffectState.AMBIGUOUS:
        ledger.mark_recovery_required(
            effect.effect_id,
            fence,
            dispatch_id=dispatch_id,
            reason_code="TEST_AMBIGUOUS",
            authorization_snapshot=snapshot,
        )
    elif state == EffectState.UNKNOWN:
        ledger.mark_unknown(
            effect.effect_id,
            fence,
            dispatch_id=dispatch_id,
            reason_code="TEST_UNKNOWN",
            authorization_snapshot=snapshot,
        )
        ledger.mark_recovery_required(
            effect.effect_id,
            fence,
            dispatch_id=dispatch_id,
            reason_code="TEST_UNKNOWN",
            authorization_snapshot=snapshot,
        )
    elif state == EffectState.RECOVERY_REQUIRED:
        ledger.mark_recovery_required(
            effect.effect_id,
            fence,
            dispatch_id=dispatch_id,
            reason_code="TEST_RECOVERY",
            authorization_snapshot=snapshot,
        )

    if state in {
        EffectState.DISPATCHED,
        EffectState.AMBIGUOUS,
        EffectState.UNKNOWN,
        EffectState.RECOVERY_REQUIRED,
    }:
        mission = store.load(mission_id)
        mission.transition(MissionStatus.RECOVERY_REQUIRED, "test effect requires reconciliation")
        store.save(mission, execution_fence=fence)
    if release_worker:
        queue.release(
            mission_id,
            WorkerMissionState.WAITING_FOR_TOOL,
            worker_id=identity.worker_id,
            lease_epoch=claim.lease_epoch,
            runtime_generation=identity.runtime_generation,
            worker_instance_id=identity.worker_instance_id,
            execution_fence=fence,
            now=datetime.now(timezone.utc).isoformat(),
        )
    return store, snapshot, queue, identity, claim, fence, ledger, effect


class _FakeStatusAdapter:
    provider_id = "fixture-provider"

    def __init__(self, status: ProviderEffectStatus, evidence_reference: str = "provider-receipt:opaque"):
        self.status = status
        self.evidence_reference = evidence_reference
        self.calls = []

    def lookup_status(self, effect):
        self.calls.append(effect)
        return EffectProviderObservation(
            provider_id=self.provider_id,
            effect_id=effect.effect_id,
            operation_fingerprint=effect.operation_fingerprint,
            argument_sha256=effect.argument_sha256,
            dispatch_id=effect.dispatch_id,
            idempotency_key_sha256=hashlib.sha256(effect.idempotency_key.encode()).hexdigest() if effect.idempotency_key else "",
            provider_proof=self._proof(effect, self.status, self.evidence_reference),
            status=self.status,
            evidence_reference=self.evidence_reference,
        )

    @staticmethod
    def _proof(effect, status, evidence_reference):
        binding = f"{effect.effect_id}|{effect.operation_fingerprint}|{effect.argument_sha256}|{effect.dispatch_id}|{status.value}|{evidence_reference}"
        return hashlib.sha256(binding.encode()).hexdigest()

    def verify_observation(self, effect, observation):
        expected_proof = self._proof(effect, observation.status, observation.evidence_reference)
        return (
            observation.effect_id == effect.effect_id
            and observation.operation_fingerprint == effect.operation_fingerprint
            and observation.argument_sha256 == effect.argument_sha256
            and observation.dispatch_id == effect.dispatch_id
            and observation.provider_proof == expected_proof
        )


def _grant(monkeypatch, effect, action, *, evidence_reference="owner-review:opaque"):
    context = _owner_context(monkeypatch)
    return EffectReconciliationAuthorization.issue(
        context,
        effect=effect,
        owner_identity_ref=effect.owner_identity_ref,
        action=action,
        evidence_reference=evidence_reference,
    )


def _engine(ledger, store, *, adapter=None, retry_policy=None):
    return EffectReconciliationEngine(
        ledger=ledger,
        mission_store=store,
        provider_adapters={adapter.provider_id: adapter} if adapter else {},
        retry_policy=retry_policy,
    )


def test_inspection_requires_valid_owner_context_and_returns_no_raw_payload(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(tmp_path)
    engine = _engine(ledger, store)

    with pytest.raises(EffectReconciliationError):
        engine.inspect(effect.effect_id, context=None)

    context = _owner_context(monkeypatch)
    record = engine.inspect(effect.effect_id, context=context)
    assert record.effect_id == effect.effect_id
    assert record.mission_id == effect.mission_id
    assert record.state == EffectState.RESERVED
    assert not hasattr(record, "argument")
    assert not hasattr(record, "idempotency_key")
    assert "secret-payload" not in repr(record)


def test_effect_reconciliation_grants_are_owner_signed_and_exactly_bound(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(tmp_path)
    good = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)

    assert good.validate_for(effect, owner_identity_ref=effect.owner_identity_ref, action=EffectReconciliationAction.PROVIDER_LOOKUP)
    assert not good.validate_for(effect, owner_identity_ref=effect.owner_identity_ref, action=EffectReconciliationAction.OWNER_CONFIRM_APPLIED)
    forged = replace(good, decision=replace(good.decision, decision_signature="invalid"))
    assert not forged.validate_for(effect, owner_identity_ref=effect.owner_identity_ref, action=EffectReconciliationAction.PROVIDER_LOOKUP)

    other = replace(effect, effect_id="different-effect")
    assert not good.validate_for(other, owner_identity_ref=effect.owner_identity_ref, action=EffectReconciliationAction.PROVIDER_LOOKUP)


def test_case_a_planned_or_reserved_effect_is_policy_eligible_but_not_dispatchable(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RESERVED
    )
    adapter = _FakeStatusAdapter(ProviderEffectStatus.APPLIED)
    calls = []
    engine = _engine(ledger, store, adapter=adapter, retry_policy=lambda _effect: True)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)

    result = engine.reconcile(effect.effect_id, authorization=authorization)

    assert result.status == ReconciliationStatus.RETRY_ELIGIBLE
    assert result.retry_policy_allows is True
    assert result.dispatch_authorized is False
    assert result.owner_resume_required is True
    assert result.effect_state == EffectState.RESERVED
    assert ledger.get(effect.effect_id).state == EffectState.RESERVED
    assert adapter.calls == []
    assert calls == []


def test_case_a_is_not_called_retry_and_active_worker_blocks_safe_retry_advice(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.PLANNED if hasattr(EffectState, "PLANNED") else EffectState.RESERVED,
        release_worker=False,
    )
    engine = _engine(ledger, store, retry_policy=lambda _effect: True)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)

    with pytest.raises(EffectReconciliationError, match="active_worker"):
        engine.reconcile(effect.effect_id, authorization=authorization)
    assert ledger.get(effect.effect_id).state == EffectState.RESERVED


def test_case_b_succeeded_effect_is_never_replayed(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.SUCCEEDED
    )
    adapter = _FakeStatusAdapter(ProviderEffectStatus.CONFIRMED_NO_EFFECT)
    engine = _engine(ledger, store, adapter=adapter, retry_policy=lambda _effect: True)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)

    result = engine.reconcile(effect.effect_id, authorization=authorization)

    assert result.status == ReconciliationStatus.ALREADY_SUCCEEDED
    assert result.retry_policy_allows is False
    assert result.dispatch_authorized is False
    assert ledger.get(effect.effect_id).state == EffectState.SUCCEEDED
    assert adapter.calls == []


def test_case_c_confirmed_failure_is_retryable_only_when_policy_allows(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.FAILED
    )
    engine = _engine(ledger, store, retry_policy=lambda _effect: False)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)

    result = engine.reconcile(effect.effect_id, authorization=authorization)

    assert result.status == ReconciliationStatus.RETRY_NOT_PERMITTED
    assert result.retry_policy_allows is False
    assert ledger.get(effect.effect_id).state == EffectState.FAILED


def test_case_d_unknown_without_adapter_stays_quarantined_for_owner(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.DISPATCHED
    )
    engine = _engine(ledger, store)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)

    result = engine.reconcile(effect.effect_id, authorization=authorization)

    assert result.status == ReconciliationStatus.OWNER_RECONCILIATION_REQUIRED
    assert result.retry_policy_allows is False
    assert result.effect_state == EffectState.RECOVERY_REQUIRED
    assert ledger.get(effect.effect_id).state == EffectState.RECOVERY_REQUIRED
    assert ledger.history(effect.effect_id)[-1]["resolution_source"] == "PROVIDER_STATUS"


@pytest.mark.parametrize(
    ("provider_status", "expected_status", "expected_state", "retry_allowed"),
    [
        (ProviderEffectStatus.APPLIED, ReconciliationStatus.PROVIDER_CONFIRMED_APPLIED, EffectState.SUCCEEDED, False),
        (ProviderEffectStatus.CONFIRMED_NO_EFFECT, ReconciliationStatus.RETRY_ELIGIBLE, EffectState.FAILED, True),
        (ProviderEffectStatus.UNKNOWN, ReconciliationStatus.RECOVERY_REQUIRED, EffectState.RECOVERY_REQUIRED, False),
    ],
)
def test_case_e_provider_status_lookup_reconciles_deterministically(
    tmp_path, monkeypatch, provider_status, expected_status, expected_state, retry_allowed
):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED, idempotency_supported=True
    )
    adapter = _FakeStatusAdapter(provider_status)
    engine = _engine(ledger, store, adapter=adapter, retry_policy=lambda _effect: retry_allowed)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)

    result = engine.reconcile(effect.effect_id, authorization=authorization)

    assert result.status == expected_status
    assert result.effect_state == expected_state
    assert result.retry_policy_allows is retry_allowed
    assert result.dispatch_authorized is False
    assert result.owner_resume_required is retry_allowed
    assert len(adapter.calls) == 1
    assert adapter.calls[0].idempotency_key == effect.idempotency_key
    assert ledger.get(effect.effect_id).state == expected_state
    event = ledger.history(effect.effect_id)[-1]
    assert event["resolution_source"] == "PROVIDER_STATUS"
    assert event["authorization_ref"]
    assert len(event["evidence_sha256"]) == 64
    assert event["evidence_sha256"] != hashlib.sha256(b"provider-receipt:opaque").hexdigest()
    assert event["control_request_id"] == "owner-control-request"


def test_invalid_provider_response_is_unknown_and_never_trusted(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )

    class BadAdapter:
        provider_id = "fixture-provider"
        def lookup_status(self, _effect):
            return {"status": "APPLIED", "effect": "maybe"}
        def verify_observation(self, _effect, _observation):
            return False

    adapter = BadAdapter()
    engine = _engine(ledger, store, adapter=adapter)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)

    result = engine.reconcile(effect.effect_id, authorization=authorization)

    assert result.status == ReconciliationStatus.RECOVERY_REQUIRED
    assert result.effect_state == EffectState.RECOVERY_REQUIRED
    assert ledger.get(effect.effect_id).state == EffectState.RECOVERY_REQUIRED
    assert ledger.history(effect.effect_id)[-1]["error_code"] == "INVALID_PROVIDER_RESPONSE"


def test_case_f_owner_confirmation_is_explicit_bound_and_audited_without_raw_reference(
    tmp_path, monkeypatch
):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    engine = _engine(ledger, store)
    evidence_reference = "opaque-owner-evidence-DO-NOT-STORE"
    authorization = _grant(
        monkeypatch,
        effect,
        EffectReconciliationAction.OWNER_CONFIRM_APPLIED,
        evidence_reference=evidence_reference,
    )

    result = engine.apply_owner_decision(effect.effect_id, authorization=authorization)

    assert result.status == ReconciliationStatus.OWNER_CONFIRMED_APPLIED
    assert result.effect_state == EffectState.SUCCEEDED
    assert result.retry_policy_allows is False
    assert result.dispatch_authorized is False
    event = ledger.history(effect.effect_id)[-1]
    assert event["resolution_source"] == "OWNER"
    assert event["evidence_sha256"] == hashlib.sha256(evidence_reference.encode()).hexdigest()
    assert event["authorization_ref"]
    connection = sqlite3.connect(ledger.db_path)
    try:
        serialized = repr(connection.execute("SELECT * FROM external_effects").fetchall())
        serialized += repr(connection.execute("SELECT * FROM external_effect_events").fetchall())
    finally:
        connection.close()
    assert evidence_reference not in serialized


def test_owner_no_effect_resolution_needs_exact_action_and_is_retry_policy_gated(
    tmp_path, monkeypatch
):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    engine = _engine(ledger, store, retry_policy=lambda _effect: False)
    wrong_action = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)

    with pytest.raises(EffectReconciliationError):
        engine.apply_owner_decision(effect.effect_id, authorization=wrong_action)
    assert ledger.get(effect.effect_id).state == EffectState.RECOVERY_REQUIRED

    correct = _grant(monkeypatch, effect, EffectReconciliationAction.OWNER_CONFIRM_NO_EFFECT)
    result = engine.apply_owner_decision(effect.effect_id, authorization=correct)
    assert result.status == ReconciliationStatus.RETRY_NOT_PERMITTED
    assert result.effect_state == EffectState.FAILED
    assert result.retry_policy_allows is False


def test_missing_or_misbound_owner_authorization_cannot_change_effect_state(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    engine = _engine(ledger, store)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.OWNER_CONFIRM_NO_EFFECT)

    with pytest.raises(EffectReconciliationError):
        engine.apply_owner_decision(effect.effect_id, authorization=None)
    forged = replace(authorization, decision=replace(authorization.decision, decision_signature="x" * 64))
    with pytest.raises(EffectReconciliationError):
        engine.apply_owner_decision(effect.effect_id, authorization=forged)
    assert ledger.get(effect.effect_id).state == EffectState.RECOVERY_REQUIRED


def test_owner_cannot_overwrite_a_conflicting_terminal_effect_state(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.SUCCEEDED
    )
    engine = _engine(ledger, store)
    contradictory = _grant(monkeypatch, effect, EffectReconciliationAction.OWNER_CONFIRM_NO_EFFECT)

    with pytest.raises(EffectReconciliationError, match="terminal"):
        engine.apply_owner_decision(effect.effect_id, authorization=contradictory)
    assert ledger.get(effect.effect_id).state == EffectState.SUCCEEDED


def test_owner_reconciliation_is_idempotent_for_same_outcome_and_audited_once(
    tmp_path, monkeypatch
):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    engine = _engine(ledger, store)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.OWNER_CONFIRM_APPLIED)

    first = engine.apply_owner_decision(effect.effect_id, authorization=authorization)
    second = engine.apply_owner_decision(effect.effect_id, authorization=authorization)

    assert first.status == ReconciliationStatus.OWNER_CONFIRMED_APPLIED
    assert second.status == ReconciliationStatus.ALREADY_SUCCEEDED
    assert ledger.get(effect.effect_id).state == EffectState.SUCCEEDED
    assert [e["event_type"] for e in ledger.history(effect.effect_id)].count("OWNER_CONFIRMED_APPLIED") == 1


def test_reconciliation_blocks_while_any_worker_lease_is_live(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED, release_worker=False
    )
    engine = _engine(ledger, store)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.OWNER_CONFIRM_APPLIED)

    with pytest.raises(EffectReconciliationError, match="active_worker"):
        engine.apply_owner_decision(effect.effect_id, authorization=authorization)
    assert ledger.get(effect.effect_id).state == EffectState.RECOVERY_REQUIRED


def test_ledger_migration_and_reconciliation_history_are_append_only(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    engine = _engine(ledger, store)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.OWNER_CONFIRM_APPLIED)
    engine.apply_owner_decision(effect.effect_id, authorization=authorization)

    with sqlite3.connect(ledger.db_path) as connection:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute(
                "UPDATE external_effect_events SET resolution_source='forged' WHERE effect_id=?",
                (effect.effect_id,),
            )
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute(
                "DELETE FROM external_effect_events WHERE effect_id=?",
                (effect.effect_id,),
            )


@pytest.mark.parametrize("require_execution_fence", [False, True])
def test_legacy_boolean_reconciliation_path_fails_closed_for_every_runtime(tmp_path, require_execution_fence):
    store, _snapshot, _queue, _identity, _claim, fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    runtime = MissionRuntime(
        store,
        executor=lambda *_args, **_kwargs: {"success": True},
        require_execution_fence=require_execution_fence,
    )

    with pytest.raises(ExecutionFenceError, match="authenticated Owner"):
        runtime.reconcile_in_flight(
            effect.mission_id,
            executed=True,
            observation={"success": True},
            execution_fence=fence,
        )


def test_sql_cannot_rebind_provider_or_owner_identity_columns(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(tmp_path)
    engine = _engine(ledger, store)
    with sqlite3.connect(ledger.db_path) as connection:
        with pytest.raises(sqlite3.DatabaseError, match="identity is immutable"):
            connection.execute(
                "UPDATE external_effects SET provider='rebound-provider' WHERE effect_id=?",
                (effect.effect_id,),
            )
        with pytest.raises(sqlite3.DatabaseError, match="owner identity is immutable"):
            connection.execute(
                "UPDATE external_effects SET owner_identity_ref='owner:2' WHERE effect_id=?",
                (effect.effect_id,),
            )

    record = engine.inspect(effect.effect_id, context=_owner_context(monkeypatch))
    assert record.owner_binding_status == "BOUND"
    assert ledger.get(effect.effect_id).owner_identity_ref == "owner:1"


def test_mismatched_inflight_checkpoint_cannot_be_owner_reconciled(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    mission = store.load(effect.mission_id)
    mission.checkpoint["action_id"] = "different-execution"
    store.save(mission)
    engine = _engine(ledger, store)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.OWNER_CONFIRM_APPLIED)

    with pytest.raises(EffectReconciliationError, match="execution does not match"):
        engine.apply_owner_decision(effect.effect_id, authorization=authorization)
    assert ledger.get(effect.effect_id).state == EffectState.RECOVERY_REQUIRED


def test_provider_lookup_exception_is_sanitized_and_remains_quarantined(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )

    class FailingAdapter:
        provider_id = "fixture-provider"
        def lookup_status(self, _effect):
            raise RuntimeError("provider token must never enter ledger")
        def verify_observation(self, _effect, _observation):
            return False

    engine = _engine(ledger, store, adapter=FailingAdapter())
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)
    result = engine.reconcile(effect.effect_id, authorization=authorization)

    assert result.status == ReconciliationStatus.RECOVERY_REQUIRED
    assert ledger.get(effect.effect_id).state == EffectState.RECOVERY_REQUIRED
    history = ledger.history(effect.effect_id)
    assert history[-1]["error_code"] == "PROVIDER_LOOKUP_FAILED"
    assert "provider token" not in repr(history)


def test_concurrent_conflicting_owner_outcomes_serialize_to_one_durable_truth(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    engine = _engine(ledger, store)
    applied = _grant(monkeypatch, effect, EffectReconciliationAction.OWNER_CONFIRM_APPLIED)
    not_applied = _grant(monkeypatch, effect, EffectReconciliationAction.OWNER_CONFIRM_NO_EFFECT)

    def resolve(grant):
        try:
            result = engine.apply_owner_decision(effect.effect_id, authorization=grant)
            return ("resolved", result.effect_state)
        except Exception as exc:
            return ("rejected", type(exc).__name__)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(resolve, (applied, not_applied)))

    resolved = [value for name, value in outcomes if name == "resolved"]
    rejected = [value for name, value in outcomes if name == "rejected"]
    assert len(resolved) == 1
    assert len(rejected) == 1
    assert resolved[0] in {EffectState.SUCCEEDED, EffectState.FAILED}
    assert ledger.get(effect.effect_id).state == resolved[0]
    owner_events = [event for event in ledger.history(effect.effect_id) if event["resolution_source"] == "OWNER"]
    assert len(owner_events) == 1
    assert owner_events[0]["to_state"] == resolved[0]


def test_valid_owner_context_cannot_inspect_or_authorize_another_owner_mission(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(tmp_path)
    engine = _engine(ledger, store)
    foreign_context = _owner_context(monkeypatch, token="different-owner-session", owner_id=2)

    with pytest.raises(EffectReconciliationError, match="does not own"):
        engine.inspect(effect.effect_id, context=foreign_context)
    with pytest.raises(EffectReconciliationError, match="does not own"):
        engine.authorize(
            effect.effect_id,
            context=foreign_context,
            action=EffectReconciliationAction.PROVIDER_LOOKUP,
        )


def test_provider_proof_cannot_confirm_a_different_effect_or_operation(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED, idempotency_supported=True
    )

    class ReboundAdapter(_FakeStatusAdapter):
        def lookup_status(self, target):
            self.calls.append(target)
            return EffectProviderObservation(
                provider_id=self.provider_id,
                effect_id="different-effect",
                operation_fingerprint="f" * 64,
                argument_sha256=target.argument_sha256,
                dispatch_id=target.dispatch_id,
                idempotency_key_sha256=hashlib.sha256(target.idempotency_key.encode()).hexdigest(),
                provider_proof="valid-signature-for-some-other-operation",
                status=ProviderEffectStatus.APPLIED,
                evidence_reference="provider-receipt:other-effect",
            )

        def verify_observation(self, _effect, _observation):
            return True

    adapter = ReboundAdapter(ProviderEffectStatus.APPLIED)
    engine = _engine(ledger, store, adapter=adapter)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)
    result = engine.reconcile(effect.effect_id, authorization=authorization)

    assert result.status == ReconciliationStatus.RECOVERY_REQUIRED
    assert result.effect_state == EffectState.RECOVERY_REQUIRED
    assert ledger.get(effect.effect_id).state == EffectState.RECOVERY_REQUIRED
    assert ledger.history(effect.effect_id)[-1]["error_code"] == "INVALID_PROVIDER_RESPONSE"


def test_provider_proof_verifier_is_mandatory_and_false_proof_stays_unknown(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )

    class UnverifiedAdapter(_FakeStatusAdapter):
        def verify_observation(self, _effect, _observation):
            return False

    with pytest.raises(ValueError, match="adapter registration"):
        _engine(ledger, store, adapter=type("NoVerifier", (), {"provider_id": "fixture-provider", "lookup_status": lambda self, _effect: None})())

    adapter = UnverifiedAdapter(ProviderEffectStatus.APPLIED)
    engine = _engine(ledger, store, adapter=adapter)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.PROVIDER_LOOKUP)
    result = engine.reconcile(effect.effect_id, authorization=authorization)

    assert result.status == ReconciliationStatus.RECOVERY_REQUIRED
    assert result.effect_state == EffectState.RECOVERY_REQUIRED
    assert ledger.history(effect.effect_id)[-1]["error_code"] == "INVALID_PROVIDER_PROOF"


def test_repeated_unknown_provider_status_is_audit_idempotent(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED, idempotency_supported=True
    )
    adapter = _FakeStatusAdapter(ProviderEffectStatus.UNKNOWN)
    engine = _engine(ledger, store, adapter=adapter)
    first_context = _owner_context(monkeypatch, request_id="control-unknown-1")
    first_grant = engine.authorize(
        effect.effect_id,
        context=first_context,
        action=EffectReconciliationAction.PROVIDER_LOOKUP,
    )
    first = engine.reconcile(effect.effect_id, authorization=first_grant)
    first_event_count = len(ledger.history(effect.effect_id))

    second_context = _owner_context(monkeypatch, request_id="control-unknown-2")
    second_grant = engine.authorize(
        effect.effect_id,
        context=second_context,
        action=EffectReconciliationAction.PROVIDER_LOOKUP,
    )
    second = engine.reconcile(effect.effect_id, authorization=second_grant)

    assert first.status is ReconciliationStatus.RECOVERY_REQUIRED
    assert second.status is ReconciliationStatus.RECOVERY_REQUIRED
    assert len(adapter.calls) == 2
    assert len(ledger.history(effect.effect_id)) == first_event_count
    assert [event["event_type"] for event in ledger.history(effect.effect_id)].count("PROVIDER_STATUS_UNKNOWN") == 1


def test_stale_plan_versions_cannot_be_reconciled_against_current_checkpoint(tmp_path):
    store, _snapshot, _queue, _identity, _claim, _fence, _ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    mission = store.load(effect.mission_id)
    mission.checkpoint = {**mission.checkpoint, "plan_version": effect.task_version + 1}

    with pytest.raises(EffectReconciliationError, match="plan version"):
        EffectReconciliationEngine._require_checkpoint_binding(mission, effect)


def test_parallel_checkpoint_requires_exact_execution_and_task_pair(tmp_path):
    store, _snapshot, _queue, _identity, _claim, _fence, _ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    mission = store.load(effect.mission_id)
    mission.checkpoint = {
        "status": "in_flight_parallel",
        "step_id": effect.task_id,
        "plan_version": effect.task_version,
        "execution_ids": ["another-execution"],
        "task_ids": [effect.task_id],
    }

    with pytest.raises(EffectReconciliationError, match="current in-flight"):
        EffectReconciliationEngine._require_checkpoint_binding(mission, effect)


def test_parallel_checkpoint_accepts_only_the_matching_execution_task_pair(tmp_path):
    store, _snapshot, _queue, _identity, _claim, _fence, _ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    mission = store.load(effect.mission_id)
    mission.checkpoint = {
        "status": "in_flight_parallel",
        "plan_version": effect.task_version,
        "execution_ids": [effect.execution_id],
        "task_ids": [effect.task_id],
    }

    EffectReconciliationEngine._require_checkpoint_binding(mission, effect)


def test_changed_unknown_provider_proof_is_not_deduplicated(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED, idempotency_supported=True
    )

    class ChangingUnknownAdapter(_FakeStatusAdapter):
        def lookup_status(self, target):
            if self.calls:
                self.evidence_reference = "provider-receipt:changed-observation"
            return super().lookup_status(target)

    adapter = ChangingUnknownAdapter(ProviderEffectStatus.UNKNOWN)
    engine = _engine(ledger, store, adapter=adapter)
    for request_id in ("control-unknown-a", "control-unknown-b"):
        context = _owner_context(monkeypatch, request_id=request_id)
        authorization = engine.authorize(
            effect.effect_id,
            context=context,
            action=EffectReconciliationAction.PROVIDER_LOOKUP,
        )
        result = engine.reconcile(effect.effect_id, authorization=authorization)
        assert result.status is ReconciliationStatus.RECOVERY_REQUIRED

    events = [event for event in ledger.history(effect.effect_id) if event["event_type"] == "PROVIDER_STATUS_UNKNOWN"]
    assert len(events) == 2
    assert events[0]["evidence_sha256"] != events[1]["evidence_sha256"]


def test_ambiguous_parallel_effect_can_be_owner_reconciled_by_exact_pair(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    mission = store.load(effect.mission_id)
    mission.checkpoint = {
        "status": "in_flight_parallel",
        "plan_version": effect.task_version,
        "execution_ids": [effect.execution_id],
        "task_ids": [effect.task_id],
        "tool_call_ids": ["call-ambiguous"],
        "ambiguous_tool_call_ids": ["call-ambiguous"],
        "run_id": "parallel-run",
    }
    store.save(mission)
    engine = _engine(ledger, store)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.OWNER_CONFIRM_APPLIED)

    result = engine.apply_owner_decision(effect.effect_id, authorization=authorization)

    assert result.status is ReconciliationStatus.OWNER_CONFIRMED_APPLIED
    assert result.effect_state is EffectState.SUCCEEDED
    assert ledger.get(effect.effect_id).state == EffectState.SUCCEEDED


def test_legacy_v6_effect_row_uses_immutable_mission_owner_binding(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    with sqlite3.connect(ledger.db_path) as connection:
        connection.execute("DROP TRIGGER IF EXISTS external_effect_owner_identity_immutable")
        connection.execute("ALTER TABLE external_effects DROP COLUMN owner_identity_ref")

    migrated_ledger = ExternalEffectLedger(ledger.db_path)
    with migrated_ledger._transaction() as connection:
        migrated_ledger._ensure_schema(connection)
    engine = _engine(migrated_ledger, store)

    inspection = engine.inspect(effect.effect_id, context=_owner_context(monkeypatch))
    assert inspection.owner_binding_status == "DERIVED_FROM_MISSION"
    assert migrated_ledger.get(effect.effect_id).owner_identity_ref == ""

    foreign_context = _owner_context(monkeypatch, token="foreign-owner", owner_id=2)
    with pytest.raises(EffectReconciliationError, match="does not own"):
        engine.authorize(
            effect.effect_id,
            context=foreign_context,
            action=EffectReconciliationAction.PROVIDER_LOOKUP,
        )
    assert migrated_ledger.get(effect.effect_id).owner_identity_ref == ""

    owner_context = _owner_context(monkeypatch, token="original-owner", owner_id=1)
    grant = engine.authorize(
        effect.effect_id,
        context=owner_context,
        action=EffectReconciliationAction.OWNER_CONFIRM_APPLIED,
        evidence_reference="owner-report:legacy-effect-confirmation",
    )
    assert grant.owner_identity_ref == "owner:1"
    result = engine.apply_owner_decision(effect.effect_id, authorization=grant)
    assert result.status is ReconciliationStatus.OWNER_CONFIRMED_APPLIED
    assert migrated_ledger.get(effect.effect_id).owner_identity_ref == ""
    assert migrated_ledger.history(effect.effect_id)[-1]["event_type"] == "OWNER_CONFIRMED_APPLIED"
    assert engine.inspect(effect.effect_id, context=owner_context).owner_binding_status == "DERIVED_FROM_MISSION"
    with sqlite3.connect(ledger.db_path) as connection:
        connection.create_function("external_effect_owner_binding_permit", 5, lambda *args: 1)
        connection.execute(
            """CREATE TABLE IF NOT EXISTS external_effect_owner_binding_migrations (
                effect_id TEXT PRIMARY KEY, owner_identity_ref TEXT NOT NULL,
                authorization_hash TEXT NOT NULL, control_request_id TEXT NOT NULL,
                authorization_ref TEXT NOT NULL DEFAULT '',
                owner_evidence_fingerprint TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """INSERT INTO external_effect_owner_binding_migrations
               (effect_id,owner_identity_ref,authorization_hash,control_request_id,
                authorization_ref,owner_evidence_fingerprint,created_at)
               VALUES(?,?,?,?,?,?,?)""",
            (effect.effect_id, "owner:2", effect.authorization_hash, "forged-request", "forged-auth", "forged-evidence", "now"),
        )
        with pytest.raises(sqlite3.DatabaseError, match="owner identity is immutable"):
            connection.execute(
                "UPDATE external_effects SET owner_identity_ref='owner:2' WHERE effect_id=?",
                (effect.effect_id,),
            )
        assert connection.execute(
            "SELECT owner_identity_ref FROM external_effects WHERE effect_id=?", (effect.effect_id,)
        ).fetchone()[0] == ""


def test_reconciliation_ledger_rechecks_worker_lease_inside_serialized_transaction(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    engine = _engine(ledger, store)
    authorization = _grant(monkeypatch, effect, EffectReconciliationAction.OWNER_CONFIRM_APPLIED)
    # Simulate a worker claim winning after the control-plane precheck.
    engine._check_idle = lambda _effect: None
    with sqlite3.connect(ledger.db_path) as connection:
        connection.execute(
            "UPDATE mission_queue SET lease_owner='racing-worker' WHERE mission_id=?",
            (effect.mission_id,),
        )

    with pytest.raises(EffectTransitionError, match="active worker lease"):
        engine.apply_owner_decision(effect.effect_id, authorization=authorization)
    assert ledger.get(effect.effect_id).state == EffectState.RECOVERY_REQUIRED
    assert not any(event["resolution_source"] == "OWNER" for event in ledger.history(effect.effect_id))


def test_reconciliation_serializes_mission_checkpoint_with_effect_commit(tmp_path, monkeypatch):
    store, _snapshot, _queue, _identity, _claim, _fence, ledger, effect = _fixture(
        tmp_path, state=EffectState.RECOVERY_REQUIRED
    )
    engine = _engine(ledger, store)
    owner_context = _owner_context(monkeypatch)
    grant = engine.authorize(
        effect.effect_id,
        context=owner_context,
        action=EffectReconciliationAction.OWNER_CONFIRM_APPLIED,
        evidence_reference="owner-report:attached-store-race",
    )

    save_started = threading.Event()
    writer_finished = threading.Event()
    writer_errors: list[BaseException] = []
    original_save = store._save

    def signalled_save(mission, *, execution_fence=None, allow_claimed=False):
        if threading.current_thread().name == "mission-store-racer":
            save_started.set()
        return original_save(
            mission,
            execution_fence=execution_fence,
            allow_claimed=allow_claimed,
        )

    monkeypatch.setattr(store, "_save", signalled_save)

    def change_checkpoint_after_lock():
        try:
            mission = store.load(effect.mission_id)
            mission.checkpoint["step_id"] = "changed-after-reconcile"
            store.save(mission)
        except BaseException as exc:
            writer_errors.append(exc)
        finally:
            writer_finished.set()

    writer = threading.Thread(
        target=change_checkpoint_after_lock,
        name="mission-store-racer",
        daemon=True,
    )
    original_transaction = ledger._transaction

    @contextmanager
    def transaction_with_racer(*, mission_store=None):
        with original_transaction(mission_store=mission_store) as connection:
            if mission_store is store and not writer.is_alive():
                writer.start()
                assert save_started.wait(2), "mission writer did not reach its save attempt"
                assert not writer_finished.wait(0.15), (
                    "MissionStore writer committed while reconciliation held only the effect database"
                )
            yield connection

    monkeypatch.setattr(ledger, "_transaction", transaction_with_racer)
    try:
        result = engine.apply_owner_decision(effect.effect_id, authorization=grant)
    finally:
        if writer.is_alive():
            assert writer_finished.wait(5), "blocked mission writer did not resume after reconciliation"
            writer.join(1)

    assert result.status is ReconciliationStatus.OWNER_CONFIRMED_APPLIED
    assert ledger.get(effect.effect_id).state == EffectState.SUCCEEDED
    assert not writer_errors
    assert store.load(effect.mission_id).checkpoint["step_id"] == "changed-after-reconcile"
