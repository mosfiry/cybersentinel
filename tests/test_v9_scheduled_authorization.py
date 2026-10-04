from __future__ import annotations

from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from pathlib import Path
from threading import Barrier

import pytest

from agent.agent_core import AgentCore
from agent.execution_fence import ExecutionFenceError
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import (
    MissionQueue,
    MissionScheduler,
    MissionWorker,
    WorkerMissionState,
)
from agent.model_router import ModelRouter
from agent.planning import Plan, PlanStep
from api.missions import MissionService
from owner_session_testutils import allow_owner_sessions
from runtime_authorization import make_test_snapshot
from security.session_reference import session_reference


def _fixture(tmp_path: Path, monkeypatch, *, failpoint=None):
    import core.db as core_db

    allow_owner_sessions(monkeypatch, "current-owner-session")
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "owner_auth.sqlite3")
    now = datetime.now(timezone.utc).isoformat()
    with core_db.connect() as auth_db:
        auth_db.execute(
            "INSERT INTO owner_accounts(username,password_hash,kdf_algorithm,kdf_params_json,status) "
            "VALUES(?,?,?,?,?)",
            ("owner-one", "test-verifier", "scrypt", "{}", "active"),
        )
        auth_db.execute(
            "INSERT INTO owner_sessions(session_id,owner_id,created_at,authenticated_at,expires_at,status,auth_method) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                session_reference("current-owner-session"),
                1,
                now,
                now,
                "2999-01-01T00:00:00+00:00",
                "active",
                "username_password",
            ),
        )
    store = MissionStore(tmp_path / "missions.sqlite3")
    executions: list[str] = []

    def executor(_mission, step, _action):
        executions.append(step.step_id)
        return {"success": True, "criterion_id": "done", "source": "v9-test"}

    def runtime_factory():
        return MissionRuntime(
            store,
            executor=executor,
            authorization_snapshot_factory=make_test_snapshot,
            require_authorization_snapshot=True,
            require_execution_fence=True,
        )

    runtime = runtime_factory()
    queue = MissionQueue(
        tmp_path / "queue.sqlite3",
        require_execution_fence=True,
        mission_store=store,
    )
    scheduler = MissionScheduler(
        tmp_path / "scheduler.sqlite3",
        queue,
        mission_store=store,
        fault_injector=failpoint,
    )
    core = AgentCore(ModelRouter([]), store=store)
    service = MissionService(
        runtime,
        queue,
        scheduler,
        owner_revalidator=core.prepare_mission_for_queue,
    )
    plan = Plan.initial("run one authorized scheduled step").replan(
        steps=(PlanStep("scheduled-step", "check status", action="status"),),
        reason="v9 test plan",
    )
    mission = runtime.create(
        "run one authorized scheduled step",
        "run one authorized scheduled step",
        plan,
        request_id="v9-schedule-request",
        owner_identity_ref="owner:1",
    )
    worker = MissionWorker(queue, runtime_factory, scheduler=scheduler)
    return store, runtime, queue, scheduler, service, mission, worker, executions


def _due_soon() -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()


def _schedule(service: MissionService, mission_id: str, *, schedule_id: str = "v9-once"):
    return service.schedule_mission(
        mission_id,
        owner_session_token="current-owner-session",
        run_at=_due_soon(),
        schedule_id=schedule_id,
    )


def test_schedule_requires_fresh_owner_and_persists_only_snapshot_binding(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, _executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()

    result = _schedule(service, mission.mission_id)

    assert result["schedule_id"] == "v9-once"
    assert scheduler.get("v9-once").state is WorkerMissionState.SCHEDULED
    assert queue.get(mission.mission_id).state is WorkerMissionState.SCHEDULED
    persisted = store.load(mission.mission_id)
    snapshot = persisted.authorization_snapshot
    with sqlite3.connect(scheduler.db_path) as db:
        row = db.execute(
            "SELECT owner_identity_ref,authorization_hash,authorization_version,authorization_expires_at "
            "FROM mission_schedules WHERE schedule_id=?",
            ("v9-once",),
        ).fetchone()
    assert row == (
        "owner:1",
        snapshot["authorization_hash"],
        snapshot["version"],
        snapshot["expires_at"],
    )
    with sqlite3.connect(scheduler.db_path) as db:
        raw = repr(db.execute("SELECT * FROM mission_schedules").fetchone())
    assert "current-owner-session" not in raw
    assert persisted.provenance["authorization_snapshot_version"] == snapshot["version"]


def test_scheduled_queue_row_is_not_claimable_without_snapshot_validation(tmp_path, monkeypatch):
    _store, _runtime, queue, _scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)

    item = queue.claim_next(
        now=datetime.now(timezone.utc).isoformat(),
        worker_id=worker.worker_id,
        worker_instance_id=worker.worker_instance_id,
        runtime_generation=worker.runtime_generation,
        execution_fence=worker.identity_fence,
    )

    assert item is None
    assert executions == []
    assert queue.get(mission.mission_id).state is WorkerMissionState.SCHEDULED


def test_supervised_worker_validates_and_promotes_due_schedule_before_claim(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)

    result = worker.run_once()

    assert result is not None
    assert result.state is WorkerMissionState.EXECUTING
    assert result.claim_phase == "BOUND"
    assert queue.get(mission.mission_id).state is WorkerMissionState.EXECUTING
    assert store.load(mission.mission_id).status is MissionStatus.RUNNING
    assert scheduler.get("v9-once").state is WorkerMissionState.COMPLETED
    assert executions == []


def test_expired_snapshot_quarantines_due_mission_without_dispatch(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    persisted = store.load(mission.mission_id)
    expiry = datetime.fromisoformat(persisted.authorization_snapshot["expires_at"])
    after_expiry = (expiry + timedelta(seconds=1)).isoformat()

    dispatched = scheduler.dispatch_due(now=after_expiry)

    assert len(dispatched) == 1
    assert dispatched[0].state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert executions == []


def test_owner_or_snapshot_identity_change_quarantines_instead_of_rescheduling(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    persisted = store.load(mission.mission_id)
    persisted.owner_identity_ref = "owner:2"
    store.save(persisted)

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert len(result) == 1
    assert result[0].state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert executions == []


def test_duplicate_due_poll_is_idempotent_and_never_reopens_queue(tmp_path, monkeypatch):
    _store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    current = datetime.now(timezone.utc).isoformat()

    first = scheduler.dispatch_due(now=current)
    second = scheduler.dispatch_due(now=current)

    assert len(first) == 1
    assert first[0].state is WorkerMissionState.COMPLETED
    assert second == []
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED
    assert executions == []


def test_crash_after_queue_promotion_rolls_back_queue_and_schedule_together(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)

    def die(boundary: str):
        if boundary == "after_queue_promotion":
            raise RuntimeError("injected process-death boundary")

    scheduler.fault_injector = die
    with pytest.raises(RuntimeError, match="injected process-death boundary"):
        scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert scheduler.get("v9-once").state is WorkerMissionState.SCHEDULED
    assert queue.get(mission.mission_id).state is WorkerMissionState.SCHEDULED
    assert store.load(mission.mission_id).status is MissionStatus.READY
    assert executions == []

    scheduler.fault_injector = None
    retried = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())
    assert len(retried) == 1
    assert retried[0].state is WorkerMissionState.COMPLETED
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED


def test_restart_quarantine_prevents_a_previously_valid_schedule_from_resurrecting(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)

    replacement_queue = MissionQueue(
        queue.db_path,
        require_execution_fence=True,
        mission_store=store,
    )
    replacement_scheduler = MissionScheduler(
        scheduler.db_path,
        replacement_queue,
        mission_store=store,
    )
    replacement_worker = MissionWorker(
        replacement_queue,
        lambda: MissionRuntime(
            store,
            executor=lambda *_args: executions.append("should-not-run"),
            authorization_snapshot_factory=make_test_snapshot,
            require_authorization_snapshot=True,
            require_execution_fence=True,
        ),
        scheduler=replacement_scheduler,
    )
    replacement_worker.recover_after_restart()

    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert replacement_queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    dispatched = replacement_scheduler.dispatch_due(now=(datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat())
    assert dispatched[0].state is WorkerMissionState.NEEDS_INPUT
    assert executions == []


def test_stale_or_foreign_owner_cannot_create_schedule_and_recurrence_is_rejected(tmp_path, monkeypatch):
    import security.owner_password as owner_password

    sessions = {
        "current-owner-session": {
            "session_id": "current-owner-session",
            "owner_id": 1,
            "username": "owner-one",
            "auth_method": "username_password",
            "expires_at": "2999-01-01T00:00:00+00:00",
        },
        "foreign-owner-session": {
            "session_id": "foreign-owner-session",
            "owner_id": 2,
            "username": "owner-two",
            "auth_method": "username_password",
            "expires_at": "2999-01-01T00:00:00+00:00",
        },
    }
    monkeypatch.setattr(owner_password, "resolve_session", lambda token: sessions.get(token))
    _store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()

    with pytest.raises(PermissionError):
        service.schedule_mission(
            mission.mission_id,
            owner_session_token="revoked-session",
            run_at=_due_soon(),
            schedule_id="revoked",
        )
    with pytest.raises(PermissionError):
        service.schedule_mission(
            mission.mission_id,
            owner_session_token="foreign-owner-session",
            run_at=_due_soon(),
            schedule_id="foreign",
        )
    with pytest.raises(ValueError, match="recurring missions require"):
        service.schedule_mission(
            mission.mission_id,
            owner_session_token="current-owner-session",
            run_at=_due_soon(),
            interval_seconds=60,
            schedule_id="recurring",
        )
    with pytest.raises(ValueError, match="scheduled mission retries are not supported"):
        service.schedule_mission(
            mission.mission_id,
            owner_session_token="current-owner-session",
            run_at=_due_soon(),
            retry_limit=1,
            schedule_id="automatic-retry",
        )

    with sqlite3.connect(scheduler.db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM mission_schedules").fetchone()[0] == 0
    with pytest.raises(KeyError):
        queue.get(mission.mission_id)
    assert executions == []


def test_wal_mode_fails_closed_before_creating_bound_schedule(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    with sqlite3.connect(scheduler.db_path) as db:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"

    with pytest.raises(ExecutionFenceError, match="rollback-journal mode"):
        _schedule(service, mission.mission_id)

    with sqlite3.connect(scheduler.db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM mission_schedules").fetchone()[0] == 0
    with pytest.raises(KeyError):
        queue.get(mission.mission_id)
    assert executions == []


@pytest.mark.parametrize("boundary", ["after_schedule_insert", "after_queue_scheduled"])
def test_crash_during_schedule_creation_rolls_back_both_stores(tmp_path, monkeypatch, boundary):
    def die(current: str):
        if current == boundary:
            raise RuntimeError("injected schedule-creation death")

    _store, _runtime, queue, scheduler, service, mission, worker, _executions = _fixture(
        tmp_path,
        monkeypatch,
        failpoint=die,
    )
    worker.recover_after_restart()

    with pytest.raises(RuntimeError, match="injected schedule-creation death"):
        _schedule(service, mission.mission_id)

    with sqlite3.connect(scheduler.db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM mission_schedules").fetchone()[0] == 0
    with pytest.raises(KeyError):
        queue.get(mission.mission_id)


def test_legacy_schedule_without_owner_snapshot_binding_is_quarantined(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, _service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    queue.enqueue(mission.mission_id, state=WorkerMissionState.SCHEDULED, available_at=_due_soon())
    with sqlite3.connect(scheduler.db_path) as db:
        db.execute(
            "INSERT INTO mission_schedules(schedule_id,mission_id,next_run_at,interval_seconds,retry_limit,retries,state,owner_identity_ref,authorization_hash,authorization_version,authorization_expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "legacy-unbound",
                mission.mission_id,
                _due_soon(),
                None,
                0,
                0,
                WorkerMissionState.SCHEDULED.value,
                "",
                "",
                0,
                "",
            ),
        )

    dispatched = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert len(dispatched) == 1
    assert dispatched[0].state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert executions == []


def test_due_time_beyond_owner_snapshot_expiry_is_rejected(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    far_future = "2099-01-01T00:00:00+00:00"

    with pytest.raises(PermissionError, match="outside the Owner authorization window"):
        service.schedule_mission(
            mission.mission_id,
            owner_session_token="current-owner-session",
            run_at=far_future,
            schedule_id="beyond-snapshot",
        )

    with sqlite3.connect(scheduler.db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM mission_schedules").fetchone()[0] == 0
    with pytest.raises(KeyError):
        queue.get(mission.mission_id)
    assert store.load(mission.mission_id).status is MissionStatus.READY
    assert executions == []


def test_tampered_snapshot_digest_is_quarantined_before_queue_promotion(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    persisted = store.load(mission.mission_id)
    persisted.authorization_snapshot["authorization_hash"] = "0" * 64
    store.save(persisted)

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert result[0].state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert executions == []


def test_active_worker_lease_blocks_new_schedule_without_releasing_claim(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    service.start_mission(mission.mission_id, owner_session_token="current-owner-session")
    claim = queue.claim_next(
        now=datetime.now(timezone.utc).isoformat(),
        worker_id=worker.worker_id,
        worker_instance_id=worker.worker_instance_id,
        runtime_generation=worker.runtime_generation,
        execution_fence=worker.identity_fence,
    )
    assert claim is not None
    assert claim.state is WorkerMissionState.EXECUTING

    with pytest.raises(PermissionError, match="active worker lease"):
        service.schedule_mission(
            mission.mission_id,
            owner_session_token="current-owner-session",
            run_at=_due_soon(),
            schedule_id="leased-mission",
        )

    assert queue.get(mission.mission_id).state is WorkerMissionState.EXECUTING
    assert store.load(mission.mission_id).status is MissionStatus.READY
    with sqlite3.connect(scheduler.db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM mission_schedules").fetchone()[0] == 0
    assert executions == []


def test_revoked_owner_session_before_due_dispatch_quarantines_scheduled_mission(tmp_path, monkeypatch):
    import core.db as core_db

    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    with sqlite3.connect(core_db.DB_PATH) as auth_db:
        auth_db.execute(
            "UPDATE owner_sessions SET status='revoked' WHERE session_id=?",
            (session_reference("current-owner-session"),),
        )

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert result[0].state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert executions == []


def test_owner_auth_store_wal_mode_fails_closed_before_schedule_creation(tmp_path, monkeypatch):
    import core.db as core_db

    _store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    with sqlite3.connect(core_db.DB_PATH) as auth_db:
        assert auth_db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"

    with pytest.raises(ExecutionFenceError, match="rollback-journal mode"):
        _schedule(service, mission.mission_id)

    with sqlite3.connect(scheduler.db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM mission_schedules").fetchone()[0] == 0
    with pytest.raises(KeyError):
        queue.get(mission.mission_id)
    assert executions == []


def test_schedule_with_wrong_authorization_version_is_quarantined(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    with sqlite3.connect(scheduler.db_path) as db:
        db.execute(
            "UPDATE mission_schedules SET authorization_version=authorization_version+1 WHERE schedule_id=?",
            ("v9-once",),
        )

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert result[0].state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert executions == []


def test_cancelled_mission_schedule_is_retired_without_queue_resurrection(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    service.cancel_mission(mission.mission_id, owner_session_token="current-owner-session")

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert scheduler.get("v9-once").state is WorkerMissionState.CANCELLED
    assert result == []
    assert store.load(mission.mission_id).status is MissionStatus.CANCELLED
    assert queue.get(mission.mission_id).state is WorkerMissionState.CANCELLED
    assert executions == []


def test_due_dispatch_is_portable_across_worker_evidence_key_rotation(tmp_path, monkeypatch):
    import security.owner_policy as owner_policy

    store, _runtime, queue, scheduler, service, mission, worker, _executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    monkeypatch.setattr(owner_policy, "_EVIDENCE_SECRET", b"independent-worker-process-key")

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert result[0].state is WorkerMissionState.COMPLETED
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED
    assert store.load(mission.mission_id).status is MissionStatus.READY


def test_serialized_owner_context_uses_active_session_after_process_key_rotation(tmp_path, monkeypatch):
    import core.db as core_db
    import security.owner_password as owner_password
    import security.owner_policy as owner_policy
    from security.authorization_context import AuthorizationContext

    persistent_resolver = owner_password.resolve_session
    persistent_reference_resolver = owner_password._resolve_session_reference
    store, _runtime, _queue, _scheduler, service, mission, worker, _executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    persisted = store.load(mission.mission_id)
    assert isinstance(persisted.authorization_context, dict)
    monkeypatch.setattr(owner_policy, "_EVIDENCE_SECRET", b"independent-worker-process-key")
    monkeypatch.setattr(owner_password, "resolve_session", persistent_resolver)
    monkeypatch.setattr(owner_password, "_resolve_session_reference", persistent_reference_resolver)

    context = AuthorizationContext.from_dict(dict(persisted.authorization_context))
    assert context.request_id == persisted.request_id
    forged = dict(persisted.authorization_context)
    forged["owner_evidence"] = dict(forged["owner_evidence"])
    forged["owner_evidence"]["proof_fingerprint"] = "0" * 64
    with pytest.raises(PermissionError, match="stale or invalid Owner evidence"):
        AuthorizationContext.from_dict(forged)
    with sqlite3.connect(core_db.DB_PATH) as auth_db:
        auth_db.execute("UPDATE owner_sessions SET status='revoked' WHERE session_id=?", (session_reference("current-owner-session"),))
    with pytest.raises(PermissionError, match="stale or invalid Owner evidence"):
        AuthorizationContext.from_dict(dict(persisted.authorization_context))


def test_owner_bound_scheduler_normalizes_equivalent_offset_due_times(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    offset = timezone(timedelta(hours=1))
    run_at = (datetime.now(timezone.utc) - timedelta(seconds=5)).astimezone(offset).isoformat()

    created = service.schedule_mission(
        mission.mission_id,
        owner_session_token="current-owner-session",
        run_at=run_at,
        schedule_id="offset-bound",
    )
    assert created["schedule_id"] == "offset-bound"
    assert datetime.fromisoformat(scheduler.get("offset-bound").next_run_at) == datetime.fromisoformat(run_at).astimezone(timezone.utc)

    dispatched = scheduler.dispatch_due(now=datetime.now(timezone.utc).astimezone(offset).isoformat())

    assert dispatched[0].state is WorkerMissionState.COMPLETED
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED
    assert store.load(mission.mission_id).status is MissionStatus.READY
    assert executions == []


def test_malformed_mission_provenance_version_is_quarantined(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    persisted = store.load(mission.mission_id)
    persisted.provenance["authorization_snapshot_version"] = "not-an-integer"
    store.save(persisted)

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert result[0].state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert executions == []


def test_malformed_schedule_snapshot_version_is_quarantined(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    with sqlite3.connect(scheduler.db_path) as db:
        db.execute(
            "UPDATE mission_schedules SET authorization_version=? WHERE schedule_id=?",
            ("not-an-integer", "v9-once"),
        )

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert result[0].state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert executions == []


@pytest.mark.parametrize("operation", ["start", "resume"])
def test_owner_start_or_resume_retires_pending_schedule(tmp_path, monkeypatch, operation):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)

    if operation == "start":
        service.start_mission(mission.mission_id, owner_session_token="current-owner-session")
    else:
        service.resume_mission(mission.mission_id, owner_session_token="current-owner-session")

    assert scheduler.get("v9-once").state is WorkerMissionState.CANCELLED
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED
    assert store.load(mission.mission_id).status is MissionStatus.READY
    assert scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat()) == []
    assert executions == []


def test_schedule_service_rejects_malformed_provenance_without_server_error(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    reauthorize = service.owner_revalidator

    def corrupt_after_reauthorization(mission_id: str, session_token: str):
        evidence = reauthorize(mission_id, session_token)
        persisted = store.load(mission_id)
        persisted.provenance["authorization_snapshot_version"] = "not-an-integer"
        store.save(persisted)
        return evidence

    service.owner_revalidator = corrupt_after_reauthorization

    with pytest.raises(PermissionError, match="provenance version is invalid"):
        service.schedule_mission(
            mission.mission_id,
            owner_session_token="current-owner-session",
            run_at=_due_soon(),
            schedule_id="bad-provenance",
        )

    with sqlite3.connect(scheduler.db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM mission_schedules").fetchone()[0] == 0
    with pytest.raises(KeyError):
        queue.get(mission.mission_id)
    assert executions == []


def test_malformed_queue_state_is_quarantined_without_worker_crash(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    with sqlite3.connect(queue.db_path) as db:
        db.execute("UPDATE mission_queue SET state=? WHERE mission_id=?", ("CORRUPT", mission.mission_id))

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert result[0].state is WorkerMissionState.NEEDS_INPUT
    assert scheduler.get("v9-once").state is WorkerMissionState.NEEDS_INPUT
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert worker.run_once() is None
    assert executions == []


@pytest.mark.parametrize("field", ["progress", "checkpoint"])
def test_malformed_mission_runtime_state_is_quarantined_for_recovery(tmp_path, monkeypatch, field):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    persisted = store.load(mission.mission_id)
    setattr(persisted, field, ["malformed-runtime-state"])
    import json

    with sqlite3.connect(store.db_path) as db:
        db.execute(
            "UPDATE missions SET payload=? WHERE mission_id=?",
            (json.dumps(persisted.to_dict(), ensure_ascii=False), mission.mission_id),
        )

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert result[0].state is WorkerMissionState.NEEDS_INPUT
    assert scheduler.get("v9-once").state is WorkerMissionState.NEEDS_INPUT
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    recovered = store.load(mission.mission_id)
    assert recovered.status is MissionStatus.RECOVERY_REQUIRED
    assert getattr(recovered, field) == ["malformed-runtime-state"]
    assert worker.run_once() is None
    assert executions == []


def test_malformed_due_timestamp_is_quarantined(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    with sqlite3.connect(scheduler.db_path) as db:
        db.execute("UPDATE mission_schedules SET next_run_at=? WHERE schedule_id=?", ("not-a-time", "v9-once"))

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert result[0].state is WorkerMissionState.NEEDS_INPUT
    assert scheduler.get("v9-once").state is WorkerMissionState.NEEDS_INPUT
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert worker.run_once() is None
    assert store.load(mission.mission_id).status is MissionStatus.READY
    assert executions == []


def test_malformed_mission_payload_is_quarantined_without_worker_crash(tmp_path, monkeypatch):
    _store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    with sqlite3.connect(queue.mission_store.db_path) as db:
        db.execute("UPDATE missions SET payload=? WHERE mission_id=?", ("not-json", mission.mission_id))

    result = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())

    assert result[0].state is WorkerMissionState.NEEDS_INPUT
    assert scheduler.get("v9-once").state is WorkerMissionState.NEEDS_INPUT
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert worker.run_once() is None
    assert executions == []


def test_owner_start_does_not_enqueue_when_concurrent_due_poll_quarantines_stale_snapshot(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    owner_revalidator = service.owner_revalidator

    def poll_after_snapshot_renewal(mission_id: str, session_token: str):
        evidence = owner_revalidator(mission_id, session_token)
        due = scheduler.dispatch_due(now=datetime.now(timezone.utc).isoformat())
        assert due[0].state is WorkerMissionState.NEEDS_INPUT
        return evidence

    service.owner_revalidator = poll_after_snapshot_renewal
    with pytest.raises(PermissionError, match="quarantined during Owner reauthorization"):
        service.start_mission(mission.mission_id, owner_session_token="current-owner-session")

    assert scheduler.get("v9-once").state is WorkerMissionState.NEEDS_INPUT
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert worker.run_once() is None
    assert executions == []


def test_malformed_queue_timestamp_is_quarantined_before_strict_restart_poll(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    with sqlite3.connect(queue.db_path) as db:
        db.execute("UPDATE mission_queue SET available_at=? WHERE mission_id=?", ("not-a-time", mission.mission_id))

    restarted_queue = MissionQueue(queue.db_path, require_execution_fence=True, mission_store=store)
    assert restarted_queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    restarted_scheduler = MissionScheduler(scheduler.db_path, restarted_queue, mission_store=store)
    restarted_worker = MissionWorker(restarted_queue, worker.runtime_factory, scheduler=restarted_scheduler)
    recovered = restarted_worker.recover_after_restart()

    assert recovered[0].state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert restarted_worker.run_once() is None
    assert restarted_scheduler.get("v9-once").state is WorkerMissionState.NEEDS_INPUT
    assert executions == []


def test_malformed_lease_timestamp_is_quarantined_without_claim(tmp_path):
    db_path = tmp_path / "lease-corruption.sqlite3"
    queue = MissionQueue(db_path)
    queue.enqueue("lease-corruption", available_at=_due_soon())
    claim = queue.claim_next(now=_due_soon(), worker_id="worker", lease_seconds=60)
    assert claim is not None
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE mission_queue SET lease_expires_at=? WHERE mission_id=?", ("not-a-time", "lease-corruption"))

    restarted = MissionQueue(db_path)
    quarantined = restarted.get("lease-corruption")

    assert quarantined.state is WorkerMissionState.WAITING_FOR_TOOL
    assert quarantined.lease_owner is None
    assert quarantined.lease_expires_at is None
    assert quarantined.lease_epoch == claim.lease_epoch
    assert restarted.claim_next(now=_due_soon(), worker_id="recovery-check") is None


def test_malformed_schedule_timestamp_is_quarantined_during_scheduler_startup(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    with sqlite3.connect(scheduler.db_path) as db:
        db.execute("UPDATE mission_schedules SET next_run_at=? WHERE schedule_id=?", ("not-a-time", "v9-once"))

    restarted_scheduler = MissionScheduler(scheduler.db_path, queue, mission_store=store)
    assert restarted_scheduler.get("v9-once").state is WorkerMissionState.NEEDS_INPUT
    restarted_worker = MissionWorker(queue, worker.runtime_factory, scheduler=restarted_scheduler)
    restarted_worker.recover_after_restart()

    assert restarted_worker.run_once() is None
    assert queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert executions == []


def test_null_legacy_queue_available_at_is_quarantined(tmp_path):
    db_path = tmp_path / "nullable-legacy-queue.sqlite3"
    with sqlite3.connect(db_path) as db:
        db.execute(
            "CREATE TABLE mission_queue (mission_id TEXT PRIMARY KEY,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,available_at TEXT,claimed_at TEXT,last_error TEXT NOT NULL DEFAULT '')"
        )
        db.execute(
            "INSERT INTO mission_queue(mission_id,state,available_at) VALUES(?,?,NULL)",
            ("null-queue-time", WorkerMissionState.QUEUED.value),
        )

    queue = MissionQueue(db_path)

    item = queue.get("null-queue-time")
    assert item.state is WorkerMissionState.WAITING_FOR_TOOL
    assert item.available_at
    assert "malformed" in item.last_error
    assert queue.claim_next(now=_due_soon(), worker_id="recovery-check") is None


def test_null_legacy_schedule_time_is_quarantined_at_scheduler_startup(tmp_path):
    queue = MissionQueue(tmp_path / "null-schedule-queue.sqlite3")
    scheduler_path = tmp_path / "nullable-legacy-scheduler.sqlite3"
    with sqlite3.connect(scheduler_path) as db:
        db.execute(
            "CREATE TABLE mission_schedules (schedule_id TEXT PRIMARY KEY,mission_id TEXT NOT NULL,next_run_at TEXT,interval_seconds INTEGER,retry_limit INTEGER NOT NULL,retries INTEGER NOT NULL,state TEXT NOT NULL)"
        )
        db.execute(
            "INSERT INTO mission_schedules(schedule_id,mission_id,next_run_at,retry_limit,retries,state) VALUES(?,?,?,?,?,?)",
            ("null-run-time", "mission-null-run-time", None, 0, 0, WorkerMissionState.SCHEDULED.value),
        )

    scheduler = MissionScheduler(scheduler_path, queue)

    assert scheduler.get("null-run-time").state is WorkerMissionState.NEEDS_INPUT



def test_concurrent_due_polls_promote_one_schedule_across_scheduler_instances(tmp_path, monkeypatch):
    store, _runtime, queue, scheduler, service, mission, worker, executions = _fixture(tmp_path, monkeypatch)
    worker.recover_after_restart()
    _schedule(service, mission.mission_id)
    competing_scheduler = MissionScheduler(
        scheduler.db_path,
        queue,
        mission_store=store,
    )
    due = datetime.now(timezone.utc).isoformat()
    barrier = Barrier(3)

    def poll(instance):
        barrier.wait(timeout=10)
        return instance.dispatch_due(now=due, limit=1)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(poll, instance) for instance in (scheduler, competing_scheduler)]
        barrier.wait(timeout=10)
        outcomes = [future.result(timeout=20) for future in futures]

    promoted = [item for outcome in outcomes for item in outcome]
    assert len(promoted) == 1
    assert promoted[0].state is WorkerMissionState.COMPLETED
    assert scheduler.get("v9-once").state is WorkerMissionState.COMPLETED
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED
    assert executions == []
