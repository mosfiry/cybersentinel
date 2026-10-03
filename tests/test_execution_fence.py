from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import sqlite3

import pytest

from agent.evidence import EvidenceChainStore
from agent.execution_fence import ExecutionFence, ExecutionFenceError
from agent.mission import Mission, MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, WorkerMissionState
from agent.planning import Plan, PlanStep
from security.mission_authorization import MissionAuthorizationSnapshot
from tools import registry as registry_module
from tools.registry import ToolSpec


def _authorization(mission_id: str, *, allowed_tool: str = "fence_probe") -> MissionAuthorizationSnapshot:
    created = datetime.now(timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity="owner-test",
        mission_id=mission_id,
        target_identity="target-test",
        scope=("workspace",),
        allowed_actions=(allowed_tool,),
        forbidden_actions=(),
        allowed_tools=(allowed_tool,),
        time_window={"timezone": "UTC"},
        max_duration=900,
        rate_limits={allowed_tool: 10},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("target-test",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": "/tmp"},
        policy_version="execution-fence-test",
        owner_approval="owner-proof-test",
        created_at=created.isoformat(),
        expires_at=(created + timedelta(minutes=10)).isoformat(),
    )


def _mission(store: MissionStore, mission_id: str = "fenced-mission") -> tuple[Mission, MissionAuthorizationSnapshot]:
    snapshot = _authorization(mission_id)
    mission = Mission.create(
        "test request",
        "verify a fenced side effect",
        Plan(version=1, objective="verify a fenced side effect", steps=(PlanStep("step-1", "perform the probe", action="fence_probe"),)),
        mission_id=mission_id,
        request_id="request-fence-1",
        owner_identity_ref="owner-test",
        scope_snapshot={"target_id": "target-test", "workspace_root": "/tmp"},
        authorization_snapshot=snapshot.to_dict(),
    )
    mission.transition(MissionStatus.READY, "test mission ready")
    store.save(mission)
    return mission, snapshot


def _leased_fence(tmp_path: Path):
    store = MissionStore(tmp_path / "missions.sqlite3")
    mission, snapshot = _mission(store)
    queue = MissionQueue(tmp_path / "queue.sqlite3", require_execution_fence=True, mission_store=store)
    queue.enqueue(mission.mission_id)
    identity = queue.register_worker("stable-test-worker")
    identity_fence = ExecutionFence.for_worker(queue, identity)
    now = datetime.now(timezone.utc).isoformat()
    claim = queue.claim_next(
        now=now,
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=600,
        execution_fence=identity_fence,
    )
    assert claim is not None
    fence = identity_fence.with_lease(claim).for_mission(
        mission, task_id="step-1", execution_id="execution-1"
    )
    binding = store.bind_execution_claim(mission.mission_id, fence)
    assert binding.terminal_status is None and binding.lease_binding_id is not None
    mission = store.load(mission.mission_id)
    assert mission is not None
    return store, mission, snapshot, queue, identity, claim, fence


def _mark_active_execution(store: MissionStore, mission: Mission, fence: ExecutionFence) -> Mission:
    mission.checkpoint = {
        "status": "in_flight",
        "step_id": fence.task_id,
        "action_id": fence.execution_id,
        "plan_version": mission.plan.version,
    }
    return store.save(mission, execution_fence=fence)


def test_strict_queue_claim_heartbeat_update_release_and_retirement_require_fence(tmp_path):
    store = MissionStore(tmp_path / "strict-missions.sqlite3")
    mission, _snapshot = _mission(store, "strict-mission")
    queue = MissionQueue(tmp_path / "strict.sqlite3", require_execution_fence=True, mission_store=store)
    queue.enqueue("strict-mission")
    identity = queue.register_worker("strict-worker")
    now = datetime.now(timezone.utc).isoformat()

    with pytest.raises(ExecutionFenceError, match="claim requires"):
        queue.claim_next(now=now, worker_id=identity.worker_id, worker_instance_id=identity.worker_instance_id, runtime_generation=identity.runtime_generation)
    assert queue.get("strict-mission").state is WorkerMissionState.QUEUED

    identity_fence = ExecutionFence.for_worker(queue, identity)
    claim = queue.claim_next(
        now=now,
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        execution_fence=identity_fence,
    )
    assert claim is not None
    fence = identity_fence.with_lease(claim).for_mission(mission)
    with pytest.raises(ExecutionFenceError, match="MissionStore claim marker"):
        queue.mark_claim_bound(fence)
    assert queue.get(claim.mission_id).claim_phase == "CLAIMED"
    store.bind_execution_claim(mission.mission_id, fence)
    assert queue.get(claim.mission_id).claim_phase == "BOUND"

    with pytest.raises(ExecutionFenceError, match="recovery requires"):
        queue.recover_after_restart(now=now)
    assert queue.recover_after_restart(now=now, execution_fence=identity_fence) == []

    with pytest.raises(ExecutionFenceError, match="heartbeat requires"):
        queue.heartbeat(claim.mission_id, worker_id=identity.worker_id, worker_instance_id=identity.worker_instance_id, lease_epoch=claim.lease_epoch)
    with pytest.raises(ExecutionFenceError, match="update requires"):
        queue.update(claim.mission_id, WorkerMissionState.COMPLETED, worker_id=identity.worker_id, worker_instance_id=identity.worker_instance_id, lease_epoch=claim.lease_epoch)
    with pytest.raises(ExecutionFenceError, match="release requires"):
        queue.release(claim.mission_id, WorkerMissionState.WAITING_FOR_TOOL, worker_id=identity.worker_id, worker_instance_id=identity.worker_instance_id, lease_epoch=claim.lease_epoch)
    with pytest.raises(ExecutionFenceError, match="retirement requires"):
        queue.deactivate_worker(identity)

    renewed = queue.heartbeat(
        claim.mission_id,
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_epoch=claim.lease_epoch,
        execution_fence=fence,
    )
    assert renewed.lease_epoch == claim.lease_epoch
    queue.deactivate_worker(identity, execution_fence=identity_fence)


def test_task_request_authorization_and_effect_reservation_are_bound_to_fence(tmp_path):
    _store, mission, snapshot, _queue, _identity, _claim, fence = _leased_fence(tmp_path)

    with pytest.raises(ExecutionFenceError, match="task mismatch"):
        fence.assert_current(task_id="another-task")
    with pytest.raises(ExecutionFenceError, match="task version mismatch"):
        fence.assert_current(task_version=mission.plan.version + 1)
    with pytest.raises(ExecutionFenceError, match="request mismatch"):
        fence.assert_current(request_id="another-request")
    with pytest.raises(ExecutionFenceError, match="execution identity mismatch"):
        fence.assert_current(execution_id="another-execution")
    with pytest.raises(ExecutionFenceError, match="authorization snapshot mismatch"):
        fence.assert_current(authorization_snapshot={"not": "the authorized snapshot"})

    reservation = fence.assert_effect_reservation({"provider": "fixture", "payload_digest": "digest-1"})
    assert reservation["fence_id"] == fence.fence_id
    assert reservation["authorization_hash"] == fence.authorization_hash
    assert reservation["lease_epoch"] == fence.lease_epoch
    with pytest.raises(ExecutionFenceError, match="execution identity mismatch"):
        fence.assert_effect_reservation({"execution_id": "wrong-execution"})


def test_superseded_generation_cannot_write_mission_evidence_or_dispatch_tools(tmp_path, monkeypatch):
    store, mission, snapshot, queue, identity, claim, fence = _leased_fence(tmp_path)
    effects: list[str] = []
    spec = ToolSpec(
        "fence_probe",
        "test-only side-effect probe",
        "analysis",
        False,
        None,
        lambda _argument: effects.append("ran") or {"ok": True},
    )
    monkeypatch.setattr(registry_module, "get_tool", lambda name: spec if name == spec.name else None)

    with pytest.raises(ExecutionFenceError, match="mission-bound tool dispatch requires"):
        registry_module.execute(
            "fence_probe",
            request_id=mission.request_id,
            mission_authorization=snapshot,
            mission_id=mission.mission_id,
            target_identity=snapshot.target_identity,
            execution_id="execution-1",
        )
    assert effects == []

    with pytest.raises(ExecutionFenceError, match="in-flight mission checkpoint"):
        registry_module.execute(
            "fence_probe",
            request_id=mission.request_id,
            mission_authorization=snapshot,
            mission_id=mission.mission_id,
            target_identity=snapshot.target_identity,
            execution_fence=fence,
            execution_id="execution-1",
        )
    assert effects == []
    mission = _mark_active_execution(store, mission, fence)

    wrong_identity = queue.register_worker("wrong-worker")
    wrong_worker_fence = ExecutionFence.for_worker(queue, wrong_identity).with_lease(claim).for_mission(
        mission, task_id="step-1", execution_id="execution-1"
    )
    with pytest.raises(ExecutionFenceError, match="mission lease is no longer owned"):
        registry_module.execute(
            "fence_probe",
            request_id=mission.request_id,
            mission_authorization=snapshot,
            mission_id=mission.mission_id,
            target_identity=snapshot.target_identity,
            execution_fence=wrong_worker_fence,
            execution_id="execution-1",
        )
    assert effects == []

    result = registry_module.execute(
        "fence_probe",
        request_id=mission.request_id,
        mission_authorization=snapshot,
        mission_id=mission.mission_id,
        target_identity=snapshot.target_identity,
        execution_fence=fence,
        execution_id="execution-1",
    )
    assert result == {"ok": True}
    assert effects == ["ran"]

    with pytest.raises(ExecutionFenceError, match="execution identity mismatch"):
        registry_module.execute(
            "fence_probe",
            request_id=mission.request_id,
            mission_authorization=snapshot,
            mission_id=mission.mission_id,
            target_identity=snapshot.target_identity,
            execution_fence=fence,
            execution_id="wrong-execution",
        )
    assert effects == ["ran"]

    mismatched_snapshot = _authorization(mission.mission_id)
    with pytest.raises(ExecutionFenceError, match="authorization snapshot mismatch"):
        registry_module.execute(
            "fence_probe",
            request_id=mission.request_id,
            mission_authorization=mismatched_snapshot,
            mission_id=mission.mission_id,
            target_identity=mismatched_snapshot.target_identity,
            execution_fence=fence,
            execution_id="execution-1",
        )
    assert effects == ["ran"]

    evidence_store = EvidenceChainStore(
        tmp_path / "evidence.sqlite3",
        execution_fence=fence,
        mission_store=store,
        mission=mission,
        require_execution_fence=True,
    )
    appended = evidence_store.append({
        "claim": "the fenced probe completed",
        "source": "fence_probe",
        "evidence": {"ok": True},
        "request_id": mission.request_id,
        "mission_id": mission.mission_id,
    })
    assert appended["worker_instance_id"] == identity.worker_instance_id
    assert appended["runtime_generation"] == identity.runtime_generation
    assert appended["lease_epoch"] == claim.lease_epoch
    assert appended["task_id"] == "step-1"
    assert appended["task_version"] == mission.plan.version
    assert appended["authorization_hash"] == fence.authorization_hash
    assert appended["fence_id"] == fence.fence_id
    assert evidence_store.verify()
    stored_after_evidence = store.load(mission.mission_id)
    assert stored_after_evidence.progress["execution_evidence_refs"] == [
        evidence_store._receipt(appended)
    ]
    assert mission.integrity_hash == stored_after_evidence.integrity_hash

    mission.progress["current_fenced_write"] = True
    store.save(mission, execution_fence=fence)
    assert store.load(mission.mission_id).progress["current_fenced_write"] is True

    queue.register_worker(identity.worker_id)
    mission.progress["stale_write"] = True
    with pytest.raises(ExecutionFenceError, match="active registered execution identity"):
        store.save(mission, execution_fence=fence)
    assert "stale_write" not in store.load(mission.mission_id).progress

    with pytest.raises(ExecutionFenceError, match="active registered execution identity"):
        evidence_store.append({
            "claim": "stale evidence must not append",
            "source": "fence_probe",
            "evidence": {"ok": True},
            "request_id": mission.request_id,
            "mission_id": mission.mission_id,
        })
    assert len(evidence_store.list()) == 1

    with pytest.raises(ExecutionFenceError, match="active registered execution identity"):
        registry_module.execute(
            "fence_probe",
            request_id=mission.request_id,
            mission_authorization=snapshot,
            mission_id=mission.mission_id,
            target_identity=snapshot.target_identity,
            execution_fence=fence,
            execution_id="execution-1",
        )
    assert effects == ["ran"]


def test_evidence_append_rejects_wrong_execution_and_epoch(tmp_path):
    store, mission, _snapshot, _queue, _identity, claim, fence = _leased_fence(tmp_path)
    mission = _mark_active_execution(store, mission, fence)
    evidence_store = EvidenceChainStore(
        tmp_path / "bound-evidence.sqlite3",
        execution_fence=fence,
        mission_store=store,
        mission=mission,
        require_execution_fence=True,
    )
    item = {
        "claim": "fenced evidence",
        "source": "test",
        "evidence": {"ok": True},
        "mission_id": mission.mission_id,
        "request_id": mission.request_id,
    }

    with pytest.raises(ExecutionFenceError, match="active mission checkpoint"):
        evidence_store.append(item, execution_fence=replace(fence, task_id="wrong-task"))
    with pytest.raises(ExecutionFenceError, match="active mission checkpoint"):
        evidence_store.append(item, execution_fence=replace(fence, execution_id="wrong-execution"))
    with pytest.raises(ExecutionFenceError):
        evidence_store.append(item, execution_fence=replace(fence, lease_epoch=claim.lease_epoch + 1))
    assert evidence_store.list() == []
    assert store.load(mission.mission_id).progress.get("execution_evidence_refs", []) == []


def test_evidence_append_rejects_stale_mission_snapshot_without_partial_write(tmp_path):
    store, mission, _snapshot, _queue, _identity, _claim, fence = _leased_fence(tmp_path)
    mission = _mark_active_execution(store, mission, fence)
    stale_mission = store.load(mission.mission_id)
    current_mission = store.load(mission.mission_id)
    current_mission.progress["owner_visible_update"] = "committed first"
    store.save(current_mission, execution_fence=fence)
    evidence_store = EvidenceChainStore(
        tmp_path / "stale-mission-evidence.sqlite3",
        execution_fence=fence,
        mission_store=store,
        mission=stale_mission,
        require_execution_fence=True,
    )

    with pytest.raises(ExecutionFenceError, match="mission state is stale"):
        evidence_store.append({
            "claim": "must not append",
            "source": "test",
            "evidence": {"ok": True},
            "mission_id": mission.mission_id,
            "request_id": mission.request_id,
        })

    assert evidence_store.list() == []
    assert store.load(mission.mission_id).progress.get("execution_evidence_refs", []) == []


def test_strict_evidence_chain_detects_reordered_records(tmp_path):
    store, mission, _snapshot, _queue, _identity, _claim, fence = _leased_fence(tmp_path)
    mission = _mark_active_execution(store, mission, fence)
    database = tmp_path / "reordered-evidence.sqlite3"
    evidence_store = EvidenceChainStore(
        database,
        execution_fence=fence,
        mission_store=store,
        mission=mission,
        require_execution_fence=True,
    )
    for index in range(2):
        evidence_store.append({
            "claim": f"evidence-{index}",
            "source": "test",
            "evidence": {"index": index},
            "mission_id": mission.mission_id,
            "request_id": mission.request_id,
        })
    assert evidence_store.verify()
    records = evidence_store.list()
    with sqlite3.connect(database) as db:
        db.execute("UPDATE evidence_chain SET payload=? WHERE sequence=1", (json.dumps(records[1]),))
        db.execute("UPDATE evidence_chain SET payload=? WHERE sequence=2", (json.dumps(records[0]),))
    assert evidence_store.verify() is False


def test_evidence_verification_fails_closed_for_malformed_fenced_record(tmp_path, monkeypatch):
    store, mission, _snapshot, _queue, _identity, _claim, fence = _leased_fence(tmp_path)
    mission = _mark_active_execution(store, mission, fence)
    evidence_store = EvidenceChainStore(
        tmp_path / "malformed-evidence.sqlite3",
        execution_fence=fence,
        mission_store=store,
        mission=mission,
        require_execution_fence=True,
    )
    record = evidence_store.append({
        "claim": "valid before mutation",
        "source": "test",
        "evidence": {"ok": True},
        "mission_id": mission.mission_id,
        "request_id": mission.request_id,
    })
    malformed = dict(record)
    malformed.pop("execution_id")
    monkeypatch.setattr("agent.evidence.verify_chain", lambda _records: True)
    evidence_store.list = lambda: [malformed]

    assert evidence_store.verify() is False


def test_evidence_and_mission_receipt_rollback_together_when_mission_write_fails(tmp_path):
    store, mission, _snapshot, _queue, _identity, _claim, fence = _leased_fence(tmp_path)
    mission = _mark_active_execution(store, mission, fence)
    database = tmp_path / "atomic-rollback-evidence.sqlite3"
    evidence_store = EvidenceChainStore(
        database,
        execution_fence=fence,
        mission_store=store,
        mission=mission,
        require_execution_fence=True,
    )
    with sqlite3.connect(store.db_path) as db:
        db.execute(
            "CREATE TRIGGER reject_mission_receipt BEFORE UPDATE ON missions "
            "WHEN NEW.mission_id = 'fenced-mission' BEGIN "
            "SELECT RAISE(ABORT, 'injected mission receipt failure'); END"
        )

    with pytest.raises(sqlite3.IntegrityError, match="injected mission receipt failure"):
        evidence_store.append({
            "claim": "must roll back",
            "source": "test",
            "evidence": {"ok": True},
            "mission_id": mission.mission_id,
            "request_id": mission.request_id,
        })

    assert evidence_store.list() == []
    assert store.load(mission.mission_id).progress.get("execution_evidence_refs", []) == []


def test_concurrent_fenced_evidence_appends_are_atomic_and_serialized(tmp_path):
    store, mission, _snapshot, _queue, _identity, _claim, fence = _leased_fence(tmp_path)
    mission = _mark_active_execution(store, mission, fence)
    database = tmp_path / "parallel-evidence.sqlite3"
    stores = [
        EvidenceChainStore(
            database,
            execution_fence=fence,
            mission_store=store,
            mission=mission,
            require_execution_fence=True,
        )
        for _ in range(8)
    ]

    def append(index: int):
        return stores[index % len(stores)].append({
            "claim": f"parallel-{index}",
            "source": "test",
            "evidence": {"index": index},
            "mission_id": mission.mission_id,
            "request_id": mission.request_id,
        })

    with ThreadPoolExecutor(max_workers=8) as pool:
        returned = list(pool.map(append, range(32)))

    records = stores[0].list()
    verifier = EvidenceChainStore(database, mission_store=store)
    assert len(returned) == 32
    assert [record["sequence"] for record in records] == list(range(1, 33))
    assert len({record["current_hash"] for record in records}) == 32
    assert len(store.load(mission.mission_id).progress["execution_evidence_refs"]) == 32
    assert verifier.verify()


def test_strict_mission_runtime_fails_closed_without_a_worker_fence(tmp_path):
    store = MissionStore(tmp_path / "missions.sqlite3")
    mission, _snapshot = _mission(store)
    dispatched: list[str] = []
    runtime = MissionRuntime(
        store,
        executor=lambda *_args, **_kwargs: dispatched.append("tool") or {"success": True},
        require_execution_fence=True,
    )

    with pytest.raises(ExecutionFenceError, match="execution fence"):
        runtime.run_slice(mission.mission_id)

    persisted = store.load(mission.mission_id)
    assert persisted.status is MissionStatus.READY
    assert persisted.iteration_count == 0
    assert dispatched == []


def test_run_slice_rechecks_active_checkpoint_immediately_before_executor(tmp_path, monkeypatch):
    store, mission, _snapshot, _queue, _identity, _claim, fence = _leased_fence(tmp_path)
    effects: list[str] = []

    def executor(_mission, _step, _action_id, *, execution_fence):
        effects.append(execution_fence.execution_id)
        return {"success": True}

    runtime = MissionRuntime(store, executor=executor, require_execution_fence=True)
    runtime.set_execution_fence(fence)
    original_save = runtime._save

    def save_then_stale_checkpoint(saved_mission, *, execution_fence=None):
        result = original_save(saved_mission, execution_fence=execution_fence)
        if saved_mission.checkpoint.get("status") == "in_flight":
            saved_mission.checkpoint["action_id"] = "superseded-execution"
        return result

    monkeypatch.setattr(runtime, "_save", save_then_stale_checkpoint)
    with pytest.raises(ExecutionFenceError, match="active mission checkpoint"):
        runtime.run_slice(mission.mission_id)

    assert effects == []
    persisted = store.load(mission.mission_id)
    assert persisted.checkpoint["status"] == "in_flight"
    assert persisted.checkpoint["action_id"] != "superseded-execution"


def test_strict_runtime_rejects_executor_without_fence_before_slice_mutation(tmp_path):
    store, mission, _snapshot, _queue, _identity, _claim, fence = _leased_fence(tmp_path)
    dispatched: list[str] = []
    runtime = MissionRuntime(
        store,
        executor=lambda *_args: dispatched.append("tool") or {"success": True},
        require_execution_fence=True,
    )
    runtime.set_execution_fence(fence)

    with pytest.raises(ExecutionFenceError, match="executor does not accept execution fences"):
        runtime.run_slice(mission.mission_id)

    persisted = store.load(mission.mission_id)
    assert persisted.status is MissionStatus.RUNNING
    assert persisted.checkpoint == {}
    assert persisted.iteration_count == 0
    assert dispatched == []


def test_bridge_worker_factory_requires_fenced_queue_and_runtime(tmp_path, monkeypatch):
    import bridge

    monkeypatch.setattr(bridge, "DB_PATH", tmp_path / "application.sqlite3")
    worker = bridge.build_mission_worker()
    runtime = worker.runtime_factory()

    assert worker.queue.require_execution_fence is True
    assert runtime.require_execution_fence is True
    assert worker.scheduler is not None
    assert worker.scheduler.queue is worker.queue
    assert worker.scheduler.mission_store is worker.queue.mission_store
    assert worker.scheduler.db_path == str((tmp_path / "mission_scheduler.sqlite3"))
    worker.stop()
