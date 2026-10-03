from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

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
    worker.stop()
