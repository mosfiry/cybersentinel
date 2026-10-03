from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent.execution_fence import ExecutionFence, ExecutionFenceError
from agent.mission import Mission, MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState
from agent.planning import Plan, PlanStep
from security.mission_authorization import MissionAuthorizationSnapshot


def _ready_mission(tmp_path: Path, mission_id: str = "saga-mission"):
    store = MissionStore(tmp_path / "missions.sqlite3")
    created = datetime.now(timezone.utc)
    snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="saga-owner",
        mission_id=mission_id,
        target_identity="saga-target",
        scope=("workspace",),
        allowed_actions=("saga_probe",),
        forbidden_actions=(),
        allowed_tools=("saga_probe",),
        time_window={"timezone": "UTC"},
        max_duration=900,
        rate_limits={"saga_probe": 10},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("saga-target",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(tmp_path)},
        policy_version="claim-saga-test",
        owner_approval="claim-saga-owner-proof",
        created_at=created.isoformat(),
        expires_at=(created + timedelta(minutes=20)).isoformat(),
    )
    mission = Mission.create(
        "test request",
        "validate the durable queue claim",
        Plan(
            version=1,
            objective="validate the durable queue claim",
            steps=(PlanStep("saga-step", "run a safe probe", action="saga_probe"),),
        ),
        mission_id=mission_id,
        request_id=f"request-{mission_id}",
        owner_identity_ref="saga-owner",
        scope_snapshot={"target_id": "saga-target", "workspace_root": str(tmp_path)},
        authorization_snapshot=snapshot.to_dict(),
    )
    mission.transition(MissionStatus.READY, "mission is ready")
    store.save(mission)
    return store, mission


def _worker_fence(queue: MissionQueue, worker_id: str):
    identity = queue.register_worker(worker_id)
    return identity, ExecutionFence.for_worker(queue, identity)


def test_strict_queue_requires_authoritative_mission_store(tmp_path):
    with pytest.raises(ExecutionFenceError, match="authoritative MissionStore"):
        MissionQueue(tmp_path / "queue.sqlite3", require_execution_fence=True)


def test_crash_after_queue_claim_before_mission_binding_is_recovered_without_mission_mutation(tmp_path):
    store, mission = _ready_mission(tmp_path)
    queue = MissionQueue(tmp_path / "queue.sqlite3", require_execution_fence=True, mission_store=store)
    queue.enqueue(mission.mission_id)
    identity, identity_fence = _worker_fence(queue, "claim-crash-worker")
    claim_time = datetime.now(timezone.utc)
    claim = queue.claim_next(
        now=claim_time.isoformat(),
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=60,
        execution_fence=identity_fence,
    )

    assert claim is not None
    assert claim.claim_phase == "CLAIMED"
    assert claim.claim_fence_id
    assert store.load(mission.mission_id).status is MissionStatus.READY

    replacement, replacement_fence = _worker_fence(queue, "claim-crash-worker")
    recovery_time = (claim_time + timedelta(minutes=2)).isoformat()
    recovered = queue.recover_after_restart(now=recovery_time, execution_fence=replacement_fence)

    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.QUEUED
    assert recovered[0].claim_phase == "NONE"
    assert recovered[0].claim_fence_id == ""
    assert recovered[0].lease_epoch > claim.lease_epoch
    persisted = store.load(mission.mission_id)
    assert persisted.status is MissionStatus.READY
    assert "active_execution_claim" not in persisted.progress
    assert replacement.runtime_generation == identity.runtime_generation + 1


def test_crash_after_mission_marker_before_queue_bound_allows_only_new_generation_to_resume(tmp_path, monkeypatch):
    store, mission = _ready_mission(tmp_path)
    queue = MissionQueue(tmp_path / "queue.sqlite3", require_execution_fence=True, mission_store=store)
    queue.enqueue(mission.mission_id)
    old_identity, old_identity_fence = _worker_fence(queue, "marker-crash-worker")
    claim_time = datetime.now(timezone.utc)
    old_claim = queue.claim_next(
        now=claim_time.isoformat(),
        worker_id=old_identity.worker_id,
        worker_instance_id=old_identity.worker_instance_id,
        runtime_generation=old_identity.runtime_generation,
        lease_seconds=60,
        execution_fence=old_identity_fence,
    )
    assert old_claim is not None
    old_fence = old_identity_fence.with_lease(old_claim).for_mission(
        mission, task_id="saga-step", execution_id="old-execution"
    )

    class SimulatedProcessDeath(BaseException):
        pass

    def crash_before_queue_binding(*_args, **_kwargs):
        raise SimulatedProcessDeath()

    monkeypatch.setattr(queue, "mark_claim_bound", crash_before_queue_binding)
    with pytest.raises(SimulatedProcessDeath):
        store.bind_execution_claim(mission.mission_id, old_fence)
    monkeypatch.undo()
    stale_mission = store.load(mission.mission_id)
    assert stale_mission.status is MissionStatus.RUNNING
    assert stale_mission.progress["active_execution_claim"]["lease_binding_id"] == old_fence.lease_binding_id
    assert queue.get(mission.mission_id).claim_phase == "CLAIMED"

    replacement_identity, replacement_identity_fence = _worker_fence(queue, "marker-crash-worker")
    recovery_time = (claim_time + timedelta(minutes=2)).isoformat()
    recovered = queue.recover_after_restart(
        now=recovery_time,
        execution_fence=replacement_identity_fence,
    )
    assert recovered[0].state is WorkerMissionState.QUEUED

    replacement_claim = queue.claim_next(
        now=recovery_time,
        worker_id=replacement_identity.worker_id,
        worker_instance_id=replacement_identity.worker_instance_id,
        runtime_generation=replacement_identity.runtime_generation,
        lease_seconds=600,
        execution_fence=replacement_identity_fence,
    )
    assert replacement_claim is not None
    current_mission = store.load(mission.mission_id)
    replacement_fence = replacement_identity_fence.with_lease(replacement_claim).for_mission(
        current_mission, task_id="saga-step", execution_id="new-execution"
    )
    replacement_binding = store.bind_execution_claim(mission.mission_id, replacement_fence)
    assert replacement_binding.lease_binding_id == replacement_fence.lease_binding_id

    current_mission = store.load(mission.mission_id)
    new_marker = current_mission.progress["active_execution_claim"]["lease_binding_id"]
    assert new_marker == replacement_fence.lease_binding_id
    stale_mission.progress["stale_write"] = True
    with pytest.raises(ExecutionFenceError):
        store.save(stale_mission, execution_fence=old_fence)
    assert store.load(mission.mission_id).progress["active_execution_claim"]["lease_binding_id"] == new_marker
    assert queue.get(mission.mission_id).claim_phase == "BOUND"


def test_strict_queue_cannot_advance_to_bound_without_mission_store_marker(tmp_path):
    store, mission = _ready_mission(tmp_path)
    queue = MissionQueue(tmp_path / "queue.sqlite3", require_execution_fence=True, mission_store=store)
    queue.enqueue(mission.mission_id)
    identity, identity_fence = _worker_fence(queue, "marker-mismatch-worker")
    claim = queue.claim_next(
        now=datetime.now(timezone.utc).isoformat(),
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=600,
        execution_fence=identity_fence,
    )
    fence = identity_fence.with_lease(claim).for_mission(mission)
    forged = store.load(mission.mission_id)
    forged.progress["active_execution_claim"] = {
        **fence.metadata(),
        "lease_binding_id": fence.lease_binding_id,
        "bound_at": datetime.now(timezone.utc).isoformat(),
    }
    with pytest.raises(ExecutionFenceError, match="only be changed by its current fence"):
        store.save(forged)
    with pytest.raises(ExecutionFenceError, match="MissionStore claim marker"):
        queue.mark_claim_bound(fence)
    assert queue.get(mission.mission_id).claim_phase == "CLAIMED"
    assert store.load(mission.mission_id).status is MissionStatus.READY


def test_terminal_mission_after_completion_crash_is_reconciled_without_dispatch(tmp_path):
    store, mission = _ready_mission(tmp_path)
    queue = MissionQueue(tmp_path / "queue.sqlite3", require_execution_fence=True, mission_store=store)
    queue.enqueue(mission.mission_id)
    old_identity, old_identity_fence = _worker_fence(queue, "terminal-reconcile-worker")
    claim_time = datetime.now(timezone.utc)
    old_claim = queue.claim_next(
        now=claim_time.isoformat(),
        worker_id=old_identity.worker_id,
        worker_instance_id=old_identity.worker_instance_id,
        runtime_generation=old_identity.runtime_generation,
        lease_seconds=60,
        execution_fence=old_identity_fence,
    )
    old_fence = old_identity_fence.with_lease(old_claim).for_mission(mission)
    store.bind_execution_claim(mission.mission_id, old_fence)

    completed = store.load(mission.mission_id)
    completed.transition(MissionStatus.GOAL_COMPLETED, "simulated durable completion before queue ack")
    store.save(completed, execution_fence=old_fence)
    assert queue.get(mission.mission_id).state is WorkerMissionState.EXECUTING

    replacement_time = (claim_time + timedelta(minutes=2)).isoformat()
    dispatched: list[str] = []

    class TrapRuntime(MissionRuntime):
        def run_to_completion(self, *args, **kwargs):
            dispatched.append("run_to_completion")
            raise AssertionError("terminal mission must never be dispatched")

    replacement_worker = MissionWorker(
        queue,
        lambda: TrapRuntime(
            store,
            executor=lambda *_args, **_kwargs: dispatched.append("tool"),
            require_execution_fence=True,
        ),
        worker_id="terminal-reconcile-worker",
        lease_seconds=60,
    )
    recovered = replacement_worker.recover_after_restart(now=replacement_time)
    assert recovered[0].state is WorkerMissionState.QUEUED

    result = replacement_worker.run_once(now=replacement_time)
    assert result is not None
    assert result.state is WorkerMissionState.COMPLETED
    assert result.claim_phase == "NONE"
    assert dispatched == []
    assert store.load(mission.mission_id).status is MissionStatus.GOAL_COMPLETED


def test_fenced_mission_save_fails_closed_when_cross_store_atomicity_is_unavailable(tmp_path):
    store, mission = _ready_mission(tmp_path)
    queue = MissionQueue(tmp_path / "queue.sqlite3", require_execution_fence=True, mission_store=store)
    queue.enqueue(mission.mission_id)
    identity, identity_fence = _worker_fence(queue, "wal-guard-worker")
    claim = queue.claim_next(
        now=datetime.now(timezone.utc).isoformat(),
        worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation,
        lease_seconds=600,
        execution_fence=identity_fence,
    )
    fence = identity_fence.with_lease(claim).for_mission(mission)
    store.bind_execution_claim(mission.mission_id, fence)
    persisted = store.load(mission.mission_id)
    prior_progress = dict(persisted.progress)

    with sqlite3.connect(queue.db_path) as db:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
    persisted.progress["should_not_commit"] = True
    with pytest.raises(ExecutionFenceError, match="rollback-journal"):
        store.save(persisted, execution_fence=fence)

    after = store.load(mission.mission_id)
    assert after.progress == prior_progress
    assert queue.get(mission.mission_id).claim_phase == "BOUND"
