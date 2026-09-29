from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.mission import Mission, MissionStatus
from agent.planning import Plan
from agent.mission_worker import MissionQueue, MissionScheduler, MissionWorker, WorkerMissionState

NOW = "2026-09-29T00:00:00+00:00"


@dataclass
class StubMission:
    status: MissionStatus
    error: str = ""
    evidence: list | None = None
    checkpoint: dict | None = None


class StubStore:
    def __init__(self, mission):
        self.mission = mission

    def load(self, _mission_id):
        return self.mission

    def save(self, mission):
        self.mission = mission
        return mission


def test_enqueue_is_idempotent_while_execution_lease_is_owned(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queued = queue.enqueue("mission-1", available_at=NOW)
    claimed = queue.claim_next(now=NOW, worker_id="worker-a", lease_seconds=120)
    assert claimed.state is WorkerMissionState.EXECUTING
    assert claimed.attempts == 1

    same = queue.enqueue("mission-1")
    assert same.state is WorkerMissionState.EXECUTING
    assert same.lease_owner == "worker-a"
    assert same.lease_expires_at == claimed.lease_expires_at
    assert same.attempts == 1

    recovered = queue.recover_expired(now="2026-09-29T00:02:01+00:00")
    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.QUEUED
    assert recovered[0].lease_owner is None
    assert queue.claim_next(now="2026-09-29T00:02:02+00:00", worker_id="worker-b") is not None


def test_bridge_resume_does_not_reauthorize_mission_owned_by_worker(monkeypatch):
    import bridge

    mission = SimpleNamespace(
        status=MissionStatus.RUNNING,
        checkpoint={},
        to_public_dict=lambda: {"mission_id": "mission-live", "status": "RUNNING"},
    )

    class Queue:
        def get(self, mission_id):
            assert mission_id == "mission-live"
            return SimpleNamespace(state=WorkerMissionState.EXECUTING, attempts=1, available_at=NOW)

        def enqueue(self, _mission_id):
            pytest.fail("an executing mission must not be enqueued again")

    service = SimpleNamespace(
        mission=lambda mission_id, *, owner_identity: mission,
        queue=Queue(),
    )
    monkeypatch.setattr(bridge.AgentCore, "resume_mission", lambda *_args, **_kwargs: pytest.fail("must not reauthorize an active mission"))

    result = bridge.Handler._reauthorize_and_enqueue(
        bridge.Handler.__new__(bridge.Handler),
        "mission-live",
        {"owner_id": "owner-1", "session_id": "session-1"},
        service,
    )

    assert result == {
        "mission": {"mission_id": "mission-live", "status": "RUNNING"},
        "queue": {"state": WorkerMissionState.EXECUTING.value, "attempts": 1, "available_at": NOW},
    }


def test_restart_recovery_clears_worker_lease_but_not_mission_truth(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-2", available_at=NOW)
    claimed = queue.claim_next(now=NOW, worker_id="worker-a")
    assert claimed.lease_owner == "worker-a"
    recovered = queue.recover_after_restart()
    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.QUEUED
    assert recovered[0].lease_owner is None
    assert recovered[0].last_error == "worker restart recovery"


def test_bounded_active_work_releases_lease_and_resumes_to_truthful_completion(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-3", available_at=NOW)
    outcomes = iter((MissionStatus.RUNNING, MissionStatus.GOAL_COMPLETED))
    worker = MissionWorker(
        queue,
        runtime_factory=lambda: None,
        worker_id="worker-a",
        resume_callback=lambda *_args: StubMission(next(outcomes)),
    )

    first = worker.run_once(now=NOW, max_slices=1)
    assert first.state is WorkerMissionState.QUEUED
    assert first.lease_owner is None
    second = worker.run_once(now="2026-09-29T00:00:02+00:00", max_slices=1)
    assert second.state is WorkerMissionState.COMPLETED
    assert second.lease_owner is None


def test_pause_releases_worker_lease_and_resume_can_requeue(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-4", available_at=NOW)
    worker = MissionWorker(
        queue,
        runtime_factory=lambda: None,
        worker_id="worker-a",
        resume_callback=lambda *_args: StubMission(MissionStatus.PAUSED),
    )
    paused = worker.run_once(now=NOW, max_slices=1)
    assert paused.state is WorkerMissionState.PAUSED
    assert paused.lease_owner is None
    assert queue.enqueue("mission-4").state is WorkerMissionState.QUEUED


def test_worker_exception_with_inflight_checkpoint_waits_for_reconciliation(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-5", available_at=NOW)
    mission = Mission.create("request", "objective", Plan.initial("objective"), mission_id="mission-5")
    mission.checkpoint = {"status": "in_flight"}
    worker = MissionWorker(
        queue,
        runtime_factory=lambda: SimpleNamespace(store=StubStore(mission)),
        worker_id="worker-a",
        resume_callback=lambda *_args: (_ for _ in ()).throw(RuntimeError("receipt unavailable")),
    )
    result = worker.run_once(now=NOW, max_slices=1)
    assert result.state is WorkerMissionState.WAITING_FOR_TOOL
    assert result.lease_owner is None
    assert result.last_error == "ambiguous in-flight execution requires reconciliation"
    assert mission.status is MissionStatus.RECOVERY_REQUIRED


def test_queue_and_scheduler_databases_are_private_and_symlinks_rejected(tmp_path):
    queue_path = tmp_path / "queue.sqlite3"
    scheduler_path = tmp_path / "scheduler.sqlite3"
    queue = MissionQueue(queue_path)
    MissionScheduler(scheduler_path, queue)
    assert queue_path.stat().st_mode & 0o777 == 0o600
    assert scheduler_path.stat().st_mode & 0o777 == 0o600

    outside = tmp_path / "outside.sqlite3"
    outside.write_bytes(b"not a database")
    link = tmp_path / "linked.sqlite3"
    link.symlink_to(outside)
    with pytest.raises(OSError):
        MissionQueue(link)


def test_frontend_does_not_turn_worker_or_mission_unknown_into_success():
    source = Path("web/app.js").read_text(encoding="utf-8")
    assert 'selectedMission.status === "GOAL_COMPLETED"' in source
    assert 'verification.verified === true' in source
    assert 'mission?.status || "unknown"' in source
    assert 'item.status || "completed"' not in source
    assert 'verification?.verified ?? true' not in source
    assert "localStorage" not in source
