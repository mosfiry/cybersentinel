from __future__ import annotations

from pathlib import Path

import pytest

from agent.agent_core import AgentCore
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, WorkerMissionState
from agent.model_router import ModelRouter
from agent.planning import Plan, PlanStep
from api.missions import MissionService
from owner_session_testutils import allow_owner_sessions
from runtime_authorization import make_test_snapshot


def _setup(tmp_path: Path):
    store = MissionStore(Path(tmp_path) / "missions.sqlite3")

    def should_not_execute(*_args, **_kwargs):
        pytest.fail("queue authorization must not execute a mission slice")

    runtime = MissionRuntime(
        store,
        executor=should_not_execute,
        authorization_snapshot_factory=make_test_snapshot,
        require_authorization_snapshot=True,
    )
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    plan = Plan.initial("queue authorization").replan(
        steps=(
            PlanStep(
                "status",
                "status",
                action="status",
                authorization_requirement="owner",
            ),
        ),
        reason="test",
    )
    mission = runtime.create(
        "queue authorization",
        "queue authorization",
        plan,
        request_id="queue-auth-request",
        owner_identity_ref="owner:1",
    )
    return store, runtime, queue, mission


def _assert_not_queued(queue: MissionQueue, mission_id: str) -> None:
    with pytest.raises(KeyError, match="unknown queued mission"):
        queue.get(mission_id)


def test_start_fails_closed_when_no_owner_revalidator_is_configured(tmp_path):
    _store, runtime, queue, mission = _setup(tmp_path)
    service = MissionService(runtime, queue)

    with pytest.raises(PermissionError, match="revalidation is unavailable"):
        service.start_mission(
            mission.mission_id,
            owner_session_token="current-owner-session",
        )

    _assert_not_queued(queue, mission.mission_id)


def test_resume_requires_fresh_owner_proof_and_only_then_clears_pause(
    tmp_path, monkeypatch
):
    allow_owner_sessions(monkeypatch, "fresh-owner")
    store, runtime, queue, mission = _setup(tmp_path)
    core = AgentCore(ModelRouter([]), store=store)
    service = MissionService(
        runtime,
        queue,
        owner_revalidator=core.prepare_mission_for_queue,
    )

    service.pause_mission(mission.mission_id, owner_session_token="fresh-owner")
    assert store.load(mission.mission_id).progress["pause_requested"] is True

    with pytest.raises(PermissionError, match="owner authentication required"):
        service.resume_mission(
            mission.mission_id,
            owner_session_token="stale-owner",
        )

    still_paused = store.load(mission.mission_id)
    assert still_paused.status is MissionStatus.READY
    assert still_paused.progress["pause_requested"] is True
    assert queue.get(mission.mission_id).state is WorkerMissionState.PAUSED

    resumed = service.resume_mission(
        mission.mission_id,
        owner_session_token="fresh-owner",
    )
    assert resumed["status"] == MissionStatus.READY.value
    assert "pause_requested" not in resumed["progress"]
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED

    renewed = store.load(mission.mission_id)
    owner_approval = renewed.authorization_snapshot["owner_approval"]
    assert owner_approval
    assert renewed.policy_snapshot["authentication"]["proof_fingerprint"] == owner_approval
    assert renewed.iteration_count == mission.iteration_count


def test_recovery_required_mission_is_not_reauthorized_or_enqueued(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "fresh-owner")
    store, runtime, queue, mission = _setup(tmp_path)
    mission.transition(MissionStatus.RECOVERY_REQUIRED, "ambiguous in-flight action")
    store.save(mission)
    calls = []

    def should_not_reauthorize(mission_id: str, owner_session_token: str):
        calls.append((mission_id, owner_session_token))
        raise AssertionError("recovery state must be reconciled before Owner revalidation")

    service = MissionService(runtime, queue, owner_revalidator=should_not_reauthorize)
    for action in (service.start_mission, service.resume_mission):
        with pytest.raises(ValueError, match="requires reconciliation"):
            action(mission.mission_id, owner_session_token="fresh-owner")

    assert calls == []
    assert store.load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    _assert_not_queued(queue, mission.mission_id)
