from __future__ import annotations

from pathlib import Path

import pytest

import agent.task_manager as task_manager
import security.owner_password as owner_password
from agent.mission import Mission, MissionStatus
from agent.mission_task_adapter import MissionTaskAdapter
from agent.mission_worker import MissionQueue, WorkerMissionState
from agent.planning import Plan
from agent.task import TaskStatus
from agent.task_manager import TaskManager


class FakeStore:
    def __init__(self, db_path: Path, mission: Mission):
        self.db_path = str(db_path)
        self.mission = mission

    def load(self, mission_id: str):
        return self.mission if mission_id == self.mission.mission_id else None

    def load_for_owner(self, mission_id: str, owner_identity: str):
        if mission_id != self.mission.mission_id or owner_identity != self.mission.owner_identity_ref:
            return None
        return self.mission

    def save(self, mission: Mission):
        self.mission = mission
        return mission


class FakeCore:
    def __init__(self, store: FakeStore):
        self.store = store
        self._executor = lambda *args, **kwargs: {"success": True}
        self.owner_mission_run_flags = []

    def run_owner_mission(self, objective: str, *, owner_session_token: str, scope_context=None, run: bool = True):
        self.owner_mission_run_flags.append(run)
        mission = _mission("task-created")
        mission.objective = objective
        mission.owner_request = objective
        self.store.save(mission)
        return mission

    def resume_mission(self, mission_id: str, *, owner_session_token: str, run: bool = True):
        mission = self.store.load(mission_id)
        if mission is None:
            raise KeyError("unknown_mission")
        if mission.status is MissionStatus.PAUSED:
            mission.progress.pop("pause_requested", None)
            mission.transition(MissionStatus.READY, "test owner resume")
        self.store.save(mission)
        return mission


def _mission(mission_id: str = "mission-1", owner_identity: str = "account-1") -> Mission:
    mission = Mission.create(
        "Owner request",
        "Complete an authorized task",
        Plan.initial("Complete an authorized task"),
        mission_id=mission_id,
        request_id=f"request-{mission_id}",
        owner_identity_ref=owner_identity,
    )
    mission.transition(MissionStatus.READY, "test fixture ready")
    return mission


@pytest.fixture
def adapter_env(tmp_path, monkeypatch):
    monkeypatch.setattr(task_manager, "DB_PATH", tmp_path / "tasks.sqlite3")
    task_manager._init_db()
    sessions = {
        "old-session": {"session_id": "old-session", "owner_id": "account-1", "auth_method": "username_password"},
        "new-session": {"session_id": "new-session", "owner_id": "account-1", "auth_method": "username_password"},
        "other-session": {"session_id": "other-session", "owner_id": "account-2", "auth_method": "username_password"},
    }
    monkeypatch.setattr(owner_password, "resolve_session", lambda token: sessions.get(token))
    mission = _mission()
    store = FakeStore(tmp_path / "missions.sqlite3", mission)
    queue = MissionQueue(tmp_path / "mission_queue.sqlite3")
    adapter = MissionTaskAdapter(object(), core=FakeCore(store), queue=queue)
    task = TaskManager.create_task("conversation-1", mission.request_id, "old-session", mission.objective)
    task.execution_state = {"canonical_runtime": "MissionRuntime", "mission_id": mission.mission_id, "owner_identity": "account-1", "mission": mission.to_dict()}
    TaskManager.update_task(task)
    return adapter, queue, store, task


def test_task_controls_use_stable_owner_identity_and_pause_the_mission(adapter_env):
    adapter, queue, store, task = adapter_env

    paused = adapter.pause_task(task.task_id, owner_session_token="new-session")

    assert paused.status is TaskStatus.PAUSED
    assert store.mission.status is MissionStatus.PAUSED
    assert store.mission.checkpoint["status"] == "paused"
    assert queue.list() == []


def test_task_cancel_updates_mission_and_idle_queue(adapter_env):
    adapter, queue, store, task = adapter_env
    queue.enqueue(store.mission.mission_id)

    cancelled = adapter.cancel_task(task.task_id, owner_session_token="new-session")

    assert cancelled.status is TaskStatus.CANCELLED
    assert store.mission.status is MissionStatus.CANCELLED
    assert queue.get(store.mission.mission_id).state is WorkerMissionState.CANCELLED


def test_task_read_refreshes_from_canonical_mission_state(adapter_env):
    adapter, _queue, store, task = adapter_env
    store.mission.status = MissionStatus.CANCELLED

    refreshed = adapter.get_task(task.task_id, owner_session_token="new-session")

    assert refreshed.status is TaskStatus.CANCELLED
    assert refreshed.execution_state["mission"]["status"] == MissionStatus.CANCELLED.value


def test_task_resume_reauthorizes_and_requeues_paused_mission(adapter_env):
    adapter, queue, store, task = adapter_env
    store.mission.transition(MissionStatus.PAUSED, "test pause")
    store.mission.checkpoint = {"status": "paused"}
    queue.enqueue(store.mission.mission_id, state=WorkerMissionState.PAUSED)

    resumed = adapter.resume_task(task.task_id, owner_session_token="new-session")

    assert resumed.status is TaskStatus.WAITING_FOR_MODEL
    assert store.mission.status is MissionStatus.READY
    assert queue.get(store.mission.mission_id).state is WorkerMissionState.QUEUED


def test_task_cancel_does_not_hide_ambiguous_in_flight_action(adapter_env):
    adapter, queue, store, task = adapter_env
    store.mission.checkpoint = {"status": "in_flight", "action_id": "uncertain"}
    queue.enqueue(store.mission.mission_id)
    queue.claim_next(worker_id="live-worker")

    result = adapter.cancel_task(task.task_id, owner_session_token="new-session")

    assert result.status is TaskStatus.WAITING_FOR_MODEL
    assert store.mission.status is MissionStatus.READY
    assert store.mission.progress["cancel_requested"] is True
    assert queue.get(store.mission.mission_id).state is WorkerMissionState.EXECUTING


def test_different_owner_cannot_control_mission_backed_task(adapter_env):
    adapter, _queue, store, task = adapter_env

    with pytest.raises(PermissionError, match="task access denied"):
        adapter.pause_task(task.task_id, owner_session_token="other-session")

    assert store.mission.status is MissionStatus.READY


def test_task_creation_persists_then_enqueues_without_inline_execution(adapter_env, monkeypatch):
    import agent.mission_task_adapter as adapter_module

    adapter, queue, store, _existing_task = adapter_env
    ensured = []
    monkeypatch.setattr(adapter_module, "ensure_conversation", lambda conversation_id, owner_id: ensured.append((conversation_id, owner_id)))

    task = adapter.create_task("conversation-new", "Review a security alert", owner_session_token="new-session", run=True)

    assert adapter.core.owner_mission_run_flags == [False]
    assert ensured == [("conversation-new", "account-1")]
    assert task.status is TaskStatus.WAITING_FOR_MODEL
    assert task.execution_state["mission_id"] == store.mission.mission_id
    assert queue.get(store.mission.mission_id).state is WorkerMissionState.QUEUED


def test_task_pause_defers_to_live_worker_boundary(adapter_env):
    adapter, queue, store, task = adapter_env
    queue.enqueue(store.mission.mission_id)
    queue.claim_next(worker_id="live-worker")

    result = adapter.pause_task(task.task_id, owner_session_token="new-session")

    assert result.status is TaskStatus.WAITING_FOR_MODEL
    assert store.mission.status is MissionStatus.READY
    assert store.mission.progress["pause_requested"] is True
    assert queue.get(store.mission.mission_id).state is WorkerMissionState.EXECUTING


def test_task_stream_is_read_only_and_does_not_claim_pending_task_completed(adapter_env, monkeypatch):
    import api.chat as chat_module

    adapter, _queue, _store, task = adapter_env
    monkeypatch.setattr(chat_module, "_runtime", lambda: adapter)
    task.update_status(TaskStatus.WAITING_FOR_MODEL)
    TaskManager.update_task(task)

    events = list(chat_module.task_stream(task.task_id, owner_session_token="new-session"))

    assert events[-1]["event"] == "task.status"
    assert events[-1]["data"]["task"]["status"] == TaskStatus.WAITING_FOR_MODEL.value
    refreshed = TaskManager.get_task(task.task_id)
    assert refreshed.status is TaskStatus.WAITING_FOR_MODEL
