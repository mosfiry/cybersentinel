from __future__ import annotations

from pathlib import Path
from typing import Any

from .agent_core import AgentCore
from .mission import MissionStatus
from .mission_runtime import MissionRuntime
from .mission_worker import MissionQueue, WorkerMissionState
from .task import Task, TaskStatus
from .task_manager import TaskManager
from core.db import ensure_conversation


def task_owner_matches(task: Task, owner_session: dict[str, Any]) -> bool:
    """Match new mission-backed tasks by stable account identity; retain session fallback for legacy rows."""
    if not isinstance(owner_session, dict):
        return False
    owner_identity = str(owner_session.get("owner_id", ""))
    execution_state = task.execution_state if isinstance(task.execution_state, dict) else {}
    task_owner_identity = str(execution_state.get("owner_identity", ""))
    if task_owner_identity:
        return bool(owner_identity) and task_owner_identity == owner_identity
    return bool(owner_session.get("session_id")) and task.owner_session_id == str(owner_session["session_id"])


class MissionTaskAdapter:
    """Compatibility Task API backed by the single canonical MissionRuntime."""

    def __init__(self, router: Any, *, core: AgentCore | None = None, queue: MissionQueue | None = None) -> None:
        self.router = router
        self.core = core or AgentCore(router)
        if queue is None:
            queue_path = Path(self.core.store.db_path).with_name("mission_queue.sqlite3")
            queue = MissionQueue(queue_path)
        self.queue = queue

    @staticmethod
    def _status(mission_status: MissionStatus) -> TaskStatus:
        if mission_status is MissionStatus.GOAL_COMPLETED:
            return TaskStatus.COMPLETED
        if mission_status is MissionStatus.PAUSED:
            return TaskStatus.PAUSED
        if mission_status is MissionStatus.CANCELLED:
            return TaskStatus.CANCELLED
        if mission_status in {MissionStatus.OWNER_INPUT_REQUIRED, MissionStatus.RECOVERY_REQUIRED}:
            return TaskStatus.NEEDS_INPUT
        if mission_status in {MissionStatus.READY, MissionStatus.RUNNING, MissionStatus.OBSERVING, MissionStatus.VERIFYING, MissionStatus.REPLANNING, MissionStatus.PLANNING, MissionStatus.CREATED}:
            return TaskStatus.WAITING_FOR_MODEL
        return TaskStatus.FAILED

    def _mission_service(self):
        from api.missions import MissionService

        runtime = MissionRuntime(self.core.store, executor=self.core._executor, require_authorization_snapshot=True)
        return MissionService(runtime, self.queue)

    @staticmethod
    def _live_owner(owner_session_token: str) -> dict[str, Any]:
        from security.owner_password import resolve_session

        owner = resolve_session(owner_session_token)
        if owner is None or owner.get("auth_method") != "username_password":
            raise PermissionError("owner authentication required")
        return owner

    def _owned_task(self, task_id: str, owner_session_token: str) -> tuple[Task, dict[str, Any]]:
        owner = self._live_owner(owner_session_token)
        task = TaskManager.get_task(task_id)
        if task is None:
            raise KeyError("unknown_task")
        if not task_owner_matches(task, owner):
            raise PermissionError("task access denied")
        return task, owner

    def get_task(self, task_id: str, *, owner_session_token: str) -> Task:
        task, owner = self._owned_task(task_id, owner_session_token)
        mission_id = self._mission_id(task)
        if not mission_id:
            return task
        mission = self._mission_service().mission(mission_id, owner_identity=str(owner["owner_id"]))
        return self._sync_task(task, mission)

    @staticmethod
    def _mission_id(task: Task) -> str:
        state = task.execution_state if isinstance(task.execution_state, dict) else {}
        return str(state.get("mission_id", ""))

    def _sync_task(self, task: Task, mission) -> Task:
        task.execution_state["mission"] = mission.to_dict()
        task.result = {"mission_id": mission.mission_id, "mission_status": mission.status.value}
        task.update_status(self._status(mission.status))
        TaskManager.update_task(task)
        return task

    def create_task(self, conversation_id: str, objective: str, *, owner_session_token: str, owner_session_id: str = "", authentication_method: str = "username_password", scope_context: dict[str, Any] | None = None, run: bool = True) -> Task:
        owner = self._live_owner(owner_session_token)
        if owner_session_id and owner_session_id != str(owner["session_id"]):
            raise PermissionError("task owner session does not match authenticated session")
        owner_identity = str(owner["owner_id"])
        ensure_conversation(conversation_id, owner_identity)
        # Task API work must enter the supervised durable queue; never execute
        # a long mission inside the request before its Task record exists.
        mission = self.core.run_owner_mission(objective, owner_session_token=owner_session_token, scope_context=scope_context, run=False)
        task = TaskManager.create_task(conversation_id, mission.request_id, str(owner["session_id"]), objective, authentication_method=authentication_method)
        task.execution_state = {"canonical_runtime": "MissionRuntime", "mission_id": mission.mission_id, "mission": mission.to_dict(), "owner_identity": owner_identity}
        task.result = {"mission_id": mission.mission_id, "mission_status": mission.status.value}
        task.update_status(self._status(mission.status))
        TaskManager.update_task(task)
        if run and not mission.is_terminal and mission.status is not MissionStatus.PAUSED:
            self.queue.enqueue(mission.mission_id)
        return task

    def resume_task(self, task_id: str, *, owner_session_token: str, run: bool = True) -> Task:
        task, owner = self._owned_task(task_id, owner_session_token)
        mission_id = self._mission_id(task)
        if not mission_id:
            raise ValueError("task is not bound to canonical mission")
        service = self._mission_service()
        mission = service.mission(mission_id, owner_identity=str(owner["owner_id"]))
        if not run:
            return self._sync_task(task, mission)
        if mission.status is MissionStatus.RECOVERY_REQUIRED:
            raise ValueError("in-flight mission requires reconciliation before resume")
        try:
            item = self.queue.get(mission_id)
        except KeyError:
            item = None
        if item is not None and item.state in {WorkerMissionState.EXECUTING, WorkerMissionState.QUEUED, WorkerMissionState.SCHEDULED, WorkerMissionState.SLEEPING}:
            return self._sync_task(task, mission)
        mission = self.core.resume_mission(mission_id, owner_session_token=owner_session_token, run=False)
        if not mission.is_terminal:
            self.queue.enqueue(mission_id)
        return self._sync_task(task, mission)

    def pause_task(self, task_id: str, *, owner_session_token: str) -> Task:
        task, owner = self._owned_task(task_id, owner_session_token)
        mission_id = self._mission_id(task)
        if not mission_id:
            task.request_pause()
            TaskManager.update_task(task)
            return task
        mission = self._mission_service().pause_mission(mission_id, owner_identity=str(owner["owner_id"]))
        return self._sync_task(task, self.core.store.load(mission_id) or mission)

    def cancel_task(self, task_id: str, *, owner_session_token: str) -> Task:
        task, owner = self._owned_task(task_id, owner_session_token)
        mission_id = self._mission_id(task)
        if not mission_id:
            task.request_cancel()
            TaskManager.update_task(task)
            return task
        mission = self._mission_service().cancel_mission(mission_id, owner_identity=str(owner["owner_id"]))
        return self._sync_task(task, self.core.store.load(mission_id) or mission)


__all__ = ["MissionTaskAdapter", "task_owner_matches"]
