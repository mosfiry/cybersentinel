from __future__ import annotations

from typing import Any

from .agent_core import AgentCore
from .mission import MissionStatus
from .model_router import ModelRouter
from .task import Task, TaskStatus
from .task_manager import TaskManager
from core.db import ensure_conversation


class MissionTaskAdapter:
    """Compatibility Task API backed by the single canonical MissionRuntime."""

    def __init__(self, router: Any, *, core: AgentCore | None = None) -> None:
        self.router = router
        self.core = core or AgentCore(router)

    @staticmethod
    def _status(mission_status: MissionStatus) -> TaskStatus:
        if mission_status is MissionStatus.GOAL_COMPLETED:
            return TaskStatus.COMPLETED
        if mission_status is MissionStatus.OWNER_INPUT_REQUIRED:
            return TaskStatus.NEEDS_INPUT
        if mission_status in {MissionStatus.READY, MissionStatus.RUNNING, MissionStatus.OBSERVING, MissionStatus.VERIFYING, MissionStatus.REPLANNING}:
            return TaskStatus.WAITING_FOR_MODEL
        return TaskStatus.FAILED

    def create_task(self, conversation_id: str, objective: str, *, owner_token: str, owner_session_id: str | None = None, owner_challenge: str | None = None, authentication_method: str = "owner_token", scope_context: dict[str, Any] | None = None, run: bool = True) -> Task:
        ensure_conversation(conversation_id, owner_session_id or "")
        mission = self.core.run_owner_mission(objective, owner_token=owner_token, owner_session_id=owner_session_id, owner_challenge=owner_challenge, scope_context=scope_context)
        task = TaskManager.create_task(conversation_id, mission.request_id, owner_session_id or "", objective, authentication_method=authentication_method)
        task.execution_state = {"canonical_runtime": "MissionRuntime", "mission_id": mission.mission_id, "mission": mission.to_dict()}
        task.result = {"mission_id": mission.mission_id, "mission_status": mission.status.value}
        task.update_status(self._status(mission.status))
        TaskManager.update_task(task)
        return task

    def resume_task(self, task_id: str, *, owner_token: str, max_slices: int | None = None) -> Task:
        task = TaskManager.get_task(task_id)
        if task is None:
            raise KeyError("unknown_task")
        mission_id = str(task.execution_state.get("mission_id", ""))
        if not mission_id:
            raise ValueError("task is not bound to canonical mission")
        mission = self.core.resume_mission(mission_id, owner_token=owner_token, max_slices=max_slices)
        task.execution_state["mission"] = mission.to_dict()
        task.result = {"mission_id": mission.mission_id, "mission_status": mission.status.value}
        task.update_status(self._status(mission.status))
        TaskManager.update_task(task)
        return task


__all__ = ["MissionTaskAdapter"]
