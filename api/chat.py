from __future__ import annotations

import json
import uuid
from typing import Any, Iterator

from agent.task import TaskStatus
from agent.task_manager import TaskManager
from agent.mission_task_adapter import MissionTaskAdapter, task_owner_matches
from agent.agent_core import AgentCore
from agent.mission import MissionStatus
from agent.model_router import ModelSelectionError
from core.db import add_conversation_message, conversation_info, conversation_messages, ensure_conversation
from core.engine import RUNTIME
from security import owner_password
from api.models import requested_model_id


def _owner_session(owner_session_token: str) -> dict[str, Any]:
    session = owner_password.resolve_session(owner_session_token)
    if session is None or session.get("auth_method") != "username_password":
        raise PermissionError("owner authentication required")
    return session


def _runtime() -> MissionTaskAdapter:
    return MissionTaskAdapter(RUNTIME.router)


def _agent_core() -> AgentCore:
    return AgentCore(RUNTIME.router)


def _task_public(task) -> dict[str, Any]:
    def redact(item: Any) -> Any:
        if isinstance(item, dict):
            return {key: redact(child) for key, child in item.items() if key not in {"session_id", "owner_session_id"}}
        if isinstance(item, list):
            return [redact(child) for child in item]
        return item

    value = redact(task.to_dict())
    value["events"] = task.execution_state.get("events", [])
    return value


def _conversation_id(payload: dict[str, Any]) -> str:
    conversation_id = str(payload.get("conversation_id") or uuid.uuid4().hex).strip()
    if len(conversation_id) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in conversation_id):
        raise ValueError("invalid_conversation_id")
    return conversation_id


def create_task(payload: dict[str, Any], *, owner_session_token: str, run: bool = True) -> dict[str, Any]:
    text = str(payload.get("text", payload.get("objective", ""))).strip()
    if not text:
        raise ValueError("text_required")
    conversation_id = _conversation_id(payload)
    owner = _owner_session(owner_session_token)
    task_runtime = _runtime()
    task = task_runtime.create_task(conversation_id, text, owner_session_token=owner_session_token, owner_session_id=owner["session_id"], authentication_method="username_password", scope_context=payload.get("scope_context"), run=run)
    return {"task": _task_public(task)}


def get_task(task_id: str, *, owner_session_token: str) -> dict[str, Any]:
    task = _runtime().get_task(task_id, owner_session_token=owner_session_token)
    return {"task": _task_public(task)}


def resume_task(task_id: str, *, owner_session_token: str, run: bool = True) -> dict[str, Any]:
    owner = _owner_session(owner_session_token)
    task = TaskManager.get_task(task_id)
    if task is None:
        raise KeyError("unknown_task")
    if not task_owner_matches(task, owner):
        raise PermissionError("task access denied")
    if run:
        task = _runtime().resume_task(task_id, owner_session_token=owner_session_token, run=True)
    else:
        task = _runtime().get_task(task_id, owner_session_token=owner_session_token)
    return {"task": _task_public(task)}


def pause_task(task_id: str, *, owner_session_token: str) -> dict[str, Any]:
    task = _runtime().pause_task(task_id, owner_session_token=owner_session_token)
    return {"task": _task_public(task)}


def cancel_task(task_id: str, *, owner_session_token: str) -> dict[str, Any]:
    task = _runtime().cancel_task(task_id, owner_session_token=owner_session_token)
    return {"task": _task_public(task)}


def chat(payload: dict[str, Any], *, owner_session_token: str) -> dict[str, Any]:
    text = str(payload.get("text", "")).strip()
    if not text:
        raise ValueError("text_required")
    conversation_id = _conversation_id(payload)
    # All chat modes now enter the same durable MissionRuntime.  The legacy
    # task/core-engine branch remains available only through the explicit task
    # compatibility endpoints below; it is not a chat execution path.
    owner = _owner_session(owner_session_token)
    requested_profile = requested_model_id(payload, default=None)
    core = _agent_core()
    owner_id = str(owner["owner_id"])
    ensure_conversation(conversation_id, owner_id)
    add_conversation_message(conversation_id, "user", text, owner_id=owner_id)
    if payload.get("mission_id"):
        mission_id = str(payload["mission_id"])
        existing = core.store.load_for_owner(mission_id, owner_id)
        if existing is None:
            raise KeyError("unknown_mission")
        pinned_profile = str((existing.model_selection or {}).get("profile_id") or "auto")
        if requested_profile is not None and requested_profile != pinned_profile:
            raise ModelSelectionError("mission_model_selection_locked")
        mission = core.resume_mission(mission_id, owner_session_token=owner_session_token)
    else:
        mission = core.run_owner_mission(
            text,
            owner_session_token=owner_session_token,
            request_id=str(payload.get("request_id") or uuid.uuid4().hex),
            scope_context=payload.get("scope_context"),
            completion_criteria=payload.get("completion_criteria"),
            model_id=requested_profile if requested_profile is not None else "auto",
        )
    if mission.provenance.get("conversation_id") != conversation_id:
        mission.provenance["conversation_id"] = conversation_id
        mission = core.store.save(mission)
    answer = str(mission.progress.get("last_model_content") or "")
    if answer:
        try:
            parsed = json.loads(answer)
            if isinstance(parsed, dict):
                answer = str(parsed.get("content", parsed.get("answer", answer)))
        except json.JSONDecodeError:
            pass
    if not answer:
        initial = mission.progress.get("initial_model_response") or {}
        answer = str(initial.get("content", "") or "")
        try:
            parsed = json.loads(answer)
            if isinstance(parsed, dict):
                answer = str(parsed.get("content", parsed.get("answer", answer)))
        except json.JSONDecodeError:
            pass
    answer = answer or "Mission " + mission.status.value
    add_conversation_message(conversation_id, "assistant", answer, {"mission_id": mission.mission_id, "status": mission.status.value, "request_id": mission.request_id, "conversation_id": conversation_id}, owner_id=owner_id)
    activity = list(mission.trajectory)
    for action in mission.action_history:
        if action.get("status") == "completed":
            activity.append({"event": "tool.completed", "tool": action.get("step_id"), "action_id": action.get("action_id")})
    return {
        "conversation_id": conversation_id,
        "answer": answer,
        "mission_id": mission.mission_id,
        "status": mission.status.value,
        "activity": activity,
        "mission": mission.to_public_dict(),
    }


def get_session(conversation_id: str, *, owner_id: str) -> dict[str, Any] | None:
    info = conversation_info(conversation_id, owner_id=owner_id)
    if info is None:
        return None
    info.pop("owner_id", None)
    info.pop("owner_session_id", None)
    info["messages"] = conversation_messages(conversation_id)
    owned_tasks = []
    for task in TaskManager.get_tasks_by_conversation(conversation_id):
        state = task.execution_state if isinstance(task.execution_state, dict) else {}
        if str(state.get("owner_identity", "")) == str(owner_id):
            owned_tasks.append(_task_public(task))
    info["tasks"] = owned_tasks
    return info


def stream(payload: dict[str, Any], *, owner_session_token: str) -> Iterator[dict[str, Any]]:
    yield {"event": "started", "data": {"conversation_id": payload.get("conversation_id")}}
    result = chat(payload, owner_session_token=owner_session_token)
    for activity in result.get("activity", []):
        event_name = activity.get("event", "tool_activity") if isinstance(activity, dict) else "tool_activity"
        yield {"event": event_name, "data": activity}
    yield {"event": "completed", "data": result}


def task_stream(task_id: str, *, owner_session_token: str) -> Iterator[dict[str, Any]]:
    result = get_task(task_id, owner_session_token=owner_session_token)
    task = TaskManager.get_task(task_id)
    for event in result["task"].get("events", []):
        yield {"event": event["event"], "data": event}
    status = result["task"].get("status")
    final_event = "task.completed" if status == TaskStatus.COMPLETED.value else ("task.terminal" if task.is_terminal else "task.status")
    yield {"event": final_event, "data": result}


def sse(event: dict[str, Any]) -> bytes:
    return (f"event: {event['event']}\ndata: {json.dumps(event['data'], ensure_ascii=False)}\n\n").encode("utf-8")
