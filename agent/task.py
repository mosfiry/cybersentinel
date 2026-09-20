"""Persistent task model for long-horizon CyberSentinel execution."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TaskStatus(Enum):
    QUEUED = "queued"
    PLANNING = "planning"
    WAITING_FOR_TOOL = "waiting_for_tool"
    EXECUTING = "executing"
    WAITING_FOR_MODEL = "waiting_for_model"
    PAUSED = "paused"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    PARTIAL_SUCCESS = "partial_success"
    NEEDS_INPUT = "needs_input"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATUSES = frozenset({TaskStatus.COMPLETED, TaskStatus.PARTIAL_SUCCESS, TaskStatus.NEEDS_INPUT, TaskStatus.FAILED, TaskStatus.CANCELLED})


@dataclass
class Task:
    task_id: str
    conversation_id: str
    request_id: str
    owner_session_id: str
    status: TaskStatus
    created_at: str
    updated_at: str
    started_at: str | None = None
    finished_at: str | None = None
    current_step: int = 0
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    retry_count: int = 0
    provider: str = ""
    model: str = ""
    objective: str = ""
    execution_state: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None
    cancel_requested: bool = False
    pause_requested: bool = False
    resume_state: dict[str, Any] | None = None
    authentication_method: str = "owner_token"

    @classmethod
    def create(cls, conversation_id: str, request_id: str, owner_session_id: str, objective: str, provider: str = "", model: str = "", authentication_method: str = "owner_token") -> "Task":
        now = datetime.now(timezone.utc).isoformat()
        return cls(uuid.uuid4().hex, conversation_id, request_id, owner_session_id, TaskStatus.QUEUED, now, now, objective=objective, provider=provider, model=model, authentication_method=authentication_method)

    def to_dict(self) -> dict[str, Any]:
        return {**self.__dict__, "status": self.status.value}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Task":
        data = data.copy()
        data["status"] = TaskStatus(data["status"])
        data.setdefault("authentication_method", "owner_token")
        return cls(**data)

    def update_status(self, new_status: TaskStatus) -> None:
        self.status = new_status
        self.updated_at = datetime.now(timezone.utc).isoformat()
        if new_status in TERMINAL_STATUSES:
            self.finished_at = self.updated_at
        elif new_status == TaskStatus.EXECUTING and self.started_at is None:
            self.started_at = self.updated_at

    def record_tool_call(self, tool_call_id: str, tool_name: str, status: str, *, request_id: str, owner_session_id: str, result: Any = None, argument: Any = None) -> bool:
        """Append exactly once; returns False for a replayed call id."""
        if tool_call_id and any(item.get("tool_call_id") == tool_call_id for item in self.tool_calls):
            return False
        self.tool_calls.append({"tool_call_id": tool_call_id or uuid.uuid4().hex, "task_id": self.task_id, "conversation_id": self.conversation_id, "tool_name": tool_name, "argument": argument, "status": status, "request_id": request_id, "owner_session_id": owner_session_id, "result": result, "timestamp": datetime.now(timezone.utc).isoformat()})
        self.updated_at = datetime.now(timezone.utc).isoformat()
        return True

    def add_tool_call(self, tool_name: str, status: str, request_id: str | None = None) -> None:
        self.record_tool_call(uuid.uuid4().hex, tool_name, status, request_id=request_id or self.request_id, owner_session_id=self.owner_session_id)

    def has_tool_call(self, tool_call_id: str) -> bool:
        return any(item.get("tool_call_id") == tool_call_id for item in self.tool_calls)

    def increment_step(self) -> None:
        self.current_step += 1
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def increment_retry(self) -> None:
        self.retry_count += 1
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def request_cancel(self) -> None:
        self.cancel_requested = True
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def request_pause(self) -> None:
        self.pause_requested = True
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def save_resume_state(self, state: dict[str, Any]) -> None:
        self.resume_state = state
        self.updated_at = datetime.now(timezone.utc).isoformat()

    @property
    def is_active(self) -> bool:
        return self.status not in TERMINAL_STATUSES

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES
