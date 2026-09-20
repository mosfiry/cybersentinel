"""
CyberSentinel X - Phase 5B: Task Management

Task system for long-horizon conversational execution.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TaskStatus(Enum):
    """Task execution states."""
    QUEUED = "queued"
    PLANNING = "planning"
    WAITING_FOR_TOOL = "waiting_for_tool"
    EXECUTING = "executing"
    WAITING_FOR_MODEL = "waiting_for_model"
    PAUSED = "paused"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    """Persistent task representation for long-horizon execution."""
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
    
    @classmethod
    def create(
        cls,
        conversation_id: str,
        request_id: str,
        owner_session_id: str,
        objective: str,
        provider: str = "",
        model: str = "",
    ) -> Task:
        """Create a new task."""
        now = datetime.now(timezone.utc).isoformat()
        return cls(
            task_id=uuid.uuid4().hex,
            conversation_id=conversation_id,
            request_id=request_id,
            owner_session_id=owner_session_id,
            status=TaskStatus.QUEUED,
            created_at=now,
            updated_at=now,
            started_at=None,
            finished_at=None,
            current_step=0,
            tool_calls=[],
            retry_count=0,
            provider=provider,
            model=model,
            objective=objective,
            execution_state={},
            result=None,
            error=None,
            cancel_requested=False,
            pause_requested=False,
            resume_state=None,
        )
    
    def to_dict(self) -> dict[str, Any]:
        """Convert task to dictionary for serialization."""
        return {
            "task_id": self.task_id,
            "conversation_id": self.conversation_id,
            "request_id": self.request_id,
            "owner_session_id": self.owner_session_id,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "current_step": self.current_step,
            "tool_calls": self.tool_calls,
            "retry_count": self.retry_count,
            "provider": self.provider,
            "model": self.model,
            "objective": self.objective,
            "execution_state": self.execution_state,
            "result": self.result,
            "error": self.error,
            "cancel_requested": self.cancel_requested,
            "pause_requested": self.pause_requested,
            "resume_state": self.resume_state,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Task:
        """Create task from dictionary."""
        data = data.copy()
        data["status"] = TaskStatus(data["status"])
        return cls(**data)
    
    def update_status(self, new_status: TaskStatus) -> None:
        """Update task status."""
        self.status = new_status
        self.updated_at = datetime.now(timezone.utc).isoformat()
        
        if new_status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED):
            self.finished_at = self.updated_at
        elif new_status == TaskStatus.EXECUTING and self.started_at is None:
            self.started_at = self.updated_at
    
    def add_tool_call(self, tool_name: str, status: str, request_id: str | None = None) -> None:
        """Record a tool call."""
        self.tool_calls.append({
            "tool_call_id": uuid.uuid4().hex,
            "tool_name": tool_name,
            "status": status,
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self.updated_at = datetime.now(timezone.utc).isoformat()
    
    def increment_step(self) -> None:
        """Increment current step."""
        self.current_step += 1
        self.updated_at = datetime.now(timezone.utc).isoformat()
    
    def increment_retry(self) -> None:
        """Increment retry count."""
        self.retry_count += 1
        self.updated_at = datetime.now(timezone.utc).isoformat()
    
    def request_cancel(self) -> None:
        """Request task cancellation."""
        self.cancel_requested = True
        self.updated_at = datetime.now(timezone.utc).isoformat()
    
    def request_pause(self) -> None:
        """Request task pause."""
        self.pause_requested = True
        self.updated_at = datetime.now(timezone.utc).isoformat()
    
    def save_resume_state(self, state: dict[str, Any]) -> None:
        """Save state for resumption."""
        self.resume_state = state
        self.updated_at = datetime.now(timezone.utc).isoformat()
    
    @property
    def is_active(self) -> bool:
        """Check if task is still active."""
        return self.status in (
            TaskStatus.QUEUED,
            TaskStatus.PLANNING,
            TaskStatus.WAITING_FOR_TOOL,
            TaskStatus.EXECUTING,
            TaskStatus.WAITING_FOR_MODEL,
            TaskStatus.PAUSED,
        )
    
    @property
    def is_terminal(self) -> bool:
        """Check if task has reached a terminal state."""
        return self.status in (
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        )
