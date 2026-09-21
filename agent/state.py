"""
CyberSentinel X - Phase 5B: Execution State Management

State management for long-horizon conversational execution.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ExecutionStatus(Enum):
    """Execution status states."""
    INITIAL = "initial"
    RUNNING = "running"
    WAITING = "waiting"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ExecutionState:
    """Execution state for long-horizon tasks."""
    request_id: str
    conversation_id: str
    task_id: str | None = None
    step: int = 0
    tool_calls_used: int = 0
    remaining_steps: int = 0
    provider: str = ""
    model: str = ""
    status: ExecutionStatus = ExecutionStatus.INITIAL
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def initial(
        cls,
        request_id: str,
        conversation_id: str,
        provider: str = "",
        model: str = "",
    ) -> ExecutionState:
        """Create initial execution state."""
        now = datetime.now(timezone.utc).isoformat()
        return cls(
            request_id=request_id,
            conversation_id=conversation_id,
            task_id=None,
            step=0,
            tool_calls_used=0,
            remaining_steps=0,
            provider=provider,
            model=model,
            status=ExecutionStatus.INITIAL,
            created_at=now,
            updated_at=now,
            metadata={},
        )
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "request_id": self.request_id,
            "conversation_id": self.conversation_id,
            "task_id": self.task_id,
            "step": self.step,
            "tool_calls_used": self.tool_calls_used,
            "remaining_steps": self.remaining_steps,
            "provider": self.provider,
            "model": self.model,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionState:
        """Create from dictionary."""
        data = data.copy()
        data["status"] = ExecutionStatus(data["status"])
        return cls(**data)
    
    def update(
        self,
        step: int | None = None,
        tool_calls_used: int | None = None,
        remaining_steps: int | None = None,
        status: ExecutionStatus | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Update execution state."""
        if step is not None:
            self.step = step
        if tool_calls_used is not None:
            self.tool_calls_used = tool_calls_used
        if remaining_steps is not None:
            self.remaining_steps = remaining_steps
        if status is not None:
            self.status = status
        if metadata is not None:
            self.metadata.update(metadata)
        self.updated_at = datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class TaskState:
    """Immutable task state snapshot."""
    task_id: str
    conversation_id: str
    request_id: str
    owner_session_id: str
    status: str
    current_step: int
    tool_calls_count: int
    retry_count: int
    provider: str
    model: str
    objective: str
    created_at: str
    updated_at: str
    started_at: str | None
    finished_at: str | None
    
    @classmethod
    def from_task(cls, task: Any) -> TaskState:
        """Create from Task object."""
        from .task import Task
        return cls(
            task_id=task.task_id,
            conversation_id=task.conversation_id,
            request_id=task.request_id,
            owner_session_id=task.owner_session_id,
            status=task.status.value,
            current_step=task.current_step,
            tool_calls_count=len(task.tool_calls),
            retry_count=task.retry_count,
            provider=task.provider,
            model=task.model,
            objective=task.objective,
            created_at=task.created_at,
            updated_at=task.updated_at,
            started_at=task.started_at,
            finished_at=task.finished_at,
        )


@dataclass(frozen=True)
class MissionState:
    """Auditable, serializable state projection for the native Agent Core."""
    mission_id: str
    request_id: str
    objective: str
    owner_instruction: str
    policy_snapshot: dict[str, Any]
    authorization_context: dict[str, Any] | None
    scope_snapshot: dict[str, Any] | None
    assumptions: tuple[str, ...] = ()
    facts: tuple[dict[str, Any], ...] = ()
    hypotheses: tuple[dict[str, Any], ...] = ()
    unknowns: tuple[str, ...] = ()
    observations: tuple[dict[str, Any], ...] = ()
    evidence: tuple[dict[str, Any], ...] = ()
    completed_steps: tuple[str, ...] = ()
    failed_steps: tuple[str, ...] = ()
    active_plan: dict[str, Any] | None = None
    plan_history: tuple[dict[str, Any], ...] = ()
    rejected_plans: tuple[dict[str, Any], ...] = ()
    pending_actions: tuple[dict[str, Any], ...] = ()
    tool_history: tuple[dict[str, Any], ...] = ()
    resource_state: dict[str, Any] = field(default_factory=dict)
    verification_state: dict[str, Any] = field(default_factory=dict)
    failure_state: dict[str, Any] = field(default_factory=dict)
    recovery_state: dict[str, Any] = field(default_factory=dict)
    context_state: dict[str, Any] = field(default_factory=dict)
    next_action: dict[str, Any] | None = None
    loop_detection_state: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mission(cls, mission: Any) -> "MissionState":
        completed = tuple(item["step_id"] for item in mission.action_history if item.get("status") == "completed")
        failed = tuple(item["step_id"] for item in mission.action_history if item.get("status") == "failed")
        return cls(
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            objective=mission.objective,
            owner_instruction=mission.owner_instruction,
            policy_snapshot=dict(mission.policy_snapshot or {}),
            authorization_context=mission.authorization_context,
            scope_snapshot=mission.scope_snapshot,
            assumptions=tuple(mission.plan.assumptions),
            observations=tuple(mission.observations),
            evidence=tuple(mission.evidence),
            completed_steps=completed,
            failed_steps=failed,
            active_plan=mission.plan.to_dict(),
            plan_history=tuple(mission.plan_history),
            tool_history=tuple(mission.action_history),
            verification_state=dict(mission.verification_state),
            failure_state=dict(mission.failures[-1]) if mission.failures else {},
            recovery_state={"retry_count": mission.retry_count},
            resource_state={"iteration_count": mission.iteration_count, "max_iterations": mission.max_iterations},
            next_action=mission.current_plan_step.to_dict() if mission.current_plan_step else None,
            provenance=dict(mission.provenance),
        )

    def to_dict(self) -> dict[str, Any]:
        value = self.__dict__.copy()
        for key in ("assumptions", "facts", "hypotheses", "unknowns", "observations", "evidence", "completed_steps", "failed_steps", "plan_history", "rejected_plans", "pending_actions", "tool_history"):
            value[key] = list(value[key])
        return value
