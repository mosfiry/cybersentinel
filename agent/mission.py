from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import uuid

from .planning import Plan, GoalVerification


class MissionStatus(str, Enum):
    CREATED = "CREATED"
    PLANNING = "PLANNING"
    READY = "READY"
    RUNNING = "RUNNING"
    OBSERVING = "OBSERVING"
    VERIFYING = "VERIFYING"
    REPLANNING = "REPLANNING"
    GOAL_COMPLETED = "GOAL_COMPLETED"
    OWNER_INPUT_REQUIRED = "OWNER_INPUT_REQUIRED"
    AUTHORIZATION_BLOCKED = "AUTHORIZATION_BLOCKED"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"
    RESOURCE_BLOCKED = "RESOURCE_BLOCKED"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    FAILED_RETRY_EXHAUSTED = "FAILED_RETRY_EXHAUSTED"
    CANCELLED = "CANCELLED"


TERMINAL_MISSION_STATUSES = frozenset({
    MissionStatus.GOAL_COMPLETED, MissionStatus.OWNER_INPUT_REQUIRED,
    MissionStatus.AUTHORIZATION_BLOCKED, MissionStatus.SCOPE_BLOCKED,
    MissionStatus.RESOURCE_BLOCKED, MissionStatus.SAFETY_BLOCKED,
    MissionStatus.FAILED_RETRY_EXHAUSTED, MissionStatus.CANCELLED,
})


@dataclass
class Mission:
    mission_id: str
    owner_request: str
    objective: str
    status: MissionStatus
    plan: Plan
    current_step: int = 0
    progress: dict[str, Any] = field(default_factory=dict)
    observations: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    failures: list[dict[str, Any]] = field(default_factory=list)
    authorization_context: dict[str, Any] | None = None
    scope_snapshot: dict[str, Any] | None = None
    completion_criteria: list[dict[str, Any]] = field(default_factory=list)
    verification_state: dict[str, Any] = field(default_factory=dict)
    checkpoint: dict[str, Any] = field(default_factory=dict)
    plan_history: list[dict[str, Any]] = field(default_factory=list)
    action_history: list[dict[str, Any]] = field(default_factory=list)
    transitions: list[dict[str, Any]] = field(default_factory=list)
    retry_count: int = 0
    max_iterations: int = 50
    iteration_count: int = 0
    error: str = ""

    @classmethod
    def create(cls, owner_request: str, objective: str, plan: Plan, *, mission_id: str | None = None, authorization_context: dict[str, Any] | None = None, scope_snapshot: dict[str, Any] | None = None, completion_criteria: list[dict[str, Any]] | None = None, max_iterations: int = 50) -> "Mission":
        mission = cls(mission_id or uuid.uuid4().hex, owner_request, objective, MissionStatus.CREATED, plan, authorization_context=authorization_context, scope_snapshot=scope_snapshot, completion_criteria=completion_criteria or [], max_iterations=max_iterations)
        mission.plan_history = [{"version": plan.version, "fingerprint": plan.fingerprint, "reason": "created"}]
        mission.transition(MissionStatus.PLANNING, "mission created")
        return mission

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_MISSION_STATUSES

    @property
    def current_plan_step(self):
        return self.plan.steps[self.current_step] if self.current_step < len(self.plan.steps) else None

    def transition(self, target: MissionStatus, reason: str, **data: Any) -> None:
        self.status = target
        self.transitions.append({"from": self.transitions[-1]["to"] if self.transitions else "CREATED", "to": target.value, "reason": reason, "data": data, "iteration": self.iteration_count})

    def record_observation(self, observation: dict[str, Any]) -> None:
        self.observations.append(dict(observation))
        self.progress["last_observation"] = observation.get("type", "observation")

    def record_action(self, action_id: str, step_id: str, status: str, observation: dict[str, Any] | None = None) -> None:
        if any(item.get("action_id") == action_id for item in self.action_history):
            return
        self.action_history.append({"action_id": action_id, "step_id": step_id, "status": status, "observation": observation or {}})

    def to_dict(self) -> dict[str, Any]:
        return {"mission_id": self.mission_id, "owner_request": self.owner_request, "objective": self.objective, "status": self.status.value, "plan": self.plan.to_dict(), "current_step": self.current_step, "progress": self.progress, "observations": self.observations, "evidence": self.evidence, "artifacts": self.artifacts, "failures": self.failures, "authorization_context": self.authorization_context, "scope_snapshot": self.scope_snapshot, "completion_criteria": self.completion_criteria, "verification_state": self.verification_state, "checkpoint": self.checkpoint, "plan_history": self.plan_history, "action_history": self.action_history, "transitions": self.transitions, "retry_count": self.retry_count, "max_iterations": self.max_iterations, "iteration_count": self.iteration_count, "error": self.error}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Mission":
        raw = dict(data)
        plan_data = raw.pop("plan")
        from .planning import PlanStep
        steps = tuple(PlanStep(**{**step, "prerequisites": tuple(step.get("prerequisites", ())), "verification": tuple(step.get("verification", ()))}) for step in plan_data.get("steps", []))
        raw["plan"] = Plan(version=plan_data["version"], objective=plan_data["objective"], assumptions=tuple(plan_data.get("assumptions", ())), steps=steps, dependencies=tuple(plan_data.get("dependencies", ())), completion_criteria=tuple(plan_data.get("completion_criteria", ())), risk=plan_data.get("risk", "unknown"), created_from=plan_data.get("created_from", ""))
        raw["status"] = MissionStatus(raw["status"])
        return cls(**raw)


class MissionStore:
    """Durable JSON-backed SQLite store; the HTTP request is never the mission lifetime."""

    def __init__(self, db_path):
        import sqlite3
        self.db_path = str(db_path)
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS missions (mission_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")

    def save(self, mission: Mission) -> Mission:
        import json, sqlite3
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT OR REPLACE INTO missions(mission_id,payload) VALUES(?,?)", (mission.mission_id, json.dumps(mission.to_dict(), ensure_ascii=False)))
        return mission

    def load(self, mission_id: str) -> Mission | None:
        import json, sqlite3
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT payload FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
        return Mission.from_dict(json.loads(row[0])) if row else None


__all__ = ["Mission", "MissionStatus", "MissionStore", "TERMINAL_MISSION_STATUSES"]
