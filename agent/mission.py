from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import uuid
import hashlib
import json

from .planning import Plan, GoalVerification
from .trajectory import EventType, TrajectoryEvent, verify_trajectory


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
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    FAILED_RETRY_EXHAUSTED = "FAILED_RETRY_EXHAUSTED"
    CANCELLED = "CANCELLED"


TERMINAL_MISSION_STATUSES = frozenset({
    MissionStatus.GOAL_COMPLETED, MissionStatus.OWNER_INPUT_REQUIRED,
    MissionStatus.AUTHORIZATION_BLOCKED, MissionStatus.SCOPE_BLOCKED,
    MissionStatus.RESOURCE_BLOCKED, MissionStatus.RECOVERY_REQUIRED, MissionStatus.SAFETY_BLOCKED,
    MissionStatus.FAILED_RETRY_EXHAUSTED, MissionStatus.CANCELLED,
})


_ALLOWED_EXIT_STATES = frozenset({
    MissionStatus.READY, MissionStatus.RUNNING, MissionStatus.OBSERVING, MissionStatus.VERIFYING,
    MissionStatus.REPLANNING, MissionStatus.GOAL_COMPLETED, MissionStatus.OWNER_INPUT_REQUIRED,
    MissionStatus.AUTHORIZATION_BLOCKED, MissionStatus.SCOPE_BLOCKED, MissionStatus.RESOURCE_BLOCKED,
    MissionStatus.RECOVERY_REQUIRED, MissionStatus.SAFETY_BLOCKED, MissionStatus.FAILED_RETRY_EXHAUSTED,
    MissionStatus.CANCELLED,
})

ALLOWED_MISSION_TRANSITIONS: dict[MissionStatus, frozenset[MissionStatus]] = {
    # CREATED exists only between Mission.create and plan persistence.
    MissionStatus.CREATED: frozenset({MissionStatus.PLANNING, MissionStatus.CANCELLED}),
    MissionStatus.PLANNING: frozenset({MissionStatus.READY, MissionStatus.CANCELLED}),
    # Active execution states may move to any runtime exit state; the runtime
    # still owns WHICH exit is legitimate for a given observation.
    MissionStatus.READY: _ALLOWED_EXIT_STATES,
    MissionStatus.RUNNING: _ALLOWED_EXIT_STATES,
    MissionStatus.OBSERVING: _ALLOWED_EXIT_STATES,
    MissionStatus.VERIFYING: _ALLOWED_EXIT_STATES,
    MissionStatus.REPLANNING: _ALLOWED_EXIT_STATES,
    # Recovery must be reconciled before any other continuation.
    MissionStatus.RECOVERY_REQUIRED: frozenset({MissionStatus.RECOVERY_REQUIRED, MissionStatus.READY}),
    # Owner intervention is the only terminal state that can be resolved.
    MissionStatus.OWNER_INPUT_REQUIRED: frozenset({MissionStatus.OWNER_INPUT_REQUIRED, MissionStatus.AUTHORIZATION_BLOCKED, MissionStatus.READY}),
    # All other terminal states are immutable.
    MissionStatus.GOAL_COMPLETED: frozenset({MissionStatus.GOAL_COMPLETED}),
    MissionStatus.AUTHORIZATION_BLOCKED: frozenset({MissionStatus.AUTHORIZATION_BLOCKED}),
    MissionStatus.SCOPE_BLOCKED: frozenset({MissionStatus.SCOPE_BLOCKED}),
    MissionStatus.RESOURCE_BLOCKED: frozenset({MissionStatus.RESOURCE_BLOCKED}),
    MissionStatus.SAFETY_BLOCKED: frozenset({MissionStatus.SAFETY_BLOCKED}),
    MissionStatus.FAILED_RETRY_EXHAUSTED: frozenset({MissionStatus.FAILED_RETRY_EXHAUSTED}),
    MissionStatus.CANCELLED: frozenset({MissionStatus.CANCELLED}),
}


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
    request_id: str = ""
    owner_identity_ref: str = ""
    owner_instruction: str = ""
    policy_snapshot: dict[str, Any] | None = None
    authorization_snapshot: dict[str, Any] | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    trajectory: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    strategy_state: dict[str, Any] = field(default_factory=dict)
    knowledge_context: list[dict[str, Any]] = field(default_factory=list)
    interpretations: list[dict[str, Any]] = field(default_factory=list)
    strategy_decisions: list[dict[str, Any]] = field(default_factory=list)
    replan_history: list[dict[str, Any]] = field(default_factory=list)
    verification_history: list[dict[str, Any]] = field(default_factory=list)
    recovery_events: list[dict[str, Any]] = field(default_factory=list)
    semantic_intent: dict[str, Any] = field(default_factory=dict)
    integrity_hash: str = ""

    @classmethod
    def create(cls, owner_request: str, objective: str, plan: Plan, *, mission_id: str | None = None, authorization_context: dict[str, Any] | None = None, scope_snapshot: dict[str, Any] | None = None, completion_criteria: list[dict[str, Any]] | None = None, max_iterations: int = 50, request_id: str = "", owner_identity_ref: str = "", owner_instruction: str = "", policy_snapshot: dict[str, Any] | None = None, authorization_snapshot: dict[str, Any] | None = None, provenance: dict[str, Any] | None = None) -> "Mission":
        mission = cls(mission_id or uuid.uuid4().hex, owner_request, objective, MissionStatus.CREATED, plan, authorization_context=authorization_context, scope_snapshot=scope_snapshot, completion_criteria=completion_criteria or [], max_iterations=max_iterations, request_id=request_id, owner_identity_ref=owner_identity_ref, owner_instruction=owner_instruction or owner_request, policy_snapshot=policy_snapshot, authorization_snapshot=authorization_snapshot, provenance=provenance or {})
        mission.plan_history = [{"version": plan.version, "fingerprint": plan.fingerprint, "reason": "created"}]
        mission.transition(MissionStatus.PLANNING, "mission created")
        mission.emit(EventType.MISSION_STARTED, data={"objective": mission.objective})
        mission.emit(EventType.PLAN_CREATED, data={"version": plan.version, "fingerprint": plan.fingerprint})
        return mission

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_MISSION_STATUSES

    @property
    def current_plan_step(self):
        return self.plan.steps[self.current_step] if self.current_step < len(self.plan.steps) else None

    def transition(self, target: MissionStatus, reason: str, **data: Any) -> None:
        if not isinstance(target, MissionStatus):
            raise TypeError("mission transition requires MissionStatus")
        allowed_targets = ALLOWED_MISSION_TRANSITIONS.get(self.status, frozenset({self.status}))
        if target is not self.status and target not in allowed_targets:
            if self.status is MissionStatus.RECOVERY_REQUIRED:
                raise ValueError("recovery requires reconciliation before continuation")
            if self.status in TERMINAL_MISSION_STATUSES:
                raise ValueError(f"terminal mission cannot transition {self.status.value}->{target.value}")
            raise ValueError(f"invalid mission transition {self.status.value}->{target.value}")
        self.status = target
        self.transitions.append({"from": self.transitions[-1]["to"] if self.transitions else "CREATED", "to": target.value, "reason": reason, "data": data, "iteration": self.iteration_count})

    def emit(self, event_type: EventType, *, step_id: str = "", data: dict[str, Any] | None = None) -> None:
        previous_hash = str(self.trajectory[-1].get("event_hash", "")) if self.trajectory else ""
        event = TrajectoryEvent(event_type, self.mission_id, self.request_id, step_id=step_id, provenance=dict(self.provenance), data=data or {}, previous_hash=previous_hash)
        self.trajectory.append(event.to_dict())

    def record_observation(self, observation: dict[str, Any]) -> None:
        self.observations.append(dict(observation))
        self.progress["last_observation"] = observation.get("type", "observation")
        self.emit(EventType.OBSERVATION_RECEIVED, step_id=str(observation.get("step_id", "")), data={"status": observation.get("status", observation.get("success")), "action_id": observation.get("action_id", "")})

    def record_action(self, action_id: str, step_id: str, status: str, observation: dict[str, Any] | None = None) -> None:
        if any(item.get("action_id") == action_id for item in self.action_history):
            return
        self.action_history.append({"action_id": action_id, "step_id": step_id, "status": status, "observation": observation or {}})
        self.emit(EventType.TOOL_EXECUTED, step_id=step_id, data={"action_id": action_id, "status": status})

    def _unsigned_dict(self) -> dict[str, Any]:
        return {"mission_id": self.mission_id, "owner_request": self.owner_request, "objective": self.objective, "status": self.status.value, "plan": self.plan.to_dict(), "current_step": self.current_step, "progress": self.progress, "observations": self.observations, "evidence": self.evidence, "artifacts": self.artifacts, "failures": self.failures, "authorization_context": self.authorization_context, "scope_snapshot": self.scope_snapshot, "completion_criteria": self.completion_criteria, "verification_state": self.verification_state, "checkpoint": self.checkpoint, "plan_history": self.plan_history, "action_history": self.action_history, "transitions": self.transitions, "retry_count": self.retry_count, "max_iterations": self.max_iterations, "iteration_count": self.iteration_count, "error": self.error, "request_id": self.request_id, "owner_identity_ref": self.owner_identity_ref, "owner_instruction": self.owner_instruction, "policy_snapshot": self.policy_snapshot, "authorization_snapshot": self.authorization_snapshot, "provenance": self.provenance, "trajectory": self.trajectory, "hypotheses": self.hypotheses, "strategy_state": self.strategy_state, "knowledge_context": self.knowledge_context, "interpretations": self.interpretations, "strategy_decisions": self.strategy_decisions, "replan_history": self.replan_history, "verification_history": self.verification_history, "recovery_events": self.recovery_events, "semantic_intent": self.semantic_intent}

    def to_dict(self) -> dict[str, Any]:
        payload = self._unsigned_dict()
        payload["integrity_hash"] = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Mission":
        raw = dict(data)
        supplied_hash = str(raw.pop("integrity_hash", "") or "")
        if supplied_hash:
            expected_hash = hashlib.sha256(json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
            if supplied_hash != expected_hash:
                raise ValueError("mission_integrity_hash_mismatch")
        trajectory = raw.get("trajectory") or []
        if trajectory and any("event_hash" in item for item in trajectory):
            if not all("event_hash" in item for item in trajectory) or not verify_trajectory(trajectory):
                raise ValueError("trajectory_integrity_mismatch")
        plan_data = raw.pop("plan")
        from .planning import PlanStep
        steps = tuple(PlanStep(**{**step, "prerequisites": tuple(step.get("prerequisites", ())), "verification": tuple(step.get("verification", ()))}) for step in plan_data.get("steps", []))
        raw["plan"] = Plan(version=plan_data["version"], objective=plan_data["objective"], assumptions=tuple(plan_data.get("assumptions", ())), steps=steps, dependencies=tuple(plan_data.get("dependencies", ())), completion_criteria=tuple(plan_data.get("completion_criteria", ())), risk=plan_data.get("risk", "unknown"), created_from=plan_data.get("created_from", ""))
        raw["status"] = MissionStatus(raw["status"])
        raw["integrity_hash"] = supplied_hash
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
            payload = mission.to_dict()
            encoded = json.dumps(payload, ensure_ascii=False)
            existing = db.execute("SELECT payload FROM missions WHERE mission_id=?", (mission.mission_id,)).fetchone()
            if existing is None:
                db.execute("INSERT INTO missions(mission_id,payload) VALUES(?,?)", (mission.mission_id, encoded))
            else:
                current_hash = str(json.loads(existing[0]).get("integrity_hash", ""))
                if not mission.integrity_hash or current_hash != mission.integrity_hash:
                    raise ValueError("stale mission write rejected")
                updated = db.execute("UPDATE missions SET payload=? WHERE mission_id=? AND payload=?", (encoded, mission.mission_id, existing[0]))
                if updated.rowcount != 1:
                    raise ValueError("concurrent mission write rejected")
            mission.integrity_hash = str(payload["integrity_hash"])
        return mission

    def load(self, mission_id: str) -> Mission | None:
        import json, sqlite3
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT payload FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
        return Mission.from_dict(json.loads(row[0])) if row else None


__all__ = ["Mission", "MissionStatus", "MissionStore", "TERMINAL_MISSION_STATUSES"]
