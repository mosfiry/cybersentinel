from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from datetime import datetime, timezone
import uuid
import hashlib
import json

from .planning import Plan
from .trajectory import EventType, TrajectoryEvent, verify_trajectory
from .execution_fence import ExecutionFence, ExecutionFenceError
from security.session_reference import normalize_persisted_session_fields


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
    OWNER_REAUTH_REQUIRED = "OWNER_REAUTH_REQUIRED"
    AUTHORIZATION_BLOCKED = "AUTHORIZATION_BLOCKED"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"
    RESOURCE_BLOCKED = "RESOURCE_BLOCKED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    FAILED_RETRY_EXHAUSTED = "FAILED_RETRY_EXHAUSTED"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True)
class MissionClaimBinding:
    lease_binding_id: str | None
    terminal_status: MissionStatus | None = None


TERMINAL_MISSION_STATUSES = frozenset({
    MissionStatus.GOAL_COMPLETED, MissionStatus.OWNER_INPUT_REQUIRED,
    MissionStatus.OWNER_REAUTH_REQUIRED,
    MissionStatus.AUTHORIZATION_BLOCKED, MissionStatus.SCOPE_BLOCKED,
    MissionStatus.RESOURCE_BLOCKED, MissionStatus.RECOVERY_REQUIRED, MissionStatus.SAFETY_BLOCKED,
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
    request_id: str = ""
    owner_identity_ref: str = ""
    owner_instruction: str = ""
    policy_snapshot: dict[str, Any] | None = None
    authorization_snapshot: dict[str, Any] | None = None
    authorization_snapshot_history: list[dict[str, Any]] = field(default_factory=list)
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
        recovery_reauthorization = (
            self.status is MissionStatus.RECOVERY_REQUIRED
            and target is MissionStatus.OWNER_REAUTH_REQUIRED
            and self.progress.get("reconciliation_complete") is True
        )
        if self.status is MissionStatus.RECOVERY_REQUIRED and target not in {MissionStatus.RECOVERY_REQUIRED, MissionStatus.READY} and not recovery_reauthorization:
            raise ValueError("recovery requires reconciliation before continuation")
        recovery_reconciled = self.status is MissionStatus.RECOVERY_REQUIRED and target is MissionStatus.READY
        owner_intervention = self.status is MissionStatus.OWNER_INPUT_REQUIRED and target in {MissionStatus.AUTHORIZATION_BLOCKED, MissionStatus.READY}
        owner_reauthorized = self.status is MissionStatus.OWNER_REAUTH_REQUIRED and target is MissionStatus.READY
        owner_cancelled = self.status in {MissionStatus.OWNER_INPUT_REQUIRED, MissionStatus.OWNER_REAUTH_REQUIRED} and target is MissionStatus.CANCELLED
        if self.is_terminal and target is not self.status and not recovery_reconciled and not recovery_reauthorization and not owner_intervention and not owner_reauthorized and not owner_cancelled:
            raise ValueError(f"terminal mission cannot transition {self.status.value}->{target.value}")
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
        return {
            "mission_id": self.mission_id,
            "owner_request": self.owner_request,
            "objective": self.objective,
            "status": self.status.value,
            "plan": self.plan.to_dict(),
            "current_step": self.current_step,
            "progress": self.progress,
            "observations": self.observations,
            "evidence": self.evidence,
            "artifacts": self.artifacts,
            "failures": self.failures,
            "authorization_context": self.authorization_context,
            "scope_snapshot": self.scope_snapshot,
            "completion_criteria": self.completion_criteria,
            "verification_state": self.verification_state,
            "checkpoint": self.checkpoint,
            "plan_history": self.plan_history,
            "action_history": self.action_history,
            "transitions": self.transitions,
            "retry_count": self.retry_count,
            "max_iterations": self.max_iterations,
            "iteration_count": self.iteration_count,
            "error": self.error,
            "request_id": self.request_id,
            "owner_identity_ref": self.owner_identity_ref,
            "owner_instruction": self.owner_instruction,
            "policy_snapshot": self.policy_snapshot,
            "authorization_snapshot": self.authorization_snapshot,
            "authorization_snapshot_history": self.authorization_snapshot_history,
            "provenance": self.provenance,
            "trajectory": self.trajectory,
            "hypotheses": self.hypotheses,
            "strategy_state": self.strategy_state,
            "knowledge_context": self.knowledge_context,
            "interpretations": self.interpretations,
            "strategy_decisions": self.strategy_decisions,
            "replan_history": self.replan_history,
            "verification_history": self.verification_history,
            "recovery_events": self.recovery_events,
            "semantic_intent": self.semantic_intent,
        }

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
            rows = db.execute("SELECT mission_id, payload FROM missions").fetchall()
            for mission_id, encoded in rows:
                payload = json.loads(encoded)
                changed = False
                for field_name in (
                    "authorization_context",
                    "authorization_snapshot",
                    "authorization_snapshot_history",
                    "scope_snapshot",
                    "policy_snapshot",
                ):
                    value = payload.get(field_name)
                    if value is None:
                        continue
                    normalized = normalize_persisted_session_fields(value)
                    if normalized != value:
                        payload[field_name] = normalized
                        changed = True
                if changed:
                    payload.pop("integrity_hash", None)
                    payload["integrity_hash"] = hashlib.sha256(
                        json.dumps(
                            payload,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                            default=str,
                        ).encode()
                    ).hexdigest()
                    db.execute(
                        "UPDATE missions SET payload=? WHERE mission_id=?",
                        (json.dumps(payload, ensure_ascii=False), mission_id),
                    )

    def _attach_queue_database(self, db, execution_fence: ExecutionFence) -> None:
        from pathlib import Path

        mission_path = str(Path(self.db_path).resolve())
        queue_path = str(Path(execution_fence.queue.db_path).resolve())
        if mission_path == queue_path:
            schemas = ("main",)
        else:
            db.execute("ATTACH DATABASE ? AS execution_queue", (queue_path,))
            schemas = ("main", "execution_queue")
        for schema in schemas:
            mode = str(db.execute(f"PRAGMA {schema}.journal_mode").fetchone()[0]).lower()
            if mode not in {"delete", "truncate", "persist"}:
                raise ExecutionFenceError("mission and queue writes require SQLite rollback-journal mode")

    def _save(self, mission: Mission, *, execution_fence: ExecutionFence | None, allow_claimed: bool) -> Mission:
        import sqlite3
        if execution_fence is not None:
            execution_fence.assert_current(mission=mission, allow_claimed=allow_claimed)
            if execution_fence.queue.require_execution_fence:
                marker = mission.progress.get("active_execution_claim")
                if not isinstance(marker, dict) or marker.get("lease_binding_id") != execution_fence.lease_binding_id:
                    raise ExecutionFenceError("mission write requires its current durable claim marker")
                bound_at = marker.get("bound_at")
                marker.update(execution_fence.metadata())
                marker["lease_binding_id"] = execution_fence.lease_binding_id
                marker["bound_at"] = bound_at
        with sqlite3.connect(self.db_path, timeout=30) as db:
            if execution_fence is not None:
                self._attach_queue_database(db, execution_fence)
            db.execute("BEGIN IMMEDIATE")
            if execution_fence is not None:
                # The queue DB is attached to this write transaction, preventing
                # lease recovery/reclaim between fence validation and mission CAS.
                execution_fence.assert_current(mission=mission, db=db, allow_claimed=allow_claimed)
            payload = mission.to_dict()
            encoded = json.dumps(payload, ensure_ascii=False)
            existing = db.execute("SELECT payload FROM missions WHERE mission_id=?", (mission.mission_id,)).fetchone()
            if execution_fence is None:
                current_marker = None
                if existing is not None:
                    current_progress = json.loads(existing[0]).get("progress", {})
                    if not isinstance(current_progress, dict):
                        raise ExecutionFenceError("stored mission claim marker state is invalid")
                    current_marker = current_progress.get("active_execution_claim")
                proposed_marker = mission.progress.get("active_execution_claim")
                if proposed_marker != current_marker:
                    raise ExecutionFenceError("active execution claim can only be changed by its current fence")
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

    def save(self, mission: Mission, *, execution_fence: ExecutionFence | None = None) -> Mission:
        return self._save(mission, execution_fence=execution_fence, allow_claimed=False)

    def bind_execution_claim(self, mission_id: str, execution_fence: ExecutionFence) -> MissionClaimBinding:
        """Persist mission RUNNING + lease marker before the queue allows dispatch."""
        mission = self.load(mission_id)
        if mission is None:
            raise KeyError("unknown mission")
        if mission.is_terminal:
            execution_fence.assert_current(mission=mission, allow_claimed=True)
            return MissionClaimBinding(None, mission.status)
        if mission.status not in {
            MissionStatus.READY,
            MissionStatus.RUNNING,
            MissionStatus.OBSERVING,
            MissionStatus.VERIFYING,
            MissionStatus.REPLANNING,
        }:
            raise ExecutionFenceError("mission state is not eligible for worker claim binding")
        bound_fence = (
            execution_fence
            if execution_fence.task_version is not None and execution_fence.authorization_hash
            else execution_fence.for_mission(mission)
        )
        bound_fence.assert_current(mission=mission, allow_claimed=True)
        if bound_fence.queue.require_execution_fence and bound_fence.queue.mission_store is not self:
            raise ExecutionFenceError("strict queue must be configured with this MissionStore")
        if mission.status is not MissionStatus.RUNNING:
            mission.transition(
                MissionStatus.RUNNING,
                "durable queue claim bound before execution",
                worker_instance_id=bound_fence.worker_instance_id,
                runtime_generation=bound_fence.runtime_generation,
                lease_epoch=bound_fence.lease_epoch,
            )
        mission.progress["active_execution_claim"] = {
            **bound_fence.metadata(),
            "lease_binding_id": bound_fence.lease_binding_id,
            "bound_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save(mission, execution_fence=bound_fence, allow_claimed=True)
        bound_fence.queue.mark_claim_bound(bound_fence, mission_store=self)
        return MissionClaimBinding(bound_fence.lease_binding_id)

    def load(self, mission_id: str) -> Mission | None:
        import sqlite3
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT payload FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
        return Mission.from_dict(json.loads(row[0])) if row else None


__all__ = ["Mission", "MissionStatus", "MissionClaimBinding", "MissionStore", "TERMINAL_MISSION_STATUSES"]
