from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import hashlib
import json


class EventType(str, Enum):
    MISSION_STARTED = "MissionStarted"
    PLAN_CREATED = "PlanCreated"
    PLAN_REVISED = "PlanRevised"
    STEP_SELECTED = "StepSelected"
    TOOL_PROPOSED = "ToolProposed"
    AUTHORIZATION_CHECKED = "AuthorizationChecked"
    TOOL_EXECUTED = "ToolExecuted"
    OBSERVATION_RECEIVED = "ObservationReceived"
    OBSERVATION_INTERPRETED = "ObservationInterpreted"
    EVIDENCE_ADDED = "EvidenceAdded"
    HYPOTHESIS_UPDATED = "HypothesisUpdated"
    STRATEGY_DECIDED = "StrategyDecided"
    FAILURE_DETECTED = "FailureDetected"
    FAILURE_DIAGNOSED = "FailureDiagnosed"
    RECOVERY_ATTEMPTED = "RecoveryAttempted"
    REPLAN_TRIGGERED = "ReplanTriggered"
    OWNER_INPUT_REQUIRED = "OwnerInputRequired"
    GOAL_VERIFICATION_STARTED = "GoalVerificationStarted"
    GOAL_VERIFIED = "GoalVerified"
    MISSION_COMPLETED = "MissionCompleted"
    RECOVERY_REQUIRED = "RecoveryRequired"
    MODEL_TURN = "ModelTurn"


@dataclass(frozen=True)
class TrajectoryEvent:
    event_type: EventType
    mission_id: str
    request_id: str
    step_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)
    previous_hash: str = ""
    event_hash: str = ""

    def __post_init__(self) -> None:
        if not self.event_hash:
            payload = {
                "event": self.event_type.value, "mission_id": self.mission_id,
                "request_id": self.request_id, "step_id": self.step_id,
                "timestamp": self.timestamp, "provenance": self.provenance,
                "data": self.data, "previous_hash": self.previous_hash,
            }
            object.__setattr__(self, "event_hash", hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest())

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event_type.value,
            "mission_id": self.mission_id,
            "request_id": self.request_id,
            "step_id": self.step_id,
            "timestamp": self.timestamp,
            "provenance": dict(self.provenance),
            "data": dict(self.data),
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }


def verify_trajectory(events: list[dict[str, Any]]) -> bool:
    previous = ""
    for item in events:
        if item.get("previous_hash", "") != previous:
            return False
        candidate = TrajectoryEvent(
            EventType(item["event"]), str(item["mission_id"]), str(item["request_id"]),
            step_id=str(item.get("step_id", "")), timestamp=str(item["timestamp"]),
            provenance=dict(item.get("provenance", {})), data=dict(item.get("data", {})),
            previous_hash=str(item.get("previous_hash", "")), event_hash="",
        )
        if candidate.event_hash != item.get("event_hash"):
            return False
        previous = candidate.event_hash
    return True


__all__ = ["EventType", "TrajectoryEvent", "verify_trajectory"]
