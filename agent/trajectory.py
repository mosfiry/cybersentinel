from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


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


@dataclass(frozen=True)
class TrajectoryEvent:
    event_type: EventType
    mission_id: str
    request_id: str
    step_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event_type.value,
            "mission_id": self.mission_id,
            "request_id": self.request_id,
            "step_id": self.step_id,
            "timestamp": self.timestamp,
            "provenance": dict(self.provenance),
            "data": dict(self.data),
        }


__all__ = ["EventType", "TrajectoryEvent"]
