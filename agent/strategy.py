from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from .observation_intelligence import InformationGain, ObservationInterpretationProposal, ReplanTrigger


class StrategyDecisionType(str, Enum):
    CONTINUE_PLAN = "CONTINUE_PLAN"
    REPLAN = "REPLAN"
    ADD_EVIDENCE = "ADD_EVIDENCE"
    CHANGE_HYPOTHESIS = "CHANGE_HYPOTHESIS"
    DROP_HYPOTHESIS = "DROP_HYPOTHESIS"
    REQUEST_MISSING_EVIDENCE = "REQUEST_MISSING_EVIDENCE"
    WAIT_FOR_DEPENDENCY = "WAIT_FOR_DEPENDENCY"
    OWNER_INPUT_REQUIRED = "OWNER_INPUT_REQUIRED"
    VERIFY_GOAL = "VERIFY_GOAL"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"


@dataclass
class StrategyState:
    current_strategy: str
    objective: str
    active_hypotheses: list[str] = field(default_factory=list)
    known_facts: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)
    blocked_paths: list[str] = field(default_factory=list)
    completed_paths: list[str] = field(default_factory=list)
    candidate_next_actions: list[dict[str, Any]] = field(default_factory=list)
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_strategy": self.current_strategy,
            "objective": self.objective,
            "active_hypotheses": list(self.active_hypotheses),
            "known_facts": list(self.known_facts),
            "unknowns": list(self.unknowns),
            "required_evidence": list(self.required_evidence),
            "blocked_paths": list(self.blocked_paths),
            "completed_paths": list(self.completed_paths),
            "candidate_next_actions": [dict(item) for item in self.candidate_next_actions],
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, objective: str | None = None) -> "StrategyState":
        return cls(
            current_strategy=str(data.get("current_strategy", "investigate")),
            objective=str(objective or data.get("objective", "")),
            active_hypotheses=list(data.get("active_hypotheses", ())),
            known_facts=list(data.get("known_facts", ())),
            unknowns=list(data.get("unknowns", ())),
            required_evidence=list(data.get("required_evidence", ())),
            blocked_paths=list(data.get("blocked_paths", ())),
            completed_paths=list(data.get("completed_paths", ())),
            candidate_next_actions=[dict(item) for item in data.get("candidate_next_actions", ())],
            version=int(data.get("version", 1)),
        )


@dataclass(frozen=True)
class StrategyDecision:
    decision: StrategyDecisionType
    reason: str
    triggers: tuple[ReplanTrigger, ...] = ()
    information_gain: InformationGain = InformationGain.NO_CHANGE
    required_evidence: tuple[str, ...] = ()
    next_strategy: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "triggers": [item.value for item in self.triggers],
            "information_gain": self.information_gain.value,
            "required_evidence": list(self.required_evidence),
            "next_strategy": self.next_strategy,
            "provenance": dict(self.provenance),
        }


def classify_information_gain(*, new_evidence: int = 0, contradictions: int = 0, hypothesis_changes: int = 0, new_dependencies: int = 0, verification_changed: bool = False, strategy_invalidated: bool = False) -> InformationGain:
    if strategy_invalidated or (contradictions and hypothesis_changes):
        return InformationGain.CRITICAL
    if contradictions or verification_changed:
        return InformationGain.HIGH
    if hypothesis_changes or new_dependencies:
        return InformationGain.MEDIUM
    if new_evidence:
        return InformationGain.LOW
    return InformationGain.NO_CHANGE


def decide(proposal: ObservationInterpretationProposal, *, action_success: bool, objective_verified: bool = False, scope_blocked: bool = False) -> StrategyDecision:
    if scope_blocked:
        return StrategyDecision(StrategyDecisionType.SCOPE_BLOCKED, "observation requires a target outside the deterministic scope", (ReplanTrigger.SCOPE_CHANGE,), proposal.information_gain, provenance={"source": "deterministic_strategy_engine"})
    if objective_verified:
        return StrategyDecision(StrategyDecisionType.VERIFY_GOAL, "verification criteria should be evaluated", (ReplanTrigger.GOAL_PROGRESS,), proposal.information_gain, tuple(proposal.required_next_evidence), provenance={"source": "deterministic_strategy_engine"})
    if proposal.new_dependencies:
        return StrategyDecision(StrategyDecisionType.WAIT_FOR_DEPENDENCY, "new dependency blocks the current strategy", (ReplanTrigger.NEW_DEPENDENCY,), proposal.information_gain, tuple(proposal.required_next_evidence), next_strategy=proposal.recommended_strategy_change, provenance={"source": "deterministic_strategy_engine"})
    if proposal.contradictions or proposal.information_gain in {InformationGain.HIGH, InformationGain.CRITICAL}:
        return StrategyDecision(StrategyDecisionType.REPLAN, proposal.replan_reason or "contradictory evidence invalidated the current strategy", proposal.triggers, proposal.information_gain, tuple(proposal.required_next_evidence), next_strategy=proposal.recommended_strategy_change, provenance={"source": "deterministic_strategy_engine"})
    if proposal.hypothesis_updates or proposal.confidence_changes:
        return StrategyDecision(StrategyDecisionType.CHANGE_HYPOTHESIS, "hypothesis state changed; strategy must be reevaluated", proposal.triggers, proposal.information_gain, tuple(proposal.required_next_evidence), next_strategy=proposal.recommended_strategy_change, provenance={"source": "deterministic_strategy_engine"})
    if proposal.required_next_evidence:
        return StrategyDecision(StrategyDecisionType.ADD_EVIDENCE, "additional evidence is required", proposal.triggers, proposal.information_gain, tuple(proposal.required_next_evidence), next_strategy=proposal.recommended_strategy_change, provenance={"source": "deterministic_strategy_engine"})
    if not action_success:
        return StrategyDecision(StrategyDecisionType.REPLAN, proposal.replan_reason or "action failed", (ReplanTrigger.FAILURE,), proposal.information_gain, provenance={"source": "deterministic_strategy_engine"})
    return StrategyDecision(StrategyDecisionType.CONTINUE_PLAN, "observation did not materially invalidate the current strategy", proposal.triggers, proposal.information_gain, provenance={"source": "deterministic_strategy_engine"})


__all__ = ["StrategyDecision", "StrategyDecisionType", "StrategyState", "classify_information_gain", "decide"]
