from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
import json
from typing import Any, Callable, Iterable


class ReplanTrigger(str, Enum):
    FAILURE = "FAILURE"
    NEW_EVIDENCE = "NEW_EVIDENCE"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    HYPOTHESIS_CHANGE = "HYPOTHESIS_CHANGE"
    CONFIDENCE_SHIFT = "CONFIDENCE_SHIFT"
    NEW_DEPENDENCY = "NEW_DEPENDENCY"
    SCOPE_CHANGE = "SCOPE_CHANGE"
    AUTHORIZATION_CHANGE = "AUTHORIZATION_CHANGE"
    GOAL_PROGRESS = "GOAL_PROGRESS"
    VERIFICATION_FAILURE = "VERIFICATION_FAILURE"
    INFORMATION_GAIN = "INFORMATION_GAIN"
    HYPOTHESIS_WEAKENED = "HYPOTHESIS_WEAKENED"
    HYPOTHESIS_REJECTED = "HYPOTHESIS_REJECTED"
    NEW_HIGH_VALUE_EVIDENCE = "NEW_HIGH_VALUE_EVIDENCE"
    CRITICAL_UNKNOWN = "CRITICAL_UNKNOWN"
    LOW_INFORMATION_GAIN = "LOW_INFORMATION_GAIN"


class InformationGain(str, Enum):
    NO_CHANGE = "NO_CHANGE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class ConfidenceChange:
    hypothesis_id: str
    delta: float
    reason: str
    supporting_evidence_ids: tuple[str, ...] = ()
    counter_evidence_ids: tuple[str, ...] = ()
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "delta": self.delta,
            "reason": self.reason,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "counter_evidence_ids": list(self.counter_evidence_ids),
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True)
class ObservationInterpretationProposal:
    observation_id: str
    summary: str
    facts: tuple[str, ...] = ()
    new_evidence: tuple[dict[str, Any], ...] = ()
    contradictions: tuple[dict[str, Any], ...] = ()
    supporting_evidence_ids: tuple[str, ...] = ()
    counter_evidence_ids: tuple[str, ...] = ()
    hypothesis_updates: tuple[dict[str, Any], ...] = ()
    unknowns: tuple[str, ...] = ()
    new_dependencies: tuple[str, ...] = ()
    recommended_strategy_change: str = ""
    replan_reason: str = ""
    confidence_changes: tuple[ConfidenceChange, ...] = ()
    required_next_evidence: tuple[str, ...] = ()
    information_gain: InformationGain = InformationGain.NO_CHANGE
    triggers: tuple[ReplanTrigger, ...] = ()
    provenance: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.observation_id or not self.summary:
            raise ValueError("observation_id and summary are required")
        if self.information_gain in {InformationGain.HIGH, InformationGain.CRITICAL} and not self.replan_reason:
            raise ValueError("material information gain requires a replan reason")

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "summary": self.summary,
            "facts": list(self.facts),
            "new_evidence": [dict(item) for item in self.new_evidence],
            "contradictions": [dict(item) for item in self.contradictions],
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "counter_evidence_ids": list(self.counter_evidence_ids),
            "hypothesis_updates": [dict(item) for item in self.hypothesis_updates],
            "unknowns": list(self.unknowns),
            "new_dependencies": list(self.new_dependencies),
            "recommended_strategy_change": self.recommended_strategy_change,
            "replan_reason": self.replan_reason,
            "confidence_changes": [item.to_dict() for item in self.confidence_changes],
            "required_next_evidence": list(self.required_next_evidence),
            "information_gain": self.information_gain.value,
            "triggers": [item.value for item in self.triggers],
            "provenance": dict(self.provenance),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ObservationInterpretationProposal":
        changes = tuple(ConfidenceChange(**{
            **item,
            "supporting_evidence_ids": tuple(item.get("supporting_evidence_ids", ())),
            "counter_evidence_ids": tuple(item.get("counter_evidence_ids", ())),
        }) for item in data.get("confidence_changes", ()))
        return cls(
            observation_id=str(data["observation_id"]),
            summary=str(data["summary"]),
            facts=tuple(str(item) for item in data.get("facts", ())),
            new_evidence=tuple(dict(item) for item in data.get("new_evidence", ())),
            contradictions=tuple(dict(item) for item in data.get("contradictions", ())),
            supporting_evidence_ids=tuple(str(item) for item in data.get("supporting_evidence_ids", ())),
            counter_evidence_ids=tuple(str(item) for item in data.get("counter_evidence_ids", ())),
            hypothesis_updates=tuple(dict(item) for item in data.get("hypothesis_updates", ())),
            unknowns=tuple(str(item) for item in data.get("unknowns", ())),
            new_dependencies=tuple(str(item) for item in data.get("new_dependencies", ())),
            recommended_strategy_change=str(data.get("recommended_strategy_change", "")),
            replan_reason=str(data.get("replan_reason", "")),
            confidence_changes=changes,
            required_next_evidence=tuple(str(item) for item in data.get("required_next_evidence", ())),
            information_gain=InformationGain(data.get("information_gain", InformationGain.NO_CHANGE.value)),
            triggers=tuple(ReplanTrigger(item) for item in data.get("triggers", ())),
            provenance=dict(data.get("provenance", {})),
        )


def observation_id(action_id: str, observation: dict[str, Any]) -> str:
    payload = json.dumps({"action_id": action_id, "observation": observation}, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return "obs-" + sha256(payload.encode()).hexdigest()[:20]


def should_interpret_observation(observation: dict[str, Any], *, previous: dict[str, Any] | None = None) -> bool:
    if previous is None:
        return True
    if observation != previous:
        return True
    if observation.get("success") is False or observation.get("ok") is False:
        return True
    return any(key in observation for key in ("evidence", "counter_evidence", "hypothesis", "verification", "dependency", "scope"))


class ObservationInterpreter:
    """Produces typed proposals; it never mutates authority, scope, or authorization."""

    def __init__(self, proposer: Callable[[dict[str, Any]], dict[str, Any]] | None = None):
        self.proposer = proposer

    def interpret(self, *, mission: dict[str, Any], plan: dict[str, Any], current_step: dict[str, Any] | None, action: str, observation: dict[str, Any], evidence: Iterable[dict[str, Any]], hypothesis_state: dict[str, Any], knowledge_context: Iterable[dict[str, Any]] = (), conversation_context: Iterable[dict[str, Any]] = ()) -> ObservationInterpretationProposal:
        obs_id = observation_id(str(observation.get("action_id", action)), observation)
        base = self._deterministic(mission, plan, current_step, action, observation, obs_id)
        if self.proposer is None:
            return base
        try:
            proposal = dict(self.proposer({
                "mission": mission,
                "plan": plan,
                "current_step": current_step,
                "action": action,
                "observation": observation,
                "evidence": list(evidence),
                "hypothesis_state": hypothesis_state,
                "knowledge_context": list(knowledge_context),
                "conversation_context": list(conversation_context),
            }) or {})
        except Exception as exc:
            return ObservationInterpretationProposal(
                **{**base.__dict__, "provenance": {**base.provenance, "model_status": "unavailable_or_malformed", "model_error": type(exc).__name__}}
            )
        # The model can enrich the proposal, but deterministic authority fields are discarded.
        proposal.pop("owner_instruction", None)
        proposal.pop("owner_policy", None)
        proposal.pop("authorization", None)
        proposal.pop("scope", None)
        proposal.pop("identity", None)
        proposal.pop("objective", None)
        proposal.setdefault("observation_id", base.observation_id)
        proposal.setdefault("summary", base.summary)
        proposal.setdefault("provenance", {"source": "model_proposal", "base": base.provenance})
        try:
            return self._validate_model_proposal(proposal, base)
        except (TypeError, ValueError, KeyError) as exc:
            return ObservationInterpretationProposal(
                **{**base.__dict__, "provenance": {**base.provenance, "model_status": "proposal_rejected", "model_error": type(exc).__name__}}
            )

    @staticmethod
    def _deterministic(mission: dict[str, Any], plan: dict[str, Any], current_step: dict[str, Any] | None, action: str, observation: dict[str, Any], obs_id: str) -> ObservationInterpretationProposal:
        success = bool(observation.get("success", observation.get("ok", False)))
        summary = str(observation.get("summary") or observation.get("error") or observation.get("status") or ("action succeeded" if success else "action failed"))[:1000]
        facts = tuple(str(item) for item in observation.get("facts", ()))
        evidence = tuple(dict(item) for item in observation.get("evidence", ()))
        contradictions = tuple(dict(item) for item in observation.get("counter_evidence", observation.get("contradictions", ())))
        unknowns = tuple(str(item) for item in observation.get("unknowns", ()))
        required = tuple(str(item) for item in observation.get("required_next_evidence", ()))
        confidence_changes = tuple(ConfidenceChange(
            hypothesis_id=str(item.get("hypothesis_id", "")),
            delta=float(item.get("delta", 0.0)),
            reason=str(item.get("reason", "")),
            supporting_evidence_ids=tuple(str(value) for value in item.get("supporting_evidence_ids", ())),
            counter_evidence_ids=tuple(str(value) for value in item.get("counter_evidence_ids", ())),
            provenance=dict(item.get("provenance", {"source": "observation"})),
        ) for item in observation.get("confidence_changes", ()) if item.get("hypothesis_id"))
        triggers: list[ReplanTrigger] = []
        gain = InformationGain.NO_CHANGE
        if not success:
            triggers.append(ReplanTrigger.FAILURE)
            gain = InformationGain.MEDIUM
        if evidence:
            triggers.append(ReplanTrigger.NEW_EVIDENCE)
            gain = max(gain, InformationGain.MEDIUM, key=lambda item: list(InformationGain).index(item))
        if contradictions:
            triggers.extend((ReplanTrigger.CONTRADICTORY_EVIDENCE, ReplanTrigger.HYPOTHESIS_CHANGE))
            gain = InformationGain.HIGH
        if any(float(item.get("delta", 0.0)) < 0 for item in observation.get("confidence_changes", ())):
            triggers.append(ReplanTrigger.HYPOTHESIS_WEAKENED)
        if any(float(item.get("delta", 0.0)) <= -0.8 for item in observation.get("confidence_changes", ())):
            triggers.append(ReplanTrigger.HYPOTHESIS_REJECTED)
        if unknowns or required:
            triggers.append(ReplanTrigger.INFORMATION_GAIN)
            gain = max(gain, InformationGain.LOW, key=lambda item: list(InformationGain).index(item))
            if not evidence:
                triggers.append(ReplanTrigger.LOW_INFORMATION_GAIN)
        if any(str(item).casefold() in {"critical", "critical_unknown"} for item in unknowns):
            triggers.append(ReplanTrigger.CRITICAL_UNKNOWN)
        if evidence and any(float(item.get("information_gain", 0.0)) >= 0.8 for item in evidence):
            triggers.append(ReplanTrigger.NEW_HIGH_VALUE_EVIDENCE)
        replan_reason = "observation changed mission understanding" if gain in {InformationGain.HIGH, InformationGain.CRITICAL} else ("action failed" if not success else "")
        return ObservationInterpretationProposal(obs_id, summary, facts, evidence, contradictions, tuple(item.get("evidence_id", "") for item in evidence if item.get("evidence_id")), tuple(item.get("evidence_id", "") for item in contradictions if item.get("evidence_id")), tuple(dict(item) for item in observation.get("hypothesis_updates", ())), unknowns, tuple(str(item) for item in observation.get("new_dependencies", ())), str(observation.get("recommended_strategy_change", "")), replan_reason, confidence_changes, required, gain, tuple(dict.fromkeys(triggers)), {"source": "deterministic_observation_interpreter", "action": action, "mission_id": mission.get("mission_id", "")})

    @staticmethod
    def _validate_model_proposal(data: dict[str, Any], base: ObservationInterpretationProposal) -> ObservationInterpretationProposal:
        candidate = ObservationInterpretationProposal.from_dict(data)
        if candidate.observation_id != base.observation_id:
            raise ValueError("model cannot change observation identity")
        if any(item.get("status") == "CONFIRMED" for item in candidate.hypothesis_updates):
            raise ValueError("model cannot confirm hypotheses")
        for change in candidate.confidence_changes:
            if not change.reason or (not change.supporting_evidence_ids and not change.counter_evidence_ids):
                raise ValueError("confidence change lacks evidence provenance")
        return candidate


__all__ = ["ConfidenceChange", "InformationGain", "ObservationInterpretationProposal", "ObservationInterpreter", "ReplanTrigger", "observation_id", "should_interpret_observation"]
