from __future__ import annotations

"""Typed planning, bounded recovery, and goal verification primitives.

This module deliberately contains no authorization logic. Plans are proposals and
verification evidence is an observation; both remain subordinate to the
AuthorizationContext and tool firewall.
"""

from dataclasses import dataclass, field, replace
from enum import Enum
import hashlib
import json
from typing import Any, Callable, Iterable


class ReasoningMode(str, Enum):
    FAST = "fast"
    BALANCED = "balanced"
    DEEP = "deep"


@dataclass(frozen=True)
class ReasoningProfile:
    mode: ReasoningMode
    temperature: float
    long_horizon: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode.value, "temperature": self.temperature, "long_horizon": self.long_horizon}


@dataclass(frozen=True)
class TaskProfile:
    objective: str
    task_type: str = "general"
    constraints: tuple[str, ...] = ()
    expected_outcome: str = ""
    required_evidence: tuple[str, ...] = ()
    likely_tools: tuple[str, ...] = ()
    complexity: str = "unknown"
    uncertainty: str = "unknown"
    horizon: str = "single_step"
    verification_requirements: tuple[str, ...] = ()

    @classmethod
    def from_proposal(cls, objective: str, proposal: dict[str, Any] | None = None) -> "TaskProfile":
        proposal = proposal or {}
        return cls(
            objective=str(proposal.get("objective", objective)).strip(),
            task_type=str(proposal.get("task_type", "general")),
            constraints=tuple(str(item) for item in proposal.get("constraints", ()) if item),
            expected_outcome=str(proposal.get("expected_outcome", "")),
            required_evidence=tuple(str(item) for item in proposal.get("required_evidence", ()) if item),
            likely_tools=tuple(str(item) for item in proposal.get("likely_tools", ()) if item),
            complexity=str(proposal.get("complexity", "unknown")),
            uncertainty=str(proposal.get("uncertainty", "unknown")),
            horizon=str(proposal.get("horizon", "single_step")),
            verification_requirements=tuple(str(item) for item in proposal.get("verification_requirements", ()) if item),
        )

    def to_dict(self) -> dict[str, Any]:
        result = dict(self.__dict__)
        for key in ("constraints", "required_evidence", "likely_tools", "verification_requirements"):
            result[key] = list(result[key])
        return result


def select_reasoning_profile(objective: str) -> ReasoningProfile:
    """Select a bounded generation profile from task shape, never from authority."""
    text = str(objective or "").casefold()
    long_horizon = any(token in text for token in ("build", "بناء", "اختبر", "test", "fix", "أصلح", "resume", "استأنف"))
    deep = any(token in text for token in ("incident", "حادث", "analy", "حلل", "investigat", "تحقيق", "debug", "ثغرات"))
    if long_horizon or deep:
        return ReasoningProfile(ReasoningMode.DEEP, 0.1, long_horizon=long_horizon)
    if len(text) > 160 or any(token in text for token in ("compare", "قارن", "plan", "خطة", "research", "ابحث")):
        return ReasoningProfile(ReasoningMode.BALANCED, 0.2)
    return ReasoningProfile(ReasoningMode.FAST, 0.4)


class FailureClass(str, Enum):
    TRANSIENT = "TRANSIENT"
    DEPENDENCY = "DEPENDENCY"
    COMPILATION = "COMPILATION"
    TEST_FAILURE = "TEST_FAILURE"
    NETWORK = "NETWORK"
    PROVIDER = "PROVIDER"
    TOOL = "TOOL"
    AUTHORIZATION = "AUTHORIZATION"
    SCOPE = "SCOPE"
    RESOURCE = "RESOURCE"
    LOGIC = "LOGIC"
    UNKNOWN = "UNKNOWN"


class RecoveryAction(str, Enum):
    RETRY = "RETRY"
    REPLAN = "REPLAN"
    OWNER_INPUT_REQUIRED = "OWNER_INPUT_REQUIRED"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"
    RESOURCE_BLOCKED = "RESOURCE_BLOCKED"
    FAIL = "FAIL"


@dataclass(frozen=True)
class RecoveryPolicy:
    max_retries: int = 3
    retryable: frozenset[FailureClass] = frozenset({FailureClass.TRANSIENT, FailureClass.NETWORK, FailureClass.PROVIDER})

    def action_for(self, failure: FailureClass, retry_count: int) -> RecoveryAction:
        if failure in {FailureClass.AUTHORIZATION}:
            return RecoveryAction.OWNER_INPUT_REQUIRED
        if failure is FailureClass.SCOPE:
            return RecoveryAction.SCOPE_BLOCKED
        if failure is FailureClass.RESOURCE:
            return RecoveryAction.RESOURCE_BLOCKED
        if failure in self.retryable and retry_count < self.max_retries:
            return RecoveryAction.RETRY
        if failure in {FailureClass.COMPILATION, FailureClass.TEST_FAILURE, FailureClass.LOGIC} and retry_count < self.max_retries:
            return RecoveryAction.REPLAN
        return RecoveryAction.FAIL


@dataclass(frozen=True)
class PlanStep:
    step_id: str
    objective: str
    prerequisites: tuple[str, ...] = ()
    action: str = ""
    expected_observation: str = ""
    authorization_requirement: str = ""
    scope_requirement: str = ""
    retry_policy: dict[str, Any] = field(default_factory=dict)
    verification: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "objective": self.objective,
            "prerequisites": list(self.prerequisites),
            "action": self.action,
            "expected_observation": self.expected_observation,
            "authorization_requirement": self.authorization_requirement,
            "scope_requirement": self.scope_requirement,
            "retry_policy": dict(self.retry_policy),
            "verification": list(self.verification),
        }


@dataclass(frozen=True)
class Plan:
    version: int
    objective: str
    assumptions: tuple[str, ...] = ()
    steps: tuple[PlanStep, ...] = ()
    dependencies: tuple[str, ...] = ()
    completion_criteria: tuple[str, ...] = ()
    risk: str = "unknown"
    created_from: str = ""

    @classmethod
    def initial(cls, objective: str, *, created_from: str = "conversation") -> "Plan":
        if not str(objective).strip():
            raise ValueError("plan objective must not be empty")
        return cls(version=1, objective=str(objective).strip(), created_from=created_from)

    def replan(self, *, steps: Iterable[PlanStep], assumptions: Iterable[str] = (), reason: str = "observation") -> "Plan":
        return replace(self, version=self.version + 1, steps=tuple(steps), assumptions=tuple(assumptions), created_from=reason)

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "objective": self.objective, "assumptions": list(self.assumptions), "steps": [step.to_dict() for step in self.steps], "dependencies": list(self.dependencies), "completion_criteria": list(self.completion_criteria), "risk": self.risk, "created_from": self.created_from}

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class PlanRevision:
    plan: Plan
    reason: str
    observation_hash: str = ""


@dataclass(frozen=True)
class VerificationCriterion:
    criterion_id: str
    description: str
    check: str
    required: bool = True


@dataclass(frozen=True)
class VerificationEvidence:
    criterion_id: str
    passed: bool
    source: str
    result_hash: str
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GoalVerification:
    goal: str
    criteria: tuple[VerificationCriterion, ...]
    evidence: tuple[VerificationEvidence, ...]
    verified: bool
    missing_criteria: tuple[str, ...]

    @classmethod
    def evaluate(cls, goal: str, criteria: Iterable[VerificationCriterion], evidence: Iterable[VerificationEvidence]) -> "GoalVerification":
        criteria_tuple = tuple(criteria)
        evidence_by_id = {item.criterion_id: item for item in evidence}
        missing = tuple(item.criterion_id for item in criteria_tuple if item.required and (item.criterion_id not in evidence_by_id or not evidence_by_id[item.criterion_id].passed))
        return cls(str(goal), criteria_tuple, tuple(evidence_by_id.values()), not missing, missing)

    def require_verified(self) -> None:
        if not self.verified:
            raise ValueError("goal verification incomplete: " + ", ".join(self.missing_criteria))


def evidence_for(criterion_id: str, passed: bool, source: str, result: Any, *, provenance: dict[str, Any] | None = None) -> VerificationEvidence:
    result_hash = hashlib.sha256(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()
    return VerificationEvidence(criterion_id, bool(passed), source, result_hash, provenance or {})


__all__ = [
    "FailureClass", "GoalVerification", "Plan", "PlanRevision", "PlanStep", "TaskProfile",
    "ReasoningMode", "ReasoningProfile", "RecoveryAction", "RecoveryPolicy",
    "VerificationCriterion", "VerificationEvidence", "evidence_for", "select_reasoning_profile",
]
