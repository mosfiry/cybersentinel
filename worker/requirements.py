from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .capability import CapabilityStatus, WorkerCapabilitySet


class RequirementDecision(str, Enum):
    """Deterministic requirement-check outcomes. There is no EXECUTE_ANYWAY:
    a missing capability always produces a BLOCKED decision."""

    ALLOWED_BY_CAPABILITY = "ALLOWED_BY_CAPABILITY"
    ALLOWED_WITH_LIMITATIONS = "ALLOWED_WITH_LIMITATIONS"
    BLOCKED_CAPABILITY = "BLOCKED_CAPABILITY"
    BLOCKED_UNKNOWN_CAPABILITY = "BLOCKED_UNKNOWN_CAPABILITY"


@dataclass(frozen=True)
class CapabilityRequirement:
    """A capability a task deterministically needs before execution."""

    name: str


@dataclass(frozen=True)
class CapabilityCheckResult:
    """Provable check result: decision plus the exact missing capabilities."""

    decision: RequirementDecision
    missing: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()
    limited: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.decision in (
            RequirementDecision.ALLOWED_BY_CAPABILITY,
            RequirementDecision.ALLOWED_WITH_LIMITATIONS,
        )


def check_requirements(
    requirements: Iterable[CapabilityRequirement],
    capability_set: WorkerCapabilitySet,
) -> CapabilityCheckResult:
    """Deterministic, LLM-independent capability check.

    Resolution rules (fixed, no heuristics):
      * NOT_AVAILABLE requirement  -> BLOCKED_CAPABILITY, listed in missing
      * UNKNOWN requirement        -> BLOCKED_UNKNOWN_CAPABILITY (UNKNOWN is
                                       never treated as AVAILABLE)
      * AVAILABLE_WITH_LIMITATIONS  -> decision ALLOWED_WITH_LIMITATIONS,
                                       capability listed in limited
      * otherwise                   -> ALLOWED_BY_CAPABILITY
    A single missing or unknown capability blocks the whole task; partial
    execution is never silently attempted.
    """
    missing: list[str] = []
    unknown: list[str] = []
    limited: list[str] = []
    for req in requirements:
        status = capability_set.status_of(req.name)
        if status is CapabilityStatus.NOT_AVAILABLE:
            missing.append(req.name)
        elif status is CapabilityStatus.UNKNOWN:
            unknown.append(req.name)
        elif status is CapabilityStatus.AVAILABLE_WITH_LIMITATIONS:
            limited.append(req.name)
    if missing:
        return CapabilityCheckResult(RequirementDecision.BLOCKED_CAPABILITY, tuple(missing), tuple(unknown), tuple(limited))
    if unknown:
        return CapabilityCheckResult(RequirementDecision.BLOCKED_UNKNOWN_CAPABILITY, (), tuple(unknown), tuple(limited))
    if limited:
        return CapabilityCheckResult(RequirementDecision.ALLOWED_WITH_LIMITATIONS, (), (), tuple(limited))
    return CapabilityCheckResult(RequirementDecision.ALLOWED_BY_CAPABILITY)
