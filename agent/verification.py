from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable
import hashlib
import json


class VerificationResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True)
class FindingClaim:
    claim: str
    target: str
    reproduction: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationPlan:
    validator_id: str
    required_evidence: tuple[str, ...] = ()
    validator: Callable[[FindingClaim, tuple[dict[str, Any], ...]], VerificationResult] | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class VerificationReport:
    claim: FindingClaim
    validator_id: str
    result: VerificationResult
    evidence: tuple[dict[str, Any], ...]
    evidence_hash: str
    reason: str


class VerificationEngine:
    """Deterministic validation boundary: model claims are proposals, not facts."""

    def verify(self, claim: FindingClaim, plan: VerificationPlan, evidence: Iterable[dict[str, Any]]) -> VerificationReport:
        records = tuple(dict(item) for item in evidence)
        if not plan.validator_id or plan.validator is None:
            result, reason = VerificationResult.UNKNOWN, "no independent validator configured"
        elif not all(any(name in {str(item.get("type")), str(item.get("source")), str(item.get("criterion_id"))} for item in records) for name in plan.required_evidence):
            result, reason = VerificationResult.INSUFFICIENT_EVIDENCE, "required evidence is missing"
        else:
            result = plan.validator(claim, records)
            if not isinstance(result, VerificationResult):
                raise TypeError("validator must return VerificationResult")
            reason = "independent validator result"
        digest = hashlib.sha256(json.dumps(records, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":")).encode()).hexdigest()
        return VerificationReport(claim, plan.validator_id, result, records, digest, reason)


__all__ = ["FindingClaim", "VerificationEngine", "VerificationPlan", "VerificationReport", "VerificationResult"]
