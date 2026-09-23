from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
import time


@dataclass(frozen=True)
class RepairRecord:
    phase: str
    detail: str
    attempt: int
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True)
class SelfRepairResult:
    success: bool
    attempts: int
    records: tuple[RepairRecord, ...]
    final_result: Any = None
    reason: str = ""


class BoundedSelfRepair:
    """Failure -> diagnosis -> hypothesis -> repair -> retry -> verify with hard bounds."""

    def __init__(self, *, max_retries: int = 3, time_budget_seconds: float = 60.0):
        if max_retries < 0 or time_budget_seconds <= 0:
            raise ValueError("self-repair bounds must be positive")
        self.max_retries = max_retries
        self.time_budget_seconds = time_budget_seconds

    def run(self, action: Callable[[], Any], diagnose: Callable[[Exception], str], repair: Callable[[str, int], None], verify: Callable[[Any], bool], authorize_repair: Callable[[str], bool] | None = None) -> SelfRepairResult:
        started = time.monotonic()
        records: list[RepairRecord] = []
        for attempt in range(self.max_retries + 1):
            try:
                result = action()
                records.append(RepairRecord("result", "action returned", attempt))
                if verify(result):
                    records.append(RepairRecord("verify", "verification passed", attempt))
                    return SelfRepairResult(True, attempt, tuple(records), result, "verified")
                error = RuntimeError("verification failed")
            except Exception as exc:
                error = exc
                records.append(RepairRecord("failure", f"{type(exc).__name__}: {exc}", attempt))
            if attempt >= self.max_retries or time.monotonic() - started >= self.time_budget_seconds:
                return SelfRepairResult(False, attempt + 1, tuple(records), None, "retry limit or time budget exhausted")
            diagnosis = diagnose(error)
            records.append(RepairRecord("diagnosis", diagnosis, attempt))
            hypothesis = f"repair hypothesis for attempt {attempt + 1}: {diagnosis}"
            records.append(RepairRecord("hypothesis", hypothesis, attempt))
            if authorize_repair is not None and not authorize_repair(diagnosis):
                records.append(RepairRecord("authorization", "repair denied by mission authorization", attempt))
                return SelfRepairResult(False, attempt + 1, tuple(records), None, "repair authorization denied")
            repair(diagnosis, attempt + 1)
            records.append(RepairRecord("repair", diagnosis, attempt + 1))
            if time.monotonic() - started >= self.time_budget_seconds:
                return SelfRepairResult(False, attempt + 1, tuple(records), None, "time budget exhausted")
        return SelfRepairResult(False, self.max_retries + 1, tuple(records), None, "unreachable")


__all__ = ["BoundedSelfRepair", "RepairRecord", "SelfRepairResult"]
