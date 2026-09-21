from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ReasoningMode(str, Enum):
    FAST = "FAST"
    BALANCED = "BALANCED"
    DEEP = "DEEP"


@dataclass(frozen=True)
class ReasoningBudget:
    mode: ReasoningMode
    max_model_turns: int
    max_context_tokens: int
    max_tool_calls: int
    critic_depth: int
    verification_depth: int


def budget_for(mode: ReasoningMode) -> ReasoningBudget:
    return {ReasoningMode.FAST: ReasoningBudget(mode, 6, 4096, 8, 0, 1), ReasoningMode.BALANCED: ReasoningBudget(mode, 12, 8192, 16, 1, 2), ReasoningMode.DEEP: ReasoningBudget(mode, 32, 16384, 32, 2, 3)}[mode]


class ReasoningController:
    def select(self, objective: str, *, requested: ReasoningMode | None = None) -> ReasoningBudget:
        if requested is not None: return budget_for(requested)
        text = str(objective).casefold()
        if len(text) > 180 or any(token in text for token in ("investigate", "incident", "incident", "حلل", "حادث", "تحقق")):
            return budget_for(ReasoningMode.DEEP)
        if any(token in text for token in ("research", "evidence", "دليل", "ابحث")):
            return budget_for(ReasoningMode.BALANCED)
        return budget_for(ReasoningMode.FAST)


__all__ = ["ReasoningBudget", "ReasoningController", "ReasoningMode", "budget_for"]
