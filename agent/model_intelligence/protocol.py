from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, Sequence


@dataclass(frozen=True)
class ConversationTurn:
    role: str
    content: str = ""
    tool_call_id: str = ""
    name: str = ""
    tool_calls: tuple[dict[str, Any], ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = {"role": self.role, "content": self.content}
        if self.tool_call_id: result["tool_call_id"] = self.tool_call_id
        if self.name: result["name"] = self.name
        if self.tool_calls: result["tool_calls"] = [dict(item) for item in self.tool_calls]
        return result


@dataclass(frozen=True)
class ToolCallProposal:
    tool_call_id: str
    mission_id: str
    run_id: str
    turn_id: str
    action_id: str
    request_id: str
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    plan_version: int = 0
    step_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"tool_call_id": self.tool_call_id, "mission_id": self.mission_id, "run_id": self.run_id, "turn_id": self.turn_id, "action_id": self.action_id, "request_id": self.request_id, "tool_name": self.tool_name, "arguments": dict(self.arguments), "plan_version": self.plan_version, "step_id": self.step_id}


@dataclass(frozen=True)
class ToolCallResult:
    tool_call_id: str
    execution_id: str
    status: str
    normalized_result: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {"tool_call_id": self.tool_call_id, "execution_id": self.execution_id, "status": self.status, "normalized_result": dict(self.normalized_result), "provenance": dict(self.provenance), "timestamp": self.timestamp}


@dataclass(frozen=True)
class ModelTurn:
    mission_id: str
    run_id: str
    turn_id: str
    request_id: str
    plan_version: int
    step_id: str
    provider: str
    model: str
    content: str = ""
    tool_calls: tuple[ToolCallProposal, ...] = ()
    finish_reason: str = "stop"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def is_final(self) -> bool:
        return not self.tool_calls


@dataclass(frozen=True)
class ReasoningContinuation:
    mission_id: str
    run_id: str
    previous_turn_id: str
    observation_ids: tuple[str, ...] = ()
    strategy_version: int = 0
    context_hash: str = ""


@dataclass(frozen=True)
class ModelFinal:
    mission_id: str
    run_id: str
    turn_id: str
    content: str
    verified: bool = False
    evidence_count: int = 0


class ModelIntelligence(Protocol):
    def reason(self, messages: Sequence[ConversationTurn], tools: Sequence[dict[str, Any]], *, mission_id: str, run_id: str, turn_id: str, request_id: str, plan_version: int, step_id: str = "") -> ModelTurn: ...


class RouterModelIntelligence:
    """Provider-neutral adapter over ModelRouter native tool calling."""

    def __init__(self, router: Any):
        self.router = router

    def reason(self, messages: Sequence[ConversationTurn], tools: Sequence[dict[str, Any]], *, mission_id: str, run_id: str, turn_id: str, request_id: str, plan_version: int, step_id: str = "") -> ModelTurn:
        response = self.router.tool_calling([item.to_dict() for item in messages], list(tools))
        proposals = []
        for raw in response.get("tool_calls", ()):
            if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
                continue
            proposals.append(ToolCallProposal(str(raw.get("id") or f"{turn_id}:call:{len(proposals) + 1}"), mission_id, run_id, turn_id, f"{mission_id}:{turn_id}:{len(proposals) + 1}", request_id, raw["name"], dict(raw.get("arguments") or {}), plan_version, step_id))
        return ModelTurn(mission_id, run_id, turn_id, request_id, plan_version, step_id, str(response.get("provider", "")), str(response.get("model", "")), str(response.get("content", "") or ""), tuple(proposals), str(response.get("finish_reason", "tool_calls" if proposals else "stop")))


__all__ = ["ConversationTurn", "ModelFinal", "ModelIntelligence", "ModelTurn", "ReasoningContinuation", "RouterModelIntelligence", "ToolCallProposal", "ToolCallResult"]
