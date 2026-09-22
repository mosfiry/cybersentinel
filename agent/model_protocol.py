from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence
import uuid


@dataclass(frozen=True)
class ConversationTurn:
    """A provider-neutral conversation message, including tool responses."""

    role: str
    content: str = ""
    tool_call_id: str = ""
    name: str = ""
    tool_calls: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_call_id:
            result["tool_call_id"] = self.tool_call_id
        if self.name:
            result["name"] = self.name
        if self.tool_calls:
            result["tool_calls"] = [dict(item) for item in self.tool_calls]
        return result


@dataclass(frozen=True)
class ToolCallProposal:
    """Untrusted model proposal. It is never an authorization decision."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    mission_id: str = ""
    run_id: str = ""
    turn_id: str = ""
    action_id: str = ""
    tool_call_id: str = ""
    request_id: str = ""
    plan_version: int = 0
    step_id: str = ""
    authorization_context_id: str = ""
    scope_snapshot_id: str = ""

    @classmethod
    def create(cls, name: str, arguments: dict[str, Any] | None = None, **ids: Any) -> "ToolCallProposal":
        return cls(name=name, arguments=dict(arguments or {}), tool_call_id=str(ids.pop("tool_call_id", "call_" + uuid.uuid4().hex)), **ids)

    def identity(self) -> dict[str, Any]:
        return {"mission_id": self.mission_id, "run_id": self.run_id, "turn_id": self.turn_id, "action_id": self.action_id, "tool_call_id": self.tool_call_id, "request_id": self.request_id, "plan_version": self.plan_version, "step_id": self.step_id, "authorization_context_id": self.authorization_context_id, "scope_snapshot_id": self.scope_snapshot_id}

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "arguments": dict(self.arguments), **self.identity()}


@dataclass(frozen=True)
class ToolCallResult:
    proposal: ToolCallProposal
    ok: bool
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"tool_call_id": self.proposal.tool_call_id, "name": self.proposal.name, "arguments": dict(self.proposal.arguments), "ok": self.ok, "result": dict(self.result), "error": self.error, **self.proposal.identity()}


@dataclass(frozen=True)
class ModelTurn:
    turn_id: str
    content: str = ""
    tool_calls: tuple[ToolCallProposal, ...] = ()
    provider: str = ""
    model: str = ""
    finish_reason: str = "stop"
    usage: dict[str, Any] = field(default_factory=dict)

    @property
    def is_final(self) -> bool:
        return not self.tool_calls

    def to_dict(self) -> dict[str, Any]:
        return {"turn_id": self.turn_id, "content": self.content, "tool_calls": [item.to_dict() for item in self.tool_calls], "provider": self.provider, "model": self.model, "finish_reason": self.finish_reason, "usage": dict(self.usage)}


@dataclass(frozen=True)
class ReasoningContinuation:
    turn_id: str
    observations: tuple[ToolCallResult, ...]
    next_action: str = "continue"


@dataclass(frozen=True)
class ModelFinal:
    content: str
    turn_id: str
    verified: bool = False
    evidence_count: int = 0


class NativeModel(Protocol):
    def complete(self, messages: Sequence[ConversationTurn], tools: Sequence[dict[str, Any]], *, mission_id: str, run_id: str, turn_id: str, plan_version: int) -> ModelTurn:
        """Return one real model turn; tool calls are proposals only."""


def model_turn_from_provider(response: dict[str, Any], *, mission_id: str, run_id: str, turn_id: str, request_id: str, plan_version: int, step_id: str = "") -> ModelTurn:
    calls: list[ToolCallProposal] = []
    for raw in response.get("tool_calls") or []:
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            continue
        calls.append(ToolCallProposal.create(raw["name"], raw.get("arguments") if isinstance(raw.get("arguments"), dict) else {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, action_id=f"{mission_id}:{turn_id}:{raw.get('id') or uuid.uuid4().hex}", tool_call_id=str(raw.get("id") or "call_" + uuid.uuid4().hex), request_id=request_id, plan_version=plan_version, step_id=step_id))
    return ModelTurn(turn_id=turn_id, content=str(response.get("content", "") or ""), tool_calls=tuple(calls), provider=str(response.get("provider", "")), model=str(response.get("model", "")), finish_reason=str(response.get("finish_reason", "tool_calls" if calls else "stop")), usage=dict(response.get("usage") or {}))


class RouterNativeModel:
    """Adapter from the existing ModelRouter to the native protocol."""

    def __init__(self, router: Any):
        self.router = router

    def complete(self, messages: Sequence[ConversationTurn], tools: Sequence[dict[str, Any]], *, mission_id: str, run_id: str, turn_id: str, plan_version: int) -> ModelTurn:
        payload = [item.to_dict() for item in messages]
        try:
            response = self.router.tool_calling(payload, list(tools))
        except (AttributeError, NotImplementedError, RuntimeError):
            # Text-capable providers remain on the same canonical MissionRuntime;
            # their output is still normalized into untrusted typed proposals.
            response = self.router.generate(payload)
        return model_turn_from_provider(response, mission_id=mission_id, run_id=run_id, turn_id=turn_id, request_id="", plan_version=plan_version)


__all__ = ["ConversationTurn", "ModelFinal", "ModelTurn", "NativeModel", "ReasoningContinuation", "RouterNativeModel", "ToolCallProposal", "ToolCallResult", "model_turn_from_provider"]
