from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence
import uuid

from .provider_api import (
    MAX_PROVIDER_ARGUMENT_BYTES,
    MAX_PROVIDER_CALL_ID_CHARS,
    MAX_PROVIDER_FINISH_REASON_CHARS,
    MAX_PROVIDER_LABEL_CHARS,
    MAX_PROVIDER_TEXT_CHARS,
    MAX_PROVIDER_TOOL_CALLS,
    MAX_PROVIDER_TOOL_NAME_CHARS,
    MAX_PROVIDER_USAGE_BYTES,
    CapabilityUnsupported,
    InvalidModelResponse,
    enforce_json_byte_limit,
)


MAX_MODEL_IDENTITY_CHARS = 512


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
    if not isinstance(response, dict):
        raise InvalidModelResponse("model adapter received a non-object response")
    calls: list[ToolCallProposal] = []
    raw_calls = response.get("tool_calls")
    if raw_calls is None:
        raw_calls = []
    if not isinstance(raw_calls, (list, tuple)) or len(raw_calls) > MAX_PROVIDER_TOOL_CALLS:
        raise InvalidModelResponse("model adapter received malformed tool calls")
    for raw in raw_calls:
        if not isinstance(raw, dict):
            raise InvalidModelResponse("model adapter received a malformed tool call")
        name = raw.get("name")
        if not isinstance(name, str) or len(name) > MAX_PROVIDER_TOOL_NAME_CHARS or not name.strip():
            raise InvalidModelResponse("model adapter received a tool call without a valid name")
        arguments = raw.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise InvalidModelResponse("model adapter received non-object tool arguments")
        enforce_json_byte_limit(arguments, max_bytes=MAX_PROVIDER_ARGUMENT_BYTES, message="model adapter received oversized or malformed tool arguments")
        raw_call_id = raw.get("id")
        if raw_call_id is None or raw_call_id == "":
            call_id = "call_" + uuid.uuid4().hex
        elif not isinstance(raw_call_id, str) or len(raw_call_id) > MAX_PROVIDER_CALL_ID_CHARS:
            raise InvalidModelResponse("model adapter received malformed tool-call identity")
        else:
            call_id = raw_call_id
        calls.append(ToolCallProposal.create(name, arguments, mission_id=mission_id, run_id=run_id, turn_id=turn_id, action_id=f"{mission_id}:{turn_id}:{call_id}", tool_call_id=call_id, request_id=request_id, plan_version=plan_version, step_id=step_id))
    content = response.get("content", "")
    if content is None:
        content = ""
    if not isinstance(content, str):
        raise InvalidModelResponse("model adapter received malformed text")
    finish_reason = response.get("finish_reason", "tool_calls" if calls else "stop")
    if finish_reason is None:
        finish_reason = "tool_calls" if calls else "stop"
    if not isinstance(finish_reason, str):
        raise InvalidModelResponse("model adapter received malformed finish reason")
    usage = response.get("usage")
    if usage is None:
        usage = {}
    if not isinstance(usage, dict):
        raise InvalidModelResponse("model adapter received malformed usage metadata")
    provider_name = response.get("provider", "")
    model_name = response.get("model", "")
    if not isinstance(provider_name, str) or not isinstance(model_name, str):
        raise InvalidModelResponse("model adapter received malformed provider identity")
    return validate_model_turn(ModelTurn(turn_id=turn_id, content=content, tool_calls=tuple(calls), provider=provider_name, model=model_name, finish_reason=finish_reason, usage=usage))


def validate_model_turn(value: Any) -> ModelTurn:
    """Reject malformed NativeModel values before they enter mission orchestration."""
    if not isinstance(value, ModelTurn):
        raise InvalidModelResponse("model returned an unsupported turn")
    if not isinstance(value.turn_id, str) or not value.turn_id or len(value.turn_id) > MAX_PROVIDER_CALL_ID_CHARS:
        raise InvalidModelResponse("model returned malformed turn identity")
    try:
        value.turn_id.encode("utf-8")
    except UnicodeError as exc:
        raise InvalidModelResponse("model returned invalid turn identity encoding") from exc
    if not isinstance(value.content, str) or len(value.content) > MAX_PROVIDER_TEXT_CHARS:
        raise InvalidModelResponse("model returned malformed turn text or identity")
    try:
        value.content.encode("utf-8")
    except UnicodeError as exc:
        raise InvalidModelResponse("model returned invalid text encoding") from exc
    if not isinstance(value.tool_calls, (list, tuple)) or len(value.tool_calls) > MAX_PROVIDER_TOOL_CALLS:
        raise InvalidModelResponse("model returned malformed tool-call collection")
    seen_ids: set[str] = set()
    for proposal in value.tool_calls:
        if (
            not isinstance(proposal, ToolCallProposal)
            or not isinstance(proposal.name, str)
            or len(proposal.name) > MAX_PROVIDER_TOOL_NAME_CHARS
            or not proposal.name.strip()
            or not isinstance(proposal.arguments, dict)
            or not isinstance(proposal.tool_call_id, str)
            or not proposal.tool_call_id
            or len(proposal.tool_call_id) > MAX_PROVIDER_CALL_ID_CHARS
            or proposal.turn_id != value.turn_id
        ):
            raise InvalidModelResponse("model returned malformed tool proposal")
        if proposal.tool_call_id in seen_ids:
            raise InvalidModelResponse("model returned duplicate tool-call identifiers")
        seen_ids.add(proposal.tool_call_id)
        try:
            proposal.name.encode("utf-8")
            proposal.tool_call_id.encode("utf-8")
        except UnicodeError as exc:
            raise InvalidModelResponse("model returned invalid tool proposal encoding") from exc
        for identity_name in ("mission_id", "run_id", "turn_id", "action_id", "request_id", "step_id", "authorization_context_id", "scope_snapshot_id"):
            identity_value = getattr(proposal, identity_name)
            if not isinstance(identity_value, str) or len(identity_value) > MAX_MODEL_IDENTITY_CHARS:
                raise InvalidModelResponse("model returned malformed tool proposal identity")
            try:
                identity_value.encode("utf-8")
            except UnicodeError as exc:
                raise InvalidModelResponse("model returned invalid tool proposal identity encoding") from exc
        if isinstance(proposal.plan_version, bool) or not isinstance(proposal.plan_version, int) or proposal.plan_version < 0:
            raise InvalidModelResponse("model returned malformed plan identity")
        enforce_json_byte_limit(proposal.arguments, max_bytes=MAX_PROVIDER_ARGUMENT_BYTES, message="model returned oversized or malformed tool arguments")
    if (
        not isinstance(value.finish_reason, str)
        or len(value.finish_reason) > MAX_PROVIDER_FINISH_REASON_CHARS
        or not isinstance(value.provider, str)
        or len(value.provider) > MAX_PROVIDER_LABEL_CHARS
        or not isinstance(value.model, str)
        or len(value.model) > MAX_PROVIDER_LABEL_CHARS
        or not isinstance(value.usage, dict)
    ):
        raise InvalidModelResponse("model returned malformed turn metadata")
    try:
        value.finish_reason.encode("utf-8")
        value.provider.encode("utf-8")
        value.model.encode("utf-8")
    except UnicodeError as exc:
        raise InvalidModelResponse("model returned invalid turn metadata encoding") from exc
    enforce_json_byte_limit(value.usage, max_bytes=MAX_PROVIDER_USAGE_BYTES, message="model returned oversized or malformed usage metadata")
    return value


class RouterNativeModel:
    """Adapter from the existing ModelRouter to the native protocol."""

    def __init__(self, router: Any):
        self.router = router

    def complete(self, messages: Sequence[ConversationTurn], tools: Sequence[dict[str, Any]], *, mission_id: str, run_id: str, turn_id: str, plan_version: int) -> ModelTurn:
        payload = [item.to_dict() for item in messages]
        try:
            response = self.router.tool_calling(payload, list(tools))
        except CapabilityUnsupported:
            # Text-capable providers remain on the same canonical MissionRuntime;
            # a real native provider failure must propagate into MissionRuntime
            # recovery and must never be disguised as a generate() response.
            response = self.router.generate(payload)
        return model_turn_from_provider(response, mission_id=mission_id, run_id=run_id, turn_id=turn_id, request_id="", plan_version=plan_version)


__all__ = ["ConversationTurn", "ModelFinal", "ModelTurn", "NativeModel", "ReasoningContinuation", "RouterNativeModel", "ToolCallProposal", "ToolCallResult", "model_turn_from_provider", "validate_model_turn"]
