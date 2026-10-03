from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


MAX_PROVIDER_RESPONSE_BYTES = 1_048_576


class ProviderFailureKind(StrEnum):
    CAPABILITY_UNSUPPORTED = "CAPABILITY_UNSUPPORTED"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    INVALID_MODEL_RESPONSE = "INVALID_MODEL_RESPONSE"
    TIMEOUT = "TIMEOUT"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"


class ProviderError(RuntimeError):
    """Typed provider boundary error; never silently changes execution mode."""

    def __init__(self, kind: ProviderFailureKind, message: str, *, provider: str = "", model: str = "", attempts: list[dict[str, str]] | tuple[dict[str, str], ...] = ()) -> None:
        super().__init__(message)
        self.kind = kind
        self.provider = provider
        self.model = model
        self.attempts = tuple(
            {key: str(item.get(key, "")) for key in ("provider", "model", "kind")}
            for item in attempts
            if isinstance(item, dict)
        )


class CapabilityUnsupported(ProviderError):
    def __init__(self, message: str = "provider capability unsupported", **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.CAPABILITY_UNSUPPORTED, message, **kwargs)


class ProviderFailure(ProviderError):
    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.PROVIDER_FAILURE, message, **kwargs)


class InvalidModelResponse(ProviderError):
    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.INVALID_MODEL_RESPONSE, message, **kwargs)


class ProviderTimeout(ProviderError):
    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.TIMEOUT, message, **kwargs)


class ProviderAuthenticationFailure(ProviderError):
    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.AUTHENTICATION_FAILURE, message, **kwargs)


@dataclass(frozen=True)
class ProviderCapabilities:
    generate: bool = True
    stream: bool = False
    tool_calling: bool = False
    structured_output: bool = False
    chat: bool = False
    native_chat: bool = False
    parallel_tool_calls: bool = False
    reasoning: bool = False
    reasoning_budget: bool = False
    long_context: bool = False
    vision: bool = False


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""


@dataclass
class ProviderResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = "stop"
    provider: str = ""
    model: str = ""
    usage: dict[str, Any] = field(default_factory=dict)
    capability: str = "generate"

    def public(self) -> dict[str, Any]:
        return {
            "content": self.text,
            "tool_calls": [{"id": c.call_id, "name": c.name, "arguments": c.arguments} for c in self.tool_calls],
            "finish_reason": self.finish_reason,
            "provider": self.provider,
            "model": self.model,
            "usage": self.usage,
            "capability": self.capability,
        }


def response_from_legacy(value: dict[str, Any], *, provider: str, model: str, capability: str = "generate") -> ProviderResponse:
    if not isinstance(value, dict):
        raise InvalidModelResponse("provider returned a non-object response", provider=provider, model=model)
    calls: list[ToolCall] = []
    raw_calls = value.get("tool_calls")
    if raw_calls is None:
        raw_calls = []
    if not isinstance(raw_calls, (list, tuple)):
        raise InvalidModelResponse("provider returned malformed tool calls", provider=provider, model=model)
    for item in raw_calls:
        if not isinstance(item, dict):
            raise InvalidModelResponse("provider returned malformed tool call", provider=provider, model=model)
        if "function" in item:
            function = item.get("function")
            if not isinstance(function, dict):
                raise InvalidModelResponse("provider returned malformed tool function", provider=provider, model=model)
        else:
            function = item
        name = function.get("name")
        if not isinstance(name, str) or not name.strip():
            raise InvalidModelResponse("provider returned a tool call without a valid name", provider=provider, model=model)
        arguments = function.get("arguments", {})
        if arguments is None:
            arguments = {}
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except (json.JSONDecodeError, TypeError) as exc:
                raise InvalidModelResponse("provider returned malformed tool arguments", provider=provider, model=model) from exc
        if not isinstance(arguments, dict):
            raise InvalidModelResponse("provider tool arguments must be an object", provider=provider, model=model)
        calls.append(ToolCall(name, arguments, str(item.get("id") or "")))
    text = value.get("content", value.get("text", ""))
    if text is None:
        text = ""
    if not isinstance(text, str):
        raise InvalidModelResponse("provider returned malformed text", provider=provider, model=model)
    default_finish_reason = "tool_calls" if calls else "stop"
    finish_reason = value.get("finish_reason")
    if finish_reason is None:
        finish_reason = default_finish_reason
    elif not isinstance(finish_reason, str):
        raise InvalidModelResponse("provider returned malformed finish reason", provider=provider, model=model)
    elif not finish_reason:
        finish_reason = default_finish_reason
    usage = value.get("usage")
    if usage is None:
        usage = {}
    elif not isinstance(usage, dict):
        raise InvalidModelResponse("provider returned malformed usage metadata", provider=provider, model=model)
    return ProviderResponse(
        text=text,
        tool_calls=calls,
        finish_reason=finish_reason,
        provider=provider,
        model=model,
        usage=usage,
        capability=capability,
    )


__all__ = [
    "CapabilityUnsupported", "InvalidModelResponse", "ProviderAuthenticationFailure", "ProviderError",
    "ProviderFailure", "ProviderFailureKind", "ProviderResponse", "ProviderTimeout", "ProviderCapabilities", "ToolCall",
    "MAX_PROVIDER_RESPONSE_BYTES", "response_from_legacy",
]
