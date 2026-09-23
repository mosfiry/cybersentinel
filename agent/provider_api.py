from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ProviderFailureKind(StrEnum):
    CAPABILITY_UNSUPPORTED = "CAPABILITY_UNSUPPORTED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    INVALID_MODEL_RESPONSE = "INVALID_MODEL_RESPONSE"
    TIMEOUT = "TIMEOUT"
    RATE_LIMIT = "RATE_LIMIT"
    CONTEXT_OVERFLOW = "CONTEXT_OVERFLOW"
    MODEL_REFUSAL = "MODEL_REFUSAL"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"


class ProviderError(RuntimeError):
    """Typed provider boundary error; never silently changes execution mode."""

    def __init__(self, kind: ProviderFailureKind, message: str, *, provider: str = "", model: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.provider = provider
        self.model = model


class CapabilityUnsupported(ProviderError):
    def __init__(self, message: str = "provider capability unsupported", **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.CAPABILITY_UNSUPPORTED, message, **kwargs)


class ProviderFailure(ProviderError):
    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.PROVIDER_FAILURE, message, **kwargs)


class ProviderUnavailable(ProviderError):
    def __init__(self, message: str = "provider unavailable", **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.PROVIDER_UNAVAILABLE, message, **kwargs)


class InvalidModelResponse(ProviderError):
    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.INVALID_MODEL_RESPONSE, message, **kwargs)


class ProviderTimeout(ProviderError):
    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.TIMEOUT, message, **kwargs)


class ProviderRateLimit(ProviderError):
    def __init__(self, message: str = "provider rate limit", **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.RATE_LIMIT, message, **kwargs)


class ContextOverflow(ProviderError):
    def __init__(self, message: str = "context limit exceeded", **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.CONTEXT_OVERFLOW, message, **kwargs)


class ModelRefusal(ProviderError):
    def __init__(self, message: str = "model refused request", **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.MODEL_REFUSAL, message, **kwargs)


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
    calls: list[ToolCall] = []
    for item in value.get("tool_calls") or []:
        if not isinstance(item, dict):
            continue
        function = item.get("function") if isinstance(item.get("function"), dict) else item
        name = function.get("name")
        if not isinstance(name, str):
            continue
        arguments = function.get("arguments", {})
        if isinstance(arguments, str):
            try:
                arguments = __import__("json").loads(arguments)
            except Exception:
                arguments = {}
        calls.append(ToolCall(name, arguments if isinstance(arguments, dict) else {}, str(item.get("id") or "")))
    return ProviderResponse(
        text=str(value.get("content", value.get("text", "")) or ""),
        tool_calls=calls,
        finish_reason=str(value.get("finish_reason") or ("tool_calls" if calls else "stop")),
        provider=provider,
        model=model,
        usage=value.get("usage") or {},
        capability=capability,
    )


__all__ = [
    "CapabilityUnsupported", "ContextOverflow", "InvalidModelResponse", "ModelRefusal", "ProviderAuthenticationFailure", "ProviderError",
    "ProviderFailure", "ProviderFailureKind", "ProviderResponse", "ProviderRateLimit", "ProviderTimeout", "ProviderUnavailable", "ProviderCapabilities", "ToolCall",
    "response_from_legacy",
]
