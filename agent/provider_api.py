from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


MAX_PROVIDER_RESPONSE_BYTES = 1_048_576
MAX_PROVIDER_TEXT_CHARS = 32_000
MAX_PROVIDER_TOOL_CALLS = 10
MAX_PROVIDER_TOOL_NAME_CHARS = 128
MAX_PROVIDER_CALL_ID_CHARS = 128
MAX_PROVIDER_ARGUMENT_BYTES = 4_096
MAX_PROVIDER_USAGE_BYTES = 8_192
MAX_PROVIDER_FINISH_REASON_CHARS = 64
MAX_PROVIDER_LABEL_CHARS = 128


class ProviderFailureKind(StrEnum):
    CAPABILITY_UNSUPPORTED = "CAPABILITY_UNSUPPORTED"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    REQUEST_REJECTED = "REQUEST_REJECTED"
    INVALID_MODEL_RESPONSE = "INVALID_MODEL_RESPONSE"
    TIMEOUT = "TIMEOUT"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"


class ProviderError(RuntimeError):
    """Typed provider boundary error; never silently changes execution mode."""

    def __init__(self, kind: ProviderFailureKind, message: str, *, provider: str = "", model: str = "", attempts: list[dict[str, str]] | tuple[dict[str, str], ...] = (), status_code: int | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.provider = provider
        self.model = model
        self.status_code = status_code if isinstance(status_code, int) and not isinstance(status_code, bool) and 100 <= status_code <= 599 else None
        self.attempts = tuple(
            {
                **{key: str(item.get(key, "")) for key in ("provider", "model", "kind")},
                **({"http_status": str(item["http_status"])} if item.get("http_status") is not None else {}),
            }
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


class ProviderRequestRejected(ProviderError):
    def __init__(self, message: str, *, status_code: int | None = None, **kwargs: Any) -> None:
        super().__init__(ProviderFailureKind.REQUEST_REJECTED, message, status_code=status_code, **kwargs)


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


class ProviderDeployment(StrEnum):
    LOCAL = "local"
    REMOTE = "remote"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class HardwareRequirements:
    accelerator: str = "unknown"
    min_ram_gib: int | None = None
    min_vram_gib: int | None = None
    min_cpu_cores: int | None = None
    min_disk_gib: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.accelerator, str) or self.accelerator not in {
            "cpu", "nvidia", "amd", "apple", "any", "unknown"
        }:
            raise ValueError("invalid provider accelerator requirement")
        for name in ("min_ram_gib", "min_vram_gib", "min_cpu_cores", "min_disk_gib"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 1_000_000
            ):
                raise ValueError(f"invalid provider hardware requirement: {name}")

    def public(self) -> dict[str, Any]:
        return {
            "accelerator": self.accelerator,
            "min_ram_gib": self.min_ram_gib,
            "min_vram_gib": self.min_vram_gib,
            "min_cpu_cores": self.min_cpu_cores,
            "min_disk_gib": self.min_disk_gib,
        }


@dataclass(frozen=True)
class ProviderMetadata:
    provider_id: str
    model_identity: str
    capabilities: ProviderCapabilities
    context_length: int | None = None
    model_version: str | None = None
    quantization: str | None = None
    deployment: ProviderDeployment = ProviderDeployment.UNKNOWN
    hardware_requirements: HardwareRequirements = field(default_factory=HardwareRequirements)

    def __post_init__(self) -> None:
        for name, value, limit in (
            ("provider_id", self.provider_id, 128),
            ("model_identity", self.model_identity, 256),
        ):
            if (
                not isinstance(value, str)
                or not value.strip()
                or len(value) > limit
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                raise ValueError(f"invalid provider metadata: {name}")
        for name, value in (("model_version", self.model_version), ("quantization", self.quantization)):
            if value is not None and (
                not isinstance(value, str)
                or not value.strip()
                or len(value) > 64
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                raise ValueError(f"invalid provider metadata: {name}")
        if self.context_length is not None and (
            isinstance(self.context_length, bool)
            or not isinstance(self.context_length, int)
            or self.context_length < 1
        ):
            raise ValueError("invalid provider metadata: context_length")
        if not isinstance(self.capabilities, ProviderCapabilities):
            raise ValueError("invalid provider metadata: capabilities")
        if any(type(value) is not bool for value in self.capabilities.__dict__.values()):
            raise ValueError("invalid provider metadata: capability flags must be boolean")
        if not isinstance(self.hardware_requirements, HardwareRequirements):
            raise ValueError("invalid provider metadata: hardware_requirements")
        try:
            deployment = ProviderDeployment(self.deployment)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid provider deployment") from exc
        object.__setattr__(self, "deployment", deployment)

    def public(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "model_identity": self.model_identity,
            "model_version": self.model_version,
            "quantization": self.quantization,
            "context_length": self.context_length,
            "tool_calling": self.capabilities.tool_calling,
            "streaming": self.capabilities.stream,
            "structured_output": self.capabilities.structured_output,
            "reasoning": self.capabilities.reasoning,
            "capabilities": self.capabilities.__dict__.copy(),
            "deployment": self.deployment.value,
            "hardware_requirements": self.hardware_requirements.public(),
        }


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


def enforce_json_byte_limit(
    value: Any,
    *,
    max_bytes: int,
    message: str,
    provider: str = "",
    model: str = "",
) -> int:
    """Measure JSON-compatible input without materializing an unbounded JSON string."""
    try:
        encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        total = 0
        for piece in encoder.iterencode(value):
            if len(piece) > max_bytes - total:
                raise InvalidModelResponse(message, provider=provider, model=model)
            total += len(piece.encode("utf-8"))
            if total > max_bytes:
                raise InvalidModelResponse(message, provider=provider, model=model)
        return total
    except InvalidModelResponse:
        raise
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError) as exc:
        raise InvalidModelResponse(message, provider=provider, model=model) from exc


def validate_provider_response(
    response: Any,
    *,
    provider: str = "",
    model: str = "",
) -> ProviderResponse:
    """Validate every adapter's normalized response before it reaches orchestration."""
    error_provider = provider or (response.provider if isinstance(response, ProviderResponse) else "")
    error_model = model or (response.model if isinstance(response, ProviderResponse) else "")

    def invalid(message: str) -> InvalidModelResponse:
        return InvalidModelResponse(message, provider=error_provider, model=error_model)

    if not isinstance(response, ProviderResponse):
        raise invalid("provider returned an unsupported response")
    if not isinstance(response.text, str) or len(response.text) > MAX_PROVIDER_TEXT_CHARS:
        raise invalid("provider returned invalid or oversized text")
    try:
        response.text.encode("utf-8")
    except UnicodeError as exc:
        raise invalid("provider returned invalid text encoding") from exc
    if not isinstance(response.tool_calls, (list, tuple)) or len(response.tool_calls) > MAX_PROVIDER_TOOL_CALLS:
        raise invalid("provider returned invalid or excessive tool calls")
    seen_ids: set[str] = set()
    for call in response.tool_calls:
        if (
            not isinstance(call, ToolCall)
            or not isinstance(call.name, str)
            or len(call.name) > MAX_PROVIDER_TOOL_NAME_CHARS
            or not call.name.strip()
            or not isinstance(call.call_id, str)
            or len(call.call_id) > MAX_PROVIDER_CALL_ID_CHARS
            or not isinstance(call.arguments, dict)
        ):
            raise invalid("provider returned a malformed or oversized tool call")
        if call.call_id:
            if call.call_id in seen_ids:
                raise invalid("provider returned duplicate tool-call identifiers")
            seen_ids.add(call.call_id)
        enforce_json_byte_limit(
            call.arguments,
            max_bytes=MAX_PROVIDER_ARGUMENT_BYTES,
            message="provider returned oversized or malformed tool arguments",
            provider=error_provider,
            model=error_model,
        )
    if not isinstance(response.finish_reason, str) or len(response.finish_reason) > MAX_PROVIDER_FINISH_REASON_CHARS:
        raise invalid("provider returned malformed finish reason")
    if (
        not isinstance(response.provider, str)
        or len(response.provider) > MAX_PROVIDER_LABEL_CHARS
        or not isinstance(response.model, str)
        or len(response.model) > MAX_PROVIDER_LABEL_CHARS
        or not isinstance(response.capability, str)
        or len(response.capability) > MAX_PROVIDER_LABEL_CHARS
    ):
        raise invalid("provider returned malformed response identity metadata")
    try:
        for text_value in (
            *(value for call in response.tool_calls for value in (call.name, call.call_id)),
            response.finish_reason,
            response.provider,
            response.model,
            response.capability,
        ):
            text_value.encode("utf-8")
    except UnicodeError as exc:
        raise invalid("provider returned invalid response metadata encoding") from exc
    if not isinstance(response.usage, dict):
        raise invalid("provider returned malformed usage metadata")
    enforce_json_byte_limit(
        response.usage,
        max_bytes=MAX_PROVIDER_USAGE_BYTES,
        message="provider returned oversized or malformed usage metadata",
        provider=error_provider,
        model=error_model,
    )
    return response


def response_from_legacy(value: dict[str, Any], *, provider: str, model: str, capability: str = "generate") -> ProviderResponse:
    if not isinstance(value, dict):
        raise InvalidModelResponse("provider returned a non-object response", provider=provider, model=model)
    calls: list[ToolCall] = []
    raw_calls = value.get("tool_calls")
    if raw_calls is None:
        raw_calls = []
    if not isinstance(raw_calls, (list, tuple)) or len(raw_calls) > MAX_PROVIDER_TOOL_CALLS:
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
        if not isinstance(name, str) or len(name) > MAX_PROVIDER_TOOL_NAME_CHARS or not name.strip():
            raise InvalidModelResponse("provider returned a tool call without a valid name", provider=provider, model=model)
        arguments = function.get("arguments", {})
        if arguments is None:
            arguments = {}
        if isinstance(arguments, str):
            try:
                if len(arguments.encode("utf-8")) > MAX_PROVIDER_ARGUMENT_BYTES:
                    raise InvalidModelResponse("provider returned oversized tool arguments", provider=provider, model=model)
            except UnicodeError as exc:
                raise InvalidModelResponse("provider returned malformed tool arguments", provider=provider, model=model) from exc
            try:
                arguments = json.loads(arguments)
            except (json.JSONDecodeError, TypeError) as exc:
                raise InvalidModelResponse("provider returned malformed tool arguments", provider=provider, model=model) from exc
        if not isinstance(arguments, dict):
            raise InvalidModelResponse("provider tool arguments must be an object", provider=provider, model=model)
        call_id = item.get("id", "")
        if call_id is None:
            call_id = ""
        if not isinstance(call_id, str):
            raise InvalidModelResponse("provider returned malformed tool-call identity", provider=provider, model=model)
        calls.append(ToolCall(name, arguments, call_id))
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
    return validate_provider_response(ProviderResponse(
        text=text,
        tool_calls=calls,
        finish_reason=finish_reason,
        provider=provider,
        model=model,
        usage=usage,
        capability=capability,
    ), provider=provider, model=model)


__all__ = [
    "CapabilityUnsupported", "InvalidModelResponse", "ProviderAuthenticationFailure", "ProviderError", "ProviderRequestRejected",
    "ProviderFailure", "ProviderFailureKind", "ProviderResponse", "ProviderTimeout", "ProviderCapabilities", "ToolCall",
    "MAX_PROVIDER_RESPONSE_BYTES", "MAX_PROVIDER_TEXT_CHARS", "MAX_PROVIDER_TOOL_CALLS",
    "MAX_PROVIDER_TOOL_NAME_CHARS", "MAX_PROVIDER_CALL_ID_CHARS", "MAX_PROVIDER_ARGUMENT_BYTES",
    "MAX_PROVIDER_USAGE_BYTES", "MAX_PROVIDER_FINISH_REASON_CHARS", "MAX_PROVIDER_LABEL_CHARS",
    "enforce_json_byte_limit", "response_from_legacy", "validate_provider_response",
]
