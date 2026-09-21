from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProviderCapabilities:
    generate: bool = True
    stream: bool = False
    tool_calling: bool = False
    structured_output: bool = False
    chat: bool = False


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
