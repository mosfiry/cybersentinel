from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol


@dataclass(frozen=True)
class ProviderCapabilities:
    generate: bool = True
    stream: bool = False
    tool_calling: bool = False
    structured_output: bool = False


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
    request_metadata: dict[str, Any] = field(default_factory=dict)
    capability: str = "generate"

    def public(self) -> dict[str, Any]:
        return {
            "content": self.text,
            "tool_calls": [{"id": c.call_id, "name": c.name, "arguments": c.arguments} for c in self.tool_calls],
            "finish_reason": self.finish_reason,
            "provider": self.provider,
            "model": self.model,
            "usage": self.usage,
            "request_metadata": self.request_metadata,
            "capability": self.capability,
        }


class LLMProvider(Protocol):
    name: str
    model: str
    capabilities: ProviderCapabilities

    def generate(self, messages: list[dict], temperature: float = 0, **kwargs: Any) -> ProviderResponse: ...
    def stream(self, messages: list[dict], temperature: float = 0, **kwargs: Any) -> Iterable[dict[str, Any]]: ...
    def tool_calling(self, messages: list[dict], tools: list[dict], temperature: float = 0, **kwargs: Any) -> ProviderResponse: ...


def response_from_legacy(value: dict[str, Any], *, provider: str, model: str, capability: str = "generate") -> ProviderResponse:
    """Normalize legacy provider dictionaries; provider identity is router-owned."""
    calls = []
    for item in value.get("tool_calls") or []:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        args = item.get("arguments") if isinstance(item.get("arguments"), dict) else {}
        calls.append(ToolCall(item["name"], args, str(item.get("id") or "")))
    text = value.get("content", value.get("text", ""))
    return ProviderResponse(str(text or ""), calls, str(value.get("finish_reason") or ("tool_calls" if calls else "stop")), provider, model, value.get("usage") or {}, {}, capability)
