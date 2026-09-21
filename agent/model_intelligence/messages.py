from __future__ import annotations

from typing import Any, Iterable
from .protocol import ConversationTurn


def normalize_messages(messages: Iterable[ConversationTurn | dict[str, Any]]) -> list[ConversationTurn]:
    result = []
    for item in messages:
        if isinstance(item, ConversationTurn):
            result.append(item)
        elif isinstance(item, dict) and item.get("role") in {"system", "user", "assistant", "tool"}:
            result.append(ConversationTurn(role=str(item["role"]), content=str(item.get("content", "") or ""), tool_call_id=str(item.get("tool_call_id", "")), name=str(item.get("name", "")), tool_calls=tuple(item.get("tool_calls", ()) or ())))
    return result


def provider_messages(messages: Iterable[ConversationTurn | dict[str, Any]]) -> list[dict[str, Any]]:
    return [item.to_dict() for item in normalize_messages(messages)]


__all__ = ["normalize_messages", "provider_messages"]
