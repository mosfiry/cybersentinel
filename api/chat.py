from __future__ import annotations

import json
import uuid
from typing import Any, Iterator

from agent.loop import AgentLoop
from core.db import add_conversation_message, conversation_info, conversation_messages, ensure_conversation
from core.engine import RUNTIME, handle


def _execute(text: str, *, owner_token: str, owner_session_id: str | None = None, owner_challenge: str | None = None) -> dict[str, Any]:
    return handle(text, source="chat", owner_token=owner_token, owner_session_id=owner_session_id, owner_challenge=owner_challenge)


def chat(payload: dict[str, Any], *, owner_token: str, owner_session_id: str | None = None, owner_challenge: str | None = None) -> dict[str, Any]:
    text = str(payload.get("text", "")).strip()
    if not text:
        raise ValueError("text_required")
    conversation_id = str(payload.get("conversation_id") or uuid.uuid4().hex).strip()
    if len(conversation_id) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in conversation_id):
        raise ValueError("invalid_conversation_id")
    if RUNTIME.router.providers:
        executor = lambda command, *, owner_token, owner_session_id=None: _execute(command, owner_token=owner_token, owner_session_id=owner_session_id, owner_challenge=owner_challenge)
        return AgentLoop(RUNTIME.router, executor).run(conversation_id, text, owner_token=owner_token, owner_session_id=owner_session_id)
    ensure_conversation(conversation_id, owner_session_id or "")
    add_conversation_message(conversation_id, "user", text)
    result = _execute(text, owner_token=owner_token, owner_session_id=owner_session_id, owner_challenge=owner_challenge)
    answer = result.get("answer", "")
    add_conversation_message(conversation_id, "assistant", answer, {"request_id": result.get("request_id"), "planner": result.get("planner")})
    return {"conversation_id": conversation_id, "answer": answer, "activity": [{"type": "execution", "request_id": result.get("request_id"), "status": result.get("decision")}], "execution": result}


def get_session(conversation_id: str) -> dict[str, Any] | None:
    info = conversation_info(conversation_id)
    if info is None:
        return None
    info["messages"] = conversation_messages(conversation_id)
    return info


def stream(payload: dict[str, Any], *, owner_token: str, owner_session_id: str | None = None, owner_challenge: str | None = None) -> Iterator[dict[str, Any]]:
    yield {"event": "started", "data": {"conversation_id": payload.get("conversation_id")}}
    result = chat(payload, owner_token=owner_token, owner_session_id=owner_session_id, owner_challenge=owner_challenge)
    for activity in result.get("activity", []):
        yield {"event": "tool_activity", "data": activity}
    yield {"event": "completed", "data": result}


def sse(event: dict[str, Any]) -> bytes:
    return (f"event: {event['event']}\ndata: {json.dumps(event['data'], ensure_ascii=False)}\n\n").encode("utf-8")
