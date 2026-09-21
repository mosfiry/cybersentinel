from __future__ import annotations

import json
from typing import Any, Callable

from .conversation import ConversationActionProposal, ConversationContext, ConversationInput, ConversationIntent, ConversationParser, ConversationProvider, ConversationResponse, IntentType


FORBIDDEN_MODEL_FIELDS = frozenset({"authority_granted", "owner_authenticated", "authorization_granted", "scope_approved", "policy_approved"})
ALLOWED_FIELDS = frozenset({"intent", "action_proposal", "arguments", "evidence_needed"})


class ConversationSchemaError(ValueError):
    pass


class LocalModelConversationProvider:
    """Adapter for a local/router model; returns only validated untrusted proposals."""

    def __init__(self, router: Any, *, parser: ConversationParser | None = None):
        self.router = router
        self.parser = parser or ConversationParser()

    @staticmethod
    def _decode(raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            content = raw.get("content", raw)
        else:
            content = getattr(raw, "text", raw)
        if isinstance(content, dict):
            value = content
        else:
            try:
                value = json.loads(str(content))
            except (TypeError, json.JSONDecodeError) as exc:
                raise ConversationSchemaError("model response must be a JSON object") from exc
        if not isinstance(value, dict):
            raise ConversationSchemaError("model response must be a JSON object")
        forbidden = set(value) & FORBIDDEN_MODEL_FIELDS
        if forbidden:
            raise ConversationSchemaError(f"model cannot return authority fields: {sorted(forbidden)}")
        unknown = set(value) - ALLOWED_FIELDS
        if unknown:
            raise ConversationSchemaError(f"unknown model response fields: {sorted(unknown)}")
        if not isinstance(value.get("intent"), str) or value["intent"] not in {item.value for item in IntentType}:
            raise ConversationSchemaError("intent must be a known IntentType")
        if value.get("action_proposal") is not None and not isinstance(value.get("action_proposal"), str):
            raise ConversationSchemaError("action_proposal must be a string or null")
        if not isinstance(value.get("arguments", {}), dict):
            raise ConversationSchemaError("arguments must be an object")
        if not isinstance(value.get("evidence_needed", []), list) or not all(isinstance(item, str) for item in value.get("evidence_needed", [])):
            raise ConversationSchemaError("evidence_needed must be a string array")
        return value

    def respond(self, conversation_input: ConversationInput, context: ConversationContext) -> ConversationResponse:
        messages = [
            {"role": "system", "content": "Return JSON only with exactly: intent, action_proposal, arguments, evidence_needed. Never return authority, policy, scope, or authentication fields."},
            {"role": "user", "content": conversation_input.text},
        ]
        try:
            raw = self.router.generate(messages)
        except AttributeError:
            raw = self.router.chat(messages)
        value = self._decode(raw)
        intent_type = IntentType(value["intent"])
        parsed = self.parser.understand(conversation_input.text)
        intent = ConversationIntent(intent_type, conversation_input.text, parsed.entities, 0.7, intent_type is IntentType.SCOPED_TEST, False)
        proposal = None
        action = value.get("action_proposal")
        if action:
            proposal = ConversationActionProposal(action, dict(value.get("arguments", {})), intent_type, "PROPOSED", True, intent_type is IntentType.SCOPED_TEST)
        return ConversationResponse(
            natural_language="Model output was parsed as an untrusted proposal pending policy and authorization.",
            intent=intent,
            action_proposal=proposal,
            confidence=0.7,
            evidence_needed=tuple(value.get("evidence_needed", [])),
            provider=getattr(self.router, "name", "local"),
            model=getattr(self.router, "model", "unknown"),
        )


__all__ = ["LocalModelConversationProvider", "ConversationSchemaError", "FORBIDDEN_MODEL_FIELDS"]
