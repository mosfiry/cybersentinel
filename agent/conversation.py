from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Protocol


class IntentType(str, Enum):
    ANALYZE_INCIDENT = "ANALYZE_INCIDENT"
    RESEARCH = "RESEARCH"
    EXPLAIN_EVIDENCE = "EXPLAIN_EVIDENCE"
    LEARN = "LEARN"
    ANALYZE_CODE = "ANALYZE_CODE"
    SCOPED_TEST = "SCOPED_TEST"
    EXPLAIN_REJECTION = "EXPLAIN_REJECTION"
    GENERAL_CONVERSATION = "GENERAL_CONVERSATION"


class ModelOutputKind(str, Enum):
    ANALYSIS = "ANALYSIS"
    PROPOSAL = "PROPOSAL"
    HYPOTHESIS = "HYPOTHESIS"
    PLAN = "PLAN"
    OBSERVATION_INTERPRETATION = "OBSERVATION_INTERPRETATION"
    WARNING = "WARNING"
    UNCERTAINTY = "UNCERTAINTY"


@dataclass(frozen=True)
class ConversationInput:
    text: str
    conversation_id: str = ""
    request_id: str = ""
    language: str = "auto"


@dataclass(frozen=True)
class ConversationContext:
    conversation_id: str
    request_id: str
    policy_snapshot_fingerprint: str = ""
    scope_snapshot_fingerprint: str = ""
    evidence_ids: tuple[str, ...] = ()
    prior_turn_references: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConversationIntent:
    intent_type: IntentType
    raw_text: str
    entities: tuple[str, ...] = ()
    confidence: float = 0.0
    authorization_required: bool = False
    # Retained for compatibility; it is always false at the understanding layer.
    authority_granted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_type": self.intent_type.value,
            "raw_text": self.raw_text,
            "entities": list(self.entities),
            "confidence": self.confidence,
            "authorization_required": self.authorization_required,
            "authority_granted": False,
        }


@dataclass(frozen=True)
class ConversationActionProposal:
    action: str
    arguments: dict[str, Any] = field(default_factory=dict)
    intent_type: IntentType = IntentType.GENERAL_CONVERSATION
    status: str = "PROPOSED"
    requires_policy_evaluation: bool = True
    authorization_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "arguments": self.arguments,
            "intent_type": self.intent_type.value,
            "status": self.status,
            "requires_policy_evaluation": self.requires_policy_evaluation,
            "authorization_required": self.authorization_required,
        }


@dataclass(frozen=True)
class ConversationResponse:
    natural_language: str
    intent: ConversationIntent
    action_proposal: ConversationActionProposal | None = None
    tool_calls: tuple[dict[str, Any], ...] = ()
    confidence: float = 0.0
    evidence_needed: tuple[str, ...] = ()
    provider: str = "deterministic"
    model: str = "rule-based"
    output_kind: ModelOutputKind = ModelOutputKind.PROPOSAL

    def public(self) -> dict[str, Any]:
        # Deliberately no authority_granted field: authorization is external to the provider.
        return {
            "natural_language": self.natural_language,
            "intent": self.intent.to_dict(),
            "action_proposal": self.action_proposal.to_dict() if self.action_proposal else None,
            "tool_calls": list(self.tool_calls),
            "confidence": self.confidence,
            "evidence_needed": list(self.evidence_needed),
            "provider": self.provider,
            "model": self.model,
            "output_kind": self.output_kind.value,
        }


class ConversationProvider(Protocol):
    def respond(self, conversation_input: ConversationInput, context: ConversationContext) -> ConversationResponse:
        """Return understanding and an untrusted proposal; never authorize or execute."""


class ConversationParser:
    """Deterministic intent baseline; understanding never authenticates or authorizes."""

    _rules = (
        (IntentType.LEARN, ("علمني", "علّم", "teach me", "learn ")),
        (IntentType.EXPLAIN_REJECTION, ("لماذا رفض", "why was", "why did the system reject")),
        (IntentType.SCOPED_TEST, ("اختبر الهدف", "test the target", "authorized scope", "داخل النطاق")),
        (IntentType.EXPLAIN_EVIDENCE, ("الأدلة", "evidence", "لماذا تعتقد", "compare this hypothesis", "what evidence is missing", "cve", "فهم تأثير")),
        (IntentType.ANALYZE_CODE, ("حلل هذا الكود", "افحص هذا الكود", "analyze this code", "review this code")),
        (IntentType.ANALYZE_INCIDENT, ("حلل هذه الحادثة", "analyze this incident", "incident analysis")),
        (IntentType.RESEARCH, ("ابحث عن", "research", "find vulnerabilities", "الثغرات المحتملة")),
    )

    def parse(self, text: str) -> ConversationIntent:
        raw = str(text or "").strip()
        folded = raw.casefold()
        for intent_type, phrases in self._rules:
            if any(phrase.casefold() in folded for phrase in phrases):
                entities = tuple(dict.fromkeys(re.findall(r"https?://[^\s]+|T\d{4}(?:\.\d{3})?|CVE-\d{4}-\d+", raw, flags=re.IGNORECASE)))
                return ConversationIntent(intent_type, raw, entities, 0.8, intent_type is IntentType.SCOPED_TEST, False)
        return ConversationIntent(IntentType.GENERAL_CONVERSATION, raw, (), 0.2, False, False)

    def understand(self, text: str) -> ConversationIntent:
        return self.parse(text)

    def propose(self, intent: ConversationIntent) -> ConversationActionProposal | None:
        if intent.intent_type is IntentType.SCOPED_TEST:
            return ConversationActionProposal("scoped_test", {"entities": list(intent.entities)}, intent.intent_type, authorization_required=True)
        if intent.intent_type is IntentType.RESEARCH:
            return ConversationActionProposal("research", {"query": intent.raw_text}, intent.intent_type)
        if intent.intent_type is IntentType.ANALYZE_CODE:
            return ConversationActionProposal("analyze_code", {"input": intent.raw_text}, intent.intent_type)
        return None

    def respond(self, conversation_input: ConversationInput, context: ConversationContext) -> ConversationResponse:
        intent = self.understand(conversation_input.text)
        proposal = self.propose(intent)
        evidence_needed = ("valid scope and authorization evidence",) if intent.authorization_required else ()
        return ConversationResponse(
            natural_language="Understood; any action remains a proposal pending policy, authorization, scope, and tool validation.",
            intent=intent,
            action_proposal=proposal,
            confidence=intent.confidence,
            evidence_needed=evidence_needed,
        )


__all__ = [
    "IntentType", "ModelOutputKind", "ConversationInput", "ConversationContext", "ConversationIntent",
    "ConversationActionProposal", "ConversationResponse", "ConversationProvider", "ConversationParser",
]
