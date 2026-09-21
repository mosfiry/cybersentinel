from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re


class IntentType(str, Enum):
    ANALYZE_INCIDENT = "ANALYZE_INCIDENT"
    RESEARCH = "RESEARCH"
    EXPLAIN_EVIDENCE = "EXPLAIN_EVIDENCE"
    LEARN = "LEARN"
    ANALYZE_CODE = "ANALYZE_CODE"
    SCOPED_TEST = "SCOPED_TEST"
    EXPLAIN_REJECTION = "EXPLAIN_REJECTION"
    GENERAL_CONVERSATION = "GENERAL_CONVERSATION"


@dataclass(frozen=True)
class ConversationIntent:
    intent_type: IntentType
    raw_text: str
    entities: tuple[str, ...] = ()
    confidence: float = 0.0
    authorization_required: bool = False
    authority_granted: bool = False

    def to_dict(self) -> dict:
        return {
            "intent_type": self.intent_type.value,
            "raw_text": self.raw_text,
            "entities": list(self.entities),
            "confidence": self.confidence,
            "authorization_required": self.authorization_required,
            "authority_granted": self.authority_granted,
        }


class ConversationParser:
    """Deterministic intent baseline; understanding never authenticates or authorizes."""

    _rules = (
        (IntentType.LEARN, ("علمني", "علّم", "teach me", "learn ")),
        (IntentType.EXPLAIN_REJECTION, ("لماذا رفض", "why was", "why did the system reject")),
        (IntentType.SCOPED_TEST, ("اختبر الهدف", "test the target", "authorized scope", "داخل النطاق")),
        (IntentType.EXPLAIN_EVIDENCE, ("الأدلة", "evidence", "لماذا تعتقد", "compare this hypothesis")),
        (IntentType.ANALYZE_CODE, ("حلل هذا الكود", "analyze this code", "review this code")),
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


__all__ = ["IntentType", "ConversationIntent", "ConversationParser"]
