from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Callable

from agent.model_intelligence.intent import validate_intent_proposal


@dataclass(frozen=True)
class MissionIntent:
    objective: str
    intent_type: str = "GENERAL_CONVERSATION"
    constraints: tuple[str, ...] = ()
    requested_artifacts: tuple[str, ...] = ()
    verification_criteria: tuple[str, ...] = ()
    scope_references: tuple[str, ...] = ()
    authorization_requirements: tuple[str, ...] = ()
    entities: tuple[str, ...] = ()
    ambiguities: tuple[str, ...] = ()
    semantic_fingerprint: str = ""
    source: str = "model"

    def to_dict(self) -> dict[str, Any]:
        return {"objective": self.objective, "intent_type": self.intent_type, "constraints": list(self.constraints), "requested_artifacts": list(self.requested_artifacts), "verification_criteria": list(self.verification_criteria), "scope_references": list(self.scope_references), "authorization_requirements": list(self.authorization_requirements), "entities": list(self.entities), "ambiguities": list(self.ambiguities), "semantic_fingerprint": self.semantic_fingerprint, "source": self.source}


class NaturalLanguageUnderstanding:
    """Uses a model proposer when supplied; deterministic fallback is explicitly marked.

    R1 authority rules (INV-INTENT-1, INV-INTENT-2):

    - Every model proposal passes the deterministic intent validator
      (agent/model_intelligence/intent.py) BEFORE it becomes a typed
      MissionIntent. Authority-shaped proposals are rejected and the
      deterministic fallback interpretation is used instead; the rejection
      is recorded in the intent ambiguities.
    - A failed, empty, or non-dict model turn is NEVER labeled as model
      provenance: the fallback path always carries
      source="deterministic_fallback".
    """

    def __init__(self, proposer: Callable[[str], dict[str, Any]] | None = None):
        self.proposer = proposer

    def understand(self, text: str) -> MissionIntent:
        raw = str(text or "").strip()
        data: dict[str, Any] = {}
        source = "deterministic_fallback"
        rejection = ""
        if self.proposer:
            try:
                candidate = self.proposer(raw)
                if isinstance(candidate, dict) and candidate:
                    ok, reason = validate_intent_proposal(candidate)
                    if ok:
                        data, source = candidate, "model"
                    else:
                        rejection = reason
            except Exception:
                data = {}
        if not data:
            data = self._fallback(raw)
        objective = str(data.get("objective") or raw).strip()
        import hashlib
        fingerprint = hashlib.sha256(json.dumps({key: data.get(key, ()) for key in ("objective", "constraints", "requested_artifacts", "verification_criteria", "scope_references", "authorization_requirements", "entities")}, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()
        intent_type = str(data.get("intent_type") or self._fallback_intent_type(raw))
        ambiguities = tuple(map(str, data.get("ambiguities", ())))
        if rejection:
            ambiguities = ambiguities + ("deterministic intent validator rejected the model proposal: " + rejection,)
        return MissionIntent(objective=objective, intent_type=intent_type, constraints=tuple(map(str, data.get("constraints", ()))), requested_artifacts=tuple(map(str, data.get("requested_artifacts", ()))), verification_criteria=tuple(map(str, data.get("verification_criteria", ()))), scope_references=tuple(map(str, data.get("scope_references", ()))), authorization_requirements=tuple(map(str, data.get("authorization_requirements", ()))), entities=tuple(map(str, data.get("entities", ()))), ambiguities=ambiguities, semantic_fingerprint=fingerprint, source=source)

    @staticmethod
    def _fallback(text: str) -> dict[str, Any]:
        return {"objective": text, "verification_criteria": ("distinguish facts, inferences, hypotheses, and unknowns",), "ambiguities": ("model unavailable; semantic interpretation requires owner review",)}

    @staticmethod
    def _fallback_intent_type(text: str) -> str:
        folded = text.casefold()
        if any(token in folded for token in ("incident", "root cause", "حادث", "السبب الجذري")):
            return "MISSION_REQUEST"
        if any(token in folded for token in ("status", "الحالة", "حالة النظام")):
            return "STATUS_REQUEST"
        if any(token in folded for token in ("tool", "أداة", "نفذ")):
            return "TOOL_REQUEST"
        return "GENERAL_CONVERSATION"


__all__ = ["MissionIntent", "NaturalLanguageUnderstanding"]
