from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Callable


@dataclass(frozen=True)
class MissionIntent:
    objective: str
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
        return {"objective": self.objective, "constraints": list(self.constraints), "requested_artifacts": list(self.requested_artifacts), "verification_criteria": list(self.verification_criteria), "scope_references": list(self.scope_references), "authorization_requirements": list(self.authorization_requirements), "entities": list(self.entities), "ambiguities": list(self.ambiguities), "semantic_fingerprint": self.semantic_fingerprint, "source": self.source}


class NaturalLanguageUnderstanding:
    """Uses a model proposer when supplied; deterministic fallback is explicitly marked."""

    def __init__(self, proposer: Callable[[str], dict[str, Any]] | None = None):
        self.proposer = proposer

    def understand(self, text: str) -> MissionIntent:
        raw = str(text or "").strip()
        data: dict[str, Any] = {}
        source = "fallback"
        if self.proposer:
            try:
                candidate = self.proposer(raw)
                if isinstance(candidate, dict): data, source = candidate, "model"
            except Exception:
                data = {}
        if not data:
            data = self._fallback(raw)
        objective = str(data.get("objective") or raw).strip()
        import hashlib
        fingerprint = hashlib.sha256(json.dumps({key: data.get(key, ()) for key in ("objective", "constraints", "requested_artifacts", "verification_criteria", "scope_references", "authorization_requirements", "entities")}, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()
        return MissionIntent(objective=objective, constraints=tuple(map(str, data.get("constraints", ()))), requested_artifacts=tuple(map(str, data.get("requested_artifacts", ()))), verification_criteria=tuple(map(str, data.get("verification_criteria", ()))), scope_references=tuple(map(str, data.get("scope_references", ()))), authorization_requirements=tuple(map(str, data.get("authorization_requirements", ()))), entities=tuple(map(str, data.get("entities", ()))), ambiguities=tuple(map(str, data.get("ambiguities", ()))), semantic_fingerprint=fingerprint, source=source)

    @staticmethod
    def _fallback(text: str) -> dict[str, Any]:
        return {"objective": text, "verification_criteria": ("distinguish facts, inferences, hypotheses, and unknowns",), "ambiguities": ("model unavailable; semantic interpretation requires owner review",)}


__all__ = ["MissionIntent", "NaturalLanguageUnderstanding"]
