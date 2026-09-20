from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from cyber_knowledge.models import KnowledgeObject


@dataclass(frozen=True)
class RetrievalHit:
    object_id: str
    score: int
    source: str
    source_type: str
    content_hash: str
    observation: str
    technique: str


class LocalRetriever:
    def __init__(self, objects: Iterable[KnowledgeObject] = ()):
        self._objects = tuple(objects)

    def search(self, query: str, limit: int = 5) -> list[RetrievalHit]:
        terms = {term.lower() for term in query.split() if len(term) > 2}
        hits = []
        for obj in self._objects:
            haystack = " ".join((obj.observation, obj.technique, obj.hypothesis, *obj.evidence, *obj.mitre, *obj.cwe)).lower()
            score = sum(1 for term in terms if term in haystack)
            if score:
                hits.append(RetrievalHit(obj.object_id, score, obj.source, obj.source_type, obj.content_hash, obj.observation, obj.technique))
        return sorted(hits, key=lambda hit: (-hit.score, hit.object_id))[:limit]
