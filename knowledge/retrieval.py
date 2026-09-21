from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol

from .foundation import KnowledgeKind, KnowledgeObject


@dataclass(frozen=True)
class RetrievalHit:
    object_id: str
    score: float
    kind: KnowledgeKind
    exact_source: bool
    trust_class: str
    provenance: dict


class Retriever(Protocol):
    def search(self, query: str, *, kind: KnowledgeKind | None = None, limit: int = 20) -> list[RetrievalHit]: ...


class BM25Retriever:
    """Reserved adapter contract; implementation must preserve provenance and trust."""
    def __init__(self, objects: Iterable[KnowledgeObject] = ()):
        self.objects = tuple(objects)

    def search(self, query: str, *, kind: KnowledgeKind | None = None, limit: int = 20) -> list[RetrievalHit]:
        needle = query.casefold()
        candidates = [obj for obj in self.objects if (kind is None or obj.kind is kind) and needle in (obj.title + " " + obj.content).casefold()]
        return [RetrievalHit(obj.object_id, 1.0, obj.kind, obj.is_exact_source, obj.trust_class.value, {"source_id": obj.source_id, "source_url": obj.source_url, "content_hash": obj.content_hash}) for obj in candidates[:limit]]


class VectorRetriever:
    """Future vector adapter boundary; no embedding or execution permission is implied."""
    def search(self, query: str, *, kind: KnowledgeKind | None = None, limit: int = 20) -> list[RetrievalHit]:
        raise NotImplementedError("vector index is not installed in Knowledge Foundation")


class HybridRetriever:
    """Future hybrid adapter boundary combining lexical and vector hits."""
    def search(self, query: str, *, kind: KnowledgeKind | None = None, limit: int = 20) -> list[RetrievalHit]:
        raise NotImplementedError("hybrid index is not installed in Knowledge Foundation")
