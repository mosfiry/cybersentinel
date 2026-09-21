from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from knowledge.foundation import KnowledgeKind, KnowledgeObject, TrustClass
from knowledge.retrieval import HybridRetriever, KnowledgeQuery, RetrievalHit
from knowledge.store import search as store_search


@dataclass(frozen=True)
class RetrievalResult:
    knowledge_id: str
    source_id: str
    source_type: str
    title: str
    content: str
    relevance: float
    claim_type: str
    attribution_status: str
    created_at: str
    provenance: dict[str, Any] = field(default_factory=dict)
    relationships: dict[str, tuple[str, ...]] = field(default_factory=dict)
    authority: None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "knowledge_id": self.knowledge_id,
            "object_id": self.knowledge_id,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "title": self.title,
            "content": self.content,
            "relevance": self.relevance,
            "claim_type": self.claim_type,
            "attribution_status": self.attribution_status,
            "created_at": self.created_at,
            "provenance": dict(self.provenance),
            "relationships": {key: list(value) for key, value in self.relationships.items()},
            "authority": None,
            "trust": "UNTRUSTED_DATA",
        }


def _result(obj: KnowledgeObject, score: float, hit: RetrievalHit | None = None) -> RetrievalResult:
    metadata = dict(obj.metadata or {})
    relationships = {}
    for key in ("cve", "cwe", "capec", "technique", "techniques", "ioc", "iocs", "actor", "campaign", "poc"):
        value = metadata.get(key)
        if value is not None:
            relationships[key] = tuple(value) if isinstance(value, (list, tuple, set)) else (str(value),)
    return RetrievalResult(
        knowledge_id=obj.object_id,
        source_id=obj.source_id,
        source_type=obj.kind.value,
        title=obj.title,
        content=obj.content,
        relevance=float(score),
        claim_type=str(metadata.get("claim_type", "UNSPECIFIED")),
        attribution_status=str(metadata.get("attribution_status", "UNKNOWN")),
        created_at=obj.created_at,
        provenance={
            "source_id": obj.source_id,
            "source_url": obj.source_url,
            "content_hash": obj.content_hash,
            "trust_class": obj.trust_class.value,
            "transformation_policy": obj.transformation_policy.value,
            "retriever": "knowledge.store + BM25Retriever",
            "authority": None,
            **({"retrieval_hit": hit.provenance} if hit else {}),
        },
        relationships=relationships,
    )


class TypedKnowledgeRetriever:
    """Retrieves from the append-only typed store; knowledge remains untrusted data."""

    def __init__(self, objects: Iterable[KnowledgeObject] = (), *, fallback_store: bool = True):
        self.objects = tuple(objects)
        self.fallback_store = fallback_store

    def _objects(self, query: str) -> tuple[KnowledgeObject, ...]:
        if self.objects:
            return self.objects
        if not self.fallback_store:
            return ()
        try:
            return tuple(store_search(query, limit=50))
        except Exception:
            return ()

    def retrieve(self, query: str, *, limit: int = 5, kind: KnowledgeKind | None = None) -> list[RetrievalResult]:
        objects = self._objects(query)
        if not objects:
            return []
        retriever = HybridRetriever(objects)
        hits = retriever.search(KnowledgeQuery(text=query, kind=kind, limit=limit))
        by_id = {obj.object_id: obj for obj in objects}
        return [_result(by_id[hit.object_id], hit.score, hit) for hit in hits if hit.object_id in by_id]

    def retrieve_relevant(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.retrieve(query, limit=limit)]

    def retrieve_adaptive(self, query: str, *, required_evidence: Iterable[str] = (), limit: int = 5) -> dict[str, Any]:
        """Retrieve, inspect gaps, and issue deterministic refinement queries."""
        initial = self.retrieve(query, limit=limit)
        missing = [item for item in required_evidence if not any(str(item).casefold() in result.content.casefold() for result in initial)]
        refined = []
        for item in missing[:3]:
            refined.extend(self.retrieve(f"{query} {item}", limit=limit))
        by_id = {item.knowledge_id: item for item in (*initial, *refined)}
        return {"query": query, "results": [item.to_dict() for item in by_id.values()], "missing_evidence": missing, "refined_queries": [f"{query} {item}" for item in missing[:3]], "provenance": {"retrieval": "hybrid_adaptive", "authority": None}}

    def available(self) -> bool:
        return bool(self.objects) or self.fallback_store


__all__ = ["RetrievalResult", "TypedKnowledgeRetriever"]
