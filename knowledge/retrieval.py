from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
import re
from typing import Iterable, Protocol

from .foundation import KnowledgeKind, KnowledgeObject, TrustClass

_TOKEN_RE = re.compile(r"[\w\u0600-\u06ff]+", re.UNICODE)


@dataclass(frozen=True)
class KnowledgeQuery:
    text: str = ""
    actor: str | None = None
    campaign: str | None = None
    technique: str | None = None
    cve: str | None = None
    cwe: str | None = None
    capec: str | None = None
    malware: str | None = None
    trust_class: TrustClass | None = None
    claim_type: str | None = None
    attribution_status: str | None = None
    source: str | None = None
    date: str | None = None
    content_role: str | None = None
    kind: KnowledgeKind | None = None
    limit: int = 20

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError("query limit must be positive")

    @classmethod
    def from_value(cls, value: "KnowledgeQuery | str", **kwargs) -> "KnowledgeQuery":
        if isinstance(value, cls):
            meaningful = {key: item for key, item in kwargs.items() if not (key == "kind" and item is None) and not (key == "limit" and item == 20)}
            if meaningful:
                raise ValueError("query kwargs cannot accompany a KnowledgeQuery")
            return value
        return cls(text=str(value), **kwargs)


@dataclass(frozen=True)
class RetrievalHit:
    object_id: str
    score: float
    kind: KnowledgeKind
    exact_source: bool
    trust_class: str
    provenance: dict


class Retriever(Protocol):
    def search(self, query: KnowledgeQuery | str, *, kind: KnowledgeKind | None = None, limit: int = 20, **filters) -> list[RetrievalHit]: ...


def _metadata_value(obj: KnowledgeObject, key: str):
    metadata = obj.metadata or {}
    if key in metadata:
        return metadata[key]
    for container in ("corpus", "provenance", "ingestion_manifest"):
        nested = metadata.get(container)
        if isinstance(nested, dict) and key in nested:
            return nested[key]
    return None


def _matches(obj: KnowledgeObject, query: KnowledgeQuery) -> bool:
    if query.kind is not None and obj.kind is not query.kind:
        return False
    if query.trust_class is not None and obj.trust_class is not query.trust_class:
        return False
    mapping = {
        "actor": "actor_id", "campaign": "campaign_id", "technique": "technique",
        "cve": "cve", "cwe": "cwe", "capec": "capec", "malware": "malware",
        "claim_type": "claim_type", "attribution_status": "attribution_status",
        "source": "source_id", "date": "date", "content_role": "content_role",
    }
    for field, key in mapping.items():
        expected = getattr(query, field)
        if expected is not None:
            actual = _metadata_value(obj, key)
            values = actual if isinstance(actual, (list, tuple, set)) else (actual,)
            if not any(str(expected).casefold() == str(value).casefold() or str(expected).casefold() in str(value).casefold() for value in values if value is not None):
                return False
    return True


def _hit(obj: KnowledgeObject, score: float) -> RetrievalHit:
    return RetrievalHit(
        obj.object_id, float(score), obj.kind, obj.is_exact_source, obj.trust_class.value,
        {"source_id": obj.source_id, "source_url": obj.source_url, "content_hash": obj.content_hash, "metadata": dict(obj.metadata)},
    )


class LexicalRetriever:
    """Explicit substring/term-presence retriever; not BM25."""
    def __init__(self, objects: Iterable[KnowledgeObject] = ()):
        self.objects = tuple(objects)

    def search(self, query: KnowledgeQuery | str, *, kind: KnowledgeKind | None = None, limit: int = 20, **filters) -> list[RetrievalHit]:
        q = KnowledgeQuery.from_value(query, kind=kind, limit=limit, **filters)
        needle = q.text.casefold()
        hits = [_hit(obj, 1.0) for obj in self.objects if _matches(obj, q) and (not needle or needle in (obj.title + " " + obj.content).casefold())]
        return hits[: q.limit]


class BM25Retriever:
    """In-memory BM25 implementation with metadata filtering and provenance."""
    def __init__(self, objects: Iterable[KnowledgeObject] = (), *, k1: float = 1.5, b: float = 0.75):
        self.objects = tuple(objects)
        self.k1 = k1
        self.b = b

    def search(self, query: KnowledgeQuery | str, *, kind: KnowledgeKind | None = None, limit: int = 20, **filters) -> list[RetrievalHit]:
        q = KnowledgeQuery.from_value(query, kind=kind, limit=limit, **filters)
        candidates = [obj for obj in self.objects if _matches(obj, q)]
        terms = _TOKEN_RE.findall(q.text.casefold())
        if not terms:
            return [_hit(obj, 0.0) for obj in candidates[: q.limit]]
        tokenized = [_TOKEN_RE.findall((obj.title + " " + obj.content).casefold()) for obj in candidates]
        avgdl = sum(len(tokens) for tokens in tokenized) / max(len(tokenized), 1)
        document_frequency = Counter(term for tokens in tokenized for term in set(tokens))
        scored: list[tuple[float, KnowledgeObject]] = []
        for obj, tokens in zip(candidates, tokenized):
            counts = Counter(tokens)
            dl = len(tokens)
            score = 0.0
            for term in terms:
                if not counts[term]:
                    continue
                df = document_frequency[term]
                idf = math.log(1.0 + (len(candidates) - df + 0.5) / (df + 0.5))
                tf = counts[term]
                score += idf * (tf * (self.k1 + 1)) / (tf + self.k1 * (1 - self.b + self.b * dl / max(avgdl, 1)))
            if score > 0:
                scored.append((score, obj))
        scored.sort(key=lambda pair: (-pair[0], pair[1].object_id))
        return [_hit(obj, score) for score, obj in scored[: q.limit]]


class MetadataRetriever:
    """Metadata-only filter; it never infers authority or execution permission."""
    def __init__(self, objects: Iterable[KnowledgeObject] = ()):
        self.objects = tuple(objects)

    def search(self, query: KnowledgeQuery | str = "", *, kind: KnowledgeKind | None = None, limit: int = 20, **filters) -> list[RetrievalHit]:
        q = KnowledgeQuery.from_value(query, kind=kind, limit=limit, **filters)
        return [_hit(obj, 1.0) for obj in self.objects if _matches(obj, q)][: q.limit]


class VectorRetriever:
    """Interface only: no vector backend is installed in Knowledge Foundation."""
    status = "NOT_IMPLEMENTED"

    def search(self, query: KnowledgeQuery | str, *, kind: KnowledgeKind | None = None, limit: int = 20, **filters) -> list[RetrievalHit]:
        raise NotImplementedError("vector index is not installed in Knowledge Foundation")


class HybridRetriever:
    """Deterministic fusion of BM25, exact lexical, and metadata retrieval.

    This deliberately does not pretend to be a vector index. Each component keeps
    its provenance and the fused score is only a ranking signal, never authority.
    """
    status = "READY"

    def __init__(self, objects: Iterable[KnowledgeObject] = (), *, bm25_weight: float = 0.65, lexical_weight: float = 0.25, metadata_weight: float = 0.10):
        self.objects = tuple(objects)
        self.bm25_weight = float(bm25_weight)
        self.lexical_weight = float(lexical_weight)
        self.metadata_weight = float(metadata_weight)

    def search(self, query: KnowledgeQuery | str, *, kind: KnowledgeKind | None = None, limit: int = 20, **filters) -> list[RetrievalHit]:
        q = KnowledgeQuery.from_value(query, kind=kind, limit=limit, **filters)
        bm25 = {item.object_id: item for item in BM25Retriever(self.objects).search(q)}
        lexical = {item.object_id: item for item in LexicalRetriever(self.objects).search(q)}
        metadata = {item.object_id: item for item in MetadataRetriever(self.objects).search(q)}
        objects = {item.object_id: item for item in self.objects}
        ranked: list[RetrievalHit] = []
        for object_id, obj in objects.items():
            if object_id not in bm25 and object_id not in lexical and object_id not in metadata:
                continue
            score = self.bm25_weight * bm25.get(object_id, RetrievalHit(object_id, 0.0, obj.kind, obj.is_exact_source, obj.trust_class.value, {})).score
            score += self.lexical_weight * (1.0 if object_id in lexical else 0.0)
            score += self.metadata_weight * (1.0 if object_id in metadata else 0.0)
            ranked.append(_hit(obj, score))
        ranked.sort(key=lambda item: (-item.score, item.object_id))
        return ranked[:q.limit]


__all__ = ["KnowledgeQuery", "RetrievalHit", "Retriever", "LexicalRetriever", "BM25Retriever", "MetadataRetriever", "VectorRetriever", "HybridRetriever"]
