from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
from typing import Any, Mapping

from . import store
from .foundation import (
    IntegrityError,
    KnowledgeError,
    KnowledgeKind,
    KnowledgeObject,
    TransformationPolicy,
    TrustClass,
)


@dataclass(frozen=True)
class IngestionManifest:
    """Owner-supplied metadata required before a source can enter the store."""

    source_id: str
    source_url: str
    edition: str
    author: str
    language: str
    retrieved_at: str
    license: str
    expected_hash: str
    trust_class: TrustClass
    transformation_policy: TransformationPolicy

    def __post_init__(self) -> None:
        required = {
            "source_id": self.source_id,
            "source_url": self.source_url,
            "edition": self.edition,
            "author": self.author,
            "language": self.language,
            "retrieved_at": self.retrieved_at,
            "license": self.license,
            "expected_hash": self.expected_hash,
        }
        missing = [name for name, value in required.items() if not isinstance(value, str) or not value.strip()]
        if missing:
            raise KnowledgeError(f"manifest fields are required: {', '.join(missing)}")
        if len(self.expected_hash) != 64 or any(char not in "0123456789abcdefABCDEF" for char in self.expected_hash):
            raise KnowledgeError("expected_hash must be a SHA-256 hexadecimal digest")
        if not isinstance(self.trust_class, TrustClass):
            raise KnowledgeError("trust_class must be a TrustClass")
        if not isinstance(self.transformation_policy, TransformationPolicy):
            raise KnowledgeError("transformation_policy must be a TransformationPolicy")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "IngestionManifest":
        try:
            values = dict(data)
            values["trust_class"] = TrustClass(values["trust_class"])
            values["transformation_policy"] = TransformationPolicy(values["transformation_policy"])
            return cls(**values)
        except KeyError as exc:
            raise KnowledgeError(f"manifest field is missing: {exc.args[0]}") from exc
        except ValueError as exc:
            raise KnowledgeError(str(exc)) from exc

    def as_metadata(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "source_url": self.source_url,
            "edition": self.edition,
            "author": self.author,
            "language": self.language,
            "retrieved_at": self.retrieved_at,
            "license": self.license,
            "expected_hash": self.expected_hash.lower(),
            "trust_class": self.trust_class.value,
            "transformation_policy": self.transformation_policy.value,
        }


def ingest_bytes(
    *,
    object_id: str,
    kind: KnowledgeKind,
    title: str,
    manifest: IngestionManifest,
    payload: bytes,
    destination=store,
) -> KnowledgeObject:
    """Validate and append a source without normalizing or silently rewriting it."""

    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes so hashing precedes decoding")
    actual_hash = hashlib.sha256(payload).hexdigest()
    if actual_hash != manifest.expected_hash.lower():
        raise IntegrityError("source bytes do not match manifest expected_hash")
    try:
        content = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise IntegrityError("source is not valid UTF-8; no lossy decoding is allowed") from exc

    obj = KnowledgeObject.create(
        object_id=object_id,
        kind=kind,
        title=title,
        language=manifest.language,
        source_id=manifest.source_id,
        source_url=manifest.source_url,
        edition=manifest.edition,
        author=manifest.author,
        trust_class=manifest.trust_class,
        transformation_policy=manifest.transformation_policy,
        content=content,
        metadata={"ingestion_manifest": manifest.as_metadata(), "raw_sha256": actual_hash},
    )
    if obj.content_hash != actual_hash:
        raise IntegrityError("decoded content hash differs from source byte hash")
    destination.add(obj)
    return obj


def ingest_file(
    *,
    object_id: str,
    kind: KnowledgeKind,
    title: str,
    manifest: IngestionManifest,
    path: str | Path,
    destination=store,
) -> KnowledgeObject:
    """Read a file as raw bytes and delegate to the hash-first ingestion path."""

    payload = Path(path).read_bytes()
    return ingest_bytes(
        object_id=object_id,
        kind=kind,
        title=title,
        manifest=manifest,
        payload=payload,
        destination=destination,
    )


__all__ = ["IngestionManifest", "ingest_bytes", "ingest_file"]
