from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any


class KnowledgeKind(str, Enum):
    IMMUTABLE_RELIGIOUS = "IMMUTABLE_RELIGIOUS"
    INTERPRETATION = "INTERPRETATION"
    GENERAL = "GENERAL"
    CYBER = "CYBER"
    OSINT = "OSINT"
    LAB = "LAB"


class TrustClass(str, Enum):
    PRIMARY_SOURCE = "PRIMARY_SOURCE"
    CURATED_SOURCE = "CURATED_SOURCE"
    REFERENCE = "REFERENCE"
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"


class TransformationPolicy(str, Enum):
    EXACT_ONLY = "EXACT_ONLY"
    DERIVED_ALLOWED = "DERIVED_ALLOWED"
    RETRIEVAL_ALLOWED = "RETRIEVAL_ALLOWED"


class KnowledgeError(ValueError):
    pass


class IntegrityError(KnowledgeError):
    pass


@dataclass(frozen=True)
class KnowledgeObject:
    object_id: str
    kind: KnowledgeKind
    title: str
    language: str
    source_id: str
    source_url: str
    edition: str
    author: str
    trust_class: TrustClass
    transformation_policy: TransformationPolicy
    content: str
    content_hash: str
    created_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def exact_hash(content: str) -> str:
        if not isinstance(content, str):
            raise TypeError("content must be str so exact UTF-8 text is explicit")
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @classmethod
    def create(cls, *, object_id: str, kind: KnowledgeKind, title: str, language: str, source_id: str,
               source_url: str = "", edition: str = "", author: str = "", trust_class: TrustClass,
               transformation_policy: TransformationPolicy, content: str, metadata: dict[str, Any] | None = None,
               created_at: str | None = None) -> "KnowledgeObject":
        if kind is KnowledgeKind.IMMUTABLE_RELIGIOUS and transformation_policy is not TransformationPolicy.EXACT_ONLY:
            raise KnowledgeError("immutable religious sources require EXACT_ONLY")
        if kind is KnowledgeKind.IMMUTABLE_RELIGIOUS and trust_class is TrustClass.UNTRUSTED_EXTERNAL:
            raise KnowledgeError("immutable religious exact sources cannot be untrusted external")
        if source_id.startswith("external:") and trust_class is not TrustClass.UNTRUSTED_EXTERNAL:
            raise KnowledgeError("external provenance cannot self-elevate trust")
        if not object_id or not title or not language or not source_id:
            raise KnowledgeError("object_id, title, language, and source_id are required")
        if not isinstance(content, str):
            raise TypeError("content must be str")
        return cls(object_id, kind, title, language, source_id, source_url, edition, author,
                   trust_class, transformation_policy, content, cls.exact_hash(content),
                   created_at or datetime.now(timezone.utc).isoformat(), metadata or {})

    def verify_integrity(self) -> bool:
        actual = self.exact_hash(self.content)
        if actual != self.content_hash:
            raise IntegrityError("content hash mismatch; exact source is untrusted")
        return True

    @property
    def is_exact_source(self) -> bool:
        return self.kind is KnowledgeKind.IMMUTABLE_RELIGIOUS and self.transformation_policy is TransformationPolicy.EXACT_ONLY

    @property
    def authority(self) -> None:
        return None

    def to_record(self) -> dict[str, Any]:
        self.verify_integrity()
        return {
            "object_id": self.object_id, "kind": self.kind.value, "title": self.title,
            "language": self.language, "source_id": self.source_id, "source_url": self.source_url,
            "edition": self.edition, "author": self.author, "trust_class": self.trust_class.value,
            "transformation_policy": self.transformation_policy.value, "content": self.content,
            "content_hash": self.content_hash, "created_at": self.created_at, "metadata": dict(self.metadata),
        }

    @classmethod
    def from_record(cls, row: dict[str, Any]) -> "KnowledgeObject":
        import json
        obj = cls(object_id=row["object_id"], kind=KnowledgeKind(row["kind"]), title=row["title"],
                  language=row["language"], source_id=row["source_id"], source_url=row["source_url"],
                  edition=row["edition"], author=row["author"], trust_class=TrustClass(row["trust_class"]),
                  transformation_policy=TransformationPolicy(row["transformation_policy"]), content=row["content"],
                  content_hash=row["content_hash"], created_at=row["created_at"],
                  metadata=json.loads(row.get("metadata_json", "{}")))
        obj.verify_integrity()
        return obj


class CyberLevel(int, Enum):
    FUNDAMENTALS = 0
    NETWORKING = 1
    LINUX = 2
    WINDOWS = 3
    WEB_SECURITY = 4
    APPLICATION_SECURITY = 5
    CLOUD_SECURITY = 6
    IDENTITY_AUTHENTICATION = 7
    CRYPTOGRAPHY = 8
    VULNERABILITY_RESEARCH = 9
    DETECTION_ENGINEERING = 10
    SOC = 11
    INCIDENT_RESPONSE = 12
    THREAT_INTELLIGENCE = 13
    OSINT = 14
    ADVANCED_SECURITY_RESEARCH = 15


@dataclass(frozen=True)
class CyberKnowledge:
    concept: str
    domain: str
    level: CyberLevel
    definition: str
    prerequisites: tuple[str, ...] = ()
    mechanism: str = ""
    examples: tuple[str, ...] = ()
    counterexamples: tuple[str, ...] = ()
    attack_perspective: str = ""
    defense_perspective: str = ""
    detection: str = ""
    evidence_requirements: tuple[str, ...] = ()
    counter_evidence: tuple[str, ...] = ()
    alternative_explanations: tuple[str, ...] = ()
    common_mistakes: tuple[str, ...] = ()
    false_positives: tuple[str, ...] = ()
    false_negatives: tuple[str, ...] = ()
    how: str = ""
    why: str = ""
    when: str = ""
    why_not: str = ""
    cwe: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    capec: tuple[str, ...] = ()
    mitre_attack: tuple[str, ...] = ()
    malware: tuple[str, ...] = ()
    campaigns: tuple[str, ...] = ()
    labs: tuple[str, ...] = ()
    mitigations: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def __post_init__(self):
        if not self.concept or not self.definition or not self.domain:
            raise KnowledgeError("cyber concept, domain, and definition are required")
        if not isinstance(self.level, CyberLevel):
            raise KnowledgeError("level must be a CyberLevel")

    def to_dict(self) -> dict[str, Any]:
        return {key: (value.value if isinstance(value, Enum) else list(value) if isinstance(value, tuple) else value)
                for key, value in self.__dict__.items()}


@dataclass(frozen=True)
class LabReference:
    lab_id: str
    kind: str
    title: str
    authorized_only: bool = True
    execution_permission: bool = False

    def __post_init__(self):
        if self.kind not in {"LAB", "SAFE_POC", "VULNERABILITY_CASE", "DETECTION_CASE"}:
            raise KnowledgeError("unsupported lab reference kind")
        if not self.authorized_only or self.execution_permission:
            raise KnowledgeError("knowledge references never grant execution permission")
