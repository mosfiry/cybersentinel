from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from hashlib import sha256
import json
from typing import Any, Iterable, Mapping

from .foundation import KnowledgeError, TrustClass

UNKNOWN = "UNKNOWN"


class ClaimType(str, Enum):
    OBSERVED = "OBSERVED"
    REPORTED = "REPORTED"
    ASSESSED = "ASSESSED"
    INFERRED = "INFERRED"
    DISPUTED = "DISPUTED"


class AttributionStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    MODERATE_CONFIDENCE = "MODERATE_CONFIDENCE"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    DISPUTED = "DISPUTED"
    UNKNOWN = "UNKNOWN"


class DatasetSplit(str, Enum):
    TRAINING = "TRAINING"
    EVALUATION = "EVALUATION"


class ContentRole(str, Enum):
    RAW_SOURCE = "RAW_SOURCE"
    NORMALIZED_FACT = "NORMALIZED_FACT"
    ANALYTIC_CASE = "ANALYTIC_CASE"
    UNTRUSTED_ATTACK_DATA = "UNTRUSTED_ATTACK_DATA"
    TRAINING_EXAMPLE = "TRAINING_EXAMPLE"
    EVALUATION_EXAMPLE = "EVALUATION_EXAMPLE"


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    url: str
    title: str
    publisher: str
    trust_class: TrustClass
    license: str = "UNKNOWN"
    terms: str = "UNKNOWN"
    redistribution_allowed: bool = False
    storage_policy: str = "METADATA_AND_SHORT_EXCERPTS_ONLY"
    publication_date: str = UNKNOWN
    retrieved_at: str = UNKNOWN
    source_hash: str = ""
    hash_basis: str = "LOCATOR_METADATA_NOT_DOCUMENT_BYTES"

    def __post_init__(self) -> None:
        if not self.source_id or not self.url or not self.title or not self.publisher:
            raise KnowledgeError("source_id, url, title, and publisher are required")
        if not self.source_hash:
            digest = sha256(f"{self.source_id}|{self.url}|{self.title}".encode()).hexdigest()
            object.__setattr__(self, "source_hash", digest)
        if self.storage_policy == "FULL_RAW_COPY" and not self.redistribution_allowed:
            raise KnowledgeError("full raw source storage requires redistribution permission")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SourceRecord":
        values = dict(data)
        values["trust_class"] = TrustClass(values["trust_class"])
        return cls(**values)


@dataclass(frozen=True)
class EvidenceClaim:
    claim_id: str
    subject_id: str
    field: str
    value: str
    source_id: str
    source_hash: str
    source_location: str = UNKNOWN
    confidence: float = 0.0
    claim_type: ClaimType = ClaimType.REPORTED
    attribution_status: AttributionStatus = AttributionStatus.UNKNOWN

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.strip() for value in (self.claim_id, self.subject_id, self.field, self.value, self.source_id, self.source_hash)):
            raise KnowledgeError("claim identity, value, source, and source_hash are required")
        if not 0.0 <= self.confidence <= 1.0:
            raise KnowledgeError("claim confidence must be between 0 and 1")
        if not isinstance(self.claim_type, ClaimType) or not isinstance(self.attribution_status, AttributionStatus):
            raise KnowledgeError("claim_type and attribution_status must use their enums")
        if self.claim_type is ClaimType.INFERRED and self.attribution_status is AttributionStatus.CONFIRMED:
            raise KnowledgeError("inferred claims cannot be confirmed attribution")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceClaim":
        values = dict(data)
        values["claim_type"] = ClaimType(values.get("claim_type", ClaimType.REPORTED))
        values["attribution_status"] = AttributionStatus(values.get("attribution_status", AttributionStatus.UNKNOWN))
        return cls(**values)


@dataclass(frozen=True)
class TechniqueMapping:
    technique_id: str
    tactic: str = UNKNOWN
    technique_name: str = UNKNOWN
    subtechnique_id: str = UNKNOWN
    source_claim_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.technique_id.startswith("T"):
            raise KnowledgeError("ATT&CK mapping must use an original technique ID")
        if not self.source_claim_ids:
            raise KnowledgeError("ATT&CK mapping requires source claim IDs")


@dataclass(frozen=True)
class ThreatActorProfile:
    actor_id: str
    name: str
    aliases: tuple[str, ...] = ()
    attribution_status: AttributionStatus = AttributionStatus.UNKNOWN
    attribution_source_claim_ids: tuple[str, ...] = ()
    coverage_status: str = "PARTIAL_PUBLIC_COVERAGE"

    def __post_init__(self) -> None:
        if not self.actor_id or not self.name:
            raise KnowledgeError("actor_id and name are required")
        if self.attribution_status is not AttributionStatus.UNKNOWN and not self.attribution_source_claim_ids:
            raise KnowledgeError("non-unknown actor attribution requires source claim IDs")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ThreatActorProfile":
        values = dict(data)
        values["aliases"] = tuple(values.get("aliases", ()))
        values["attribution_status"] = AttributionStatus(values.get("attribution_status", AttributionStatus.UNKNOWN))
        values["attribution_source_claim_ids"] = tuple(values.get("attribution_source_claim_ids", ()))
        return cls(**values)


@dataclass(frozen=True)
class CampaignCase:
    campaign_id: str
    actor_id: str
    name: str
    aliases: tuple[str, ...] = ()
    first_seen: str = UNKNOWN
    last_seen: str = UNKNOWN
    target: tuple[str, ...] = ()
    geography: tuple[str, ...] = ()
    sector: tuple[str, ...] = ()
    objective: str = UNKNOWN
    initial_access: str = UNKNOWN
    execution: str = UNKNOWN
    persistence: str = UNKNOWN
    privilege_escalation: str = UNKNOWN
    defense_evasion: str = UNKNOWN
    credential_access: str = UNKNOWN
    discovery: str = UNKNOWN
    lateral_movement: str = UNKNOWN
    collection: str = UNKNOWN
    command_and_control: str = UNKNOWN
    exfiltration: str = UNKNOWN
    impact: str = UNKNOWN
    malware: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    vulnerabilities: tuple[str, ...] = ()
    exploitation_concept: str = UNKNOWN
    techniques: tuple[TechniqueMapping, ...] = ()
    detection: tuple[str, ...] = ()
    forensics: tuple[str, ...] = ()
    mitigations: tuple[str, ...] = ()
    evidence_claim_ids: tuple[str, ...] = ()
    counter_evidence: tuple[str, ...] = ()
    alternative_hypotheses: tuple[str, ...] = ()
    attribution_status: AttributionStatus = AttributionStatus.UNKNOWN
    attribution_source_claim_ids: tuple[str, ...] = ()
    coverage_status: str = "PARTIAL_PUBLIC_COVERAGE"

    def __post_init__(self) -> None:
        if not self.campaign_id or not self.actor_id or not self.name:
            raise KnowledgeError("campaign_id, actor_id, and name are required")
        if self.attribution_status is not AttributionStatus.UNKNOWN and not self.attribution_source_claim_ids:
            raise KnowledgeError("non-unknown attribution requires source claim IDs")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CampaignCase":
        values = dict(data)
        values["techniques"] = tuple(TechniqueMapping(**item) for item in values.get("techniques", ()))
        for key in ("aliases", "target", "geography", "sector", "malware", "tools", "vulnerabilities", "detection", "forensics", "mitigations", "evidence_claim_ids", "counter_evidence", "alternative_hypotheses", "attribution_source_claim_ids"):
            values[key] = tuple(values.get(key, ()))
        values["attribution_status"] = AttributionStatus(values.get("attribution_status", AttributionStatus.UNKNOWN))
        return cls(**values)


@dataclass(frozen=True)
class PoCKnowledge:
    poc_id: str
    source: str
    vulnerability: str
    affected_component: str
    description: str
    expected_observation: str
    detection: str = UNKNOWN
    mitigation: str = UNKNOWN
    references: tuple[str, ...] = ()
    lab_only: bool = True
    authorized_only: bool = True
    execution_permission: bool = False
    risk_class: str = "LAB_ONLY"

    def __post_init__(self) -> None:
        if not self.lab_only or not self.authorized_only or self.execution_permission:
            raise KnowledgeError("PoC knowledge is lab-only, authorized-only, and never executable")


@dataclass(frozen=True)
class PromptInjectionCase:
    case_id: str
    attack_text_exact: str
    language: str
    encoding: str
    attack_class: str
    attack_vector: str
    target_behavior: str
    expected_failure: str
    expected_defense: str
    source_id: str
    provenance: str
    split: DatasetSplit
    content_role: ContentRole = ContentRole.UNTRUSTED_ATTACK_DATA

    def __post_init__(self) -> None:
        if self.content_role is not ContentRole.UNTRUSTED_ATTACK_DATA:
            raise KnowledgeError("prompt injection text must remain UNTRUSTED_ATTACK_DATA")
        if not self.attack_text_exact:
            raise KnowledgeError("exact attack text is required")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PromptInjectionCase":
        values = dict(data)
        values["split"] = DatasetSplit(values["split"])
        values["content_role"] = ContentRole(values.get("content_role", ContentRole.UNTRUSTED_ATTACK_DATA))
        return cls(**values)


@dataclass(frozen=True)
class AdversarialCase:
    case_id: str
    attack: str
    context: str
    expected_model_behavior: tuple[str, ...]
    expected_tool_behavior: tuple[str, ...]
    expected_authorization: tuple[str, ...]
    expected_scope: tuple[str, ...]
    expected_evidence: tuple[str, ...]
    expected_defense: tuple[str, ...]
    split: DatasetSplit
    attack_class: str
    content_role: ContentRole = ContentRole.UNTRUSTED_ATTACK_DATA

    def __post_init__(self) -> None:
        if self.content_role is not ContentRole.UNTRUSTED_ATTACK_DATA:
            raise KnowledgeError("adversarial inputs remain untrusted data")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AdversarialCase":
        values = dict(data)
        values["split"] = DatasetSplit(values["split"])
        values["content_role"] = ContentRole(values.get("content_role", ContentRole.UNTRUSTED_ATTACK_DATA))
        for key in ("expected_model_behavior", "expected_tool_behavior", "expected_authorization", "expected_scope", "expected_evidence", "expected_defense"):
            values[key] = tuple(values.get(key, ()))
        return cls(**values)


@dataclass(frozen=True)
class DatasetManifest:
    dataset_id: str
    version: str
    created_at: str
    source_count: int
    object_count: int
    coverage: str
    license_summary: str
    schema_version: str
    ingestion_version: str
    hash: str = ""

    def __post_init__(self) -> None:
        if self.source_count < 0 or self.object_count < 0:
            raise KnowledgeError("manifest counts cannot be negative")
        if not self.hash:
            payload = {key: value for key, value in asdict(self).items() if key != "hash"}
            digest = sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
            object.__setattr__(self, "hash", digest)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def verify_integrity(self) -> bool:
        payload = {key: value for key, value in asdict(self).items() if key != "hash"}
        expected = sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        if expected != self.hash:
            raise KnowledgeError("dataset manifest hash mismatch")
        return True


@dataclass(frozen=True)
class CorpusDataset:
    manifest: DatasetManifest
    sources: tuple[SourceRecord, ...]
    claims: tuple[EvidenceClaim, ...]
    actors: tuple[ThreatActorProfile, ...]
    campaigns: tuple[CampaignCase, ...]
    prompt_injections: tuple[PromptInjectionCase, ...] = ()
    adversarial_cases: tuple[AdversarialCase, ...] = ()
    poc_references: tuple[PoCKnowledge, ...] = ()

    def validate(self) -> None:
        source_ids = {source.source_id for source in self.sources}
        claim_ids = {claim.claim_id for claim in self.claims}
        actor_ids = {actor.actor_id for actor in self.actors}
        if len(source_ids) != len(self.sources) or len(claim_ids) != len(self.claims):
            raise KnowledgeError("source and claim IDs must be unique")
        if len(actor_ids) != len(self.actors):
            raise KnowledgeError("actor IDs must be unique")
        for claim in self.claims:
            if claim.source_id not in source_ids:
                raise KnowledgeError(f"claim {claim.claim_id} references unknown source")
        for campaign in self.campaigns:
            if campaign.actor_id not in actor_ids:
                raise KnowledgeError(f"campaign {campaign.campaign_id} references unknown actor")
            if any(claim_id not in claim_ids for claim_id in campaign.evidence_claim_ids + campaign.attribution_source_claim_ids):
                raise KnowledgeError(f"campaign {campaign.campaign_id} references unknown claim")
            for mapping in campaign.techniques:
                if any(claim_id not in claim_ids for claim_id in mapping.source_claim_ids):
                    raise KnowledgeError(f"technique {mapping.technique_id} references unknown claim")
        prompt_ids = {case.case_id for case in self.prompt_injections}
        eval_ids = {case.case_id for case in self.prompt_injections if case.split is DatasetSplit.EVALUATION}
        if len(prompt_ids) != len(self.prompt_injections):
            raise KnowledgeError("prompt injection case IDs must be unique")
        if eval_ids & (prompt_ids - eval_ids):
            raise KnowledgeError("evaluation and training prompt IDs overlap")
        if self.manifest.source_count != len(self.sources) or self.manifest.object_count != len(self.actors) + len(self.claims) + len(self.campaigns) + len(self.prompt_injections) + len(self.adversarial_cases) + len(self.poc_references):
            raise KnowledgeError("dataset manifest counts do not match corpus objects")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CorpusDataset":
        dataset = cls(
            manifest=DatasetManifest(**data["manifest"]),
            sources=tuple(SourceRecord.from_dict(item) for item in data.get("sources", ())),
            claims=tuple(EvidenceClaim.from_dict(item) for item in data.get("claims", ())),
            actors=tuple(ThreatActorProfile.from_dict(item) for item in data.get("actors", ())),
            campaigns=tuple(CampaignCase.from_dict(item) for item in data.get("campaigns", ())),
            prompt_injections=tuple(PromptInjectionCase.from_dict(item) for item in data.get("prompt_injections", ())),
            adversarial_cases=tuple(AdversarialCase.from_dict(item) for item in data.get("adversarial_cases", ())),
            poc_references=tuple(PoCKnowledge(**item) for item in data.get("poc_references", ())),
        )
        dataset.manifest.verify_integrity()
        dataset.validate()
        return dataset


__all__ = ["UNKNOWN", "ClaimType", "AttributionStatus", "DatasetSplit", "ContentRole", "SourceRecord", "EvidenceClaim", "TechniqueMapping", "ThreatActorProfile", "CampaignCase", "PoCKnowledge", "PromptInjectionCase", "AdversarialCase", "DatasetManifest", "CorpusDataset"]
