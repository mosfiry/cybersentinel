from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Any

from security.scope import ProgramAuthorization


@dataclass(frozen=True)
class ExternalProgramData:
    platform: str
    program_id: str
    raw: dict[str, Any]
    retrieved_at: str
    source_url: str = ""
    trust_classification: str = "untrusted_data"
    raw_hash: str = ""

    def __post_init__(self) -> None:
        if not self.raw_hash:
            object.__setattr__(self, "raw_hash", sha256(json.dumps(self.raw, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest())


@dataclass(frozen=True)
class NormalizedProgram:
    platform: str
    program_id: str
    name: str
    scope_version: str
    in_scope_assets: tuple[dict[str, Any], ...]
    out_of_scope_assets: tuple[dict[str, Any], ...]
    allowed_methods: tuple[str, ...]
    prohibited_methods: tuple[str, ...]
    rate_limits: dict[str, int]
    testing_window: dict[str, Any]
    disclosure_policy: dict[str, Any]
    provenance: dict[str, Any]
    source_data: ExternalProgramData

    def to_authorization_candidate(self, *, owner_session_id: str = "") -> ProgramAuthorization:
        return ProgramAuthorization(
            program_id=self.program_id,
            platform=self.platform,
            scope_version=self.scope_version,
            retrieved_at=self.source_data.retrieved_at,
            in_scope_assets=self.in_scope_assets,
            out_of_scope_assets=self.out_of_scope_assets,
            allowed_methods=self.allowed_methods,
            prohibited_methods=self.prohibited_methods,
            rate_limits=self.rate_limits,
            testing_window=self.testing_window,
            disclosure_policy=self.disclosure_policy,
            owner_session_id=owner_session_id,
            source=self.source_data.source_url or self.platform,
        )


@dataclass(frozen=True)
class ProgramCandidate:
    normalized: NormalizedProgram
    approved: bool = False
    approval_required: bool = True

    def public(self) -> dict[str, Any]:
        return {
            "platform": self.normalized.platform,
            "program_id": self.normalized.program_id,
            "name": self.normalized.name,
            "scope_version": self.normalized.scope_version,
            "in_scope_assets": list(self.normalized.in_scope_assets),
            "out_of_scope_assets": list(self.normalized.out_of_scope_assets),
            "allowed_methods": list(self.normalized.allowed_methods),
            "prohibited_methods": list(self.normalized.prohibited_methods),
            "rate_limits": self.normalized.rate_limits,
            "provenance": self.normalized.provenance,
            "trust_classification": self.normalized.source_data.trust_classification,
            "raw_hash": self.normalized.source_data.raw_hash,
            "approved": self.approved,
            "approval_required": self.approval_required,
        }
