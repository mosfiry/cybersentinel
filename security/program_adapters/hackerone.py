from __future__ import annotations

from .base import ProgramAdapter, as_assets, first, methods
from .models import ExternalProgramData, NormalizedProgram


class HackerOneAdapter(ProgramAdapter):
    platform = "hackerone"

    def normalize_program(self, data: ExternalProgramData) -> NormalizedProgram:
        raw = data.raw
        attributes = raw.get("attributes") if isinstance(raw.get("attributes"), dict) else raw
        relationships = raw.get("relationships") if isinstance(raw.get("relationships"), dict) else {}
        scope = first(attributes, "scope", "structured_scope", "targets", default=relationships.get("structured_scopes", []))
        in_scope = as_assets(scope)
        out_scope = as_assets(first(attributes, "out_of_scope", "excluded_assets", default=[]))
        allowed, prohibited = methods(attributes)
        scope_version = str(first(attributes, "scope_version", "updated_at", default=data.raw_hash[:16]))
        name = str(first(attributes, "name", "title", "handle", default=data.program_id))
        rate_limits = first(attributes, "rate_limits", default={})
        if not isinstance(rate_limits, dict):
            rate_limits = {}
        disclosure = first(attributes, "disclosure_policy", "disclosure", default={})
        if not isinstance(disclosure, dict):
            disclosure = {}
        return NormalizedProgram(
            platform=self.platform,
            program_id=data.program_id,
            name=name,
            scope_version=scope_version,
            in_scope_assets=in_scope,
            out_of_scope_assets=out_scope,
            allowed_methods=allowed,
            prohibited_methods=prohibited,
            rate_limits=rate_limits,
            testing_window=first(attributes, "testing_window", default={}) if isinstance(first(attributes, "testing_window", default={}), dict) else {},
            disclosure_policy=disclosure,
            provenance={"platform": self.platform, "source_url": data.source_url, "raw_hash": data.raw_hash, "fields": {"attributes": "external_data", "relationships": "external_data"}},
            source_data=data,
        )
