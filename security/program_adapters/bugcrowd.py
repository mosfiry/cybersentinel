from __future__ import annotations

from typing import Any

from .base import ProgramAdapter, as_assets, first, methods
from .models import ExternalProgramData, NormalizedProgram


class BugcrowdAdapter(ProgramAdapter):
    platform = "bugcrowd"

    def normalize_program(self, data: ExternalProgramData) -> NormalizedProgram:
        raw = data.raw
        program = raw.get("program") if isinstance(raw.get("program"), dict) else raw
        brief = first(program, "current_brief", "brief", "policy", default={})
        if not isinstance(brief, dict):
            brief = {}
        groups = first(raw, "target_groups", "targetGroups", default=[])
        targets = first(raw, "targets", "target_groups", "targetGroups", default=groups)
        in_scope = as_assets(first(brief, "in_scope", "in_scope_assets", "targets", default=targets))
        out_scope = as_assets(first(brief, "out_of_scope", "out_of_scope_assets", "excluded", default=[]))
        allowed, prohibited = methods({**program, "rules": first(program, "rules", "policy", default=brief)})
        scope_version = str(first(brief, "version", "updated_at", default=data.raw_hash[:16]))
        name = str(first(program, "name", "title", "program_name", default=data.program_id))
        return NormalizedProgram(
            platform=self.platform,
            program_id=data.program_id,
            name=name,
            scope_version=scope_version,
            in_scope_assets=in_scope,
            out_of_scope_assets=out_scope,
            allowed_methods=allowed,
            prohibited_methods=prohibited,
            rate_limits=first(brief, "rate_limits", default={}) if isinstance(first(brief, "rate_limits", default={}), dict) else {},
            testing_window=first(brief, "testing_window", "testing_hours", default={}) if isinstance(first(brief, "testing_window", "testing_hours", default={}), dict) else {},
            disclosure_policy=first(brief, "disclosure_policy", "disclosure", default={}) if isinstance(first(brief, "disclosure_policy", "disclosure", default={}), dict) else {},
            provenance={"platform": self.platform, "source_url": data.source_url, "raw_hash": data.raw_hash, "fields": {"program": "external_data", "brief": "external_data", "targets": "external_data"}},
            source_data=data,
        )
