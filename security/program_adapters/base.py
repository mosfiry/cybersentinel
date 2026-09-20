from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import json
from typing import Any, Callable

from .models import ExternalProgramData, NormalizedProgram, ProgramCandidate


class AdapterError(ValueError):
    pass


class ProgramAdapter(ABC):
    platform = "unknown"

    def __init__(self, *, transport: Callable[..., Any] | None = None, source_url: str = ""):
        self.transport = transport
        self.source_url = source_url

    @abstractmethod
    def normalize_program(self, data: ExternalProgramData) -> NormalizedProgram:
        raise NotImplementedError

    def fetch_program(self, program_id: str) -> ExternalProgramData:
        if not self.transport:
            raise AdapterError("adapter transport is not configured")
        raw = self.transport(program_id)
        if not isinstance(raw, dict):
            raise AdapterError("external program response must be an object")
        return ExternalProgramData(self.platform, str(program_id), raw, datetime.now(timezone.utc).isoformat(), self.source_url)

    def get_program(self, program_id: str) -> ProgramCandidate:
        external = self.fetch_program(program_id)
        return ProgramCandidate(self.normalize_program(external))

    def build_authorization(self, data: ExternalProgramData | dict[str, Any]):
        if isinstance(data, dict):
            data = ExternalProgramData(self.platform, str(data.get("id") or data.get("program_id") or ""), data, datetime.now(timezone.utc).isoformat(), self.source_url)
        return self.normalize_program(data).to_authorization_candidate()

    def save_scope(self, *args: Any, **kwargs: Any) -> None:
        raise AdapterError("adapters cannot save scope; Owner approval and ScopeStore are required")

    def approve_scope(self, *args: Any, **kwargs: Any) -> None:
        raise AdapterError("adapters cannot approve scope")

    def execute_target(self, *args: Any, **kwargs: Any) -> None:
        raise AdapterError("adapters cannot execute targets")


def first(raw: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = raw.get(key)
        if value is not None:
            return value
    return default


def as_assets(value: Any) -> tuple[dict[str, Any], ...]:
    if isinstance(value, dict):
        value = value.get("targets") or value.get("assets") or value.get("items") or []
    if isinstance(value, str):
        value = [{"host": value}]
    if not isinstance(value, list):
        return ()
    result = []
    for item in value:
        if isinstance(item, str):
            result.append({"host": item})
        elif isinstance(item, dict):
            host = first(item, "host", "hostname", "asset", "name", "url")
            if host:
                normalized = {"host": str(host).strip()}
                for key in ("schemes", "ports", "paths", "allowed_paths", "excluded_paths", "asset_type", "type"):
                    if key in item:
                        normalized[key] = item[key]
                result.append(normalized)
    return tuple(result)


def methods(raw: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    rules = first(raw, "rules", "policy", "brief", default={})
    if not isinstance(rules, dict):
        rules = {}
    allowed = first(rules, "allowed_methods", "methods", default=raw.get("allowed_methods", ["GET", "HEAD"]))
    prohibited = first(rules, "prohibited_methods", "disallowed_methods", "forbidden_methods", default=raw.get("prohibited_methods", ["DELETE", "PATCH", "PUT"]))
    if isinstance(allowed, str):
        allowed = [allowed]
    if isinstance(prohibited, str):
        prohibited = [prohibited]
    return tuple(str(item).upper() for item in (allowed or [])), tuple(str(item).upper() for item in (prohibited or []))
