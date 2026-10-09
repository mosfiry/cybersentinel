from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

CATALOG_FORMAT_VERSION = 1
DEFAULT_CATALOG_PATH = Path(__file__).with_name("catalog.json")
_MODEL_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,127}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FILENAME = re.compile(r"^[A-Za-z0-9_.-]{1,180}\.gguf$")
_ALLOWED_DOWNLOAD_SOURCES = {"huggingface.co"}
_ALLOWED_ADVISOR_CAPABILITIES = {"coding", "reasoning", "tool_use", "multilingual"}


@dataclass(frozen=True)
class ModelSpec:
    model_id: str
    family: str
    display_name: str
    parameter_size: str
    repository: str
    revision: str
    filename: str
    size_bytes: int
    sha256: str
    quantization: str
    license: str
    min_ram_gib: int
    recommended_ram_gib: int
    context_length: int = 4096
    model_version: str = ""
    min_vram_gib: int = 0
    recommended_vram_gib: int = 0
    min_cpu_cores: int = 1
    backend_compatibility: tuple[str, ...] = ("llama.cpp-cpu",)
    download_source: str = "huggingface.co"
    license_url: str = ""
    capability_evidence_url: str = ""
    advisor_capabilities: tuple[str, ...] = ()

    @property
    def download_url(self) -> str:
        filename = quote(self.filename, safe="-_.")
        return (
            f"https://huggingface.co/{self.repository}/resolve/"
            f"{self.revision}/{filename}?download=true"
        )

    def public(self) -> dict[str, object]:
        return {
            "model_id": self.model_id,
            "family": self.family,
            "display_name": self.display_name,
            "model_version": self.model_version,
            "parameter_size": self.parameter_size,
            "repository": self.repository,
            "revision": self.revision,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "quantization": self.quantization,
            "license": self.license,
            "license_url": self.license_url,
            "download_source": self.download_source,
            "min_ram_gib": self.min_ram_gib,
            "recommended_ram_gib": self.recommended_ram_gib,
            "min_vram_gib": self.min_vram_gib,
            "recommended_vram_gib": self.recommended_vram_gib,
            "min_cpu_cores": self.min_cpu_cores,
            "backend_compatibility": list(self.backend_compatibility),
            "context_length": self.context_length,
            "capability_evidence_url": self.capability_evidence_url,
            "advisor_capabilities": list(self.advisor_capabilities),
        }


def _positive_int(value: Any, key: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"invalid_catalog_{key}")
    if value < (0 if allow_zero else 1):
        raise ValueError(f"invalid_catalog_{key}")
    return value


def _model_spec(raw: Any) -> ModelSpec:
    if not isinstance(raw, dict):
        raise ValueError("invalid_catalog_model")
    try:
        backend_values = raw.get("backend_compatibility", ["llama.cpp-cpu"])
        if not isinstance(backend_values, list) or not backend_values or any(
            not isinstance(item, str) or not item.strip() or len(item) > 80
            for item in backend_values
        ):
            raise ValueError("invalid_catalog_backend_compatibility")
        advisor_values = raw.get("advisor_capabilities", [])
        if not isinstance(advisor_values, list) or any(
            not isinstance(item, str) or item not in _ALLOWED_ADVISOR_CAPABILITIES
            for item in advisor_values
        ) or len(set(advisor_values)) != len(advisor_values):
            raise ValueError("invalid_catalog_advisor_capabilities")
        model = ModelSpec(
            model_id=str(raw["model_id"]),
            family=str(raw["family"]),
            display_name=str(raw["display_name"]),
            parameter_size=str(raw["parameter_size"]),
            repository=str(raw["repository"]),
            revision=str(raw["revision"]),
            filename=str(raw["filename"]),
            size_bytes=_positive_int(raw["size_bytes"], "size_bytes"),
            sha256=str(raw["sha256"]),
            quantization=str(raw["quantization"]),
            license=str(raw["license"]),
            min_ram_gib=_positive_int(raw["min_ram_gib"], "min_ram_gib"),
            recommended_ram_gib=_positive_int(
                raw["recommended_ram_gib"], "recommended_ram_gib"
            ),
            context_length=_positive_int(raw.get("context_length", 4096), "context_length"),
            model_version=str(raw.get("model_version", "")),
            min_vram_gib=_positive_int(raw.get("min_vram_gib", 0), "min_vram_gib", allow_zero=True),
            recommended_vram_gib=_positive_int(
                raw.get("recommended_vram_gib", 0), "recommended_vram_gib", allow_zero=True
            ),
            min_cpu_cores=_positive_int(raw.get("min_cpu_cores", 1), "min_cpu_cores"),
            backend_compatibility=tuple(backend_values),
            download_source=str(raw.get("download_source", "huggingface.co")),
            license_url=str(raw.get("license_url", "")),
            capability_evidence_url=str(raw.get("capability_evidence_url", "")),
            advisor_capabilities=tuple(advisor_values),
        )
    except KeyError as exc:
        raise ValueError(f"catalog_field_missing:{exc.args[0]}") from exc
    except (TypeError, OverflowError) as exc:
        raise ValueError("invalid_catalog_model") from exc

    if not _MODEL_ID.fullmatch(model.model_id):
        raise ValueError("invalid_catalog_model_id")
    if not _REPOSITORY.fullmatch(model.repository):
        raise ValueError("invalid_catalog_repository")
    if not _REVISION.fullmatch(model.revision):
        raise ValueError("invalid_catalog_revision")
    if not _FILENAME.fullmatch(model.filename) or ".." in model.filename:
        raise ValueError("invalid_catalog_filename")
    if not _SHA256.fullmatch(model.sha256):
        raise ValueError("invalid_catalog_sha256")
    if model.recommended_ram_gib < model.min_ram_gib:
        raise ValueError("invalid_catalog_ram_requirements")
    if model.recommended_vram_gib < model.min_vram_gib:
        raise ValueError("invalid_catalog_vram_requirements")
    if model.download_source not in _ALLOWED_DOWNLOAD_SOURCES:
        raise ValueError("unsupported_catalog_download_source")
    if not model.family or len(model.family) > 128 or not model.display_name or len(model.display_name) > 160:
        raise ValueError("invalid_catalog_display_metadata")
    if not model.quantization or len(model.quantization) > 64 or not model.license or len(model.license) > 128:
        raise ValueError("invalid_catalog_license_metadata")
    if model.license_url and not model.license_url.startswith("https://"):
        raise ValueError("invalid_catalog_license_url")
    if model.capability_evidence_url:
        parsed_evidence = urlsplit(model.capability_evidence_url)
        if parsed_evidence.scheme != "https" or parsed_evidence.hostname != "huggingface.co" or parsed_evidence.username or parsed_evidence.password:
            raise ValueError("invalid_catalog_capability_evidence_url")
    return model


def load_catalog(path: str | Path | None = None) -> tuple[str, tuple[ModelSpec, ...]]:
    """Load and validate a versioned, data-only model catalog.

    The packaged JSON manifest is deliberately separate from manager logic so
    future signed catalog updates can replace the data without changing agent
    core. Callers handling downloaded manifests must verify publisher signatures
    before passing a path here; this loader validates structure and safety only.
    """
    source = Path(path) if path is not None else DEFAULT_CATALOG_PATH
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("model_catalog_unavailable_or_invalid") from exc
    if not isinstance(payload, dict) or payload.get("format_version") != CATALOG_FORMAT_VERSION:
        raise ValueError("unsupported_model_catalog_format")
    version = payload.get("catalog_version")
    rows = payload.get("models")
    if not isinstance(version, str) or not version.strip() or len(version) > 80:
        raise ValueError("invalid_catalog_version")
    if not isinstance(rows, list) or not rows or len(rows) > 500:
        raise ValueError("invalid_catalog_models")
    models = tuple(_model_spec(row) for row in rows)
    ids = [item.model_id for item in models]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate_catalog_model_id")
    return version, models


CATALOG_VERSION, MODEL_CATALOG = load_catalog()
MODELS_BY_ID = {item.model_id: item for item in MODEL_CATALOG}


def get_model(model_id: str) -> ModelSpec:
    try:
        return MODELS_BY_ID[str(model_id)]
    except KeyError as exc:
        raise KeyError("unknown_model") from exc
