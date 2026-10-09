from __future__ import annotations

import re
from typing import Any, Iterable

from .catalog import ModelSpec
from .hardware import GIB, assess_compatibility

_ROLE_LABELS = {
    "best_overall": "Best overall balance",
    "best_coding": "Best coding / engineering fit",
    "strongest_practical": "Strongest practical reasoning choice",
}


def _parameter_count(spec: ModelSpec) -> float:
    match = re.search(r"(\d+(?:\.\d+)?)\s*[bB]", spec.parameter_size)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            pass
    return 0.0


def _ratio(value: float, maximum: float) -> float:
    return min(1.0, max(0.0, value / maximum)) if maximum > 0 else 0.0


def _scores(spec: ModelSpec, specs: tuple[ModelSpec, ...], hardware: dict[str, Any]) -> dict[str, float]:
    max_size = max((item.size_bytes for item in specs), default=0)
    max_params = max((_parameter_count(item) for item in specs), default=0.0)
    budget = hardware.get("inference_memory_budget_bytes")
    if not isinstance(budget, int) or isinstance(budget, bool):
        budget = hardware.get("ram_bytes")
    budget = budget if isinstance(budget, int) and not isinstance(budget, bool) else 0
    logical_cores = hardware.get("logical_cpu_count", hardware.get("cpu_count"))
    logical_cores = logical_cores if isinstance(logical_cores, int) and not isinstance(logical_cores, bool) else 0

    size_efficiency = 1.0 - _ratio(float(spec.size_bytes), float(max_size))
    memory_fit = min(1.0, budget / max(1, spec.recommended_ram_gib * GIB))
    cpu_fit = min(1.0, logical_cores / max(1, spec.min_cpu_cores))
    context_fit = min(1.0, spec.context_length / 4096.0)
    parameter_scale = _ratio(_parameter_count(spec), max_params)
    is_qwen3 = spec.model_id.startswith("qwen3-") and "coding" in spec.advisor_capabilities
    is_reasoning_distill = spec.model_id.startswith("deepseek-r1-distill-") and "reasoning" in spec.advisor_capabilities

    # These are transparent catalog-based ranking heuristics, not measured scores.
    return {
        "best_overall": round(0.55 * size_efficiency + 0.25 * memory_fit + 0.10 * cpu_fit + 0.10 * context_fit, 6),
        "best_coding": round(0.40 * float(is_qwen3) + 0.40 * parameter_scale + 0.20 * memory_fit, 6),
        "strongest_practical": round(0.55 * float(is_reasoning_distill) + 0.35 * parameter_scale + 0.10 * memory_fit, 6),
    }


def _reason(role: str, spec: ModelSpec) -> tuple[str, str, list[str]]:
    if role == "best_overall":
        return (
            "Smallest eligible download in this catalog, with the catalog's lowest RAM estimate; selected for balance and responsiveness, not a speed benchmark.",
            "Footprint and compatibility use the pinned catalog and current hardware facts; relative quality and speed have not been benchmarked on this PC.",
            ["CPU-only inference; no GPU acceleration in the bundled runtime.", "The desktop runtime currently limits context to the catalog's 4096-token setting.", "No comparative local quality or tokens/second benchmark is available."],
        )
    if role == "best_coding":
        return (
            "Qwen3 model-card documentation describes coding and tool-use capability; among eligible catalog candidates this role favors the larger Qwen3 parameter size.",
            "Capability basis: upstream Qwen3 model-card claims; model suitability has not been benchmarked in CyberSentinel or on this PC.",
            ["This is a general Qwen3 model, not a coding-specialized checkpoint.", "The recommendation is not a measured coding score or guarantee.", "CPU-only inference and 4096-token app context may limit larger engineering tasks."],
        )
    return (
        "The pinned DeepSeek-R1 distilled family is reasoning-focused; this role uses that model-card intent as a fit signal while requiring the device to pass the same conservative memory, disk, OS, and backend checks.",
        "Capability basis: upstream DeepSeek-R1 model-card description of reasoning distillation and code/reasoning tasks; relative local performance is unmeasured.",
        ["The base model's published terms may differ from the third-party GGUF conversion's metadata; review both before redistribution.", "No on-device comparative benchmark or quality guarantee is available.", "CPU-only inference and 4096-token app context may reduce responsiveness."],
    )


def build_advisor(specs: Iterable[ModelSpec], hardware: dict[str, Any]) -> dict[str, Any]:
    """Return up to three unique eligible models in distinct, deterministic roles."""
    catalog = tuple(specs)
    assessments = {spec.model_id: assess_compatibility(spec, hardware) for spec in catalog}
    runtime_missing = hardware.get("runtime_binary_available") is False
    eligible = [
        spec for spec in catalog
        if assessments[spec.model_id]["compatible"]
        and "llama.cpp-cpu" in spec.backend_compatibility
        and spec.filename.lower().endswith(".gguf")
        and not runtime_missing
    ]
    score_by_id = {spec.model_id: _scores(spec, catalog, hardware) for spec in eligible}
    role_order = ("best_overall", "best_coding", "strongest_practical")
    chosen: list[dict[str, Any]] = []
    used: set[str] = set()

    for role in role_order:
        ranked = sorted(
            (spec for spec in eligible if spec.model_id not in used),
            key=lambda item: (-score_by_id[item.model_id][role], item.model_id),
        )
        if not ranked:
            break
        spec = ranked[0]
        used.add(spec.model_id)
        why, evidence, limitations = _reason(role, spec)
        source_url = f"https://huggingface.co/{spec.repository}/tree/{spec.revision}"
        budget = hardware.get("inference_memory_budget_gib")
        if budget is None:
            byte_budget = hardware.get("inference_memory_budget_bytes", hardware.get("ram_bytes"))
            budget = round(byte_budget / GIB, 1) if isinstance(byte_budget, int) and not isinstance(byte_budget, bool) else None
        chosen.append({
            "rank": len(chosen) + 1,
            "role": role,
            "role_label": _ROLE_LABELS[role],
            "model_id": spec.model_id,
            "display_name": spec.display_name,
            "parameter_size": spec.parameter_size,
            "quantization": spec.quantization,
            "repository": spec.repository,
            "revision": spec.revision,
            "source_url": source_url,
            "capability_evidence_url": spec.capability_evidence_url,
            "advisor_capabilities": list(spec.advisor_capabilities),
            "download_source": spec.download_source,
            "filename": spec.filename,
            "size_bytes": spec.size_bytes,
            "sha256": spec.sha256,
            "license": spec.license,
            "license_url": spec.license_url,
            "required_disk_bytes": assessments[spec.model_id]["required_disk_bytes"],
            "estimated_runtime_memory": {
                "minimum_gib": spec.min_ram_gib,
                "recommended_gib": spec.recommended_ram_gib,
                "safe_budget_gib_at_scan": budget,
                "evidence_type": "catalog estimate; not a measured benchmark",
            },
            "backend_requirement": "llama.cpp-cpu; x64 Windows/Linux only; no GPU acceleration",
            "context_tokens": spec.context_length,
            "evidence_basis": evidence,
            "confidence": "Moderate for resource compatibility; low for comparative quality or responsiveness (no local benchmark).",
            "score": score_by_id[spec.model_id][role],
            "score_type": "deterministic catalog-based heuristic, not a benchmark",
            "why_recommended": why,
            "known_limitations": limitations,
        })

    if not chosen:
        if runtime_missing:
            explanation = "The compatible llama.cpp CPU runtime binary is not present; models are not recommended as runnable until that verified runtime is available. No threshold was relaxed to fill recommendation slots."
        else:
            explanation = "No curated catalog model currently passes the local RAM, disk, OS/architecture, and CPU-backend compatibility checks. No threshold was relaxed to fill recommendation slots."
    elif len(chosen) < 3:
        explanation = f"Only {len(chosen)} distinct curated model(s) pass current compatibility checks; remaining recommendations are omitted rather than forcing an ineligible model."
    else:
        explanation = "Three distinct eligible models are ranked for balance, coding/engineering, and reasoning-oriented use. Scores are heuristics, not measured quality or throughput."

    return {
        "status": "ready" if chosen else "no_eligible_models",
        "policy": "curated-pinned-catalog-only",
        "eligible_model_count": len(eligible),
        "recommendation_count": len(chosen),
        "explanation": explanation,
        "recommendations": chosen,
        "alternative_search": {
            "mode": "verified-catalog-search-plus-metadata-only-review",
            "install_arbitrary_urls": False,
            "review_endpoint": "/api/public/desktop/models/review",
            "review_requires": {"repository_id": "Hugging Face namespace/model", "revision": "immutable 40-character commit SHA"},
            "review_downloads_weights": False,
            "unlisted_candidates_installable": False,
            "review_checks": ["resolved immutable revision", "GGUF filenames and quantization", "published file sizes", "Hub-declared LFS SHA-256", "declared model-card license"],
            "curation_gates": ["inspect GGUF architecture metadata", "verify bundled Windows llama.cpp CPU support", "independently pin and test the exact artifact", "maintainer review and catalog inclusion"],
            "unlisted_model_status": "not_installable_until repository, immutable revision, exact GGUF file, license, architecture/backend compatibility, and trusted SHA-256 are independently verified and curated",
        },
        "estimates_are_benchmarks": False,
    }
