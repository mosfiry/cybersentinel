from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent.local_runtime.advisor import build_advisor
from agent.local_runtime.catalog import MODEL_CATALOG, ModelSpec
from agent.local_runtime.hardware import GIB, assess_compatibility, detect_hardware


def _hardware(*, budget_gib=32, disk_gib=80, os_name="windows", arch="amd64", cores=8, backends=None):
    return {
        "os": os_name,
        "architecture": arch,
        "cpu_model": "Mocked CPU",
        "cpu_count": cores,
        "logical_cpu_count": cores,
        "physical_core_count": max(1, cores // 2),
        "cpu_instruction_sets": ["avx2", "fma"],
        "ram_bytes": 64 * GIB,
        "available_ram_bytes": 40 * GIB,
        "inference_memory_budget_bytes": budget_gib * GIB,
        "inference_memory_budget_gib": float(budget_gib),
        "free_disk_bytes": disk_gib * GIB,
        "gpu_devices": [],
        "vram_bytes": None,
        "supported_backends": backends or ["llama.cpp-cpu"],
        "runtime_platform_supported": True,
        "gpu_acceleration_available": False,
    }


def test_detect_hardware_collects_local_facts_and_does_not_create_storage(monkeypatch, tmp_path):
    storage = tmp_path / "not-created" / "models"
    probe = tmp_path
    monkeypatch.setattr("agent.local_runtime.hardware._memory_snapshot", lambda: (16 * GIB, 12 * GIB, "mocked-local-api"))
    monkeypatch.setattr("agent.local_runtime.hardware._logical_cpu_count", lambda: 8)
    monkeypatch.setattr("agent.local_runtime.hardware._physical_core_count", lambda: 4)
    monkeypatch.setattr("agent.local_runtime.hardware._cpu_model", lambda: "Mock Intel CPU")
    monkeypatch.setattr("agent.local_runtime.hardware._cpu_instruction_sets", lambda: (["avx2", "fma"], "mocked-local-api"))
    monkeypatch.setattr("agent.local_runtime.hardware._gpu_inventory", lambda: ([], "not_detected_or_unavailable"))
    monkeypatch.setattr("agent.local_runtime.hardware.platform.system", lambda: "Windows")
    monkeypatch.setattr("agent.local_runtime.hardware.platform.machine", lambda: "AMD64")
    monkeypatch.setattr("agent.local_runtime.hardware.shutil.disk_usage", lambda _path: shutil._ntuple_diskusage(100 * GIB, 20 * GIB, 80 * GIB))

    result = detect_hardware(storage)

    assert result["cpu_model"] == "Mock Intel CPU"
    assert result["logical_cpu_count"] == 8
    assert result["physical_core_count"] == 4
    assert result["cpu_instruction_sets"] == ["avx2", "fma"]
    assert result["ram_bytes"] == 16 * GIB
    assert result["available_ram_bytes"] == 12 * GIB
    assert result["inference_memory_budget_bytes"] == 10 * GIB
    assert result["free_disk_bytes"] == 80 * GIB
    assert result["gpu_devices"] == []
    assert result["vram_bytes"] is None
    assert result["gpu_acceleration_available"] is False
    assert result["runtime_platform_supported"] is True
    assert result["supported_model_formats"] == ["GGUF"]
    assert storage.exists() is False


def test_detect_hardware_preserves_partial_failures_as_unknown(monkeypatch, tmp_path):
    monkeypatch.setattr("agent.local_runtime.hardware._memory_snapshot", lambda: (None, None, "unavailable"))
    monkeypatch.setattr("agent.local_runtime.hardware._logical_cpu_count", lambda: None)
    monkeypatch.setattr("agent.local_runtime.hardware._physical_core_count", lambda: None)
    monkeypatch.setattr("agent.local_runtime.hardware._cpu_model", lambda: "unknown")
    monkeypatch.setattr("agent.local_runtime.hardware._cpu_instruction_sets", lambda: ([], "unavailable"))
    monkeypatch.setattr("agent.local_runtime.hardware._gpu_inventory", lambda: ([], "nvidia_smi_failed"))
    monkeypatch.setattr("agent.local_runtime.hardware.shutil.disk_usage", lambda _path: (_ for _ in ()).throw(OSError("probe failed")))
    monkeypatch.setattr("agent.local_runtime.hardware.platform.system", lambda: "Windows")
    monkeypatch.setattr("agent.local_runtime.hardware.platform.machine", lambda: "ARM64")

    result = detect_hardware(tmp_path)

    assert result["ram_bytes"] is None
    assert result["available_ram_bytes"] is None
    assert result["inference_memory_budget_bytes"] is None
    assert result["free_disk_bytes"] is None
    assert result["disk_detection_status"] == "unavailable"
    assert result["gpu_devices"] == []
    assert result["vram_bytes"] is None
    assert result["gpu_detection_status"] == "nvidia_smi_failed"
    assert result["runtime_platform_supported"] is False


def test_compatibility_blocks_safe_memory_disk_backend_and_unsupported_formats():
    model = MODEL_CATALOG[0]
    low_ram = assess_compatibility(model, _hardware(budget_gib=model.min_ram_gib - 1))
    low_disk = assess_compatibility(model, _hardware(disk_gib=0))
    backend = assess_compatibility(model, _hardware(backends=["exllamav3-exl3"]))
    architecture = assess_compatibility(model, _hardware(arch="arm64"))

    assert "insufficient_system_memory" in low_ram["reasons"]
    assert "insufficient_free_disk" in low_disk["reasons"]
    assert "unsupported_runtime_backend" in backend["reasons"]
    assert "unsupported_runtime_architecture" in architecture["reasons"]
    assert low_ram["memory_estimates_are_benchmarks"] is False


def test_insufficient_vram_is_blocking_when_a_catalog_model_requires_it():
    model = ModelSpec(**{**MODEL_CATALOG[0].__dict__, "min_vram_gib": 8, "recommended_vram_gib": 12})
    result = assess_compatibility(model, _hardware())
    assert result["compatible"] is False
    assert "insufficient_vram" in result["reasons"]


def test_advisor_ranks_three_distinct_models_with_stable_ties_and_explains_heuristics():
    facts = _hardware()
    first = build_advisor(MODEL_CATALOG, facts)
    second = build_advisor(tuple(reversed(MODEL_CATALOG)), facts)

    assert first["recommendation_count"] == 3
    assert len({item["model_id"] for item in first["recommendations"]}) == 3
    assert [item["model_id"] for item in first["recommendations"]] == [item["model_id"] for item in second["recommendations"]]
    assert [item["role"] for item in first["recommendations"]] == ["best_overall", "best_coding", "strongest_practical"]
    for item in first["recommendations"]:
        assert len(item["revision"]) == 40
        assert len(item["sha256"]) == 64
        assert item["required_disk_bytes"] > item["size_bytes"]
        assert item["estimated_runtime_memory"]["evidence_type"].startswith("catalog estimate")
        assert "not a benchmark" in item["score_type"]


def test_advisor_shows_only_qualifying_models_and_never_relaxes_thresholds():
    result = build_advisor(MODEL_CATALOG, _hardware(budget_gib=1, disk_gib=1))
    assert result["recommendation_count"] == 0
    assert result["status"] == "no_eligible_models"
    assert "No threshold was relaxed" in result["explanation"]


def test_missing_runtime_binary_suppresses_recommendations():
    result = build_advisor(MODEL_CATALOG, {**_hardware(), "runtime_binary_available": False})
    assert result["recommendation_count"] == 0
    assert "runtime binary is not present" in result["explanation"]


def test_selected_catalog_model_outside_top_three_remains_available():
    extra = ModelSpec(**{
        **MODEL_CATALOG[0].__dict__,
        "model_id": "extra-curated-model",
        "display_name": "Extra eligible model",
        "family": "Extra",
        "parameter_size": "1B",
        "repository": "tests/curated-fixture",
        "revision": "b" * 40,
        "filename": "extra-small.gguf",
        "size_bytes": 1024,
        "sha256": "c" * 64,
        "min_ram_gib": 1,
        "recommended_ram_gib": 1000,
        "min_cpu_cores": 64,
        "context_length": 1,
        "advisor_capabilities": (),
    })
    result = build_advisor((*MODEL_CATALOG, extra), _hardware())
    recommended_ids = {item["model_id"] for item in result["recommendations"]}
    assert result["recommendation_count"] == 3
    assert extra.model_id not in recommended_ids
    assert result["alternative_search"]["install_arbitrary_urls"] is False
    assert "trusted SHA-256" in result["alternative_search"]["unlisted_model_status"]
