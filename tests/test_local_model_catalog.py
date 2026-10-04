from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.local_runtime.catalog import CATALOG_VERSION, MODEL_CATALOG, load_catalog
from agent.local_runtime.hardware import GIB, assess_compatibility


def _hardware(ram_gib: int) -> dict:
    return {
        "os": "windows",
        "architecture": "amd64",
        "cpu_model": "Acceptance CPU",
        "cpu_count": 8,
        "ram_bytes": ram_gib * GIB,
        "ram_gib": float(ram_gib),
        "free_disk_bytes": 80 * GIB,
        "free_disk_gib": 80.0,
        "gpu_devices": [],
        "vram_bytes": 0,
        "vram_gib": 0.0,
        "gpu_acceleration_available": False,
    }


def test_catalog_is_versioned_data_with_pinned_source_license_and_backend_metadata():
    assert CATALOG_VERSION
    qwen = next(item for item in MODEL_CATALOG if item.model_id == "qwen3-4b-q4-k-m")
    assert qwen.filename == "Qwen3-4B-Q4_K_M.gguf"
    assert qwen.download_source == "huggingface.co"
    assert len(qwen.sha256) == 64
    assert qwen.revision and len(qwen.revision) == 40
    assert qwen.license == "Apache-2.0"
    assert qwen.license_url.startswith("https://")
    assert qwen.backend_compatibility == ("llama.cpp-cpu",)
    assert qwen.min_ram_gib < qwen.recommended_ram_gib


def test_hardware_assessment_separates_recommendation_from_oversized_models():
    qwen = next(item for item in MODEL_CATALOG if item.model_id == "qwen3-4b-q4-k-m")
    recommended = assess_compatibility(qwen, _hardware(16))
    too_large = assess_compatibility(qwen, _hardware(4))

    assert recommended["compatible"] is True
    assert recommended["recommended"] is True
    assert recommended["too_large"] is False
    assert too_large["compatible"] is False
    assert too_large["recommended"] is False
    assert too_large["too_large"] is True
    assert "insufficient_system_memory" in too_large["reasons"]


def test_catalog_loader_rejects_unsafe_repository_and_duplicate_model_ids(tmp_path):
    payload = json.loads(Path("agent/local_runtime/catalog.json").read_text(encoding="utf-8"))
    payload["models"][0]["repository"] = "https://attacker.example/repo"
    unsafe_path = tmp_path / "unsafe.json"
    unsafe_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid_catalog_repository"):
        load_catalog(unsafe_path)

    payload["models"][0]["repository"] = "unsloth/Qwen3-4B-GGUF"
    payload["models"].append(dict(payload["models"][0]))
    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate_catalog_model_id"):
        load_catalog(duplicate_path)
