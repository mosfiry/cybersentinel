from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.local_runtime.catalog import ModelSpec
from agent.local_runtime.runtime import LlamaCppRuntime
from agent.model_router import ModelRouter
from agent.provider_api import (
    CapabilityUnsupported,
    HardwareRequirements,
    ProviderCapabilities,
    ProviderTimeout,
)
from agent.providers import OpenAICompatibleProvider


class _FakeProvider:
    def __init__(self, name, deployment, *, model="test-model", tool_calling=False, error=None, result=None):
        self.name = name
        self.model = model
        self.deployment = deployment
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=tool_calling)
        self.error = error
        self.result = result or {"content": f"result-from-{name}"}
        self.calls = 0

    def generate(self, messages, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        return self.result

    def tool_calling(self, messages, tools, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        return self.result


def test_provider_status_exposes_bounded_metadata_without_credentials():
    secret = "provider-private-marker"
    provider = OpenAICompatibleProvider(
        "deepseek-compatible",
        "https://llm.example/v1",
        "deepseek-r1",
        secret,
        tool_calling=True,
        streaming=True,
        structured_output=True,
        reasoning=True,
        context_length=8192,
        model_version="R1",
        quantization="BF16",
        deployment="remote",
        hardware_requirements=HardwareRequirements(
            accelerator="nvidia", min_ram_gib=16, min_vram_gib=8, min_cpu_cores=6
        ),
    )

    status = provider.status()
    metadata = status["metadata"]

    assert metadata["provider_id"] == "deepseek-compatible"
    assert metadata["model_identity"] == "deepseek-r1"
    assert metadata["model_version"] == "R1"
    assert metadata["quantization"] == "BF16"
    assert metadata["context_length"] == 8192
    assert metadata["deployment"] == "remote"
    assert metadata["tool_calling"] is True
    assert metadata["streaming"] is True
    assert metadata["structured_output"] is True
    assert metadata["reasoning"] is True
    assert metadata["capabilities"]["tool_calling"] is True
    assert metadata["capabilities"]["stream"] is True
    assert metadata["capabilities"]["structured_output"] is True
    assert metadata["capabilities"]["reasoning"] is True
    assert metadata["hardware_requirements"] == {
        "accelerator": "nvidia",
        "min_ram_gib": 16,
        "min_vram_gib": 8,
        "min_cpu_cores": 6,
        "min_disk_gib": None,
    }
    assert "api_key" not in status
    assert secret not in json.dumps(status)


def test_provider_metadata_rejects_invalid_deployment_and_hardware():
    with pytest.raises(ValueError):
        OpenAICompatibleProvider("p", "http://127.0.0.1/v1", "m", deployment="maybe")
    with pytest.raises(ValueError):
        HardwareRequirements(accelerator="unlisted-gpu")
    with pytest.raises(ValueError):
        HardwareRequirements(min_ram_gib=True)
    with pytest.raises(ValueError):
        HardwareRequirements(min_cpu_cores=0)
    with pytest.raises(ValueError):
        HardwareRequirements(accelerator=[])
    with pytest.raises(ValueError):
        OpenAICompatibleProvider("p", "http://127.0.0.1/v1", "m", tool_calling=1)


def test_default_router_does_not_fall_back_from_local_to_remote_generation():
    local = _FakeProvider("local-qwen", "local", error=TimeoutError("unavailable"))
    remote = _FakeProvider("remote-cloud", "remote")
    router = ModelRouter([local, remote])

    with pytest.raises(ProviderTimeout):
        router.generate([{"role": "user", "content": "bounded"}])

    assert local.calls == 1
    assert remote.calls == 0
    assert any(
        item.get("provider") == "remote-cloud"
        and item.get("reason") == "deployment_boundary"
        for item in router.last_trace
    )


def test_default_router_does_not_use_remote_tool_provider_when_local_lacks_capability():
    local = _FakeProvider("local-qwen", "local", tool_calling=False)
    remote = _FakeProvider("remote-cloud", "remote", tool_calling=True)
    router = ModelRouter([local, remote])

    with pytest.raises(CapabilityUnsupported):
        router.tool_calling([{"role": "user", "content": "bounded"}], [])

    assert local.calls == 0
    assert remote.calls == 0
    assert any(item.get("reason") == "deployment_boundary" for item in router.last_trace)


def test_unknown_primary_locality_fails_closed_for_provider_fallback():
    unknown = _FakeProvider("unclassified", "unknown", error=TimeoutError("unavailable"))
    remote = _FakeProvider("remote-cloud", "remote")
    router = ModelRouter([unknown, remote])

    with pytest.raises(ProviderTimeout):
        router.generate([{"role": "user", "content": "bounded"}])

    assert unknown.calls == 1
    assert remote.calls == 0


def test_cross_deployment_fallback_requires_explicit_opt_in_and_is_traced():
    local = _FakeProvider("local-qwen", "local", error=TimeoutError("unavailable"))
    remote = _FakeProvider("remote-cloud", "remote")
    router = ModelRouter([local, remote], allow_cross_deployment_fallback=True)

    result = router.generate([{"role": "user", "content": "bounded"}])

    assert result["provider"] == "remote-cloud"
    assert remote.calls == 1
    assert any(
        item.get("status") == "explicit_cross_deployment_fallback_enabled"
        and item.get("to_deployment") == "remote"
        for item in router.last_trace
    )


class _HealthResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeProcess:
    def __init__(self, *args, **kwargs):
        self.alive = True

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.alive = False

    def wait(self, timeout=None):
        self.alive = False
        return 0


def test_local_runtime_binds_provider_metadata_from_validated_catalog(monkeypatch, tmp_path):
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    (runtime_dir / "llama-server").write_bytes(b"test-only-runtime-placeholder")
    model_path = tmp_path / "fixture.gguf"
    model_path.write_bytes(b"fixture")
    spec = ModelSpec(
        model_id="test-qwen3",
        family="Qwen3",
        display_name="Test Qwen3",
        parameter_size="4B",
        repository="tests/pinned-fixture",
        revision="a" * 40,
        filename=model_path.name,
        size_bytes=model_path.stat().st_size,
        sha256="0" * 64,
        quantization="Q4_K_M",
        license="Apache-2.0",
        min_ram_gib=8,
        recommended_ram_gib=12,
        context_length=4096,
        model_version="3",
        min_vram_gib=4,
        recommended_vram_gib=6,
        min_cpu_cores=4,
        backend_compatibility=("llama.cpp-cpu",),
    )
    monkeypatch.setattr("agent.local_runtime.runtime.subprocess.Popen", _FakeProcess)
    monkeypatch.setattr("agent.local_runtime.runtime.urllib.request.urlopen", lambda *args, **kwargs: _HealthResponse())
    runtime = LlamaCppRuntime(runtime_dir, startup_timeout=1)

    provider = runtime.start(spec, model_path)
    metadata = provider.status()["metadata"]

    assert metadata["provider_id"] == "local_llama_cpp"
    assert metadata["model_identity"] == "test-qwen3"
    assert metadata["model_version"] == "3"
    assert metadata["quantization"] == "Q4_K_M"
    assert metadata["context_length"] == 4096
    assert metadata["deployment"] == "local"
    assert metadata["hardware_requirements"] == {
        "accelerator": "cpu",
        "min_ram_gib": 8,
        "min_vram_gib": 4,
        "min_cpu_cores": 4,
        "min_disk_gib": 2,
    }
    runtime.stop()
