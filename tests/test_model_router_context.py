from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent.model_router import ModelRouter


_PROVIDER_ENV_SUFFIXES = (
    "LLM_BASE_URL",
    "LLM_MODEL",
    "LLM_API_KEY",
    "LLM_TOOL_CALLING",
    "LLM_STREAMING",
    "LLM_STRUCTURED_OUTPUT",
    "LLM_PRIORITY",
    "LLM_CONTEXT_LENGTH",
    "LLM_DEPLOYMENT",
    "LLM_MODEL_VERSION",
    "LLM_QUANTIZATION",
    "LLM_MIN_RAM_GIB",
    "LLM_MIN_VRAM_GIB",
    "LLM_MIN_CPU_CORES",
    "LLM_MIN_DISK_GIB",
    "LLM_ACCELERATOR",
    "LLM_REASONING",
    "LLM_REASONING_BUDGET",
    "LLM_PARALLEL_TOOL_CALLS",
    "LLM_LONG_CONTEXT",
    "LLM_VISION",
)


def _clear_provider_env(monkeypatch):
    for prefix in ("LOCAL", "COLAB", "HF"):
        for suffix in _PROVIDER_ENV_SUFFIXES:
            monkeypatch.delenv(f"{prefix}_{suffix}", raising=False)
    for suffix in _PROVIDER_ENV_SUFFIXES:
        monkeypatch.delenv(suffix, raising=False)
    monkeypatch.delenv("LLM_ALLOW_CROSS_DEPLOYMENT_FALLBACK", raising=False)


def test_router_uses_minimum_window_for_same_deployment_fallbacks():
    router = ModelRouter([
        SimpleNamespace(context_length=8192, deployment="local"),
        SimpleNamespace(context_length=4096, deployment="local"),
    ])
    assert router.context_length == 4096


def test_router_disables_shared_window_when_reachable_fallback_window_is_unknown():
    router = ModelRouter([
        SimpleNamespace(context_length=8192, deployment="local"),
        SimpleNamespace(context_length=None, deployment="local"),
    ])
    assert router.context_length is None


def test_router_ignores_remote_window_when_cross_deployment_fallback_is_disabled():
    router = ModelRouter([
        SimpleNamespace(context_length=8192, deployment="local"),
        SimpleNamespace(context_length=None, deployment="remote"),
    ])
    assert router.context_length == 8192


def test_explicit_cross_deployment_fallback_includes_all_windows():
    router = ModelRouter([
        SimpleNamespace(context_length=8192, deployment="local"),
        SimpleNamespace(context_length=None, deployment="remote"),
    ], allow_cross_deployment_fallback=True)
    assert router.context_length is None


def test_from_env_loads_provider_window_and_structured_metadata(monkeypatch):
    _clear_provider_env(monkeypatch)
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "test-local-model")
    monkeypatch.setenv("LOCAL_LLM_CONTEXT_LENGTH", "8192")
    monkeypatch.setenv("LOCAL_LLM_DEPLOYMENT", "local")
    monkeypatch.setenv("LOCAL_LLM_MODEL_VERSION", "3")
    monkeypatch.setenv("LOCAL_LLM_QUANTIZATION", "Q4_K_M")
    monkeypatch.setenv("LOCAL_LLM_MIN_RAM_GIB", "8")
    monkeypatch.setenv("LOCAL_LLM_MIN_CPU_CORES", "4")
    monkeypatch.setenv("LOCAL_LLM_ACCELERATOR", "cpu")
    monkeypatch.setenv("LOCAL_LLM_REASONING", "true")

    router = ModelRouter.from_env()

    assert len(router.providers) == 1
    provider = router.providers[0]
    assert provider.context_length == 8192
    assert router.context_length == 8192
    assert router.allow_cross_deployment_fallback is False
    metadata = provider.status()["metadata"]
    assert metadata["model_version"] == "3"
    assert metadata["quantization"] == "Q4_K_M"
    assert metadata["deployment"] == "local"
    assert metadata["capabilities"]["reasoning"] is True
    assert metadata["hardware_requirements"]["min_ram_gib"] == 8
    assert metadata["hardware_requirements"]["min_cpu_cores"] == 4


def test_from_env_rejects_malformed_context_length_without_echoing_value(monkeypatch):
    _clear_provider_env(monkeypatch)
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "test-local-model")
    malformed = "not-a-number-private-marker"
    monkeypatch.setenv("LOCAL_LLM_CONTEXT_LENGTH", malformed)

    with pytest.raises(ValueError) as error:
        ModelRouter.from_env()

    assert "LOCAL_LLM_CONTEXT_LENGTH" in str(error.value)
    assert malformed not in str(error.value)


def test_from_env_rejects_invalid_provider_deployment(monkeypatch):
    _clear_provider_env(monkeypatch)
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "test-local-model")
    monkeypatch.setenv("LOCAL_LLM_DEPLOYMENT", "remote-marker-invalid")

    with pytest.raises(ValueError) as error:
        ModelRouter.from_env()

    assert "LOCAL_LLM_DEPLOYMENT" in str(error.value)
    assert "remote-marker-invalid" not in str(error.value)


def test_from_env_rejects_ambiguous_cross_deployment_fallback_flag(monkeypatch):
    _clear_provider_env(monkeypatch)
    monkeypatch.setenv("LLM_ALLOW_CROSS_DEPLOYMENT_FALLBACK", "sometimes")

    with pytest.raises(ValueError) as error:
        ModelRouter.from_env()

    assert "LLM_ALLOW_CROSS_DEPLOYMENT_FALLBACK" in str(error.value)
    assert "sometimes" not in str(error.value)


def test_from_env_excludes_unreachable_remote_window_by_default(monkeypatch):
    _clear_provider_env(monkeypatch)
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "test-local-model")
    monkeypatch.setenv("LOCAL_LLM_CONTEXT_LENGTH", "8192")
    monkeypatch.setenv("LOCAL_LLM_DEPLOYMENT", "local")
    monkeypatch.setenv("HF_LLM_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("HF_LLM_MODEL", "test-hf-model")
    monkeypatch.setenv("HF_LLM_DEPLOYMENT", "remote")

    router = ModelRouter.from_env()

    assert len(router.providers) == 2
    assert router.context_length == 8192
    assert router.allow_cross_deployment_fallback is False


def test_from_env_cross_deployment_opt_in_makes_all_windows_relevant(monkeypatch):
    _clear_provider_env(monkeypatch)
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "test-local-model")
    monkeypatch.setenv("LOCAL_LLM_CONTEXT_LENGTH", "8192")
    monkeypatch.setenv("LOCAL_LLM_DEPLOYMENT", "local")
    monkeypatch.setenv("HF_LLM_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("HF_LLM_MODEL", "test-hf-model")
    monkeypatch.setenv("HF_LLM_DEPLOYMENT", "remote")
    monkeypatch.setenv("LLM_ALLOW_CROSS_DEPLOYMENT_FALLBACK", "true")

    router = ModelRouter.from_env()

    assert router.allow_cross_deployment_fallback is True
    assert router.context_length is None
