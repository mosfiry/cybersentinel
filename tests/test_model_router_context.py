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
)


def _clear_provider_env(monkeypatch):
    for prefix in ("LOCAL", "COLAB", "HF"):
        for suffix in _PROVIDER_ENV_SUFFIXES:
            monkeypatch.delenv(f"{prefix}_{suffix}", raising=False)
    for suffix in _PROVIDER_ENV_SUFFIXES:
        monkeypatch.delenv(suffix, raising=False)


def test_router_uses_minimum_declared_context_window_for_fallbacks():
    router = ModelRouter([
        SimpleNamespace(context_length=8192),
        SimpleNamespace(context_length=4096),
    ])
    assert router.context_length == 4096


def test_router_disables_shared_window_when_any_fallback_window_is_unknown():
    router = ModelRouter([
        SimpleNamespace(context_length=8192),
        SimpleNamespace(context_length=None),
    ])
    assert router.context_length is None


def test_from_env_loads_configured_local_context_length(monkeypatch):
    _clear_provider_env(monkeypatch)
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "test-local-model")
    monkeypatch.setenv("LOCAL_LLM_CONTEXT_LENGTH", "8192")

    router = ModelRouter.from_env()

    assert len(router.providers) == 1
    assert router.providers[0].context_length == 8192
    assert router.context_length == 8192


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


def test_from_env_does_not_treat_one_known_provider_as_router_wide_limit(monkeypatch):
    _clear_provider_env(monkeypatch)
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "test-local-model")
    monkeypatch.setenv("LOCAL_LLM_CONTEXT_LENGTH", "8192")
    monkeypatch.setenv("HF_LLM_BASE_URL", "http://127.0.0.1:5678/v1")
    monkeypatch.setenv("HF_LLM_MODEL", "test-hf-model")

    router = ModelRouter.from_env()

    assert len(router.providers) == 2
    assert router.context_length is None
