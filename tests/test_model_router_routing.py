import pytest

from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderFailureKind, ProviderResponse


class FakeProvider:
    def __init__(self, name, model, outcomes, *, tool_calling=False, enabled=True):
        self.name = name
        self.model = model
        self.outcomes = list(outcomes)
        self.calls = []
        self.enabled = enabled
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=tool_calling)

    def generate(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_single_provider_success_and_provenance_overwrites_forged_metadata():
    provider = FakeProvider("qwen", "qwen-model", [ProviderResponse(text="ok", provider="forged", model="forged")])
    result = ModelRouter([provider]).generate([{"role": "user", "content": "hello"}])
    assert result["content"] == "ok"
    assert result["provider"] == "qwen"
    assert result["model"] == "qwen-model"


def test_model_refusal_is_classified_and_falls_back_without_changing_kwargs():
    first = FakeProvider("qwen", "qwen-model", [ProviderResponse(finish_reason="refusal")])
    second = FakeProvider("deepseek", "deepseek-model", [ProviderResponse(text="safe fallback")])
    messages = [{"role": "user", "content": "request"}]
    result = ModelRouter([first, second]).generate(messages, authorization_snapshot="fixed", scope="same")
    assert result["content"] == "safe fallback"
    assert second.calls[0][1]["authorization_snapshot"] == "fixed"
    assert second.calls[0][1]["scope"] == "same"
    assert first.calls[0][1]["scope"] == "same"
    assert ModelRouter._classify(ProviderResponse(finish_reason="stop") if False else RuntimeError("refusal"), first).kind is ProviderFailureKind.MODEL_REFUSAL


def test_failure_taxonomy_distinguishes_timeout_rate_limit_auth_context_and_unavailable():
    router = ModelRouter([])
    provider = FakeProvider("x", "m", [])
    cases = {
        TimeoutError("network timeout"): ProviderFailureKind.TIMEOUT,
        RuntimeError("429 rate limit"): ProviderFailureKind.RATE_LIMIT,
        PermissionError("unauthorized"): ProviderFailureKind.AUTHENTICATION_FAILURE,
        RuntimeError("context length overflow"): ProviderFailureKind.CONTEXT_OVERFLOW,
        RuntimeError("provider unavailable"): ProviderFailureKind.PROVIDER_UNAVAILABLE,
    }
    for error, expected in cases.items():
        assert router._classify(error, provider).kind is expected


def test_capability_mismatch_is_not_silently_downgraded_to_tool_execution():
    provider = FakeProvider("text-only", "m", [ProviderResponse(text="ignored")], tool_calling=False)
    with pytest.raises(Exception) as exc:
        ModelRouter([provider]).tool_calling([], [{"name": "status"}])
    assert "tool calling" in str(exc.value).lower()
    assert provider.calls == []


def test_profiles_are_configuration_metadata_only():
    provider = FakeProvider("openai-compatible", "model-a", [], tool_calling=True)
    profile = ModelRouter([provider]).profiles[0]
    assert profile.provider == "openai-compatible"
    assert profile.model == "model-a"
    assert profile.tool_calling is True
    assert profile.enabled is True
