from __future__ import annotations

import json

import pytest

from agent.model_router import ModelRouter, ModelSelectionError
from agent.provider_api import ProviderCapabilities, ProviderFailure
from agent.providers import OpenAICompatibleProvider


class RecordingProvider:
    def __init__(self, profile_id: str, *, model: str, result=None, error=None):
        self.profile_id = profile_id
        self.name = profile_id
        self.model = model
        self.base_url = f"http://127.0.0.1/{profile_id}"
        self.priority = 10
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True, native_chat=True)
        self.result = result or {"content": "ok"}
        self.error = error
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


def _clear_model_environment(monkeypatch):
    for prefix in ("LOCAL_LLM", "COLAB_LLM", "HF_LLM", "LLM"):
        for suffix in ("BASE_URL", "MODEL", "API_KEY", "TOOL_CALLING", "STREAMING", "STRUCTURED_OUTPUT", "PRIORITY"):
            monkeypatch.delenv(f"{prefix}_{suffix}", raising=False)


def test_catalog_is_sanitized_and_auto_keeps_existing_failover_order(monkeypatch):
    _clear_model_environment(monkeypatch)
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "Qwen/Qwen3-Coder-Next")
    monkeypatch.setenv("LOCAL_LLM_API_KEY", "api-secret-canary")
    monkeypatch.setenv("COLAB_LLM_BASE_URL", "https://gateway.example/v1")
    monkeypatch.setenv("COLAB_LLM_MODEL", "remote/model-v2")
    monkeypatch.setenv("COLAB_LLM_API_KEY", "remote-secret-canary")
    monkeypatch.setenv("LLM_BASE_URL", "http://10.2.3.4:9000/v1")
    monkeypatch.setenv("LLM_MODEL", "default-model")

    router = ModelRouter.from_env()
    catalog = router.catalog()
    encoded = json.dumps(catalog, sort_keys=True)

    assert [provider.profile_id for provider in router.providers] == ["local", "colab"]
    assert [entry["id"] for entry in catalog] == ["auto", "local", "colab", "default"]
    assert catalog[0]["mode"] == "auto"
    assert catalog[1]["private_endpoint"] is True
    assert catalog[1]["adapter"] == "openai_compatible_http"
    assert catalog[2]["private_endpoint"] is False
    assert catalog[3]["private_endpoint"] is True
    assert "127.0.0.1" not in encoded
    assert "10.2.3.4" not in encoded
    assert "gateway.example" not in encoded
    assert "api-secret-canary" not in encoded
    assert "remote-secret-canary" not in encoded
    assert all("api_key" not in entry and "base_url" not in entry for entry in catalog)


def test_catalog_redacts_endpoint_like_or_secret_bearing_model_labels(monkeypatch):
    _clear_model_environment(monkeypatch)
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://192.168.1.2:8000/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "https://user:pass@example.test/model?api_key=hidden")
    monkeypatch.setenv("LOCAL_LLM_API_KEY", "different-hidden-key")

    entry = ModelRouter.from_env().catalog()[1]
    rendered = json.dumps(entry, sort_keys=True)

    assert "example.test" not in rendered
    assert "hidden" not in rendered
    assert "different-hidden-key" not in rendered


@pytest.mark.parametrize(
    ("base_url", "expected"),
    [
        ("http://127.0.0.1:8000/v1", True),
        ("http://10.20.30.40:8000/v1", True),
        ("https://[fd00::2]:8000/v1", True),
        ("http://localhost:8000/v1", True),
        ("http://inference.localhost:8000/v1", True),
        ("https://models.example.test/v1", False),
        ("https://8.8.8.8/v1", False),
    ],
)
def test_local_endpoint_label_requires_private_address_or_reserved_localhost(base_url, expected):
    provider = OpenAICompatibleProvider("local", base_url, "model", profile_id="local")
    router = ModelRouter([provider], configured_profiles={"local": provider})

    assert router.catalog()[1]["private_endpoint"] is expected


def test_auto_mode_keeps_configured_failover_but_explicit_local_does_not():
    failing = RecordingProvider("local", model="local-model", error=RuntimeError("fixture failure"))
    succeeding = RecordingProvider("colab", model="remote-model")
    router = ModelRouter(
        [failing, succeeding],
        configured_profiles={"local": failing, "colab": succeeding},
    )

    auto_router, auto_selection = router.with_model_selection("auto")
    assert auto_router is router
    assert auto_selection["mode"] == "auto"
    assert auto_router.generate([])["content"] == "ok"
    assert (failing.calls, succeeding.calls) == (1, 1)

    failing.calls = succeeding.calls = 0
    local_router, selection = router.with_model_selection("local")
    assert selection["profile_id"] == "local"
    assert local_router.providers == [failing]
    with pytest.raises(ProviderFailure, match="automatic failover is disabled"):
        local_router.generate([])
    assert (failing.calls, succeeding.calls) == (1, 0)


def test_model_selection_rejects_unknown_ids_and_configuration_drift():
    provider = RecordingProvider("local", model="model-v1")
    router = ModelRouter([provider], configured_profiles={"local": provider})
    selected, metadata = router.with_model_selection("local")

    assert selected.providers == [provider]
    assert metadata["profile_fingerprint"]
    with pytest.raises(ModelSelectionError) as invalid:
        router.with_model_selection("https://arbitrary.example/v1")
    assert invalid.value.code == "invalid_model_id"

    replacement = RecordingProvider("local", model="model-v2")
    changed = ModelRouter([replacement], configured_profiles={"local": replacement})
    with pytest.raises(ModelSelectionError) as drift:
        changed.with_model_selection("local", expected_fingerprint=metadata["profile_fingerprint"])
    assert drift.value.code == "selected_model_configuration_changed"


def test_authenticated_catalog_api_rejects_missing_owner_and_returns_only_safe_fields(monkeypatch):
    import api.models as models_api

    provider = OpenAICompatibleProvider(
        "local",
        "http://127.0.0.1:8000/v1",
        "private-model",
        "catalog-api-key-canary",
        profile_id="local",
    )
    router = ModelRouter([provider], configured_profiles={"local": provider})
    monkeypatch.setattr(models_api.owner_password, "resolve_session", lambda _token: None)
    with pytest.raises(PermissionError, match="owner authentication required"):
        models_api.model_catalog("missing", router=router)

    monkeypatch.setattr(
        models_api.owner_password,
        "resolve_session",
        lambda token: {"session_id": token, "auth_method": "username_password"},
    )
    result = models_api.model_catalog("valid", router=router)
    encoded = json.dumps(result, sort_keys=True)
    assert result["models"][0]["id"] == "auto"
    assert result["models"][1]["id"] == "local"
    assert "base_url" not in encoded
    assert "127.0.0.1" not in encoded
    assert "catalog-api-key-canary" not in encoded


def test_browser_model_request_accepts_only_catalog_id_not_provider_configuration():
    from api.models import requested_model_id

    assert requested_model_id({}) == "auto"
    assert requested_model_id({"model_id": "local"}) == "local"
    for field, value in (
        ("base_url", "http://attacker.invalid/v1"),
        ("api_key", "secret-canary"),
        ("provider", "arbitrary-provider"),
        ("model_selection", {"profile_id": "local"}),
    ):
        with pytest.raises(ValueError, match="only_model_id_is_accepted"):
            requested_model_id({"model_id": "local", field: value})
