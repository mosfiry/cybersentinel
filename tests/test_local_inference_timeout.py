from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent.local_runtime.catalog import get_model
from agent.local_runtime.runtime import LlamaCppRuntime
from agent.providers import OpenAICompatibleProvider


def _fake_http_response(*, timeout_calls: list[float]):
    def request(_url, *, method, headers, body, timeout, max_response_bytes, allow_loopback):
        assert method == "POST"
        assert isinstance(headers, dict)
        assert body
        assert max_response_bytes > 0
        assert allow_loopback is True
        timeout_calls.append(timeout)
        return SimpleNamespace(
            status=200,
            body=b'{"choices":[{"message":{"content":"verified"},"finish_reason":"stop"}]}',
            headers={},
        )

    return request


def test_provider_request_timeout_is_bounded_and_per_call_override_wins(monkeypatch):
    timeouts: list[float] = []
    monkeypatch.setattr("agent.providers.pinned_http_request", _fake_http_response(timeout_calls=timeouts))

    remote = OpenAICompatibleProvider(
        "remote",
        "https://provider.example/v1",
        "remote-model",
        tool_calling=True,
    )
    remote.tool_calling([{"role": "user", "content": "test"}], [])
    assert remote.request_timeout_seconds == 90
    assert timeouts[-1] == 90

    local = OpenAICompatibleProvider(
        "local_llama_cpp",
        "http://127.0.0.1:9000/v1",
        "qwen3-4b-q4-k-m",
        tool_calling=True,
        request_timeout_seconds=240,
    )
    local.tool_calling([{"role": "user", "content": "test"}], [])
    assert timeouts[-1] == 240

    local.tool_calling([{"role": "user", "content": "test"}], [], timeout=11)
    assert timeouts[-1] == 11


def test_local_qwen_disables_reasoning_by_default_but_preserves_explicit_override(monkeypatch):
    payloads: list[dict] = []

    def request(_url, *, method, headers, body, timeout, max_response_bytes, allow_loopback):
        assert method == "POST" and allow_loopback is True
        payloads.append(__import__("json").loads(body.decode("utf-8")))
        return SimpleNamespace(
            status=200,
            body=b'{"choices":[{"message":{"content":"verified"},"finish_reason":"stop"}]}',
            headers={},
        )

    monkeypatch.setattr("agent.providers.pinned_http_request", request)
    qwen = OpenAICompatibleProvider(
        "local_llama_cpp",
        "http://127.0.0.1:9000/v1",
        "qwen3-4b-q4-k-m",
        tool_calling=True,
        deployment="local",
        disable_qwen_thinking=True,
    )
    qwen.tool_calling([{"role": "user", "content": "test"}], [])
    assert payloads[-1]["chat_template_kwargs"] == {"enable_thinking": False}

    qwen.tool_calling(
        [{"role": "user", "content": "test"}], [],
        chat_template_kwargs={"enable_thinking": True},
    )
    assert payloads[-1]["chat_template_kwargs"] == {"enable_thinking": True}

    remote = OpenAICompatibleProvider("remote", "https://provider.example/v1", "qwen3-remote", tool_calling=True)
    remote.tool_calling([{"role": "user", "content": "test"}], [])
    assert "chat_template_kwargs" not in payloads[-1]

    with pytest.raises(ValueError, match="restricted to the managed local Qwen provider"):
        OpenAICompatibleProvider(
            "remote",
            "https://provider.example/v1",
            "qwen3-remote",
            disable_qwen_thinking=True,
        )


def test_model_manager_smoke_inference_uses_managed_provider_timeout(tmp_path):
    from agent.local_runtime.manager import LocalModelManager
    from agent.model_router import ModelRouter

    spec = get_model("qwen3-4b-q4-k-m")
    captured: dict[str, object] = {}

    class FakeRuntime:
        pass

    class FakeProvider:
        name = "local_llama_cpp"
        model = spec.model_id
        request_timeout_seconds = 240

        def generate(self, _messages, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                text="CYBERSENTINEL_LOCAL_OK",
                provider=self.name,
                model=self.model,
            )

    provider = FakeProvider()
    router = ModelRouter([])
    manager = LocalModelManager(tmp_path / "model-state", runtime=FakeRuntime(), router=router)
    manager._state["active_model_id"] = spec.model_id
    manager._state["runtime"] = {"status": "ready", "model_id": spec.model_id, "error": ""}
    manager._active_provider = provider

    result = manager.test_inference()

    assert result["real_inference"] is True
    assert captured["timeout"] == 240.0
    assert captured["chat_template_kwargs"] == {"enable_thinking": False}


@pytest.mark.parametrize("value", [True, 0, -1, 601, float("nan"), float("inf")])
def test_provider_rejects_invalid_default_timeout(value):
    with pytest.raises(ValueError, match="between 1 and 600"):
        OpenAICompatibleProvider(
            "test",
            "https://provider.example/v1",
            "model",
            request_timeout_seconds=value,
        )


@pytest.mark.parametrize("value", [True, 0, -1, 601, float("nan"), float("inf")])
def test_llama_runtime_rejects_invalid_inference_timeout(tmp_path, value):
    with pytest.raises(ValueError, match="between 1 and 600"):
        LlamaCppRuntime(tmp_path, inference_timeout_seconds=value)


def test_managed_llama_runtime_passes_bounded_timeout_to_its_provider(tmp_path, monkeypatch):
    from agent.local_runtime import runtime as runtime_module

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    binary = runtime_dir / "llama-server"
    binary.write_text("fixture executable placeholder", encoding="utf-8")

    class FakeProcess:
        def __init__(self):
            self.returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = 0

        def wait(self, timeout=None):
            return self.returncode or 0

        def kill(self):
            self.returncode = -9

    class HealthResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    process = FakeProcess()
    monkeypatch.setattr(runtime_module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(LlamaCppRuntime, "_free_loopback_port", staticmethod(lambda: 32123))
    monkeypatch.setattr(runtime_module.urllib.request, "urlopen", lambda *_args, **_kwargs: HealthResponse())

    runtime = LlamaCppRuntime(runtime_dir)
    provider = runtime.start(get_model("qwen3-4b-q4-k-m"), tmp_path / "verified-model.gguf")
    try:
        assert provider.name == "local_llama_cpp"
        assert provider.model == "qwen3-4b-q4-k-m"
        assert provider.request_timeout_seconds == 240
    finally:
        runtime.stop()
