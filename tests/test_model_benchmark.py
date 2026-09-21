from __future__ import annotations

import json

from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
from agent.providers import OpenAICompatibleProvider
from evaluation.model_benchmark import CYBERSENTINEL_MODEL_CASES, evaluate_model, score_response


def test_local_provider_is_first_when_configured(monkeypatch):
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "Qwen/Qwen3-Coder-Next")
    monkeypatch.setenv("LOCAL_LLM_TOOL_CALLING", "true")
    monkeypatch.setenv("LOCAL_LLM_PRIORITY", "1")
    monkeypatch.setenv("HF_LLM_BASE_URL", "http://127.0.0.1:9000/v1")
    monkeypatch.setenv("HF_LLM_MODEL", "other")
    monkeypatch.setenv("HF_LLM_PRIORITY", "50")
    router = ModelRouter.from_env()
    assert router.providers[0].name == "local"
    assert router.providers[0].model == "Qwen/Qwen3-Coder-Next"
    assert router.providers[0].capabilities.tool_calling is True


def test_benchmark_scores_tool_and_policy_properties():
    assert len(CYBERSENTINEL_MODEL_CASES) >= 5
    result = score_response(CYBERSENTINEL_MODEL_CASES[1], {"content": "Owner policy controls scope; deny the outside target."})
    assert result["passed"] is True


def test_benchmark_runs_against_router():
    class FakeProvider:
        name = "benchmark-fake"
        model = "benchmark-fake"
        capabilities = ProviderCapabilities(generate=True, tool_calling=True, structured_output=False)
        def generate(self, messages, temperature=0, **kwargs):
            return {"content": "Owner scope deny. hypothesis evidence redact checkpoint stop evidence max complexity."}
        def tool_calling(self, messages, tools, temperature=0, **kwargs):
            return ProviderResponse(tool_calls=[ToolCall("scoped_http_probe", {"query": "https://target.example.com/api"}, "bench-1")])
    result = evaluate_model(ModelRouter([FakeProvider()]), scope_context={"program_id": "p", "target_id": "t", "scope_snapshot_id": "s", "url": "https://target.example.com/api"})
    assert result["benchmark_version"].startswith("6A.1")
    assert len(result["cases"]) == len(CYBERSENTINEL_MODEL_CASES)
    assert "tool_selection_accuracy" in result


def test_tool_calling_does_not_imply_structured_output(monkeypatch):
    provider = OpenAICompatibleProvider("x", "http://localhost/v1", "model", tool_calling=True, structured_output=False)
    assert provider.capabilities.tool_calling is True
    assert provider.capabilities.structured_output is False
