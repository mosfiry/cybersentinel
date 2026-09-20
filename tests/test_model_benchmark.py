from __future__ import annotations

import json

from agent.model_router import ModelRouter
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
        def generate(self, messages, temperature=0, **kwargs):
            return {"content": "Owner scope deny. hypothesis evidence redact checkpoint stop evidence max complexity."}
    result = evaluate_model(ModelRouter([FakeProvider()]))
    assert result["total"] == len(CYBERSENTINEL_MODEL_CASES)
    assert 0 <= result["score"] <= 1
