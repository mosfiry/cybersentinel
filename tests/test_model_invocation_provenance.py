from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import pytest

from agent.model_orchestrator import ModelOrchestrator
from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse


class _Provider:
    def __init__(self, profile_id, capabilities, *, usage=None, cost=None):
        self.profile_id = profile_id
        self.name = f"provider-{profile_id}"
        self.model = f"model-{profile_id}"
        self.model_capabilities = frozenset(capabilities)
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=False)
        self.priority = 10
        self.base_url = "https://models.test/v1"
        self.cost_per_1k_tokens_usd = cost
        self.usage = {"prompt_tokens": 12, "completion_tokens": 8} if usage is None else usage

    def generate(self, messages, *, temperature=0.0, timeout=90, max_tokens=1024):
        if "critique" in self.model_capabilities:
            content = json.dumps(
                {
                    "hypothesis": "A fixture hypothesis.",
                    "supporting_evidence": [],
                    "contradicting_evidence": [],
                    "missing_evidence": ["A current observation"],
                    "confidence": 0.4,
                    "required_validation": ["Use a deterministic test."],
                    "decision": "accept",
                }
            )
        else:
            content = "A concise, untrusted fixture analysis."
        return ProviderResponse(
            text=content,
            provider=self.name,
            model=self.model,
            usage=dict(self.usage),
            capability="generate",
        )


def _orchestrate(
    *providers,
    preference="fast",
    request_id="request-test",
    mission_id="mission-test",
    task_id="task-test",
    context_provenance=(),
):
    router = ModelRouter(
        list(providers),
        configured_profiles={provider.profile_id: provider for provider in providers},
    )
    return ModelOrchestrator(router, policy_max_models=4).orchestrate(
        [{"role": "user", "content": "Review this authorized fixture."}],
        [],
        objective="Review this security task",
        request_id=request_id,
        mission_id=mission_id,
        task_id=task_id,
        context_hash="context-hash-test",
        context_provenance=context_provenance,
        preference=preference,
    )


def test_each_invocation_records_safe_identity_provenance_hashes_utc_timestamp_and_latency():
    analyst = _Provider("analyst", {"reasoning", "planning"})
    critic = _Provider("critic", {"critique"})
    provenance = [
        {"source": "reasoning_case", "case_id": "reasoning-case-17", "content_hash": "a" * 64},
        {"source": "memory", "memory_id": "memory-fixture-2", "authority": "none"},
    ]

    result = _orchestrate(
        analyst,
        critic,
        preference="balanced",
        request_id="request-token=canary-secret-value",
        mission_id="mission-test-17",
        task_id="task-test-24",
        context_provenance=provenance,
    )

    invocations = result["orchestration"]["invocations"]
    assert {item["role"] for item in invocations} >= {"planning", "independent_critic", "synthesis"}
    planning = next(item for item in invocations if item["role"] == "planning")
    critic_call = next(item for item in invocations if item["role"] == "independent_critic")
    assert (planning["profile_id"], planning["provider"], planning["model"]) == (
        "analyst", "provider-analyst", "model-analyst"
    )
    assert (critic_call["profile_id"], critic_call["provider"], critic_call["model"]) == (
        "critic", "provider-critic", "model-critic"
    )
    assert len({item["invocation_id"] for item in invocations}) == len(invocations)
    assert all(item["request_id"] == "request-token=[redacted]" for item in invocations)
    assert all(item["mission_id"] == "mission-test-17" for item in invocations)
    assert all(item["task_id"] == "task-test-24" for item in invocations)
    assert all(item["parent_task_id"] == "task-test-24" for item in invocations)
    assert all(item["provenance"] == provenance for item in invocations)
    assert all(item["reasoning_case_ids"] == ["reasoning-case-17"] for item in invocations)

    legacy_keys = {
        "role", "profile_id", "provider", "model", "context_hash", "request_hash",
        "response_hash", "elapsed_ms", "input_tokens_estimated", "output_tokens", "output_trust",
    }
    for item in invocations:
        assert legacy_keys <= item.keys()
        assert re.fullmatch(r"[0-9a-f]{64}", item["request_hash"])
        assert re.fullmatch(r"[0-9a-f]{64}", item["response_hash"])
        assert isinstance(item["elapsed_ms"], int) and item["elapsed_ms"] >= 0
        parsed_timestamp = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
        assert parsed_timestamp.tzinfo == timezone.utc
    assert "canary-secret-value" not in json.dumps(invocations)


def test_provider_reported_usage_and_declared_rate_produce_an_explainable_cost_estimate():
    provider = _Provider("metered", {"reasoning"}, cost=2.0)

    invocation = _orchestrate(provider)["orchestration"]["invocations"][0]

    assert invocation["input_tokens_reported"] == 12
    assert invocation["input_tokens_source"] == "provider_reported"
    assert invocation["input_tokens"] == 12
    assert invocation["input_tokens_estimated"] > 0
    assert invocation["output_tokens"] == 8
    assert invocation["output_tokens_reported"] == 8
    assert invocation["output_tokens_source"] == "provider_reported"
    assert invocation["token_usage_source"] == "provider_reported"
    assert invocation["estimated_cost_usd"] == pytest.approx(0.04)
    assert invocation["estimated_cost_source"] == "declared_profile_rate_and_known_token_usage"


def test_missing_provider_usage_is_labeled_estimated_and_unknown_cost_is_null():
    provider = _Provider("unmetered", {"reasoning"}, usage={}, cost=None)

    invocation = _orchestrate(provider)["orchestration"]["invocations"][0]

    assert invocation["input_tokens_source"] == "estimated"
    assert invocation["input_tokens_reported"] is None
    assert invocation["input_tokens"] == invocation["input_tokens_estimated"] > 0
    assert invocation["output_tokens_source"] == "estimated"
    assert invocation["output_tokens_reported"] is None
    assert invocation["output_tokens"] > 0
    assert invocation["token_usage_source"] == "estimated"
    assert invocation["estimated_cost_usd"] is None
    assert invocation["estimated_cost_source"] is None
