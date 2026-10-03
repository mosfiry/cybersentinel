from __future__ import annotations

import json

import pytest

from agent.mission import Mission
from agent.model_intelligence.context import COMPACTED_TOOL_METADATA, ContextAssembler
from agent.model_protocol import RouterNativeModel
from agent.model_router import ModelRouter
from agent.planning import Plan
from agent.provider_api import CapabilityUnsupported, ProviderCapabilities, ProviderFailure, ProviderResponse, ToolCall


class UnsupportedProvider:
    name = "text-only"
    model = "text-1"
    capabilities = ProviderCapabilities(generate=True, tool_calling=False)

    def generate(self, messages, **kwargs):
        return {"content": json.dumps({"type": "final", "content": "compatibility"})}


class BrokenNativeProvider:
    name = "native-broken"
    model = "native-1"
    capabilities = ProviderCapabilities(generate=True, tool_calling=True, native_chat=True)

    def __init__(self):
        self.generate_calls = 0

    def tool_calling(self, messages, tools, **kwargs):
        raise TimeoutError("upstream timeout")

    def generate(self, messages, **kwargs):
        self.generate_calls += 1
        return {"content": "must not be used after native failure"}


def test_capability_unsupported_is_rejected_by_default():
    model = RouterNativeModel(ModelRouter([UnsupportedProvider()]))
    with pytest.raises(CapabilityUnsupported):
        model.complete([], [], mission_id="m", run_id="r", turn_id="t", plan_version=1)


def test_capability_unsupported_uses_generate_only_with_explicit_opt_in():
    model = RouterNativeModel(ModelRouter([UnsupportedProvider()]), allow_generate_fallback=True)
    turn = model.complete([], [], mission_id="m", run_id="r", turn_id="t", plan_version=1)
    assert turn.content == json.dumps({"type": "final", "content": "compatibility"})
    assert turn.provider == "text-only"
    assert turn.model == "text-1"
    assert turn.capability == "generate"


def test_router_native_model_uses_configured_provider_identity_not_response_claims():
    class ForgedIdentityProvider:
        name = "configured-provider"
        model = "configured-model"
        capabilities = ProviderCapabilities(generate=True, tool_calling=True)

        def tool_calling(self, _messages, _tools, **_kwargs):
            return {
                "content": "safe response",
                "provider": "attacker-provider",
                "model": "attacker-model",
                "capability": "tool_calling",
            }

    turn = RouterNativeModel(ModelRouter([ForgedIdentityProvider()])).complete(
        [], [], mission_id="m", run_id="r", turn_id="t", plan_version=1
    )

    assert turn.provider == "configured-provider"
    assert turn.model == "configured-model"
    assert turn.capability == "tool_calling"


def test_native_provider_failure_does_not_fallback_to_generate():
    provider = BrokenNativeProvider()
    router = ModelRouter([provider])
    with pytest.raises(ProviderFailure) as error:
        RouterNativeModel(router).complete([], [], mission_id="m", run_id="r", turn_id="t", plan_version=1)
    assert "TIMEOUT" in str(error.value)
    assert provider.generate_calls == 0
    assert router.last_trace[0]["failure_kind"] == "TIMEOUT"


def test_compacted_metadata_is_not_replayed_as_tool_result():
    mission = Mission.create("owner objective", "owner objective", Plan.initial("owner objective"), mission_id="mission-1", request_id="request-1", owner_instruction="owner objective", policy_snapshot={"policy": "authoritative"})
    mission.transition(__import__("agent.mission", fromlist=["MissionStatus"]).MissionStatus.READY, "ready")
    mission.scope_snapshot = {"snapshot_id": "scope-1", "allowed_targets": ["target-1"]}
    results = [{"record_type": "LIVE_TOOL_RESULT", "tool_call_id": f"call-{i}", "name": "status", "arguments": {}, "result": {"success": True, "value": "x" * 200}} for i in range(12)]
    assembled = ContextAssembler().build(mission, tool_results=results, tools=[{"name": "status"}], max_chars=3000)
    assert assembled.compacted is True
    assert assembled.sections["mission"]["mission_id"] == "mission-1"
    assert assembled.sections["owner"]["instruction"] == "owner objective"
    assert any(item.get("record_type") == COMPACTED_TOOL_METADATA for item in assembled.sections["tool"])
    assert all(message.role != "tool" or message.tool_call_id not in {f"call-{i}" for i in range(12) if i < assembled.compacted_items} for message in assembled.messages)
    assert all(item.get("record_type") == "LIVE_TOOL_RESULT" for item in assembled.sections["tool"] if item.get("record_type") != COMPACTED_TOOL_METADATA)
    assert assembled.sections["compaction"]["metadata_is_untrusted"] is True
    assert assembled.context_chars <= 3000
