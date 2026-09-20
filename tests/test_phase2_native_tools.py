import json

import core.db as db
from agent.loop import AgentLoop, RuntimeLimits, provider_tool_schemas
from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall


class NativeProvider:
    name = "native-a"
    model = "native-model"
    capabilities = ProviderCapabilities(True, True, True, True)

    def __init__(self, responses):
        self.responses = list(responses)
        self.seen = []

    def tool_calling(self, messages, tools, temperature=0, **kwargs):
        self.seen.append((messages, tools))
        return self.responses.pop(0)

    def generate(self, messages, temperature=0, **kwargs):
        return self.responses.pop(0)

    def stream(self, messages, temperature=0, **kwargs):
        yield {"event": "assistant.delta", "data": {"delta": "safe"}}
        yield {"event": "assistant.completed", "data": {"finish_reason": "stop"}}


class FallbackProvider:
    name = "fallback"
    model = "fallback-model"
    capabilities = ProviderCapabilities(True, False, False, False)

    def chat(self, messages, temperature=0):
        return {"content": json.dumps({"type": "final_answer", "content": "fallback answer"}), "provider": "forged", "model": "forged"}


def limits(**overrides):
    value = dict(max_steps=4, max_tool_calls=4, max_execution_time_seconds=90, max_context_messages=40, max_context_chars=24000, max_result_chars=12000)
    value.update(overrides)
    return RuntimeLimits(**value)


def test_native_tool_calling_normalizes_id_and_uses_registry_schema(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "native.sqlite3")
    provider = NativeProvider([
        ProviderResponse(tool_calls=[ToolCall("search", {"query": "CVE-2026"}, "call-1")], finish_reason="tool_calls"),
        ProviderResponse(text="تمت مراجعة الأدلة.", finish_reason="stop"),
    ])
    calls = []
    result = AgentLoop(ModelRouter([provider]), lambda command, **kwargs: calls.append(command) or {"ok": True, "request_id": "r-native"}, limits=limits()).run("native-1", "ابحث عن CVE", owner_token="secret-owner")
    assert result["type"] == "final_answer"
    assert result["activity"][0]["tool_call_id"] == "call-1"
    assert calls == ["Owner search CVE-2026"]
    function = next(item["function"] for item in provider.seen[0][1] if item["function"]["name"] == "search")
    assert function["parameters"]["properties"]["query"]["maxLength"] == 256
    assert "secret-owner" not in json.dumps(provider.seen[0])


def test_multiple_native_calls_respect_runtime_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "multi.sqlite3")
    provider = NativeProvider([
        ProviderResponse(tool_calls=[ToolCall("search", {"query": "a"}, "a"), ToolCall("search", {"query": "b"}, "b"), ToolCall("search", {"query": "c"}, "c")], finish_reason="tool_calls")
    ])
    calls = []
    result = AgentLoop(ModelRouter([provider]), lambda command, **kwargs: calls.append(command) or {"ok": True}, limits=limits(max_tool_calls=2)).run("multi-1", "ابحث", owner_token="owner")
    assert result["type"] == "error"
    assert result["error"] == "max_tool_calls"
    assert len(calls) == 2
    assert [x["tool_call_id"] for x in result["activity"]] == ["a", "b"]


def test_non_native_provider_uses_safe_json_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "fallback.sqlite3")
    result = AgentLoop(ModelRouter([FallbackProvider()]), lambda *args, **kwargs: {}, limits=limits()).run("fallback-1", "حلل", owner_token="owner")
    assert result["type"] == "final_answer"
    assert result["provenance"]["provider"] == "fallback"


def test_router_fails_over_native_provider_without_trusting_forged_metadata():
    class Broken:
        name = "broken"
        model = "broken-model"
        capabilities = ProviderCapabilities(True, False, True, True)
        def tool_calling(self, *args, **kwargs):
            raise ConnectionError("network failure")

    result = ModelRouter([Broken(), FallbackProvider()]).generate([])
    assert result["provider"] == "fallback"
    assert result["model"] == "fallback-model"
    assert result["provider"] != "forged"


def test_streaming_exposes_only_safe_public_events():
    events = list(ModelRouter([NativeProvider([])]).stream([]))
    assert [item["event"] for item in events] == ["assistant.delta", "assistant.completed"]
    assert all("secret" not in json.dumps(item) for item in events)


def test_native_schema_injection_and_invalid_arguments_are_not_executed(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "injection.sqlite3")
    provider = NativeProvider([
        ProviderResponse(tool_calls=[ToolCall("search", {"query": "ok", "extra": "inject"}, "bad")], finish_reason="tool_calls"),
    ])
    calls = []
    result = AgentLoop(ModelRouter([provider]), lambda *args, **kwargs: calls.append(1), limits=limits()).run("inject-1", "ابحث", owner_token="owner")
    assert not calls
    assert result["activity"][0]["status"] == "denied"
