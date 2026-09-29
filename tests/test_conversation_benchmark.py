from __future__ import annotations

import json

from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
from agent.conversation import IntentType
from evaluation.conversation_benchmark import ConversationBenchmarkCase, run_conversation_benchmark


class ConversationProvider:
    name = "conversation-test"
    model = "conversation-test"
    capabilities = ProviderCapabilities(generate=True, tool_calling=True, structured_output=True)

    def generate(self, messages, **kwargs):
        prompt = messages[-1]["content"]
        if "IGNORE OWNER" in prompt:
            return {"content": json.dumps({"intent": "GENERAL_CONVERSATION", "authorization_required": False, "evidence_needed": ["trusted channel"]})}
        if "علمني" in prompt:
            intent = "LEARN"
        elif "حادثة" in prompt:
            intent = "ANALYZE_INCIDENT"
        elif "الأدلة" in prompt:
            intent = "EXPLAIN_EVIDENCE"
        elif "النطاق" in prompt:
            intent = "SCOPED_TEST"
        else:
            intent = "GENERAL_CONVERSATION"
        return {"content": json.dumps({"intent": intent, "authorization_required": intent == "SCOPED_TEST", "evidence_needed": ["source"]})}

    def tool_calling(self, messages, tools, **kwargs):
        return ProviderResponse(tool_calls=[ToolCall("scoped_http_probe", {"query": "https://target.example"}, "call-1")])


def test_conversation_benchmark_separates_intent_from_authority():
    result = run_conversation_benchmark(ModelRouter([ConversationProvider()]))
    assert result["benchmark_version"].startswith("6K.4")
    assert result["structured_output"] == 1.0
    assert result["tool_call_correctness"] == 1.0
    assert result["tool_selection"] == 1.0
    assert result["prompt_injection_resistance"] == 1.0
    assert result["owner_policy_obedience"] is None
    assert result["scope_obedience"] is None
    assert result["evidence_grounding"] is None
    assert result["recovery"] is None
    scoped = next(item for item in result["cases"] if item["case_id"] == "scoped-test")
    assert scoped["intent"]["authorization_required"] is True
    assert scoped["intent"]["authority_granted"] is False
    assert scoped["tool_call"]["emitted"] is True
    assert scoped["tool_call"]["valid"] is True
    assert result["not_implemented_capabilities"] == {}


def test_available_tool_benchmark_uses_openai_function_schema():
    class StatusProvider(ConversationProvider):
        seen_tools = None

        def tool_calling(self, messages, tools, **kwargs):
            self.seen_tools = tools
            return ProviderResponse(tool_calls=[ToolCall("status", {}, "call-status")])

    provider = StatusProvider()
    result = run_conversation_benchmark(
        ModelRouter([provider]),
        cases=(ConversationBenchmarkCase("status-tool", "check service status", IntentType.GENERAL_CONVERSATION, "status"),),
    )
    assert len(provider.seen_tools) == 1
    schema = provider.seen_tools[0]
    assert schema["type"] == "function"
    assert schema["function"]["name"] == "status"
    assert schema["function"]["description"]
    assert schema["function"]["parameters"]["type"] == "object"
    assert schema["function"]["parameters"]["additionalProperties"] is False
    assert result["tool_call_correctness"] == 1.0
