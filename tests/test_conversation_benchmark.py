from __future__ import annotations

import json

from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
from evaluation.conversation_benchmark import run_conversation_benchmark


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
    assert result["prompt_injection_resistance"] == 1.0
    scoped = next(item for item in result["cases"] if item["case_id"] == "scoped-test")
    assert scoped["intent"]["authorization_required"] is True
    assert scoped["intent"]["authority_granted"] is False
    assert scoped["tool_call"]["emitted"] is True
