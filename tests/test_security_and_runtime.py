import json

from agent.runtime import AgentRuntime
from agent.model_router import ModelRouter
from security.authorization import authorize_plan, authorize_tool


class FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, content):
        self.content = content

    def status(self):
        return {"name": self.name, "model": self.model, "configured": True, "failure_count": 0, "last_error": ""}

    def chat(self, messages, temperature=0):
        assert any("CURRENT AUTHENTICATED OWNER POLICY CONTEXT" in m["content"] for m in messages if m["role"] == "system")
        return {"content": self.content, "provider": self.name, "model": self.model}


def test_unknown_tool_and_bad_arguments_are_rejected():
    assert not authorize_tool("something_dangerous").allowed
    assert not authorize_tool(["search", {"arbitrary": "object"}]).allowed
    assert not authorize_tool(["search", "x" * 257]).allowed
    accepted, errors = authorize_plan(["status", ["search", "CVE-2026"]])
    assert not accepted
    assert errors
    assert all("INV-AUTH-3" in error for error in errors)


def test_runtime_validates_model_plan_and_preserves_provenance():
    router = ModelRouter([FakeProvider(json.dumps({"tools": [["search", "apache"]], "rationale": "read-only search"}))])
    result = AgentRuntime(router).plan("Owner ابحث عن apache")
    assert result["tools"] == [["search", "apache"]]
    assert result["provider"] == "fake"
    assert result["model"] == "fake-model"


def test_runtime_falls_back_deterministically_on_invalid_model_json():
    router = ModelRouter([FakeProvider("not json")])
    result = AgentRuntime(router).plan("Owner افحص الجهاز محليًا")
    assert result["planner"] == "local"
    assert result["tools"] == ["local_security_check"]
    assert result["fallback_reason"]
