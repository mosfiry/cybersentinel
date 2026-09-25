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
    # INV-AUTH-3: authorize_plan is fail-closed without a typed
    # AuthorizationContext; an untyped request authorizes nothing.
    assert accepted == []
    assert list(errors) == [
        "untyped authorization request rejected: typed AuthorizationContext required (INV-AUTH-3)",
        "untyped authorization request rejected: typed AuthorizationContext required (INV-AUTH-3)",
    ]


def test_runtime_model_plan_fails_closed_without_typed_context():
    # INV-AUTH-3: a model-proposed plan can no longer authorize itself
    # structurally. The planner fails closed to the deterministic fallback and
    # records the deterministic rejection reason.
    router = ModelRouter([FakeProvider(json.dumps({"tools": [["search", "apache"]], "rationale": "read-only search"}))])
    result = AgentRuntime(router).plan("Owner ابحث عن apache")
    assert result["planner"] == "local"
    assert result["provider"] == "local"
    assert result["model"] == "deterministic"
    assert result["tools"] == [["search", "apache"]]
    assert "INV-AUTH-3" in result["fallback_reason"]


def test_runtime_falls_back_deterministically_on_invalid_model_json():
    router = ModelRouter([FakeProvider("not json")])
    result = AgentRuntime(router).plan("Owner افحص الجهاز محليًا")
    assert result["planner"] == "local"
    assert result["tools"] == ["local_security_check"]
    assert result["fallback_reason"]
