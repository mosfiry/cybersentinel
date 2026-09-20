import importlib
import json

import core.db as db
import security.owner_policy as owner_policy
from agent.loop import AgentLoop, RuntimeLimits, tool_definitions


class FakeRouter:
    def __init__(self):
        self.calls = 0

    def chat(self, messages):
        self.calls += 1
        if self.calls == 1:
            return {"content": json.dumps({"type": "tool_call", "name": "search", "arguments": {"query": "CVE-2026"}}), "provider": "fake", "model": "fake-model"}
        return {"content": json.dumps({"type": "final", "content": "راجعت نتيجة البحث ولم أجد دليلًا كافيًا على اختراق."}), "provider": "fake", "model": "fake-model"}


def test_tool_definitions_are_registry_derived():
    tools = {item["name"]: item for item in tool_definitions()}
    assert "search" in tools
    assert tools["search"]["parameters"]["properties"]["query"]["maxLength"] == 256
    assert tools["red_team_assess"]["owner_required"] is True


def test_agent_loop_executes_validated_tool_and_keeps_conversation_separate(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "conversation.sqlite3")
    calls = []

    def executor(command, *, owner_token, owner_session_id=None):
        calls.append((command, owner_token, owner_session_id))
        return {"ok": True, "request_id": "req-1", "answer": "نتيجة محلية"}

    result = AgentLoop(FakeRouter(), executor).run("conv-1", "ابحث عن CVE-2026", owner_token="owner-secret")
    assert result["conversation_id"] == "conv-1"
    assert result["steps"] == 2
    assert result["activity"][0]["status"] == "completed"
    assert calls == [("Owner search CVE-2026", "owner-secret", None)]
    messages = db.conversation_messages("conv-1")
    assert [item["role"] for item in messages] == ["user", "tool", "assistant"]


def test_agent_loop_denies_unknown_tool_without_execution(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "conversation.sqlite3")

    class BadRouter:
        def chat(self, messages):
            return {"content": '{"type":"tool_call","name":"delete_everything","arguments":{}}'}

    calls = []
    result = AgentLoop(BadRouter(), lambda *args, **kwargs: calls.append(1)).run("conv-2", "اختبر", owner_token="owner-secret",)
    assert result["steps"] == 4
    assert not calls
    assert all(item["status"] == "denied" for item in result["activity"])


def test_owner_token_method_is_recorded_in_execution_context(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "engine.sqlite3")
    monkeypatch.setenv("OWNER_TOKEN", "owner-secret")
    importlib.reload(owner_policy)
    from core.engine import handle

    result = handle("Owner status", source="test", owner_token="owner-secret", request_id="auth-context-1")
    assert result["execution_context"]["authentication_method"] == "owner_token"
    assert result["execution_context"]["owner_authenticated"] is True


def test_runtime_returns_clarification_without_inventing_facts(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "clarification.sqlite3")

    class ClarifyingRouter:
        def chat(self, messages):
            return {"content": json.dumps({"type": "clarification", "question": "ما عنوان المضيف المقصود؟"})}

    result = AgentLoop(ClarifyingRouter(), lambda *args, **kwargs: {}).run("conv-clarify", "افحص الخادم", owner_token="owner-secret")
    assert result["type"] == "clarification"
    assert result["answer"] == "ما عنوان المضيف المقصود؟"
    assert result["activity"] == []


def test_runtime_enforces_policy_tool_call_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "limit.sqlite3")

    class ToolRouter:
        def chat(self, messages):
            return {"content": json.dumps({"type": "tool_call", "name": "search", "arguments": {"query": "x"}})}

    calls = []
    result = AgentLoop(
        ToolRouter(),
        lambda *args, **kwargs: calls.append(1) or {"ok": True},
        limits=RuntimeLimits(4, 1, 90, 40, 24000, 20),
    ).run("conv-limit", "ابحث", owner_token="owner-secret")
    assert result["type"] == "error"
    assert result["error"] == "max_tool_calls"
    assert len(calls) == 1


def test_runtime_converts_provider_failure_to_safe_error(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "provider-error.sqlite3")

    class BrokenRouter:
        def chat(self, messages):
            raise RuntimeError("secret provider detail must not escape")

    result = AgentLoop(BrokenRouter(), lambda *args, **kwargs: {}).run("conv-error", "حلل", owner_token="owner-secret")
    assert result["type"] == "error"
    assert result["error"] == "provider_failure"
    assert "secret provider detail" not in result["answer"]
