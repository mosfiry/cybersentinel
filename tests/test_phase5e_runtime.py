from __future__ import annotations

import json
from pathlib import Path

import pytest

import core.db as core_db
import agent.memory as memory
import agent.task_manager as task_db
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
from agent.task_manager import TaskManager
from agent.task_runtime import AgentTaskRuntime
from agent.task import TaskStatus
from agent.model_router import ModelRouter


class ScriptedProvider:
    name = "scripted"
    model = "scripted-1"
    capabilities = ProviderCapabilities(generate=True, stream=False, tool_calling=True, structured_output=True)

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def tool_calling(self, messages, tools, temperature=0, **kwargs):
        self.calls += 1
        return self.responses.pop(0)

    def generate(self, messages, temperature=0, **kwargs):
        return self.responses.pop(0)


@pytest.fixture
def isolated_dbs(tmp_path, monkeypatch):
    monkeypatch.setattr(task_db, "DB_PATH", Path(tmp_path) / "tasks.sqlite3")
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", Path(tmp_path) / "memory.sqlite3")
    monkeypatch.setattr(core_db, "DB_PATH", Path(tmp_path) / "core.sqlite3")
    task_db._init_db()
    memory._init_memory_db()
    core_db.connect().close()
    return tmp_path


def runtime_for(provider, monkeypatch, owner="owner"):
    import security.owner_policy as policy
    monkeypatch.setattr(policy, "OWNER_TOKEN", owner)
    return AgentTaskRuntime(ModelRouter([provider]), executor=lambda command, **kwargs: {"ok": True, "request_id": "exec-1", "result": {"command": command}})


def test_task_backed_runtime_persists_multi_slice_context_memory_and_events(isolated_dbs, monkeypatch):
    provider = ScriptedProvider([
        ProviderResponse(tool_calls=[ToolCall("search", {"query": "CVE-2026"}, "call-1")], finish_reason="tool_calls"),
        ProviderResponse(text=json.dumps({"type": "final", "content": "تم جمع الدليل وتحليل المهمة."}), finish_reason="stop"),
    ])
    runtime = runtime_for(provider, monkeypatch)
    task = runtime.create_task("conv-1", "ابدأ تحقيقاً دفاعياً", authentication_method="owner_token")
    completed = runtime.run_to_completion(task.task_id, owner_token="owner")
    assert completed.status == TaskStatus.COMPLETED
    assert completed.current_step == 2
    assert completed.provider == "scripted"
    assert completed.tool_calls[0]["tool_call_id"] == "call-1"
    assert completed.execution_state["memory_refs"]
    assert any(event["event"] == "evidence.added" for event in completed.execution_state["events"])
    assert TaskManager.get_task(task.task_id).result["answer"] == "تم جمع الدليل وتحليل المهمة."
    assert memory.MemoryProvider.get_relevant_memory("conv-1", limit=20)


def test_duplicate_tool_call_id_is_idempotent(isolated_dbs, monkeypatch):
    provider = ScriptedProvider([
        ProviderResponse(tool_calls=[ToolCall("search", {"query": "same"}, "same-id")]),
        ProviderResponse(tool_calls=[ToolCall("search", {"query": "same"}, "same-id")]),
        ProviderResponse(text="done"),
    ])
    import security.owner_policy as policy
    monkeypatch.setattr(policy, "OWNER_TOKEN", "owner")
    executions = []
    runtime = AgentTaskRuntime(ModelRouter([provider]), executor=lambda command, **kwargs: executions.append(command) or {"ok": True})
    task = runtime.create_task("conv-2", "investigate", authentication_method="owner_token")
    runtime.run_slice(task.task_id, owner_token="owner")
    # A replayed native id must not execute a second time.
    runtime.run_slice(task.task_id, owner_token="owner")
    assert len(executions) == 1
    restored = TaskManager.get_task(task.task_id)
    assert len(restored.tool_calls) == 1


def test_task_owner_and_conversation_isolation(isolated_dbs, monkeypatch):
    provider = ScriptedProvider([ProviderResponse(text="done")])
    runtime = runtime_for(provider, monkeypatch, owner="owner-a")
    task = runtime.create_task("conv-owner-a", "private objective")
    with pytest.raises(PermissionError):
        runtime.run_slice(task.task_id, owner_token="wrong-owner")
    assert TaskManager.get_tasks_by_conversation("conv-owner-a", owner_session_id="other-session") == []


def test_cancel_before_slice_is_persisted(isolated_dbs, monkeypatch):
    provider = ScriptedProvider([ProviderResponse(text="should not run")])
    runtime = runtime_for(provider, monkeypatch)
    task = runtime.create_task("conv-cancel", "cancel me")
    task.request_cancel()
    TaskManager.update_task(task)
    cancelled = runtime.run_slice(task.task_id, owner_token="owner")
    assert cancelled.status == TaskStatus.CANCELLED
    assert provider.calls == 0


def test_native_and_json_fallback_share_task_runtime(isolated_dbs, monkeypatch):
    class Legacy:
        name = "legacy"
        model = "legacy-1"
        capabilities = ProviderCapabilities(generate=True, tool_calling=False)
        def chat(self, messages, temperature=0):
            return {"content": json.dumps({"type": "final", "content": "fallback"})}

    runtime = runtime_for(Legacy(), monkeypatch)
    task = runtime.create_task("conv-fallback", "fallback objective")
    result = runtime.run_slice(task.task_id, owner_token="owner")
    assert result.status == TaskStatus.COMPLETED
    assert result.result["answer"] == "fallback"


def test_long_conversation_memory_compacts_without_cross_conversation_leak(isolated_dbs, monkeypatch):
    from agent.context import ContextEngine, RuntimeLimits
    from agent.memory import ConversationMemory, MemoryType, TrustClassification
    import core.db as core_db

    for turn in range(500):
        ConversationMemory.store_conversation_memory("conv-long", f"turn-{turn} objective evidence", MemoryType.RECENT, source="conversation", provenance=f"turn:{turn}", trust_classification=TrustClassification.UNTRUSTED_DATA)
        core_db.ensure_conversation("conv-long")
        core_db.add_conversation_message("conv-long", "user", f"turn-{turn} objective evidence")
    ConversationMemory.consolidate_memory("conv-long", max_items=100)
    context = ContextEngine.build(
        user_text="تابع التحقيق",
        conversation_id="conv-long",
        owner_policy_context="Owner policy: defensive evidence-based analysis",
        runtime_limits=RuntimeLimits(max_context_messages=50, max_context_chars=4000, max_result_chars=500, max_tool_calls=10, max_execution_steps=20),
    )
    assert context.truncated or len(context.messages) <= 50
    assert all("turn-" not in item["content"] or len(item["content"]) < 1000 for item in context.messages)
    other = ContextEngine.build(user_text="تابع", conversation_id="conv-other", owner_policy_context="Owner policy", runtime_limits=RuntimeLimits(max_context_messages=20, max_context_chars=2000))
    assert "turn-499" not in json.dumps(other.messages, ensure_ascii=False)
