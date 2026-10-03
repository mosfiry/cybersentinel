from __future__ import annotations

from pathlib import Path

import pytest

from owner_session_testutils import allow_owner_sessions

import agent.memory as memory
import agent.task_manager as task_db
import core.db as core_db
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
from agent.task import TaskStatus
from agent.task_manager import TaskManager
from agent.task_runtime import AgentTaskRuntime
from agent.model_router import ModelRouter


class ScriptedProvider:
    name = "scripted-v7"
    model = "scripted-v7-1"
    capabilities = ProviderCapabilities(generate=True, stream=False, tool_calling=True, structured_output=True)

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def tool_calling(self, messages, tools, temperature=0, **kwargs):
        self.calls += 1
        return self.responses.pop(0)

    def generate(self, messages, temperature=0, **kwargs):
        self.calls += 1
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


def _runtime(provider, monkeypatch, executor):
    allow_owner_sessions(monkeypatch, "owner")
    return AgentTaskRuntime(ModelRouter([provider]), executor=executor)


class SimulatedProcessDeath(BaseException):
    """Bypass ordinary exception handling to model abrupt process termination."""


def test_durable_tool_intent_precedes_executor_and_restart_requires_recovery(isolated_dbs, monkeypatch):
    task_id = ""
    executor_calls = []
    observed_intents = []

    def executor(command, **kwargs):
        executor_calls.append(command)
        persisted = TaskManager.get_task(task_id)
        assert persisted is not None
        observed_intents.extend(item for item in persisted.tool_calls if item["tool_call_id"] == "crash-call")
        assert observed_intents[-1]["status"] == "in_flight"
        assert len(observed_intents[-1]["argument_sha256"]) == 64
        assert "argument" not in observed_intents[-1]
        raise SimulatedProcessDeath()

    provider = ScriptedProvider([ProviderResponse(tool_calls=[ToolCall("search", {"query": "CVE-2026"}, "crash-call")])])
    runtime = _runtime(provider, monkeypatch, executor)
    task = runtime.create_task("v7-crash", "inspect a defensive indicator")
    task_id = task.task_id

    with pytest.raises(SimulatedProcessDeath):
        runtime.run_slice(task_id, owner_session_token="owner")

    after_crash = TaskManager.get_task(task_id)
    assert after_crash is not None
    assert after_crash.status == TaskStatus.WAITING_FOR_TOOL
    assert any(item["tool_call_id"] == "crash-call" and item["status"] == "in_flight" for item in after_crash.tool_calls)
    assert any(event["event"] == "tool.started" and event["data"].get("tool_call_id") == "crash-call" for event in after_crash.execution_state["events"])

    restart_provider = ScriptedProvider([ProviderResponse(text="must not be requested")])
    restarted = _runtime(restart_provider, monkeypatch, lambda command, **kwargs: executor_calls.append(command) or {"ok": True})
    resumed = restarted.run_slice(task_id, owner_session_token="owner")

    assert resumed.execution_state["recovery_required"]["tool_call_id"] == "crash-call"
    assert resumed.status == TaskStatus.WAITING_FOR_TOOL
    assert any(item["tool_call_id"] == "crash-call" and item["status"] == "unknown" for item in resumed.tool_calls)
    assert restart_provider.calls == 0, "restart must stop before another model proposal"
    assert len(executor_calls) == 1, "an unresolved external effect must never be replayed"


def test_non_success_tool_result_becomes_unknown_and_stops_automatic_retry(isolated_dbs, monkeypatch):
    executor_calls = []
    provider = ScriptedProvider([
        ProviderResponse(tool_calls=[ToolCall("search", {"query": "CVE-2026"}, "returned-error-call")]),
        ProviderResponse(text="must not be requested"),
    ])

    def executor(command, **kwargs):
        executor_calls.append(command)
        return {"ok": False, "error": "remote outcome not confirmed"}

    runtime = _runtime(provider, monkeypatch, executor)
    task = runtime.create_task("v7-result", "inspect a defensive indicator")
    result = runtime.run_to_completion(task.task_id, owner_session_token="owner", max_slices=4)

    assert result.status == TaskStatus.WAITING_FOR_TOOL
    assert result.execution_state["recovery_required"]["tool_call_id"] == "returned-error-call"
    assert any(item["tool_call_id"] == "returned-error-call" and item["status"] == "unknown" for item in result.tool_calls)
    assert provider.calls == 1, "an ambiguous tool result must halt the model loop"
    assert len(executor_calls) == 1


@pytest.mark.parametrize("legacy_call_id", ["legacy-started-call", ""])
def test_legacy_unmatched_tool_started_event_blocks_resume(isolated_dbs, monkeypatch, legacy_call_id):
    provider = ScriptedProvider([ProviderResponse(text="must not be requested")])
    executor_calls = []
    runtime = _runtime(provider, monkeypatch, lambda command, **kwargs: executor_calls.append(command) or {"ok": True})
    task = runtime.create_task("v7-legacy", "resume a previously started task")
    task.execution_state.setdefault("events", []).append({
        "event": "tool.started",
        "task_id": task.task_id,
        "data": {"tool": "search", "tool_call_id": legacy_call_id},
    })
    task.update_status(TaskStatus.WAITING_FOR_TOOL)
    TaskManager.update_task(task)

    resumed = runtime.run_slice(task.task_id, owner_session_token="owner")

    assert resumed.execution_state["recovery_required"]["tool_call_id"] == legacy_call_id
    assert resumed.status == TaskStatus.WAITING_FOR_TOOL
    assert provider.calls == 0
    assert executor_calls == []
