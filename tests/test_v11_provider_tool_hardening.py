from __future__ import annotations

import json
from pathlib import Path

import pytest

import agent.memory as memory
import agent.task_manager as task_db
import core.db as core_db
from agent.model_router import ModelRouter
from agent.provider_api import InvalidModelResponse, ProviderCapabilities
from agent.task import TaskStatus
from agent.task_runtime import AgentTaskRuntime
from owner_session_testutils import allow_owner_sessions
from tools import registry as registry_module
from tools.registry import MAX_ARG_LENGTH, REGISTRY, ToolSpec, tool_definitions


def test_registered_tool_schemas_are_explicit_and_exact():
    exported = tool_definitions()
    definitions = {item["name"]: item["parameters"] for item in exported}

    for name, spec in REGISTRY.items():
        schema = spec.input_schema
        assert schema == definitions[name]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        if spec.argument_type is str:
            assert schema["properties"] == {"query": {"type": "string", "maxLength": MAX_ARG_LENGTH}}
            assert schema["required"] == ["query"]
            assert spec.validate_input({"query": "status"}) == (True, "valid", "status")
            assert not spec.validate_input({})[0]
            assert not spec.validate_input({"query": "status", "extra": "ignored"})[0]
            assert not spec.validate_input({"query": 7})[0]
            assert not spec.validate_input({"query": "x" * (MAX_ARG_LENGTH + 1)})[0]
        else:
            assert schema["properties"] == {}
            assert spec.validate_input({}) == (True, "valid", None)
            assert not spec.validate_input({"extra": "ignored"})[0]

    search_definition = next(item for item in exported if item["name"] == "search")
    search_definition["parameters"]["properties"]["query"]["maxLength"] = MAX_ARG_LENGTH + 1
    search_definition["input_schema"]["properties"]["query"]["maxLength"] = MAX_ARG_LENGTH + 2
    task_search = next(item for item in AgentTaskRuntime._schemas() if item["function"]["name"] == "search")
    task_search["function"]["parameters"]["properties"]["query"]["maxLength"] = MAX_ARG_LENGTH + 3
    assert REGISTRY["search"].input_schema["properties"]["query"]["maxLength"] == MAX_ARG_LENGTH
    assert not REGISTRY["search"].validate_input({"query": "x" * (MAX_ARG_LENGTH + 1)})[0]


def test_registry_rejects_noncanonical_schema_at_construction():
    malformed = ToolSpec(
        "v11_bad_schema",
        "test-only malformed schema",
        "analysis",
        False,
        str,
        lambda _argument: {"ok": True},
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": MAX_ARG_LENGTH}},
            "required": ["query"],
        },
    )

    with pytest.raises(ValueError, match="unsupported input schema"):
        registry_module.build_registry([malformed])


def test_registry_execute_validates_raw_shapes_before_invoking_handlers(monkeypatch):
    invoked: list[str | None] = []
    query_spec = ToolSpec(
        "v11_query_probe",
        "test-only query probe",
        "analysis",
        False,
        str,
        lambda argument: invoked.append(argument) or {"ok": True, "query": argument},
    )
    noarg_spec = ToolSpec(
        "v11_noarg_probe",
        "test-only no-argument probe",
        "analysis",
        False,
        None,
        lambda argument: invoked.append(argument) or {"ok": True},
    )
    specs = {query_spec.name: query_spec, noarg_spec.name: noarg_spec}
    monkeypatch.setattr(registry_module, "get_tool", lambda name: specs.get(name))

    malformed = [
        {},
        None,
        {"query": 7},
        {"query": "valid", "extra": "ignored"},
        {"query": "x" * (MAX_ARG_LENGTH + 1)},
        "x" * (MAX_ARG_LENGTH + 1),
    ]
    for arguments in malformed:
        with pytest.raises(ValueError):
            registry_module.execute(query_spec.name, arguments)
    assert invoked == []

    assert registry_module.execute(query_spec.name, {"query": "valid"}) == {"ok": True, "query": "valid"}
    assert registry_module.execute(query_spec.name, "legacy-scalar") == {"ok": True, "query": "legacy-scalar"}
    assert registry_module.execute(noarg_spec.name, {}) == {"ok": True}
    assert registry_module.execute(noarg_spec.name) == {"ok": True}
    assert invoked == ["valid", "legacy-scalar", None, None]

    with pytest.raises(ValueError, match="unknown tool"):
        registry_module.execute("v11_unregistered", {})


def _init_task_runtime_stores(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(task_db, "DB_PATH", tmp_path / "tasks.sqlite3")
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", tmp_path / "memory.sqlite3")
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "core.sqlite3")
    task_db._init_db()
    memory._init_memory_db()
    core_db.connect().close()
    allow_owner_sessions(monkeypatch, "owner-token")


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("watch", {"query": "approved", "extra": "must-not-be-ignored"}),
        ("watch", {}),
        ("watch", {"query": "x" * (MAX_ARG_LENGTH + 1)}),
        ("status", {"extra": "no-argument-tool-is-still-strict"}),
        ("unregistered_tool", {}),
    ],
)
def test_task_runtime_rejects_schema_invalid_batches_before_dispatch(tmp_path, monkeypatch, tool_name, arguments):
    _init_task_runtime_stores(tmp_path, monkeypatch)
    executions = []

    class MalformedProvider:
        name = "schema-test-provider"
        model = "model-1"
        capabilities = ProviderCapabilities(generate=True, tool_calling=True, native_chat=True)

        def tool_calling(self, _messages, _tools, **_kwargs):
            return {"tool_calls": [{"id": "invalid-call", "name": tool_name, "arguments": arguments}]}

        def generate(self, *_args, **_kwargs):
            raise AssertionError("invalid native output must not fall back to generate")

    runtime = AgentTaskRuntime(
        ModelRouter([MalformedProvider()]),
        executor=lambda *args, **kwargs: executions.append((args, kwargs)) or {"ok": True},
    )
    task = runtime.create_task("conversation-v11", "check safe tool parsing", owner_session_id="owner-token")

    result = runtime.run_slice(task.task_id, owner_session_token="owner-token")

    assert result.status is TaskStatus.FAILED
    assert executions == []
    assert result.tool_calls == []
    assert not any(event["event"] == "tool.started" for event in result.execution_state["events"])
    failures = [event for event in result.execution_state["events"] if event["event"] == "model.provider_failure"]
    assert len(failures) == 1
    assert failures[0]["data"]["kind"] == "INVALID_MODEL_RESPONSE"


def test_task_runtime_json_embedded_tool_call_uses_registered_schema():
    valid_content = json.dumps({"type": "tool_call", "name": "watch", "arguments": {"query": "approved"}})
    kind, calls = AgentTaskRuntime._parse({"content": valid_content})
    assert kind == "tool_calls"
    assert calls[0].arguments == {"query": "approved"}

    invalid_content = json.dumps({"type": "tool_call", "name": "watch", "arguments": {"query": "approved", "extra": "rejected"}})
    with pytest.raises(InvalidModelResponse):
        AgentTaskRuntime._parse({"content": invalid_content})


def test_task_runtime_rejects_duplicate_call_ids_before_dispatch():
    with pytest.raises(InvalidModelResponse, match="duplicate"):
        AgentTaskRuntime._tool_calls(
            {
                "tool_calls": [
                    {"id": "duplicate", "name": "status", "arguments": {}},
                    {"id": "duplicate", "name": "status", "arguments": {}},
                ]
            }
        )
