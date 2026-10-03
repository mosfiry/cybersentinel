from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

import agent.memory as memory
import agent.task_manager as task_db
import core.db as core_db
from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import ModelTurn, ToolCallProposal, model_turn_from_provider, validate_model_turn
from agent.model_router import ModelRouter
from agent.planning import Plan, PlanStep
from agent.provider_api import (
    InvalidModelResponse,
    ProviderAuthenticationFailure,
    ProviderCapabilities,
    ProviderFailure,
    ProviderTimeout,
    ToolCall,
    response_from_legacy,
)
from agent.providers import OpenAICompatibleProvider
from agent.task import TaskStatus
from agent.task_manager import TaskManager
from agent.task_runtime import AgentTaskRuntime
from owner_session_testutils import allow_owner_sessions
from runtime_authorization import make_test_snapshot


def test_openai_compatible_adapter_passes_timeout_to_transport(monkeypatch):
    observed = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}'

    def fake_urlopen(request, *, timeout):
        observed["timeout"] = timeout
        observed["payload"] = json.loads(request.data.decode("utf-8"))
        return Response()

    monkeypatch.setattr("agent.providers.urllib.request.urlopen", fake_urlopen)
    provider = OpenAICompatibleProvider("test", "https://provider.invalid/v1", "model-1")

    result = provider.generate([{"role": "user", "content": "ping"}], timeout=7)

    assert result.text == "ok"
    assert observed["timeout"] == 7
    assert "timeout" not in observed["payload"]


def test_legacy_provider_tool_arguments_fail_closed():
    with pytest.raises(InvalidModelResponse):
        response_from_legacy(
            {"tool_calls": [{"id": "call-1", "name": "status", "arguments": "not-json"}]},
            provider="test",
            model="model-1",
        )
    with pytest.raises(InvalidModelResponse):
        response_from_legacy(
            {"tool_calls": [{"id": "call-1", "name": "status", "arguments": "[]"}]},
            provider="test",
            model="model-1",
        )


@pytest.mark.parametrize("bad_content", [[], {}, 7])
def test_provider_boundaries_reject_non_text_assistant_content(bad_content):
    with pytest.raises(InvalidModelResponse):
        response_from_legacy({"content": bad_content}, provider="test", model="model-1")

    provider = OpenAICompatibleProvider("test", "https://provider.invalid/v1", "model-1")
    payload = {"choices": [{"message": {"content": bad_content}, "finish_reason": "stop"}]}
    with pytest.raises(InvalidModelResponse):
        provider._normalize(payload, "generate")


def test_openai_compatible_normalizer_rejects_malformed_native_tool_call():
    provider = OpenAICompatibleProvider("test", "https://provider.invalid/v1", "model-1", tool_calling=True)
    payload = {
        "choices": [{
            "message": {
                "content": None,
                "tool_calls": [{"id": "call-1", "function": {"name": "status", "arguments": "{bad"}}],
            },
            "finish_reason": "tool_calls",
        }]
    }
    with pytest.raises(InvalidModelResponse):
        provider._normalize(payload, "tool_calling")


def test_model_protocol_rejects_invalid_arguments_and_native_turn_shapes():
    with pytest.raises(InvalidModelResponse):
        model_turn_from_provider(
            {"tool_calls": [{"id": "call-1", "name": "status", "arguments": "{\"query\":\"x\"}"}]},
            mission_id="mission-1",
            run_id="run-1",
            turn_id="turn-1",
            request_id="request-1",
            plan_version=1,
        )
    malformed = ModelTurn("turn-1", tool_calls=(ToolCallProposal(name="status", arguments="not-an-object"),))
    with pytest.raises(InvalidModelResponse):
        validate_model_turn(malformed)


class _FailingProvider:
    def __init__(self, name, model, error):
        self.name = name
        self.model = model
        self.error = error
        self.capabilities = ProviderCapabilities(generate=True)

    def generate(self, _messages, **_kwargs):
        raise self.error


def test_router_classifies_failover_attempts_and_redacts_error_bodies():
    raw_private_body = b"PRIVATE_PROVIDER_BODY_DO_NOT_PERSIST"
    unauthorized = urllib.error.HTTPError("https://provider.invalid", 401, "unauthorized", None, io.BytesIO(raw_private_body))
    first = _FailingProvider("auth-provider", "model-a", unauthorized)
    second = _FailingProvider("timeout-provider", "model-b", urllib.error.URLError(TimeoutError("secret transport detail")))
    router = ModelRouter([first, second])

    with pytest.raises(ProviderFailure) as caught:
        router.generate([])

    assert caught.value.attempts == (
        {"provider": "auth-provider", "model": "model-a", "kind": "AUTHENTICATION_FAILURE"},
        {"provider": "timeout-provider", "model": "model-b", "kind": "TIMEOUT"},
    )
    assert isinstance(ModelRouter._classify(unauthorized, first), ProviderAuthenticationFailure)
    assert isinstance(ModelRouter._classify(urllib.error.URLError(TimeoutError()), second), ProviderTimeout)
    assert "PRIVATE_PROVIDER_BODY_DO_NOT_PERSIST" not in str(caught.value)
    assert "secret transport detail" not in str(caught.value)
    assert all("failure_reason" not in row for row in router.last_trace)
    assert [row["failure_kind"] for row in router.last_trace] == ["AUTHENTICATION_FAILURE", "TIMEOUT"]
    assert all("PRIVATE_PROVIDER_BODY_DO_NOT_PERSIST" not in repr(row) for row in router.last_trace)


def test_task_runtime_rejects_bad_tool_response_before_executor(tmp_path, monkeypatch):
    task_path = Path(tmp_path) / "tasks.sqlite3"
    monkeypatch.setattr(task_db, "DB_PATH", task_path)
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", Path(tmp_path) / "memory.sqlite3")
    monkeypatch.setattr(core_db, "DB_PATH", Path(tmp_path) / "core.sqlite3")
    task_db._init_db()
    memory._init_memory_db()
    core_db.connect().close()
    allow_owner_sessions(monkeypatch, "owner-token")
    executions = []

    class MalformedProvider:
        name = "malformed"
        model = "model-1"
        capabilities = ProviderCapabilities(generate=True, tool_calling=True, native_chat=True)

        def tool_calling(self, _messages, _tools, **_kwargs):
            return {"tool_calls": [{"id": "call-malformed", "name": "status", "arguments": "PRIVATE_BAD_ARGUMENTS"}]}

        def generate(self, *_args, **_kwargs):
            raise AssertionError("invalid native output must not fall back to generate")

    runtime = AgentTaskRuntime(ModelRouter([MalformedProvider()]), executor=lambda *args, **kwargs: executions.append((args, kwargs)) or {"ok": True})
    task = runtime.create_task("conversation-v12", "check status", owner_session_id="owner-token")

    result = runtime.run_slice(task.task_id, owner_session_token="owner-token")

    assert result.status is TaskStatus.FAILED
    assert result.retry_count == 1
    assert executions == []
    failure_events = [event for event in result.execution_state["events"] if event["event"] == "model.provider_failure"]
    assert len(failure_events) == 1
    assert failure_events[0]["data"]["attempts"] == [{"provider": "malformed", "model": "model-1", "kind": "INVALID_MODEL_RESPONSE"}]
    assert "PRIVATE_BAD_ARGUMENTS" not in json.dumps(result.execution_state)
    assert "PRIVATE_BAD_ARGUMENTS" not in result.error


def test_mission_provider_failures_are_bounded_and_redacted(tmp_path):
    runtime = MissionRuntime(
        MissionStore(Path(tmp_path) / "missions.sqlite3"),
        executor=lambda *_args: {},
        authorization_snapshot_factory=make_test_snapshot,
    )
    plan = Plan.initial("observe the target").replan(
        steps=(PlanStep("observe", "observe", action="status"),),
        reason="test",
    )
    mission = runtime.create(
        "observe the target",
        "observe the target",
        plan,
        completion_criteria=[{"criterion_id": "goal"}],
    )

    class FailedNativeModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            raise ProviderFailure(
                "PRIVATE_MODEL_ERROR_BODY_DO_NOT_PERSIST",
                provider="provider-x",
                model="model-x",
                attempts=[{"provider": "provider-x", "model": "model-x", "kind": "TIMEOUT"}],
            )

    result = runtime.run_model_loop(mission.mission_id, FailedNativeModel(), tools=[], max_turns=1)

    assert result.failures[-1]["kind"] == "PROVIDER_FAILURE"
    assert result.failures[-1]["provider"] == "provider-x"
    assert result.failures[-1]["attempts"] == [{"provider": "provider-x", "model": "model-x", "kind": "TIMEOUT"}]
    assert result.failures[-1]["reason"] == "provider/model call failed"
    assert "PRIVATE_MODEL_ERROR_BODY_DO_NOT_PERSIST" not in json.dumps(result.failures)
    assert "PRIVATE_MODEL_ERROR_BODY_DO_NOT_PERSIST" not in result.error


def test_mission_runtime_preserves_untyped_native_model_crash(tmp_path):
    runtime = MissionRuntime(
        MissionStore(Path(tmp_path) / "missions.sqlite3"),
        executor=lambda *_args: {},
        authorization_snapshot_factory=make_test_snapshot,
    )
    plan = Plan.initial("observe the target").replan(
        steps=(PlanStep("observe", "observe", action="status"),),
        reason="test",
    )
    mission = runtime.create(
        "observe the target",
        "observe the target",
        plan,
        completion_criteria=[{"criterion_id": "goal"}],
    )

    class CrashingNativeModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            raise RuntimeError("PRIVATE_UNTYPED_MODEL_EXCEPTION")

    with pytest.raises(RuntimeError, match="PRIVATE_UNTYPED_MODEL_EXCEPTION"):
        runtime.run_model_loop(mission.mission_id, CrashingNativeModel(), tools=[], max_turns=1)
    persisted = runtime.store.load(mission.mission_id)
    assert persisted is not None
    assert persisted.failures == []
    assert persisted.retry_count == 0


@pytest.mark.parametrize("bad_usage", [[], "", 0, False])
def test_provider_boundaries_reject_falsey_non_object_usage_metadata(bad_usage):
    with pytest.raises(InvalidModelResponse):
        response_from_legacy({"usage": bad_usage}, provider="test", model="model-1")

    provider = OpenAICompatibleProvider("test", "https://provider.invalid/v1", "model-1")
    payload = {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}], "usage": bad_usage}
    with pytest.raises(InvalidModelResponse):
        provider._normalize(payload, "generate")

    with pytest.raises(InvalidModelResponse):
        model_turn_from_provider(
            {"usage": bad_usage},
            mission_id="mission-1",
            run_id="run-1",
            turn_id="turn-1",
            request_id="request-1",
            plan_version=1,
        )


@pytest.mark.parametrize("bad_finish_reason", [0, False, [], {}])
def test_provider_boundaries_reject_non_string_finish_reason_metadata(bad_finish_reason):
    with pytest.raises(InvalidModelResponse):
        response_from_legacy({"finish_reason": bad_finish_reason}, provider="test", model="model-1")

    provider = OpenAICompatibleProvider("test", "https://provider.invalid/v1", "model-1")
    payload = {"choices": [{"message": {"content": "ok"}, "finish_reason": bad_finish_reason}]}
    with pytest.raises(InvalidModelResponse):
        provider._normalize(payload, "generate")

    with pytest.raises(InvalidModelResponse):
        model_turn_from_provider(
            {"finish_reason": bad_finish_reason},
            mission_id="mission-1",
            run_id="run-1",
            turn_id="turn-1",
            request_id="request-1",
            plan_version=1,
        )
