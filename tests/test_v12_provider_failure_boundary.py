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
    MAX_PROVIDER_ARGUMENT_BYTES,
    MAX_PROVIDER_CALL_ID_CHARS,
    MAX_PROVIDER_RESPONSE_BYTES,
    MAX_PROVIDER_TEXT_CHARS,
    MAX_PROVIDER_TOOL_CALLS,
    MAX_PROVIDER_USAGE_BYTES,
    ProviderAuthenticationFailure,
    ProviderCapabilities,
    ProviderFailure,
    ProviderRequestRejected,
    ProviderResponse,
    ProviderTimeout,
    ToolCall,
    validate_provider_response,
    response_from_legacy,
)
from agent.providers import OpenAICompatibleProvider
from agent.task import TaskStatus
from agent.task_manager import TaskManager
from agent.task_runtime import AgentTaskRuntime
from owner_session_testutils import allow_owner_sessions
from runtime_authorization import make_test_snapshot
from security.pinned_http import PinnedHTTPResponse, PinnedRequestError


def test_openai_compatible_adapter_passes_timeout_to_transport(monkeypatch):
    observed = {}

    def fake_pinned_request(url, *, method, headers, body, timeout, max_response_bytes, allow_loopback):
        observed["url"] = url
        observed["method"] = method
        observed["headers"] = headers
        observed["timeout"] = timeout
        observed["payload"] = json.loads(body.decode("utf-8"))
        observed["max_response_bytes"] = max_response_bytes
        observed["allow_loopback"] = allow_loopback
        return PinnedHTTPResponse(200, {}, b'{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}')

    monkeypatch.setattr("agent.providers.pinned_http_request", fake_pinned_request)
    provider = OpenAICompatibleProvider("test", "https://provider.invalid/v1", "model-1")

    result = provider.generate([{"role": "user", "content": "ping"}], timeout=7)

    assert result.text == "ok"
    assert observed["timeout"] == 7
    assert observed["max_response_bytes"] == MAX_PROVIDER_RESPONSE_BYTES
    assert observed["method"] == "POST"
    assert observed["allow_loopback"] is True
    assert "timeout" not in observed["payload"]


def test_openai_compatible_provider_accepts_exact_response_limit_despite_inaccurate_length(monkeypatch):
    provider = OpenAICompatibleProvider("test", "https://provider.invalid/v1", "model-1")
    payload = {"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]}
    empty_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    content = "x" * (MAX_PROVIDER_RESPONSE_BYTES - len(empty_body))
    payload["choices"][0]["message"]["content"] = content
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    assert len(body) == MAX_PROVIDER_RESPONSE_BYTES
    observed = []

    def fake_pinned_request(_url, *, max_response_bytes, **_kwargs):
        observed.append(max_response_bytes)
        return PinnedHTTPResponse(200, {"content-length": "0"}, body)

    monkeypatch.setattr("agent.providers.pinned_http_request", fake_pinned_request)

    result = provider._request({})

    assert observed == [MAX_PROVIDER_RESPONSE_BYTES]
    assert result["choices"][0]["message"]["content"] == content


@pytest.mark.parametrize("content_length", [None, "1", str(MAX_PROVIDER_RESPONSE_BYTES * 4)])
def test_openai_compatible_provider_rejects_oversized_body_without_trusting_content_length(
    monkeypatch, content_length
):
    observed = []

    def fake_pinned_request(_url, *, max_response_bytes, **_kwargs):
        observed.append(max_response_bytes)
        raise PinnedRequestError("HTTP response exceeds the configured size limit")

    monkeypatch.setattr("agent.providers.pinned_http_request", fake_pinned_request)
    provider = OpenAICompatibleProvider("test", "https://provider.invalid/v1", "model-1")

    with pytest.raises(InvalidModelResponse, match="exceeds the configured size limit"):
        provider._request({})

    assert observed == [MAX_PROVIDER_RESPONSE_BYTES]


def test_openai_compatible_provider_malformed_response_body_is_redacted(monkeypatch):
    body = b"UNTRUSTED_PROVIDER_BODY_SENTINEL"

    monkeypatch.setattr(
        "agent.providers.pinned_http_request",
        lambda *_args, **_kwargs: PinnedHTTPResponse(200, {}, body),
    )
    provider = OpenAICompatibleProvider("test", "https://provider.invalid/v1", "model-1")

    with pytest.raises(InvalidModelResponse, match="malformed JSON") as caught:
        provider._request({})

    assert "UNTRUSTED_PROVIDER_BODY_SENTINEL" not in str(caught.value)
    assert provider.last_error == "InvalidModelResponse"


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


@pytest.mark.parametrize("legacy", [False, True])
def test_model_router_shares_hard_text_limit_for_typed_and_legacy_responses(legacy):
    class StaticProvider:
        name = "static"
        model = "model-1"
        capabilities = ProviderCapabilities(generate=True)

        def __init__(self, content):
            self.content = content

        def generate(self, *_args, **_kwargs):
            if legacy:
                return {"content": self.content}
            from agent.provider_api import ProviderResponse
            return ProviderResponse(text=self.content)

    provider = StaticProvider("x" * MAX_PROVIDER_TEXT_CHARS)
    router = ModelRouter([provider])
    assert len(router.generate([])["content"]) == MAX_PROVIDER_TEXT_CHARS

    provider.content = "x" * (MAX_PROVIDER_TEXT_CHARS + 1) + "RESPONSE_SENTINEL"
    with pytest.raises(InvalidModelResponse) as caught:
        router.generate([])

    assert caught.value.attempts[0]["kind"] == "INVALID_MODEL_RESPONSE"
    assert "RESPONSE_SENTINEL" not in str(caught.value)
    assert "RESPONSE_SENTINEL" not in repr(router.last_trace)


def test_provider_response_enforces_tool_call_count_and_unique_identifiers():
    valid_calls = [ToolCall("status", {}, f"call-{index}") for index in range(MAX_PROVIDER_TOOL_CALLS)]
    valid = validate_provider_response(ProviderResponse(tool_calls=valid_calls))
    assert len(valid.tool_calls) == MAX_PROVIDER_TOOL_CALLS

    too_many = valid_calls + [ToolCall("status", {}, "call-extra")]
    with pytest.raises(InvalidModelResponse):
        validate_provider_response(ProviderResponse(tool_calls=too_many))
    duplicate = [ToolCall("status", {}, "same-id"), ToolCall("status", {}, "same-id")]
    with pytest.raises(InvalidModelResponse, match="duplicate"):
        validate_provider_response(ProviderResponse(tool_calls=duplicate))
    with pytest.raises(InvalidModelResponse, match="duplicate"):
        response_from_legacy(
            {"tool_calls": [{"id": call.call_id, "name": call.name, "arguments": call.arguments} for call in duplicate]},
            provider="test",
            model="model-1",
        )
    with pytest.raises(InvalidModelResponse):
        response_from_legacy(
            {"tool_calls": [{"id": str(index), "name": "status", "arguments": {}} for index in range(MAX_PROVIDER_TOOL_CALLS + 1)]},
            provider="test",
            model="model-1",
        )
    with pytest.raises(InvalidModelResponse):
        response_from_legacy({"tool_calls": [{"id": 7, "name": "status", "arguments": {}}]}, provider="test", model="model-1")
    with pytest.raises(InvalidModelResponse):
        validate_provider_response(ProviderResponse(tool_calls=[ToolCall("status", {}, "x" * (MAX_PROVIDER_CALL_ID_CHARS + 1))]))


def test_provider_response_enforces_argument_and_usage_byte_limits():
    oversized_arguments = {"query": "x" * (MAX_PROVIDER_ARGUMENT_BYTES + 1)}
    with pytest.raises(InvalidModelResponse):
        response_from_legacy(
            {"tool_calls": [{"id": "call-1", "name": "status", "arguments": oversized_arguments}]},
            provider="test",
            model="model-1",
        )
    with pytest.raises(InvalidModelResponse):
        response_from_legacy(
            {"tool_calls": [{"id": "call-1", "name": "status", "arguments": json.dumps(oversized_arguments)}]},
            provider="test",
            model="model-1",
        )
    with pytest.raises(InvalidModelResponse):
        response_from_legacy({"usage": {"opaque": "x" * (MAX_PROVIDER_USAGE_BYTES + 1)}}, provider="test", model="model-1")
    with pytest.raises(InvalidModelResponse):
        validate_provider_response(ProviderResponse(usage={"opaque": "x" * (MAX_PROVIDER_USAGE_BYTES + 1)}))


def test_provider_and_native_model_reject_invalid_utf8_text_and_identifiers():
    with pytest.raises(InvalidModelResponse):
        validate_provider_response(ProviderResponse(text="\ud800"))
    with pytest.raises(InvalidModelResponse):
        response_from_legacy(
            {"tool_calls": [{"id": "\ud800", "name": "status", "arguments": {}}]},
            provider="test",
            model="model-1",
        )
    malformed = ToolCallProposal.create(
        "status",
        {},
        mission_id="mission-1",
        run_id="run-1",
        turn_id="turn-1",
        tool_call_id="\ud800",
    )
    with pytest.raises(InvalidModelResponse):
        validate_model_turn(ModelTurn("turn-1", tool_calls=(malformed,)))


def test_openai_compatible_normalizer_uses_shared_text_call_and_argument_limits():
    provider = OpenAICompatibleProvider("test", "https://provider.invalid/v1", "model-1", tool_calling=True)

    def payload(content="", calls=(), finish_reason="stop"):
        return {"choices": [{"message": {"content": content, "tool_calls": list(calls)}, "finish_reason": finish_reason}]}

    exact = provider._normalize(payload(content="x" * MAX_PROVIDER_TEXT_CHARS), "generate")
    assert len(exact.text) == MAX_PROVIDER_TEXT_CHARS
    with pytest.raises(InvalidModelResponse):
        provider._normalize(payload(content="x" * (MAX_PROVIDER_TEXT_CHARS + 1)), "generate")

    calls = [
        {"id": f"call-{index}", "function": {"name": "status", "arguments": {}}}
        for index in range(MAX_PROVIDER_TOOL_CALLS + 1)
    ]
    with pytest.raises(InvalidModelResponse):
        provider._normalize(payload(calls=calls, finish_reason="tool_calls"), "tool_calling")
    oversized_args = json.dumps({"query": "x" * (MAX_PROVIDER_ARGUMENT_BYTES + 1)})
    with pytest.raises(InvalidModelResponse):
        provider._normalize(
            payload(calls=[{"id": "call-large", "function": {"name": "status", "arguments": oversized_args}}], finish_reason="tool_calls"),
            "tool_calling",
        )


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


def test_native_model_turn_limits_and_call_identity_are_validated():
    def proposal(turn_id, call_id, arguments=None):
        return ToolCallProposal.create(
            "status",
            arguments or {},
            mission_id="mission-1",
            run_id="run-1",
            turn_id=turn_id,
            action_id=f"{turn_id}:{call_id}",
            tool_call_id=call_id,
        )

    turn = ModelTurn(
        "turn-1",
        tool_calls=tuple(proposal("turn-1", f"call-{index}") for index in range(MAX_PROVIDER_TOOL_CALLS)),
    )
    assert validate_model_turn(turn) is turn

    too_many = ModelTurn("turn-1", tool_calls=turn.tool_calls + (proposal("turn-1", "call-extra"),))
    with pytest.raises(InvalidModelResponse):
        validate_model_turn(too_many)
    duplicate = ModelTurn("turn-1", tool_calls=(proposal("turn-1", "same"), proposal("turn-1", "same")))
    with pytest.raises(InvalidModelResponse, match="duplicate"):
        validate_model_turn(duplicate)
    stale_turn = ModelTurn("turn-1", tool_calls=(proposal("turn-old", "call-old"),))
    with pytest.raises(InvalidModelResponse):
        validate_model_turn(stale_turn)
    oversized_text = ModelTurn("turn-1", content="x" * (MAX_PROVIDER_TEXT_CHARS + 1))
    with pytest.raises(InvalidModelResponse):
        validate_model_turn(oversized_text)
    oversized_arguments = ModelTurn(
        "turn-1",
        tool_calls=(proposal("turn-1", "call-large", {"query": "x" * (MAX_PROVIDER_ARGUMENT_BYTES + 1)}),),
    )
    with pytest.raises(InvalidModelResponse):
        validate_model_turn(oversized_arguments)
    oversized_call_id = ModelTurn(
        "turn-1",
        tool_calls=(proposal("turn-1", "x" * (MAX_PROVIDER_CALL_ID_CHARS + 1)),),
    )
    with pytest.raises(InvalidModelResponse):
        validate_model_turn(oversized_call_id)
    with pytest.raises(InvalidModelResponse):
        model_turn_from_provider(
            {"tool_calls": [{"id": 9, "name": "status", "arguments": {}}]},
            mission_id="mission-1",
            run_id="run-1",
            turn_id="turn-1",
            request_id="request-1",
            plan_version=1,
        )
    oversized_usage = ModelTurn("turn-1", usage={"opaque": "x" * (MAX_PROVIDER_USAGE_BYTES + 1)})
    with pytest.raises(InvalidModelResponse):
        validate_model_turn(oversized_usage)
    with pytest.raises(InvalidModelResponse):
        validate_model_turn(ModelTurn("x" * (MAX_PROVIDER_CALL_ID_CHARS + 1)))


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
        {"provider": "auth-provider", "model": "model-a", "kind": "AUTHENTICATION_FAILURE", "http_status": "401"},
        {"provider": "timeout-provider", "model": "model-b", "kind": "TIMEOUT"},
    )
    assert isinstance(ModelRouter._classify(unauthorized, first), ProviderAuthenticationFailure)
    assert isinstance(ModelRouter._classify(urllib.error.URLError(TimeoutError()), second), ProviderTimeout)
    assert "PRIVATE_PROVIDER_BODY_DO_NOT_PERSIST" not in str(caught.value)
    assert "secret transport detail" not in str(caught.value)
    assert all("failure_reason" not in row for row in router.last_trace)
    assert [row["failure_kind"] for row in router.last_trace] == ["AUTHENTICATION_FAILURE", "TIMEOUT"]
    assert all("PRIVATE_PROVIDER_BODY_DO_NOT_PERSIST" not in repr(row) for row in router.last_trace)


def test_router_preserves_http400_request_rejection_without_retrying_or_persisting_body():
    raw_private_body = b"PRIVATE_PROVIDER_BODY_DO_NOT_PERSIST"
    rejected = urllib.error.HTTPError("https://provider.invalid", 400, "bad request", None, io.BytesIO(raw_private_body))
    provider = _FailingProvider("local_llama_cpp", "qwen3-4b-q4-k-m", rejected)
    router = ModelRouter([provider])

    with pytest.raises(ProviderRequestRejected) as caught:
        router.generate([], timeout=2)

    assert caught.value.status_code == 400
    assert caught.value.attempts == (
        {"provider": "local_llama_cpp", "model": "qwen3-4b-q4-k-m", "kind": "REQUEST_REJECTED", "http_status": "400"},
    )
    assert "HTTP 400" in str(caught.value)
    assert "PRIVATE_PROVIDER_BODY_DO_NOT_PERSIST" not in str(caught.value)
    assert router.last_trace[0]["failure_kind"] == "REQUEST_REJECTED"
    assert router.last_trace[0]["http_status"] == 400
    assert isinstance(ModelRouter._classify(rejected, provider), ProviderRequestRejected)
    server_error = urllib.error.HTTPError("https://provider.invalid", 503, "unavailable", None, io.BytesIO(b"private"))
    assert isinstance(ModelRouter._classify(server_error, provider), ProviderFailure)


def test_router_fails_over_once_per_provider_with_shared_deadline_and_trusted_identity():
    import time

    calls: list[tuple[str, float | None]] = []

    class Provider:
        capabilities = ProviderCapabilities(generate=True)

        def __init__(self, name, model, error=None):
            self.name = name
            self.model = model
            self.error = error

        def generate(self, _messages, **kwargs):
            calls.append((self.name, kwargs.get("timeout")))
            if self.error is not None:
                time.sleep(0.01)
                raise self.error
            return {"content": "accepted", "provider": "forged", "model": "forged"}

    router = ModelRouter([
        Provider("first", "model-a", TimeoutError("private timeout detail")),
        Provider("second", "model-b"),
    ])

    result = router.generate([], timeout=3)

    assert result["content"] == "accepted"
    assert (result["provider"], result["model"]) == ("second", "model-b")
    assert [name for name, _timeout in calls] == ["first", "second"]
    assert calls[0][1] is not None and 0 < calls[0][1] <= 3
    assert calls[1][1] is not None and 0 < calls[1][1] <= calls[0][1]
    assert [item["status"] for item in router.last_trace] == ["failure", "success"]


def test_model_router_from_env_configures_local_qwen_compatible_endpoint_without_key(monkeypatch):
    for prefix in ("LOCAL", "COLAB", "HF"):
        for suffix in ("BASE_URL", "MODEL", "API_KEY", "TOOL_CALLING", "STREAMING", "STRUCTURED_OUTPUT", "PRIORITY"):
            monkeypatch.delenv(f"{prefix}_LLM_{suffix}", raising=False)
    for key in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "LLM_TOOL_CALLING", "LLM_STREAMING", "LLM_STRUCTURED_OUTPUT"):
        monkeypatch.delenv(key, raising=False)

    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "Qwen/Qwen3-Coder-Next")

    router = ModelRouter.from_env()

    assert len(router.providers) == 1
    provider = router.providers[0]
    assert provider.name == "local"
    assert provider.model == "Qwen/Qwen3-Coder-Next"
    assert provider.base_url == "http://127.0.0.1:8000/v1"
    assert provider.api_key == ""
    assert provider.capabilities.generate is True
    assert provider.capabilities.tool_calling is False


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
