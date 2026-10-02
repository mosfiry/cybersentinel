from __future__ import annotations

"""Provider / model runtime contract battery (V9).

Model failure is data: every provider failure must be classified, recorded on
the mission, and routed through the bounded recovery policy. A provider
failure must never become fake success or false completion.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from runtime_authorization import make_test_snapshot, signed_test_owner_kwargs

from agent.model_protocol import ConversationTurn, RouterNativeModel
from agent.model_router import ModelRouter
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import FailureClass, Plan, PlanStep
from agent.provider_api import (
    CapabilityUnsupported,
    ProviderCapabilities,
    ProviderError,
    ProviderFailure,
    ProviderFailureKind,
    ProviderTimeout,
    response_from_legacy,
)


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime, tmp_path, monkeypatch, request_id="provider-failure-test"):
    plan = Plan.initial("provider failure mission").replan(
        steps=(PlanStep("observe", "observe", action="status"),),
        reason="test",
    )
    return runtime.create(
        "provider failure mission",
        "provider failure mission",
        plan,
        completion_criteria=[{"criterion_id": "goal", "check": "system_online"}],
        **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id=request_id),
    )


class _TimeoutModel:
    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        raise ProviderTimeout("provider timed out", provider="stub", model="stub-model")


class _InvalidSchemaModel:
    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        raise ProviderError(ProviderFailureKind.INVALID_MODEL_RESPONSE, "schema violation", provider="stub", model="stub-model")


class _TimeoutThenFinalModel:
    def __init__(self):
        self.count = 0

    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        self.count += 1
        if self.count == 1:
            raise ProviderTimeout("provider timed out", provider="stub", model="stub-model")
        from agent.model_protocol import ModelTurn

        return ModelTurn(turn_id, content="recovered after timeout", finish_reason="stop")


def test_provider_timeout_is_recorded_as_data_and_never_completes(tmp_path, monkeypatch):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, tmp_path, monkeypatch)
    result = runtime.run_model_loop(mission.mission_id, _TimeoutModel(), tools=[], max_turns=10)
    assert result.status is not MissionStatus.GOAL_COMPLETED
    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED, "bounded retry must terminate honestly"
    assert result.failures, "the failure must be recorded as data"
    assert result.failures[0]["class"] == FailureClass.PROVIDER.value
    assert result.failures[0]["kind"] == "TIMEOUT"
    assert result.progress["model_failures"][0]["kind"] == "TIMEOUT"
    assert "model provider failure" in result.error
    assert not result.completion_proof


def test_invalid_model_response_kind_is_recorded_distinctly(tmp_path, monkeypatch):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, tmp_path, monkeypatch, request_id="provider-schema-test")
    result = runtime.run_model_loop(mission.mission_id, _InvalidSchemaModel(), tools=[], max_turns=10)
    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert result.failures[0]["class"] == FailureClass.PROVIDER.value
    assert result.failures[0]["kind"] == "INVALID_MODEL_RESPONSE", "schema failure is never conflated with transport failure"
    assert result.progress["model_failures"][0]["kind"] == "INVALID_MODEL_RESPONSE"


def test_single_timeout_is_retried_and_recorded_without_fake_success(tmp_path, monkeypatch):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, tmp_path, monkeypatch, request_id="provider-retry-test")
    result = runtime.run_model_loop(mission.mission_id, _TimeoutThenFinalModel(), tools=[], max_turns=6)
    assert result.failures and result.failures[0]["kind"] == "TIMEOUT"
    assert result.retry_count >= 1
    assert result.status is not MissionStatus.GOAL_COMPLETED, "a model final claim without deterministic evidence never completes"
    assert not result.completion_proof


def test_router_classifies_transport_failures():
    provider = SimpleNamespace(name="p", model="m")
    assert ModelRouter(providers=[])._classify(TimeoutError("t"), provider).kind is ProviderFailureKind.TIMEOUT
    assert ModelRouter(providers=[])._classify(PermissionError("a"), provider).kind is ProviderFailureKind.AUTHENTICATION_FAILURE
    assert ModelRouter(providers=[])._classify(ValueError("v"), provider).kind is ProviderFailureKind.INVALID_MODEL_RESPONSE
    assert ModelRouter(providers=[])._classify(RuntimeError("x"), provider).kind is ProviderFailureKind.PROVIDER_FAILURE
    typed = ProviderError(ProviderFailureKind.INVALID_MODEL_RESPONSE, "already typed")
    assert ModelRouter(providers=[])._classify(typed, provider) is typed, "typed provider errors pass through unchanged"


class _StubProvider:
    def __init__(self, name, behavior):
        self.name = name
        self.model = name + "-model"
        self.capabilities = ProviderCapabilities()
        self.behavior = behavior

    def generate(self, messages, temperature=None, **kwargs):
        return self.behavior(messages)


def _boom(messages):
    raise RuntimeError("connection refused")


def test_router_fails_over_and_records_failure_trace():
    router = ModelRouter(providers=[_StubProvider("first", _boom), _StubProvider("second", lambda m: {"content": "ok"})])
    response = router.generate([{"role": "user", "content": "hi"}])
    assert response["provider"] == "second"
    assert response["content"] == "ok"
    assert router.last_trace[0]["status"] == "failure"
    assert router.last_trace[0]["failure_kind"] == "PROVIDER_FAILURE"
    assert router.last_trace[1]["status"] == "success"


def test_router_all_providers_failed_raises_without_fake_success():
    router = ModelRouter(providers=[_StubProvider("a", _boom), _StubProvider("b", _boom)])
    with pytest.raises(ProviderFailure):
        router.generate([{"role": "user", "content": "hi"}])


def test_router_tool_calling_without_capability_is_rejected():
    router = ModelRouter(providers=[])
    with pytest.raises(CapabilityUnsupported):
        router.tool_calling([{"role": "user", "content": "hi"}], [{"name": "status"}])


class _ToollessRouter:
    def tool_calling(self, messages, tools):
        raise CapabilityUnsupported("no native tool calling")

    def generate(self, messages):
        return {"content": "text-only", "provider": "stub", "model": "stub-model"}


def test_native_adapter_falls_back_to_generate_only_on_capability_unsupported():
    native = RouterNativeModel(_ToollessRouter())
    turn = native.complete([ConversationTurn(role="user", content="hi")], [], mission_id="m", run_id="r", turn_id="t", plan_version=1)
    assert turn.content == "text-only"
    assert not turn.tool_calls


class _FailingToolRouter:
    def tool_calling(self, messages, tools):
        raise ProviderFailure("provider down")

    def generate(self, messages):
        raise AssertionError("a real provider failure must never be disguised as a generate() response")


def test_native_adapter_never_disguises_real_provider_failure():
    native = RouterNativeModel(_FailingToolRouter())
    with pytest.raises(ProviderFailure):
        native.complete([ConversationTurn(role="user", content="hi")], [], mission_id="m", run_id="r", turn_id="t", plan_version=1)


def test_legacy_response_normalization_is_deterministic_for_malformed_calls():
    response = response_from_legacy(
        {
            "content": "x",
            "tool_calls": [
                "not-a-dict",
                {"function": {"name": "t", "arguments": "{broken json"}},
                {"function": {"name": "u", "arguments": [1, 2]}},
                {"function": {"arguments": {"name": "missing"}}},
            ],
        },
        provider="p",
        model="m",
    )
    assert [call.name for call in response.tool_calls] == ["t", "u"]
    assert response.tool_calls[0].arguments == {}
    assert response.tool_calls[1].arguments == {}
