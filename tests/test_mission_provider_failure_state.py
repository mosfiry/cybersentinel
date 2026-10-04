from __future__ import annotations

import json
from pathlib import Path

from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, RecoveryPolicy
from agent.provider_api import ProviderAuthenticationFailure, ProviderFailure, ProviderRequestRejected
from runtime_authorization import make_test_snapshot


class AlwaysFailingModel:
    def __init__(self, error_factory):
        self.error_factory = error_factory
        self.calls = []

    def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
        self.calls.append((mission_id, run_id, turn_id, plan_version))
        raise self.error_factory()


def _runtime(tmp_path: Path, *, max_retries: int = 2) -> MissionRuntime:
    return MissionRuntime(
        MissionStore(tmp_path / "missions.sqlite3"),
        executor=lambda *_args: {},
        recovery_policy=RecoveryPolicy(max_retries=max_retries),
        authorization_snapshot_factory=make_test_snapshot,
    )


def _ready_mission(runtime: MissionRuntime):
    plan = Plan.initial("check status and preserve verified evidence")
    mission = runtime.create(
        "check status",
        "check status and preserve verified evidence",
        plan,
        request_id="request-provider-failure-regression",
    )
    mission.evidence.append(
        {
            "criterion_id": "status-snapshot",
            "passed": True,
            "source": "status",
            "result": {"online": True},
            "provenance": {
                "mission_id": mission.mission_id,
                "request_id": mission.request_id,
                "tool_call_id": "verified-status-call",
            },
        }
    )
    runtime.store.save(mission)
    return mission


def test_retryable_provider_failures_are_correlated_and_exhaust_to_failed(tmp_path):
    runtime = _runtime(tmp_path, max_retries=2)
    mission = _ready_mission(runtime)
    private_error_body = "PRIVATE_PROVIDER_RESPONSE_MUST_NOT_BE_PERSISTED"
    model = AlwaysFailingModel(
        lambda: ProviderFailure(
            private_error_body,
            provider="local_llama_cpp",
            model="qwen3-4b-q4-k-m",
            attempts=[
                {
                    "provider": "local_llama_cpp",
                    "model": "qwen3-4b-q4-k-m",
                    "kind": "PROVIDER_FAILURE",
                }
            ],
        )
    )

    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=[],
        run_id="provider-failure-regression-run",
        max_turns=8,
    )

    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert result.error == "model provider failure: PROVIDER_FAILURE"
    assert result.retry_count == 3  # initial failed attempt plus two policy retries
    assert len(model.calls) == 3
    assert len(result.failures) == 3
    assert result.evidence == mission.evidence
    assert [item["provider_attempt"] for item in result.failures] == [1, 2, 3]
    for failure in result.failures:
        assert failure["mission_id"] == result.mission_id
        assert failure["request_id"] == "request-provider-failure-regression"
        assert failure["kind"] == "PROVIDER_FAILURE"
        assert failure["provider"] == "local_llama_cpp"
        assert failure["model"] == "qwen3-4b-q4-k-m"
        assert failure["run_id"] == "provider-failure-regression-run"
        assert failure["turn_id"] == "provider-failure-regression-run:turn:1"
        assert failure["attempts"] == [
            {
                "provider": "local_llama_cpp",
                "model": "qwen3-4b-q4-k-m",
                "kind": "PROVIDER_FAILURE",
            }
        ]
        assert failure["reason"] == "provider/model call failed"

    provider_starts = [item for item in result.transitions if item["reason"] == "provider attempt started"]
    retry_selections = [item for item in result.transitions if item["reason"] == "provider failure; bounded retry selected"]
    assert len(provider_starts) == 3
    assert len(retry_selections) == 2
    assert all(item["to"] == MissionStatus.RUNNING.value for item in provider_starts)
    assert all(item["from"] != item["to"] for item in result.transitions)
    assert all(item["data"]["run_id"] == "provider-failure-regression-run" for item in provider_starts)
    assert all(item["data"]["attempt_number"] == index for index, item in enumerate(retry_selections, start=1))
    assert all(
        not (item["from"] == MissionStatus.READY.value and item["to"] == MissionStatus.READY.value)
        for item in result.transitions
    )

    failure_events = [
        item for item in result.trajectory
        if isinstance(item.get("data"), dict)
        and item["data"].get("request_id") == "request-provider-failure-regression"
        and item["data"].get("class") == "PROVIDER"
    ]
    assert len(failure_events) == 3
    persisted = MissionStore(tmp_path / "missions.sqlite3").load(mission.mission_id)
    assert persisted is not None
    assert persisted.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert persisted.failures == result.failures
    assert persisted.evidence == result.evidence
    assert persisted.retry_count == 3
    assert private_error_body not in json.dumps(persisted.to_dict(), sort_keys=True)


def test_nonretryable_provider_authentication_failure_is_not_retried(tmp_path):
    runtime = _runtime(tmp_path, max_retries=5)
    mission = _ready_mission(runtime)
    auth_error = ProviderAuthenticationFailure(
        "credential failure detail is redacted",
        provider="local_llama_cpp",
        model="qwen3-4b-q4-k-m",
    )
    model = AlwaysFailingModel(lambda: auth_error)

    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=[],
        run_id="provider-auth-failure-run",
        max_turns=8,
    )

    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert result.retry_count == 1
    assert len(model.calls) == 1
    expected_kind = getattr(auth_error.kind, "value", auth_error.kind)
    assert result.failures[0]["kind"] == expected_kind
    assert result.failures[0]["provider"] == "local_llama_cpp"
    assert result.failures[0]["request_id"] == "request-provider-failure-regression"
    assert not any(
        item["reason"] == "provider failure; bounded retry selected"
        for item in result.transitions
    )


def test_nonretryable_http_request_rejection_preserves_status_and_mission_evidence(tmp_path):
    runtime = _runtime(tmp_path, max_retries=5)
    mission = _ready_mission(runtime)
    rejected = ProviderRequestRejected(
        "provider request rejected (HTTP 400)",
        provider="local_llama_cpp",
        model="qwen3-4b-q4-k-m",
        status_code=400,
        attempts=[{
            "provider": "local_llama_cpp",
            "model": "qwen3-4b-q4-k-m",
            "kind": "REQUEST_REJECTED",
            "http_status": "400",
        }],
    )
    model = AlwaysFailingModel(lambda: rejected)

    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=[],
        run_id="provider-http400-regression-run",
        max_turns=8,
    )

    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert result.retry_count == 1
    assert len(model.calls) == 1
    failure = result.failures[0]
    assert failure["kind"] == "REQUEST_REJECTED"
    assert failure["http_status"] == 400
    assert failure["reason"] == "provider request rejected (HTTP 400)"
    assert failure["request_id"] == "request-provider-failure-regression"
    assert failure["run_id"] == "provider-http400-regression-run"
    assert failure["turn_id"] == "provider-http400-regression-run:turn:1"
    assert failure["attempts"] == [{
        "provider": "local_llama_cpp",
        "model": "qwen3-4b-q4-k-m",
        "kind": "REQUEST_REJECTED",
        "http_status": "400",
    }]
    assert result.error == "model provider failure: REQUEST_REJECTED (HTTP 400)"
    assert result.evidence == mission.evidence
    assert not any(item["reason"] == "provider failure; bounded retry selected" for item in result.transitions)

    persisted = MissionStore(tmp_path / "missions.sqlite3").load(mission.mission_id)
    assert persisted is not None
    assert persisted.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert persisted.failures == result.failures
    assert persisted.evidence == mission.evidence
    assert persisted.retry_count == 1


def test_model_input_context_budget_uses_provider_limit(tmp_path):
    runtime = _runtime(tmp_path)

    class LocalModel:
        context_length = 4096

    assert runtime._context_limits(LocalModel()) == (8192, 50)
