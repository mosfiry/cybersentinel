from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from agent.context import RuntimeLimits
from agent.intelligence_layer.graph import AgentGraphPolicy
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep, RecoveryPolicy
from agent.provider_api import InvalidModelResponse, ProviderAuthenticationFailure, ProviderFailure, ProviderRequestRejected
from runtime_authorization import make_test_snapshot


class AlwaysFailingModel:
    def __init__(self, error_factory):
        self.error_factory = error_factory
        self.calls = []

    def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
        self.calls.append((mission_id, run_id, turn_id, plan_version))
        raise self.error_factory()


def test_strict_model_adapter_must_accept_owner_timeout_before_call():
    calls = []

    class UnboundedModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            calls.append((mission_id, run_id, turn_id, plan_version))
            raise AssertionError("unbounded model must not be called by strict runtime")

    with pytest.raises(InvalidModelResponse, match="does not accept the Owner execution timeout"):
        MissionRuntime._complete_with_timeout(
            UnboundedModel(),
            [],
            [],
            mission_id="bounded-mission",
            run_id="bounded-run",
            turn_id="bounded-turn",
            plan_version=1,
            timeout_seconds=1.0,
            require_timeout=True,
        )

    assert calls == []


def _runtime(
    tmp_path: Path,
    *,
    max_retries: int = 2,
    runtime_limits: RuntimeLimits | None = None,
    task_graph_policy: AgentGraphPolicy | None = None,
) -> MissionRuntime:
    return MissionRuntime(
        MissionStore(tmp_path / "missions.sqlite3"),
        executor=lambda *_args: {},
        recovery_policy=RecoveryPolicy(max_retries=max_retries),
        authorization_snapshot_factory=make_test_snapshot,
        runtime_limits=runtime_limits,
        task_graph_policy=task_graph_policy,
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


def _two_step_status_mission(runtime: MissionRuntime, request_id: str):
    objective = "collect and independently confirm two local status observations"
    plan = Plan.initial(objective).replan(steps=(
        PlanStep("status-1", "collect the first local status observation", action="status"),
        PlanStep("status-2", "collect the second local status observation", action="status"),
    ))
    return runtime.create("run two local status checks", objective, plan, request_id=request_id)


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


def test_owner_runtime_retry_limit_caps_execution_and_task_graph_retries(tmp_path):
    runtime = _runtime(
        tmp_path,
        max_retries=5,
        runtime_limits=RuntimeLimits(max_retries=1),
        task_graph_policy=AgentGraphPolicy(max_retries=5),
    )
    assert runtime.recovery_policy.max_retries == 1
    assert runtime.task_graph_adapter is not None
    assert runtime.task_graph_adapter.policy.max_retries == 1
    mission = _ready_mission(runtime)
    model = AlwaysFailingModel(
        lambda: ProviderFailure(
            "private provider detail",
            provider="local_llama_cpp",
            model="qwen3-4b-q4-k-m",
        )
    )

    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=[],
        run_id="owner-retry-cap-regression",
        max_turns=8,
    )

    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert result.retry_count == 2  # one initial attempt plus exactly one Owner-authorized retry
    assert len(model.calls) == 2
    assert len(result.failures) == 2
    assert len([item for item in result.transitions if item["reason"] == "provider failure; bounded retry selected"]) == 1


def test_compatibility_run_to_completion_stops_at_owner_execution_step_limit(tmp_path):
    runtime = _runtime(
        tmp_path,
        runtime_limits=RuntimeLimits(max_execution_steps=1, max_execution_time_seconds=300),
    )
    dispatched = []
    runtime.executor = lambda _mission, step, _action_id: dispatched.append(step.step_id) or {
        "success": True,
        "result": {"online": True},
    }
    mission = _two_step_status_mission(runtime, "compatibility-owner-step-cap")

    result = runtime.run_to_completion(mission.mission_id, max_slices=10)

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_execution_steps"
    assert result.failures[-1]["limit"] == 1
    assert dispatched == ["status-1"]
    assert result.iteration_count == 1
    assert result.provenance["owner_runtime_limits"] == {
        "max_execution_steps": 1,
        "max_execution_time_seconds": 300,
    }


def test_compatibility_run_to_completion_stops_after_owner_wall_clock_budget(tmp_path):
    runtime = _runtime(
        tmp_path,
        runtime_limits=RuntimeLimits(max_execution_steps=5, max_execution_time_seconds=1),
    )
    dispatched = []
    observed_timeouts = []

    def slow_local_tool(_mission, step, _action_id, *, timeout_seconds):
        dispatched.append(step.step_id)
        observed_timeouts.append(timeout_seconds)
        time.sleep(timeout_seconds)
        return {"success": True, "result": {"online": True}}

    runtime.executor = slow_local_tool
    mission = _two_step_status_mission(runtime, "compatibility-owner-time-cap")

    result = runtime.run_to_completion(mission.mission_id, max_slices=10)

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_execution_time_seconds"
    assert result.failures[-1]["limit"] == 1
    assert dispatched == ["status-1"]
    assert len(observed_timeouts) == 1
    assert 0 < observed_timeouts[0] <= 1


def test_owner_wall_clock_deadline_persists_across_compatibility_resumption(tmp_path):
    runtime = _runtime(
        tmp_path,
        runtime_limits=RuntimeLimits(max_execution_steps=5, max_execution_time_seconds=1),
    )
    dispatched = []

    def quick_local_tool(_mission, step, _action_id, *, timeout_seconds):
        assert 0 < timeout_seconds <= 1
        dispatched.append(step.step_id)
        time.sleep(0.05)
        return {"success": True, "result": {"online": True}}

    runtime.executor = quick_local_tool
    mission = _two_step_status_mission(runtime, "compatibility-owner-resume-time-cap")

    first = runtime.run_to_completion(mission.mission_id, max_slices=1)
    assert not first.is_terminal
    assert first.progress.get("owner_execution_started_at_epoch") is not None
    assert dispatched == ["status-1"]

    time.sleep(1.05)
    resumed = runtime.run_to_completion(mission.mission_id, max_slices=1)

    assert resumed.status is MissionStatus.RESOURCE_BLOCKED
    assert resumed.failures[-1]["budget"] == "max_execution_time_seconds"
    assert dispatched == ["status-1"]


def test_owner_wall_clock_deadline_persists_across_native_model_loop_calls(tmp_path):
    runtime = _runtime(
        tmp_path,
        max_retries=5,
        runtime_limits=RuntimeLimits(max_execution_steps=5, max_execution_time_seconds=1),
    )
    mission = _ready_mission(runtime)
    model = AlwaysFailingModel(
        lambda: ProviderFailure(
            "temporary provider failure",
            provider="local_llama_cpp",
            model="qwen3-4b-q4-k-m",
            attempts=[{"provider": "local_llama_cpp", "model": "qwen3-4b-q4-k-m", "kind": "PROVIDER_FAILURE"}],
        )
    )

    first = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=[],
        run_id="owner-time-budget-first-call",
        max_turns=1,
    )
    assert not first.is_terminal
    assert len(model.calls) == 1
    assert first.progress.get("owner_execution_started_at_epoch") is not None

    time.sleep(1.05)
    resumed = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=[],
        run_id="owner-time-budget-resumed-call",
        max_turns=1,
    )

    assert resumed.status is MissionStatus.RESOURCE_BLOCKED
    assert resumed.failures[-1]["budget"] == "max_execution_time_seconds"
    assert len(model.calls) == 1


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


def test_verified_evidence_completes_when_final_model_context_is_over_budget(tmp_path):
    store = MissionStore(tmp_path / "verified-context-budget.sqlite3")
    runtime = MissionRuntime(
        store,
        executor=lambda *_args: {},
        recovery_policy=RecoveryPolicy(max_retries=2),
        authorization_snapshot_factory=make_test_snapshot,
        runtime_limits=RuntimeLimits(max_context_chars=1),
    )
    mission = runtime.create(
        "check status",
        "check status",
        Plan.initial("check status"),
        request_id="verified-context-budget-request",
        completion_criteria=[{"criterion_id": "status-snapshot", "check": "status_snapshot"}],
    )
    mission.evidence.append({
        "criterion_id": "status-snapshot",
        "passed": True,
        "source": "status",
        "result": {"online": True},
        "provenance": {"mission_id": mission.mission_id, "tool_call_id": "verified-status-call"},
    })
    store.save(mission)
    model = AlwaysFailingModel(lambda: AssertionError("budget must prevent provider dispatch"))

    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=[],
        run_id="verified-context-budget-run",
    )

    assert model.calls == []
    assert result.status is MissionStatus.GOAL_COMPLETED
    assert result.verification_state == {"verified": True, "missing_criteria": [], "evidence_count": 1}
    assert result.retry_count == 0
    assert result.evidence[0]["provenance"]["tool_call_id"] == "verified-status-call"
    failure = result.failures[0]
    assert failure["class"] == "RESOURCE"
    assert failure["kind"] == "FINAL_MODEL_TURN_BUDGET"
    assert failure["blocking"] is False
    assert failure["run_id"] == "verified-context-budget-run"
    assert failure["turn_id"] == "verified-context-budget-run:turn:1"
    assert failure["retry_policy"] == {
        "configured_recovery": "RESOURCE_BLOCKED",
        "action": "complete_from_verified_evidence",
        "retryable": False,
        "attempts": 0,
    }
    assert result.progress["final_model_turn"]["status"] == "not_generated_resource_limited"
    assert any(item.get("event") == "GoalVerified" for item in result.trajectory)
    assert any(item.get("event") == "MissionCompleted" for item in result.trajectory)
    persisted = MissionStore(tmp_path / "verified-context-budget.sqlite3").load(mission.mission_id)
    assert persisted is not None and persisted.status is MissionStatus.GOAL_COMPLETED
    assert persisted.failures == result.failures
    assert persisted.evidence == result.evidence
