from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import security.authorization as authorization_module
import tools.registry as registry_module
from agent.context import RuntimeLimits
from agent.model_router import ModelRouter
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import ModelTurn, RouterNativeModel, ToolCallProposal, model_turn_from_provider
from agent.planning import Plan, PlanStep
from agent.provider_api import MAX_PROVIDER_CALL_ID_CHARS, InvalidModelResponse, ProviderCapabilities, ProviderTimeout
from runtime_authorization import make_test_snapshot, mission_model_tools
from tools.registry import ToolSpec


def _runtime_and_mission(tmp_path: Path, limits: RuntimeLimits) -> tuple[MissionRuntime, Any]:
    objective = "enforce V11 mission resource budgets"
    runtime = MissionRuntime(
        MissionStore(tmp_path / "missions.sqlite3"),
        executor=lambda *_args: {},
        authorization_snapshot_factory=make_test_snapshot,
        runtime_limits=limits,
    )
    plan = Plan.initial(objective).replan(
        steps=(PlanStep("v11-budget-step", "run a bounded tool", action="status"),),
        reason="V11 resource-boundary test",
    )
    mission = runtime.create(
        objective,
        "v11-budget-request",
        plan,
        completion_criteria=[{"criterion_id": "v11-budget-goal"}],
    )
    return runtime, mission


def _proposal(mission: Any, run_id: str, turn_id: str, suffix: str) -> ToolCallProposal:
    return ToolCallProposal.create(
        "status",
        {},
        mission_id=mission.mission_id,
        run_id=run_id,
        turn_id=turn_id,
        request_id=mission.request_id,
        plan_version=mission.plan.version,
        tool_call_id=f"v11-budget-{suffix}",
    )


def _allow(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
    return SimpleNamespace(allowed=True, reason="test authorization", decision=None)


def test_bounded_result_preserves_small_values_and_summarizes_oversized_output():
    small = {"ok": True, "items": [1, 2, 3]}
    assert registry_module.bounded_result(small, 128) == (small, False)

    bounded, truncated = registry_module.bounded_result(
        {"ok": True, "payload": "sensitive-output" * 2_000},
        128,
    )
    assert truncated is True
    assert bounded["ok"] is True
    assert bounded["truncated"] is True
    assert len(bounded["prefix_sha256"]) == 64
    assert "payload" not in bounded
    size, _digest, is_truncated = registry_module.canonical_json_stats(bounded)
    assert size <= 128
    assert is_truncated is False


def test_registry_result_cap_is_validated_before_handler_dispatch(monkeypatch):
    calls: list[str | None] = []
    spec = ToolSpec(
        "v11_budget_probe",
        "test-only result-cap probe",
        "analysis",
        False,
        None,
        lambda _argument: calls.append("called") or {"ok": True, "payload": "x" * 10_000},
    )
    monkeypatch.setattr(registry_module, "get_tool", lambda name: spec if name == spec.name else None)

    with pytest.raises(ValueError, match="max_result_chars"):
        registry_module.execute(spec.name, max_result_chars=127)
    with pytest.raises(ValueError, match="timeout"):
        registry_module.execute(spec.name, timeout=float("nan"))
    assert calls == []

    result = registry_module.execute(spec.name, max_result_chars=128)
    assert result["ok"] is True
    assert result["truncated"] is True
    assert len(result["prefix_sha256"]) == 64
    assert calls == ["called"]


def test_model_text_over_total_output_budget_is_not_persisted(tmp_path):
    runtime, mission = _runtime_and_mission(tmp_path, RuntimeLimits(max_total_output_chars=128))

    class OversizedFinalModel:
        calls = 0

        def complete(self, _messages, _tools, *, turn_id, **_kwargs):
            self.calls += 1
            return ModelTurn(turn_id, content="x" * 129)

    model = OversizedFinalModel()
    result = runtime.run_model_loop(mission.mission_id, model, tools=[], max_turns=1)

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_total_output_chars"
    assert model.calls == 1
    assert result.progress["model_loop"]["turns"] == []
    assert not any(event["event"] == "ModelTurn" for event in result.trajectory)


def test_parallel_result_reservations_block_before_any_authorization_or_dispatch(tmp_path, monkeypatch):
    authorizations: list[Any] = []
    dispatches: list[Any] = []
    monkeypatch.setattr(
        authorization_module,
        "authorize_tool",
        lambda *args, **kwargs: authorizations.append((args, kwargs)) or _allow(),
    )
    monkeypatch.setattr(
        registry_module,
        "execute",
        lambda *args, **kwargs: dispatches.append((args, kwargs)) or {"ok": True},
    )
    runtime, mission = _runtime_and_mission(
        tmp_path,
        RuntimeLimits(max_total_output_chars=450, max_tool_calls=10, max_execution_steps=10),
    )

    class ThreeCallModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(
                turn_id,
                tool_calls=tuple(
                    _proposal(mission, run_id, turn_id, f"parallel-{index}")
                    for index in range(3)
                ),
            )

    result = runtime.run_model_loop(
        mission.mission_id,
        ThreeCallModel(),
        tools=mission_model_tools("status"),
        max_turns=1,
    )

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_total_output_chars"
    assert authorizations == []
    assert dispatches == []
    assert result.progress["model_loop"]["turns"] == []
    assert result.progress["model_loop"]["seen_call_ids"] == []


def test_mission_dispatch_passes_result_and_deadline_caps_to_registry(tmp_path, monkeypatch):
    dispatches: list[dict[str, Any]] = []
    monkeypatch.setattr(authorization_module, "authorize_tool", _allow)
    monkeypatch.setattr(
        registry_module,
        "execute",
        lambda *_args, **kwargs: dispatches.append(kwargs) or {"ok": True},
    )
    runtime, mission = _runtime_and_mission(
        tmp_path,
        RuntimeLimits(
            max_total_output_chars=512,
            max_result_chars=1_000,
            max_tool_calls=1,
            max_execution_steps=1,
        ),
    )

    class OneCallModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, tool_calls=(_proposal(mission, run_id, turn_id, "caps"),))

    result = runtime.run_model_loop(
        mission.mission_id,
        OneCallModel(),
        tools=mission_model_tools("status"),
        max_turns=1,
    )

    assert len(dispatches) == 1
    assert 128 <= dispatches[0]["max_result_chars"] <= 1_000
    assert 0 < dispatches[0]["timeout"] <= 30
    assert result.progress["model_loop"]["tool_results"]


def test_execution_step_cap_blocks_model_proposal_before_dispatch(tmp_path, monkeypatch):
    dispatches: list[Any] = []
    monkeypatch.setattr(authorization_module, "authorize_tool", _allow)
    monkeypatch.setattr(
        registry_module,
        "execute",
        lambda *args, **kwargs: dispatches.append((args, kwargs)) or {"ok": True},
    )
    runtime, mission = _runtime_and_mission(
        tmp_path,
        RuntimeLimits(max_execution_steps=0, max_tool_calls=10),
    )

    class OneCallModel:
        calls = 0

        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            self.calls += 1
            return ModelTurn(turn_id, tool_calls=(_proposal(mission, run_id, turn_id, "step"),))

    model = OneCallModel()
    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=mission_model_tools("status"),
        max_turns=1,
    )

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_execution_steps"
    assert model.calls == 0
    assert dispatches == []
    assert result.progress["model_loop"]["turns"] == []


def test_monotonic_deadline_expiry_after_provider_response_prevents_tool_dispatch(tmp_path, monkeypatch):
    import agent.mission_runtime as mission_runtime_module

    dispatches: list[Any] = []
    monkeypatch.setattr(authorization_module, "authorize_tool", _allow)
    monkeypatch.setattr(
        registry_module,
        "execute",
        lambda *args, **kwargs: dispatches.append((args, kwargs)) or {"ok": True},
    )
    runtime, mission = _runtime_and_mission(
        tmp_path,
        RuntimeLimits(max_execution_time_seconds=60, max_tool_calls=1, max_execution_steps=1),
    )
    clock_values = iter((100.0, 100.0, 100.0, 161.0))
    monkeypatch.setattr(
        mission_runtime_module,
        "time",
        SimpleNamespace(monotonic=lambda: next(clock_values)),
    )

    class OneCallModel:
        calls = 0

        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            self.calls += 1
            return ModelTurn(turn_id, tool_calls=(_proposal(mission, run_id, turn_id, "expired"),))

    model = OneCallModel()
    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=mission_model_tools("status"),
        max_turns=1,
    )

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_execution_time_seconds"
    assert model.calls == 1
    assert dispatches == []
    assert result.progress["model_loop"]["turns"] == []


def test_zero_execution_time_budget_blocks_before_provider_call(tmp_path):
    runtime, mission = _runtime_and_mission(tmp_path, RuntimeLimits(max_execution_time_seconds=0))

    class MustNotCallModel:
        calls = 0

        def complete(self, *_args, **_kwargs):
            self.calls += 1
            raise AssertionError("zero execution-time budget must block provider dispatch")

    model = MustNotCallModel()
    result = runtime.run_model_loop(mission.mission_id, model, tools=[], max_turns=1)

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_execution_time_seconds"
    assert model.calls == 0


def test_router_native_model_forwards_remaining_time_to_router():
    timeouts: list[float] = []

    class Router:
        def tool_calling(self, _messages, _tools, *, timeout):
            timeouts.append(timeout)
            return {
                "content": "bounded response",
                "tool_calls": [],
                "provider": "test-provider",
                "model": "test-model",
                "capability": "tool_calling",
            }

        def generate(self, *_args, **_kwargs):
            raise AssertionError("tool-call capability should not fall back")

    class InheritedRouterNativeModel(RouterNativeModel):
        pass

    model = InheritedRouterNativeModel(Router())
    turn = model.complete(
        [],
        [],
        mission_id="mission",
        run_id="run",
        turn_id="turn",
        plan_version=1,
        timeout_seconds=2.5,
    )

    assert timeouts == [2.5]
    assert turn.provider == "test-provider"
    assert turn.model == "test-model"
    assert MissionRuntime._bind_model_provenance(model, turn) == turn


def test_router_native_model_subclass_cannot_override_trusted_completion():
    class OverriddenRouterNativeModel(RouterNativeModel):
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version, timeout_seconds=None):
            return ModelTurn(
                turn_id,
                provider="attacker-controlled-provider",
                model="attacker-controlled-model",
                capability="tool_calling",
            )

    adapter = OverriddenRouterNativeModel(object())
    with pytest.raises(InvalidModelResponse, match="overrides trusted completion"):
        MissionRuntime._bind_model_provenance(adapter, ModelTurn("turn"))


def test_model_router_shares_one_monotonic_deadline_across_provider_failover(monkeypatch):
    import agent.model_router as model_router_module

    observed_timeouts: list[float] = []

    class FailingProvider:
        def __init__(self, name: str):
            self.name = name
            self.model = f"{name}-model"
            self.capabilities = ProviderCapabilities(tool_calling=True)

        def tool_calling(self, _messages, _tools, *, timeout, **_kwargs):
            observed_timeouts.append(timeout)
            raise TimeoutError("simulated provider timeout")

    clock_values = iter((100.0, 100.0, 104.0, 105.0))
    monkeypatch.setattr(
        model_router_module,
        "time",
        SimpleNamespace(monotonic=lambda: next(clock_values)),
    )
    router = ModelRouter([FailingProvider("first"), FailingProvider("second")])

    with pytest.raises(ProviderTimeout):
        router.tool_calling([], [], timeout=5.0)

    assert observed_timeouts == [5.0, 1.0]


def test_caller_max_turns_is_clamped_to_owner_execution_steps(tmp_path, monkeypatch):
    dispatches: list[Any] = []
    monkeypatch.setattr(authorization_module, "authorize_tool", _allow)
    monkeypatch.setattr(
        registry_module,
        "execute",
        lambda *args, **kwargs: dispatches.append((args, kwargs)) or {"ok": True},
    )
    limits = RuntimeLimits(
        max_execution_steps=1,
        max_tool_calls=10,
        max_same_tool_calls=10,
    )
    runtime, mission = _runtime_and_mission(tmp_path, limits)

    class RepeatingToolModel:
        calls = 0

        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            self.calls += 1
            return ModelTurn(
                turn_id,
                tool_calls=(_proposal(mission, run_id, turn_id, f"clamped-{self.calls}"),),
            )

    model = RepeatingToolModel()
    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=mission_model_tools("status"),
        max_turns=100,
    )

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_execution_steps"
    assert model.calls == 1
    assert len(dispatches) == 1
    assert len(result.progress["model_loop"]["turns"]) == 1


def test_persisted_model_turn_count_blocks_new_runtime_before_provider(tmp_path):
    limits = RuntimeLimits(max_execution_steps=1)
    runtime, mission = _runtime_and_mission(tmp_path, limits)
    mission.progress["model_loop"] = {
        "turns": [{"turn_id": "prior-turn", "content": "already consumed", "tool_calls": []}],
        "tool_results": [],
        "seen_call_ids": [],
    }
    runtime._save(mission)
    restarted = MissionRuntime(
        MissionStore(tmp_path / "missions.sqlite3"),
        executor=lambda *_args: {},
        authorization_snapshot_factory=make_test_snapshot,
        runtime_limits=RuntimeLimits(max_execution_steps=100),
    )

    class MustNotCallModel:
        calls = 0

        def complete(self, *_args, **_kwargs):
            self.calls += 1
            raise AssertionError("persisted Owner turn budget must block before provider dispatch")

    model = MustNotCallModel()
    result = restarted.run_model_loop(mission.mission_id, model, tools=[], max_turns=100)

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_execution_steps"
    assert model.calls == 0
    assert len(result.progress["model_loop"]["turns"]) == 1
    assert result.provenance["owner_runtime_limits"]["max_execution_steps"] == 1


def test_total_output_budget_is_cumulative_across_model_turns(tmp_path, monkeypatch):
    dispatches: list[Any] = []
    monkeypatch.setattr(authorization_module, "authorize_tool", _allow)
    monkeypatch.setattr(
        registry_module,
        "execute",
        lambda *args, **kwargs: dispatches.append((args, kwargs)) or {"ok": True},
    )
    runtime, mission = _runtime_and_mission(
        tmp_path,
        RuntimeLimits(
            max_total_output_chars=500,
            max_tool_calls=10,
            max_same_tool_calls=10,
            max_execution_steps=10,
        ),
    )

    class RepeatingOutputModel:
        calls = 0

        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            self.calls += 1
            return ModelTurn(
                turn_id,
                content="r" * 80,
                tool_calls=(_proposal(mission, run_id, turn_id, f"output-{self.calls}"),),
            )

    model = RepeatingOutputModel()
    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=mission_model_tools("status"),
        max_turns=10,
    )

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_total_output_chars"
    assert len(result.progress["model_loop"]["turns"]) == 2
    assert model.calls == 3
    assert len(dispatches) == 2
    used, exceeded = MissionRuntime._output_usage(
        result.progress["model_loop"],
        500,
    )
    assert not exceeded
    assert used < 500


@pytest.mark.parametrize("call_id", [None, "", "   ", 7, "x" * (MAX_PROVIDER_CALL_ID_CHARS + 1)])
def test_provider_adapter_rejects_missing_or_malformed_call_id(call_id):
    with pytest.raises(InvalidModelResponse, match="tool-call identity"):
        model_turn_from_provider(
            {"tool_calls": [{"id": call_id, "name": "status", "arguments": {}}]},
            mission_id="mission",
            run_id="run",
            turn_id="turn",
            request_id="request",
            plan_version=1,
        )


def test_parallel_authorization_expiry_stages_ids_until_batch_deadline_gate(tmp_path, monkeypatch):
    import agent.mission_runtime as mission_runtime_module

    dispatches: list[Any] = []
    clock = {"now": 100.0}
    monkeypatch.setattr(
        mission_runtime_module,
        "time",
        SimpleNamespace(monotonic=lambda: clock["now"]),
    )
    authorizations: list[str] = []
    runtime, mission = _runtime_and_mission(
        tmp_path,
        RuntimeLimits(
            max_execution_time_seconds=1,
            max_total_output_chars=2_000,
            max_tool_calls=10,
            max_execution_steps=10,
        ),
    )
    active_mission: dict[str, Any] = {}
    original_parallel = runtime._run_parallel_model_calls

    def inspect_staged_batch(live_mission, *args, **kwargs):
        active_mission["value"] = live_mission
        return original_parallel(live_mission, *args, **kwargs)

    runtime._run_parallel_model_calls = inspect_staged_batch

    def authorize(*_args, **_kwargs):
        authorizations.append(str(len(authorizations)))
        assert active_mission["value"].progress["model_loop"]["seen_call_ids"] == []
        if len(authorizations) == 1:
            clock["now"] = 102.0
        return _allow()

    monkeypatch.setattr(authorization_module, "authorize_tool", authorize)
    monkeypatch.setattr(
        registry_module,
        "execute",
        lambda *args, **kwargs: dispatches.append((args, kwargs)) or {"ok": True},
    )

    class ThreeCallModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version, **_kwargs):
            return ModelTurn(
                turn_id,
                tool_calls=tuple(
                    _proposal(mission, run_id, turn_id, f"deadline-{index}")
                    for index in range(3)
                ),
            )

    result = runtime.run_model_loop(
        mission.mission_id,
        ThreeCallModel(),
        tools=mission_model_tools("status"),
        max_turns=3,
    )

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_execution_time_seconds"
    assert len(authorizations) == 3
    assert dispatches == []
    assert len(result.progress["model_loop"]["seen_call_ids"]) == 3
    assert len(result.progress["model_loop"]["tool_results"]) == 3
    assert all("deadline expired before parallel dispatch" in item["error"] for item in result.progress["model_loop"]["tool_results"])


def test_accepted_serial_turn_and_checkpoint_are_persisted_before_dispatch(tmp_path, monkeypatch):
    monkeypatch.setattr(authorization_module, "authorize_tool", _allow)
    runtime, mission = _runtime_and_mission(
        tmp_path,
        RuntimeLimits(max_execution_steps=3, max_tool_calls=1),
    )
    observed: list[dict[str, Any]] = []

    def execute_spy(*_args, **_kwargs):
        persisted = runtime.store.load(mission.mission_id)
        assert persisted is not None
        observed.append(
            {
                "turns": list(persisted.progress["model_loop"]["turns"]),
                "seen": list(persisted.progress["model_loop"]["seen_call_ids"]),
                "checkpoint": dict(persisted.checkpoint),
            }
        )
        return {"ok": True}

    monkeypatch.setattr(registry_module, "execute", execute_spy)

    class OneCallModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, tool_calls=(_proposal(mission, run_id, turn_id, "persisted"),))

    result = runtime.run_model_loop(
        mission.mission_id,
        OneCallModel(),
        tools=mission_model_tools("status"),
        max_turns=1,
    )

    assert len(observed) == 1
    assert len(observed[0]["turns"]) == 1
    assert len(observed[0]["seen"]) == 1
    assert observed[0]["checkpoint"]["status"] == "in_flight"
    assert result.progress["model_loop"]["seen_call_ids"] == observed[0]["seen"]
