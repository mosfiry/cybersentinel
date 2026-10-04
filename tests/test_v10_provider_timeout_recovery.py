from __future__ import annotations

from agent.model_protocol import RouterNativeModel
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_router import ModelRouter
from agent.planning import Plan, PlanStep
from agent.provider_api import ProviderCapabilities, ProviderResponse
from runtime_authorization import make_test_snapshot, mission_model_tools


class _TimeoutOnceProvider:
    name = "v10-timeout-fixture"
    model = "v10-timeout-fixture-1"
    capabilities = ProviderCapabilities(generate=True, tool_calling=True, native_chat=True)

    def __init__(self):
        self.calls = 0

    def tool_calling(self, _messages, _tools, **_kwargs):
        self.calls += 1
        if self.calls == 1:
            raise TimeoutError("fixture timeout; details must not become mission evidence")
        return ProviderResponse(text="The observation is not independently verified.")

    def generate(self, *_args, **_kwargs):
        raise AssertionError("native tool-calling path should not fall back to generate")


def test_provider_timeout_persists_for_restart_and_later_call_is_fail_closed(tmp_path):
    db_path = tmp_path / "missions.sqlite3"
    store = MissionStore(db_path)
    runtime = MissionRuntime(
        store,
        executor=lambda *_args, **_kwargs: {},
        authorization_snapshot_factory=make_test_snapshot,
    )
    objective = "Verify the requested status after a recoverable provider timeout"
    plan = Plan.initial(objective).replan(
        steps=(PlanStep("observe", "Observe status", action="status"),),
        reason="V10 timeout recovery fixture",
    )
    mission = runtime.create(
        objective,
        objective,
        plan,
        completion_criteria=[{"criterion_id": "goal"}],
    )
    provider = _TimeoutOnceProvider()
    model = RouterNativeModel(ModelRouter([provider]))
    tools = mission_model_tools("status")

    after_timeout = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=tools,
        max_turns=1,
    )

    assert after_timeout.status is MissionStatus.READY
    assert not after_timeout.is_terminal
    assert after_timeout.retry_count == 1
    persisted = MissionStore(db_path).load(mission.mission_id)
    assert persisted.status is MissionStatus.READY
    assert persisted.retry_count == 1
    assert persisted.failures[-1]["class"] == "PROVIDER"
    assert persisted.failures[-1]["attempts"]
    assert persisted.failures[-1]["attempts"][0]["kind"] == "TIMEOUT"

    restarted_runtime = MissionRuntime(
        MissionStore(db_path),
        executor=lambda *_args, **_kwargs: {},
        authorization_snapshot_factory=make_test_snapshot,
    )
    resumed = restarted_runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=tools,
        max_turns=1,
    )

    assert provider.calls == 2
    assert resumed.status is MissionStatus.READY
    assert not resumed.is_terminal
    assert resumed.retry_count == 1
    assert resumed.error == "model final lacked deterministic goal evidence"
